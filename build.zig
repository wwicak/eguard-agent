const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const asm_optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const asm_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = target.result.os.tag,
        .abi = target.result.abi,
        .cpu_features_add = std.Target.x86.featureSet(&[_]std.Target.x86.Feature{ .aes, .sha }),
    });
    const all_artifacts = b.step("agent-artifacts", "Build eBPF and asm artifacts");

    const asm_step = b.step("asm-artifacts", "Build Zig asm static libraries");
    const ebpf_step = b.step("ebpf-artifacts", "Build eBPF object files (C via zig cc, BTF-enabled)");
    all_artifacts.dependOn(asm_step);
    all_artifacts.dependOn(ebpf_step);

    // ── Zig asm static libraries (AES-NI, SHA-NI, integrity) ────
    const asm_sources = [_]struct { name: []const u8, file: []const u8 }{
        .{ .name = "eguard_sha256_ni", .file = "zig/asm/sha256_ni.zig" },
        .{ .name = "eguard_aes_ni", .file = "zig/asm/aes_ni.zig" },
        .{ .name = "eguard_integrity", .file = "zig/asm/integrity.zig" },
    };

    for (asm_sources) |entry| {
        const module = b.createModule(.{
            .root_source_file = b.path(entry.file),
            .target = asm_target,
            .optimize = asm_optimize,
        });
        const lib = b.addLibrary(.{
            .name = entry.name,
            .root_module = module,
            .linkage = .static,
        });
        b.installArtifact(lib);
        asm_step.dependOn(&lib.step);
    }

    // ── eBPF probes (C sources compiled via `zig cc -target bpfel`) ──
    //
    // Zig's native BPF backend does not emit BTF sections, which
    // libbpf >= 1.0 requires for map definitions. Using `zig cc`
    // (clang wrapper) solves this: it emits .BTF and .BTF.ext.
    //
    // We build two object sets from the same sources:
    //   - ebpf/      → ring-buffer transport for newer kernels
    //   - ebpf-perf/ → perf-event-array fallback for older kernels
    const ebpf_c_sources = [_]struct { name: []const u8, file: []const u8 }{
        .{ .name = "process_exec_bpf", .file = "zig/ebpf/process_exec.c" },
        .{ .name = "file_open_bpf", .file = "zig/ebpf/file_open.c" },
        .{ .name = "file_write_bpf", .file = "zig/ebpf/file_write.c" },
        .{ .name = "file_rename_bpf", .file = "zig/ebpf/file_rename.c" },
        .{ .name = "file_unlink_bpf", .file = "zig/ebpf/file_unlink.c" },
        .{ .name = "tcp_connect_bpf", .file = "zig/ebpf/tcp_connect.c" },
        .{ .name = "dns_query_bpf", .file = "zig/ebpf/dns_query.c" },
        .{ .name = "module_load_bpf", .file = "zig/ebpf/module_load.c" },
        .{ .name = "lsm_block_bpf", .file = "zig/ebpf/lsm_block.c" },
    };
    const ebpf_variants = [_]struct { out_dir: []const u8, use_perfbuf: bool }{
        .{ .out_dir = "ebpf", .use_perfbuf = false },
        .{ .out_dir = "ebpf-perf", .use_perfbuf = true },
    };

    for (ebpf_variants) |variant| {
        for (ebpf_c_sources) |entry| {
            const out_path = b.fmt("{s}/{s}.o", .{ variant.out_dir, entry.name });
            const cmd = b.addSystemCommand(&.{
                "zig",
                "cc",
                "-target",
                "bpfel-freestanding-none",
                "-g",
                "-O2",
                "-Werror",
                "-fno-asynchronous-unwind-tables",
                "-fno-unwind-tables",
                "-I",
                "zig/ebpf",
                "-c",
            });
            if (variant.use_perfbuf) {
                cmd.addArg("-DEGUARD_USE_PERFBUF=1");
            }
            cmd.addFileArg(b.path(entry.file));
            const output = cmd.addPrefixedOutputFileArg("-o", out_path);
            const install = b.addInstallFile(output, out_path);
            b.getInstallStep().dependOn(&install.step);
            ebpf_step.dependOn(&install.step);
        }
    }
}
