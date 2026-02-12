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
    const ebpf_step = b.step("ebpf-artifacts", "Build Zig eBPF object files");
    all_artifacts.dependOn(asm_step);
    all_artifacts.dependOn(ebpf_step);

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

    const ebpf_target = b.resolveTargetQuery(.{
        .cpu_arch = .bpfel,
        .os_tag = .freestanding,
        .abi = .none,
    });
    const ebpf_optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const ebpf_sources = [_]struct { name: []const u8, file: []const u8 }{
        .{ .name = "process_exec_bpf", .file = "zig/ebpf/process_exec.zig" },
        .{ .name = "file_open_bpf", .file = "zig/ebpf/file_open.zig" },
        .{ .name = "tcp_connect_bpf", .file = "zig/ebpf/tcp_connect.zig" },
        .{ .name = "dns_query_bpf", .file = "zig/ebpf/dns_query.zig" },
        .{ .name = "module_load_bpf", .file = "zig/ebpf/module_load.zig" },
        .{ .name = "lsm_block_bpf", .file = "zig/ebpf/lsm_block.zig" },
    };

    for (ebpf_sources) |entry| {
        const module = b.createModule(.{
            .root_source_file = b.path(entry.file),
            .target = ebpf_target,
            .optimize = ebpf_optimize,
        });
        const obj = b.addObject(.{
            .name = entry.name,
            .root_module = module,
        });
        const install_obj = b.addInstallFile(obj.getEmittedBin(), b.fmt("ebpf/{s}.o", .{entry.name}));
        b.getInstallStep().dependOn(&install_obj.step);
        ebpf_step.dependOn(&obj.step);
    }
}
