const std = @import("std");
const builtin = @import("builtin");

const CpuidLeaf = packed struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

fn cpuid(leaf_id: u32, subid: u32) CpuidLeaf {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (leaf_id),
          [_] "{ecx}" (subid),
    );

    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

fn hasShaNi() bool {
    return switch (builtin.cpu.arch) {
        .x86, .x86_64 => blk: {
            const max_leaf = cpuid(0, 0).eax;
            if (max_leaf < 7) break :blk false;
            const leaf7 = cpuid(7, 0);
            const sha_bit = (leaf7.ebx >> 29) & 1;
            break :blk sha_bit == 1;
        },
        else => false,
    };
}

fn shaRoundProbe() void {
    if (!(builtin.cpu.arch == .x86 or builtin.cpu.arch == .x86_64)) {
        return;
    }
    if (!std.Target.x86.featureSetHas(builtin.cpu.features, .sha)) {
        return;
    }

    const V4u32 = @Vector(4, u32);
    const x: V4u32 = [_]u32{ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A };
    var y: V4u32 = [_]u32{ 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };
    y = asm ("sha256rnds2 %[x], %[y]"
        : [y] "=x" (-> V4u32),
        : [_] "0" (y),
          [x] "x" (x),
          [_] "{xmm0}" (x),
    );
    std.mem.doNotOptimizeAway(y);
}

pub export fn sha256_ni_available() bool {
    return hasShaNi();
}

pub export fn sha256_ni_hash(data: [*c]const u8, len: usize, out: [*c]u8) i32 {
    if (data == null or out == null) {
        return -1;
    }
    if (!sha256_ni_available()) {
        return 1;
    }

    shaRoundProbe();

    const input = data[0..len];
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
    const output = out[0..32];
    @memcpy(output, digest[0..]);
    return 0;
}
