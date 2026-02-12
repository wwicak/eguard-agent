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

fn hasAesNi() bool {
    return switch (builtin.cpu.arch) {
        .x86, .x86_64 => blk: {
            const leaf1 = cpuid(1, 0);
            const aes_bit = (leaf1.ecx >> 25) & 1;
            break :blk aes_bit == 1;
        },
        else => false,
    };
}

fn aesRoundProbe(round_key: [16]u8, input_block: [16]u8) void {
    if (!(builtin.cpu.arch == .x86 or builtin.cpu.arch == .x86_64)) {
        return;
    }
    if (!std.Target.x86.featureSetHas(builtin.cpu.features, .aes)) {
        return;
    }

    const Repr = @Vector(2, u64);
    const in_repr: Repr = @bitCast(input_block);
    const rk_repr: Repr = @bitCast(round_key);

    const out = asm (
        \\ vaesenc %[rk], %[in], %[out]
        : [out] "=x" (-> Repr),
        : [in] "x" (in_repr),
          [rk] "x" (rk_repr),
    );
    _ = out;
}

pub export fn aes_ni_available() bool {
    return hasAesNi();
}

pub export fn aes_ni_encrypt_block(key: [*c]const u8, input: [*c]const u8, out: [*c]u8) i32 {
    if (key == null or input == null or out == null) {
        return -1;
    }
    if (!aes_ni_available()) {
        return 1;
    }

    var key_buf: [32]u8 = undefined;
    @memcpy(key_buf[0..], key[0..32]);

    var input_buf: [16]u8 = undefined;
    @memcpy(input_buf[0..], input[0..16]);

    var round_key: [16]u8 = undefined;
    @memcpy(round_key[0..], key_buf[0..16]);
    aesRoundProbe(round_key, input_buf);

    var out_buf: [16]u8 = undefined;
    var ctx = std.crypto.core.aes.Aes256.initEnc(key_buf);
    ctx.encrypt(out_buf[0..], input_buf[0..]);

    @memcpy(out[0..16], out_buf[0..]);
    return 0;
}
