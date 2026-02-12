const std = @import("std");

pub export fn integrity_check_sha256(
    data: [*c]const u8,
    len: usize,
    expected_digest: [*c]const u8,
) bool {
    if (data == null or expected_digest == null) {
        return false;
    }

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data[0..len], &digest, .{});
    return std.mem.eql(u8, digest[0..], expected_digest[0..32]);
}
