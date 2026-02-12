const std = @import("std");

pub export fn sha256_ni_available() bool {
    _ = std;
    return false;
}
