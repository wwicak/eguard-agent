const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = target;
    _ = optimize;

    const step = b.step("agent-artifacts", "Build eBPF and asm artifacts");
    _ = step;
}
