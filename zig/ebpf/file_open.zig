const common = @import("common.zig");

const FileOpenCtx = extern struct {
    pid: u32,
    tid: u32,
    uid: u32,
    flags: u32,
    mode: u32,
    timestamp_ns: u64,
    path_ptr: [*c]const u8,
};

const FileOpenEvent = extern struct {
    header: common.EventHeader,
    flags: u32,
    mode: u32,
    path: [256]u8,
};

pub export fn lsm_file_open(ctx: *const FileOpenCtx) linksection("lsm/file_open") callconv(.c) i32 {
    return emitFileOpen(ctx);
}

pub export fn kprobe_security_file_open(ctx: *const FileOpenCtx) linksection("kprobe/security_file_open") callconv(.c) i32 {
    return emitFileOpen(ctx);
}

fn emitFileOpen(ctx: *const FileOpenCtx) i32 {
    var event: FileOpenEvent = .{
        .header = .{
            .event_type = @intFromEnum(common.EventType.file_open),
            .pid = ctx.pid,
            .tid = ctx.tid,
            .uid = ctx.uid,
            .timestamp_ns = ctx.timestamp_ns,
        },
        .flags = ctx.flags,
        .mode = ctx.mode,
        .path = [_]u8{0} ** 256,
    };

    common.readCString(ctx.path_ptr, event.path[0..]);
    if (!shouldEmitFileOpen(ctx, event.path[0..])) {
        return 0;
    }
    common.emitRecord(FileOpenEvent, &event);
    return 0;
}

fn shouldEmitFileOpen(ctx: *const FileOpenCtx, path: []const u8) bool {
    if ((ctx.mode & 0o111) != 0) {
        return true;
    }
    return hasPrefix(path, "/etc/eguard-agent/") or
        hasPrefix(path, "/var/lib/eguard-agent/") or
        hasPrefix(path, "/opt/eguard-agent/");
}

fn hasPrefix(path: []const u8, prefix: []const u8) bool {
    var i: usize = 0;
    while (i < prefix.len) : (i += 1) {
        if (i >= path.len or path[i] == 0) {
            return false;
        }
        if (path[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}
