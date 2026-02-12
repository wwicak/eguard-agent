const common = @import("common.zig");

const EPERM: i32 = -1;
const ECONNREFUSED: i32 = -111;

const BprmCtx = extern struct {
    pid: u32,
    tid: u32,
    uid: u32,
    timestamp_ns: u64,
    filename_ptr: [*c]const u8,
};

const SocketConnectCtx = extern struct {
    pid: u32,
    tid: u32,
    uid: u32,
    timestamp_ns: u64,
    daddr_v4: u32,
    dport: u16,
};

const LsmBlockEvent = extern struct {
    header: common.EventHeader,
    reason: u8,
    _pad0: [3]u8,
    subject: [128]u8,
};

pub export fn bprm_check_security(ctx: *const BprmCtx) linksection("lsm/bprm_check_security") callconv(.c) i32 {
    var filename_buf: [128]u8 = [_]u8{0} ** 128;
    common.readCString(ctx.filename_ptr, filename_buf[0..]);

    if (containsNeedle(filename_buf[0..], "eguard-malware-test-marker")) {
        emitBlockEvent(ctx.pid, ctx.tid, ctx.uid, ctx.timestamp_ns, 1, filename_buf[0..]);
        return EPERM;
    }

    return 0;
}

pub export fn socket_connect(ctx: *const SocketConnectCtx) linksection("lsm/socket_connect") callconv(.c) i32 {
    if (ctx.daddr_v4 == 0x0A0A0A0A or ctx.dport == 4444) {
        var subject: [128]u8 = [_]u8{0} ** 128;
        const n = formatIpv4Port(subject[0..], ctx.daddr_v4, ctx.dport);
        emitBlockEvent(ctx.pid, ctx.tid, ctx.uid, ctx.timestamp_ns, 2, subject[0..n]);
        return ECONNREFUSED;
    }

    return 0;
}

fn emitBlockEvent(pid: u32, tid: u32, uid: u32, timestamp_ns: u64, reason: u8, subject: []const u8) void {
    var event: LsmBlockEvent = .{
        .header = .{
            .event_type = @intFromEnum(common.EventType.lsm_block),
            .pid = pid,
            .tid = tid,
            .uid = uid,
            .timestamp_ns = timestamp_ns,
        },
        .reason = reason,
        ._pad0 = [_]u8{0} ** 3,
        .subject = [_]u8{0} ** 128,
    };

    _ = common.copyBytes(event.subject[0..], subject);
    common.emitRecord(LsmBlockEvent, &event);
}

fn containsNeedle(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) {
        return false;
    }

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var matched = true;
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            if (haystack[i + j] != needle[j]) {
                matched = false;
                break;
            }
        }
        if (matched) {
            return true;
        }
    }
    return false;
}

fn formatIpv4Port(dst: []u8, ip_be: u32, port: u16) usize {
    if (dst.len == 0) {
        return 0;
    }

    const b0: u8 = @intCast((ip_be >> 24) & 0xff);
    const b1: u8 = @intCast((ip_be >> 16) & 0xff);
    const b2: u8 = @intCast((ip_be >> 8) & 0xff);
    const b3: u8 = @intCast(ip_be & 0xff);

    var idx: usize = 0;
    idx += writeDec(dst[idx..], b0);
    idx += writeChar(dst[idx..], '.');
    idx += writeDec(dst[idx..], b1);
    idx += writeChar(dst[idx..], '.');
    idx += writeDec(dst[idx..], b2);
    idx += writeChar(dst[idx..], '.');
    idx += writeDec(dst[idx..], b3);
    idx += writeChar(dst[idx..], ':');
    idx += writeDec(dst[idx..], port);

    if (idx < dst.len) {
        dst[idx] = 0;
    }
    return idx;
}

fn writeChar(dst: []u8, c: u8) usize {
    if (dst.len == 0) {
        return 0;
    }
    dst[0] = c;
    return 1;
}

fn writeDec(dst: []u8, value: anytype) usize {
    var tmp: [20]u8 = [_]u8{0} ** 20;
    var v: u64 = @as(u64, @intCast(value));
    var len: usize = 0;
    if (v == 0) {
        if (dst.len > 0) {
            dst[0] = '0';
            return 1;
        }
        return 0;
    }

    while (v > 0 and len < tmp.len) : (len += 1) {
        tmp[len] = @as(u8, @intCast(v % 10)) + '0';
        v /= 10;
    }

    var written: usize = 0;
    while (written < len and written < dst.len) : (written += 1) {
        dst[written] = tmp[len - 1 - written];
    }
    return written;
}
