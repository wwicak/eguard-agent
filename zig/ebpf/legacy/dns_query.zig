const common = @import("common.zig");

const DnsQueryCtx = extern struct {
    pid: u32,
    tid: u32,
    uid: u32,
    timestamp_ns: u64,
    qtype: u16,
    qclass: u16,
    qname_ptr: [*c]const u8,
};

const DnsQueryEvent = extern struct {
    header: common.EventHeader,
    qtype: u16,
    qclass: u16,
    qname: [128]u8,
};

pub export fn kprobe_udp_sendmsg(ctx: *const DnsQueryCtx) linksection("kprobe/udp_sendmsg") callconv(.c) i32 {
    var event: DnsQueryEvent = .{
        .header = .{
            .event_type = @intFromEnum(common.EventType.dns_query),
            .pid = ctx.pid,
            .tid = ctx.tid,
            .uid = ctx.uid,
            .timestamp_ns = ctx.timestamp_ns,
        },
        .qtype = ctx.qtype,
        .qclass = ctx.qclass,
        .qname = [_]u8{0} ** 128,
    };

    common.readCString(ctx.qname_ptr, event.qname[0..]);
    common.emitRecord(DnsQueryEvent, &event);
    return 0;
}
