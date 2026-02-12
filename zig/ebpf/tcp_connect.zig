const common = @import("common.zig");

const TcpConnectCtx = extern struct {
    pid: u32,
    tid: u32,
    uid: u32,
    timestamp_ns: u64,
    family: u16,
    sport: u16,
    dport: u16,
    protocol: u8,
    saddr_v4: u32,
    daddr_v4: u32,
    saddr_v6: [16]u8,
    daddr_v6: [16]u8,
};

const TcpConnectEvent = extern struct {
    header: common.EventHeader,
    family: u16,
    sport: u16,
    dport: u16,
    protocol: u8,
    _pad0: u8,
    saddr_v4: u32,
    daddr_v4: u32,
    saddr_v6: [16]u8,
    daddr_v6: [16]u8,
};

pub export fn kprobe_tcp_v4_connect(ctx: *const TcpConnectCtx) linksection("kprobe/tcp_v4_connect") callconv(.c) i32 {
    return emitTcpConnect(ctx);
}

pub export fn kretprobe_tcp_v4_connect(ctx: *const TcpConnectCtx) linksection("kretprobe/tcp_v4_connect") callconv(.c) i32 {
    return emitTcpConnect(ctx);
}

pub export fn kprobe_tcp_v6_connect(ctx: *const TcpConnectCtx) linksection("kprobe/tcp_v6_connect") callconv(.c) i32 {
    return emitTcpConnect(ctx);
}

pub export fn kretprobe_tcp_v6_connect(ctx: *const TcpConnectCtx) linksection("kretprobe/tcp_v6_connect") callconv(.c) i32 {
    return emitTcpConnect(ctx);
}

fn emitTcpConnect(ctx: *const TcpConnectCtx) i32 {
    var event: TcpConnectEvent = .{
        .header = .{
            .event_type = @intFromEnum(common.EventType.tcp_connect),
            .pid = ctx.pid,
            .tid = ctx.tid,
            .uid = ctx.uid,
            .timestamp_ns = ctx.timestamp_ns,
        },
        .family = ctx.family,
        .sport = ctx.sport,
        .dport = ctx.dport,
        .protocol = ctx.protocol,
        ._pad0 = 0,
        .saddr_v4 = ctx.saddr_v4,
        .daddr_v4 = ctx.daddr_v4,
        .saddr_v6 = ctx.saddr_v6,
        .daddr_v6 = ctx.daddr_v6,
    };

    common.emitRecord(TcpConnectEvent, &event);
    return 0;
}
