const common = @import("common.zig");

const ProcessExecCtx = extern struct {
    pid: u32,
    tid: u32,
    uid: u32,
    ppid: u32,
    timestamp_ns: u64,
    cgroup_id: u64,
    comm_ptr: [*c]const u8,
    filename_ptr: [*c]const u8,
    argv_ptr: [*c]const u8,
};

const ProcessExecEvent = extern struct {
    header: common.EventHeader,
    ppid: u32,
    cgroup_id: u64,
    comm: [32]u8,
    filename: [160]u8,
    argv: [160]u8,
};

pub export fn tracepoint_sched_sched_process_exec(ctx: *const ProcessExecCtx) linksection("tracepoint/sched/sched_process_exec") callconv(.c) i32 {
    var event: ProcessExecEvent = .{
        .header = .{
            .event_type = @intFromEnum(common.EventType.process_exec),
            .pid = ctx.pid,
            .tid = ctx.tid,
            .uid = ctx.uid,
            .timestamp_ns = ctx.timestamp_ns,
        },
        .ppid = ctx.ppid,
        .cgroup_id = ctx.cgroup_id,
        .comm = [_]u8{0} ** 32,
        .filename = [_]u8{0} ** 160,
        .argv = [_]u8{0} ** 160,
    };

    common.readCString(ctx.comm_ptr, event.comm[0..]);
    common.readCString(ctx.filename_ptr, event.filename[0..]);
    common.readCString(ctx.argv_ptr, event.argv[0..]);

    common.emitRecord(ProcessExecEvent, &event);
    return 0;
}
