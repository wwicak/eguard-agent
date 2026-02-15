const common = @import("common.zig");

const ModuleLoadCtx = extern struct {
    pid: u32,
    tid: u32,
    uid: u32,
    timestamp_ns: u64,
    module_name_ptr: [*c]const u8,
};

const ModuleLoadEvent = extern struct {
    header: common.EventHeader,
    module_name: [64]u8,
};

pub export fn kprobe___do_sys_finit_module(ctx: *const ModuleLoadCtx) linksection("kprobe/__do_sys_finit_module") callconv(.c) i32 {
    var event: ModuleLoadEvent = .{
        .header = .{
            .event_type = @intFromEnum(common.EventType.module_load),
            .pid = ctx.pid,
            .tid = ctx.tid,
            .uid = ctx.uid,
            .timestamp_ns = ctx.timestamp_ns,
        },
        .module_name = [_]u8{0} ** 64,
    };

    common.readCString(ctx.module_name_ptr, event.module_name[0..]);
    common.emitRecord(ModuleLoadEvent, &event);
    return 0;
}
