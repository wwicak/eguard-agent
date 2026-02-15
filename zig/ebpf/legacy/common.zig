const root = @import("root");

pub const MAX_EVENT_SIZE: usize = 512;
pub const DEFAULT_RINGBUF_CAPACITY: u32 = 8 * 1024 * 1024;
pub const RINGBUF_CAPACITY: u32 = resolveRingbufCapacity();

pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;

fn resolveRingbufCapacity() u32 {
    if (@hasDecl(root, "RINGBUF_CAPACITY")) {
        return @as(u32, @intCast(root.RINGBUF_CAPACITY));
    }
    return DEFAULT_RINGBUF_CAPACITY;
}

pub const EventType = enum(u8) {
    process_exec = 1,
    file_open = 2,
    tcp_connect = 3,
    dns_query = 4,
    module_load = 5,
    lsm_block = 6,
};

pub const EventHeader = extern struct {
    event_type: u8,
    pid: u32,
    tid: u32,
    uid: u32,
    timestamp_ns: u64,
};

pub const MapDef = extern struct {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
};

pub export var events: MapDef linksection(".maps") = .{
    .map_type = BPF_MAP_TYPE_RINGBUF,
    .key_size = 0,
    .value_size = 0,
    .max_entries = RINGBUF_CAPACITY,
    .map_flags = 0,
};

pub export var fallback_last_event_len: u32 linksection(".bss") = 0;
pub export var fallback_last_event_data: [MAX_EVENT_SIZE]u8 linksection(".bss") = [_]u8{0} ** MAX_EVENT_SIZE;
pub export var fallback_dropped_events: u64 linksection(".bss") = 0;

extern fn bpf_ringbuf_output(map: *MapDef, data: *const anyopaque, size: u64, flags: u64) callconv(.c) i64;

pub fn emitRecord(comptime T: type, record: *const T) void {
    const size = @sizeOf(T);
    if (size > MAX_EVENT_SIZE) {
        fallback_dropped_events +%= 1;
        return;
    }

    const rc = bpf_ringbuf_output(&events, @ptrCast(record), size, 0);
    if (rc == 0) {
        return;
    }

    const src: [*]const u8 = @ptrCast(record);
    var i: usize = 0;
    while (i < size) : (i += 1) {
        fallback_last_event_data[i] = src[i];
    }
    fallback_last_event_len = @as(u32, @intCast(size));
}

pub fn copyBytes(dst: []u8, src: []const u8) usize {
    const n = if (src.len < dst.len) src.len else dst.len;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        dst[i] = src[i];
    }
    if (n < dst.len) {
        dst[n] = 0;
    }
    return n;
}

pub fn cStrLen(ptr: [*c]const u8, cap: usize) usize {
    if (ptr == null) {
        return 0;
    }
    var i: usize = 0;
    while (i < cap and ptr[i] != 0) : (i += 1) {}
    return i;
}

pub fn readCString(ptr: [*c]const u8, out: []u8) void {
    const len = cStrLen(ptr, out.len);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        out[i] = ptr[i];
    }
    if (len < out.len) {
        out[len] = 0;
    }
}
