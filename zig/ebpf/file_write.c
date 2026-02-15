/* eguard — file write probe
 *
 * Hook:    tracepoint/syscalls/sys_enter_write
 * Payload: fd(4) + size(8) + path(256)
 *
 * sys_enter_write tracepoint args (after 8-byte trace_entry):
 *   +8   __syscall_nr  i32
 *   +16  fd            i64
 *   +24  count         i64
 */
#include "bpf_helpers.h"

#define FILE_PATH_SZ 256

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DEFAULT_RINGBUF_CAPACITY);
} events SEC(".maps");

struct file_write_event {
    struct event_hdr hdr;
    __u32 fd;
    __u64 size;
    char  path[FILE_PATH_SZ];
} __attribute__((packed));

SEC("tracepoint/syscalls/sys_enter_write")
int eguard_sys_enter_write(void *ctx)
{
    struct file_write_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    bpf_memzero(e, sizeof(*e));
    fill_hdr(&e->hdr, EVENT_FILE_WRITE);

    __s64 fd_val = 0;
    __s64 count_val = 0;
    bpf_probe_read(&fd_val, sizeof(fd_val), (__u8 *)ctx + 16);
    bpf_probe_read(&count_val, sizeof(count_val), (__u8 *)ctx + 24);

    if (fd_val < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->fd = (__u32)fd_val;
    e->size = count_val > 0 ? (__u64)count_val : 0;

    if (e->size == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
