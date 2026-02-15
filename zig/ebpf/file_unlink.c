/* eguard — file unlink probe
 *
 * Hook:    tracepoint/syscalls/sys_enter_unlinkat
 * Payload: path(256)
 *
 * sys_enter_unlinkat tracepoint args (after 8-byte trace_entry):
 *   +8   __syscall_nr  i32
 *   +16  dfd           i64
 *   +24  pathname      ptr
 *   +32  flag          i32
 */
#include "bpf_helpers.h"

#define FILE_PATH_SZ 256

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DEFAULT_RINGBUF_CAPACITY);
} events SEC(".maps");

struct file_unlink_event {
    struct event_hdr hdr;
    char path[FILE_PATH_SZ];
} __attribute__((packed));

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int eguard_sys_enter_unlinkat(void *ctx)
{
    struct file_unlink_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    bpf_memzero(e, sizeof(*e));
    fill_hdr(&e->hdr, EVENT_FILE_UNLINK);

    __u64 path_ptr = 0;
    bpf_probe_read(&path_ptr, sizeof(path_ptr), (__u8 *)ctx + 24);
    if (path_ptr)
        bpf_probe_read_user_str(e->path, FILE_PATH_SZ, (const void *)path_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
