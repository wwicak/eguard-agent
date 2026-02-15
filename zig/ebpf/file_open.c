/* eguard — file open probe
 *
 * Hook:    tracepoint/syscalls/sys_enter_openat
 * Payload: flags(4) + mode(4) + path(256)
 *
 * sys_enter_openat tracepoint args (after 8-byte trace_entry):
 *   +8   __syscall_nr  i32
 *   +16  dfd           i64  (sign-extended)
 *   +24  filename      ptr  (user-space const char *)
 *   +32  flags         i64
 *   +40  mode          i64
 */
#include "bpf_helpers.h"

#define FILE_PATH_SZ 256

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DEFAULT_RINGBUF_CAPACITY);
} events SEC(".maps");

struct file_open_event {
    struct event_hdr hdr;
    __u32 flags;
    __u32 mode;
    char  path[FILE_PATH_SZ];
} __attribute__((packed));

SEC("tracepoint/syscalls/sys_enter_openat")
int eguard_sys_enter_openat(void *ctx)
{
    struct file_open_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    bpf_memzero(e, sizeof(*e));
    fill_hdr(&e->hdr, EVENT_FILE_OPEN);

    __u64 filename_ptr = 0;
    __s32 flags_val    = 0;
    __s32 mode_val     = 0;

    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), (__u8 *)ctx + 24);
    bpf_probe_read(&flags_val,    sizeof(flags_val),    (__u8 *)ctx + 32);
    bpf_probe_read(&mode_val,     sizeof(mode_val),     (__u8 *)ctx + 40);

    e->flags = (__u32)flags_val;
    e->mode  = (__u32)mode_val;

    if (filename_ptr)
        bpf_probe_read_user_str(e->path, FILE_PATH_SZ,
                                (const void *)filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
