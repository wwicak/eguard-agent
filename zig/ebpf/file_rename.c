/* eguard — file rename probe
 *
 * Hook:    tracepoint/syscalls/sys_enter_renameat2
 * Payload: oldpath(256) + newpath(256)
 *
 * sys_enter_renameat2 tracepoint args (after 8-byte trace_entry):
 *   +8   __syscall_nr  i32
 *   +16  olddirfd      i64
 *   +24  oldpath       ptr
 *   +32  newdirfd      i64
 *   +40  newpath       ptr
 */
#include "bpf_helpers.h"

#define FILE_PATH_SZ 256

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DEFAULT_RINGBUF_CAPACITY);
} events SEC(".maps");

struct file_rename_event {
    struct event_hdr hdr;
    char old_path[FILE_PATH_SZ];
    char new_path[FILE_PATH_SZ];
} __attribute__((packed));

SEC("tracepoint/syscalls/sys_enter_renameat2")
int eguard_sys_enter_renameat2(void *ctx)
{
    struct file_rename_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    bpf_memzero(e, sizeof(*e));
    fill_hdr(&e->hdr, EVENT_FILE_RENAME);

    __u64 old_ptr = 0;
    __u64 new_ptr = 0;
    bpf_probe_read(&old_ptr, sizeof(old_ptr), (__u8 *)ctx + 24);
    bpf_probe_read(&new_ptr, sizeof(new_ptr), (__u8 *)ctx + 40);

    if (old_ptr)
        bpf_probe_read_user_str(e->old_path, FILE_PATH_SZ, (const void *)old_ptr);
    if (new_ptr)
        bpf_probe_read_user_str(e->new_path, FILE_PATH_SZ, (const void *)new_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
