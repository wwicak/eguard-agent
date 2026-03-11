/* eguard — file open probe
 *
 * Hooks:
 *   - tracepoint/syscalls/sys_enter_open
 *   - tracepoint/syscalls/sys_enter_openat
 *   - tracepoint/syscalls/sys_enter_openat2
 * Payload: flags(4) + mode(4) + ppid(4) + cgroup_id(8) + comm(32) + parent_comm(32) + path(256)
 *
 * sys_enter_open tracepoint args (after 8-byte trace_entry):
 *   +8   __syscall_nr  i32
 *   +16  filename      ptr  (user-space const char *)
 *   +24  flags         i64
 *   +32  mode          i64
 *
 * sys_enter_openat tracepoint args (after 8-byte trace_entry):
 *   +8   __syscall_nr  i32
 *   +16  dfd           i64  (sign-extended)
 *   +24  filename      ptr  (user-space const char *)
 *   +32  flags         i64
 *   +40  mode          i64
 *
 * sys_enter_openat2 tracepoint args (after 8-byte trace_entry):
 *   +8   __syscall_nr  i32
 *   +16  dfd           i64  (sign-extended)
 *   +24  filename      ptr  (user-space const char *)
 *   +32  how           ptr  (user-space struct open_how *)
 *   +40  usize         usize
 */
#include "bpf_helpers.h"

#define COMM_SZ      32
#define FILE_PATH_SZ 256

EGUARD_DEFINE_EVENTS_MAP(events);

struct file_open_event {
    struct event_hdr hdr;
    __u32 flags;
    __u32 mode;
    __u32 ppid;
    __u64 cgroup_id;
    char  comm[COMM_SZ];
    char  parent_comm[COMM_SZ];
    char  path[FILE_PATH_SZ];
} __attribute__((packed));

struct open_how_local {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};

static inline __attribute__((always_inline)) void fill_file_open_metadata(struct file_open_event *e)
{
    fill_hdr(&e->hdr, EVENT_FILE_OPEN);
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(e->comm, COMM_SZ);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = 0;
        if (bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent) == 0 && parent) {
            __u32 parent_tgid = 0;
            if (bpf_probe_read_kernel(&parent_tgid, sizeof(parent_tgid), &parent->tgid) == 0) {
                e->ppid = parent_tgid;
            }
            bpf_probe_read_kernel_str(e->parent_comm, COMM_SZ, parent->comm);
        }
    }
}

SEC("tracepoint/syscalls/sys_enter_open")
int eguard_sys_enter_open(void *ctx)
{
    EGUARD_ALLOC_EVENT(file_open_event, e);
    fill_file_open_metadata(e);

    __u64 filename_ptr = 0;
    __s32 flags_val    = 0;
    __s32 mode_val     = 0;

    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), (__u8 *)ctx + 16);
    bpf_probe_read(&flags_val,    sizeof(flags_val),    (__u8 *)ctx + 24);
    bpf_probe_read(&mode_val,     sizeof(mode_val),     (__u8 *)ctx + 32);

    e->flags = (__u32)flags_val;
    e->mode  = (__u32)mode_val;

    if (filename_ptr)
        bpf_probe_read_user_str(e->path, FILE_PATH_SZ,
                                (const void *)filename_ptr);

    EGUARD_SUBMIT_EVENT(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int eguard_sys_enter_openat(void *ctx)
{
    EGUARD_ALLOC_EVENT(file_open_event, e);
    fill_file_open_metadata(e);

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

    EGUARD_SUBMIT_EVENT(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int eguard_sys_enter_openat2(void *ctx)
{
    EGUARD_ALLOC_EVENT(file_open_event, e);
    fill_file_open_metadata(e);

    __u64 filename_ptr = 0;
    __u64 how_ptr      = 0;
    struct open_how_local how = {};

    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), (__u8 *)ctx + 24);
    bpf_probe_read(&how_ptr,      sizeof(how_ptr),      (__u8 *)ctx + 32);

    if (how_ptr) {
        bpf_probe_read_user(&how, sizeof(how), (const void *)how_ptr);
        e->flags = (__u32)how.flags;
        e->mode  = (__u32)how.mode;
    }

    if (filename_ptr)
        bpf_probe_read_user_str(e->path, FILE_PATH_SZ,
                                (const void *)filename_ptr);

    EGUARD_SUBMIT_EVENT(ctx, e);
}
