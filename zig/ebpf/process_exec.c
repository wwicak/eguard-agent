/* eguard — process exec probe
 *
 * Hook:    tracepoint/sched/sched_process_exec
 * Payload: ppid(4) + cgroup_id(8) + comm(32) + parent_comm(32) + path(160) + cmdline(160)
 */
#include "bpf_helpers.h"

#define COMM_SZ    32
#define PATH_SZ   160
#define CMDLINE_SZ 160

EGUARD_DEFINE_EVENTS_MAP(events);

struct process_exec_event {
    struct event_hdr hdr;
    __u32 ppid;
    __u64 cgroup_id;
    char  comm[COMM_SZ];
    char  parent_comm[COMM_SZ];
    char  path[PATH_SZ];
    char  cmdline[CMDLINE_SZ];
} __attribute__((packed));

static __attribute__((always_inline)) void
fill_cmdline_from_mm(struct process_exec_event *e, struct task_struct *task)
{
    struct mm_struct *mm = 0;
    unsigned long arg_start = 0;
    unsigned long arg_end = 0;
    unsigned long arg_len = 0;

    if (bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm) != 0 || !mm)
        return;
    if (bpf_probe_read_kernel(&arg_start, sizeof(arg_start), &mm->arg_start) != 0 || !arg_start)
        return;
    if (bpf_probe_read_kernel(&arg_end, sizeof(arg_end), &mm->arg_end) != 0 || arg_end <= arg_start)
        return;

    arg_len = arg_end - arg_start;
    if (arg_len >= CMDLINE_SZ)
        arg_len = CMDLINE_SZ - 1;
    if (arg_len == 0)
        return;

    bpf_probe_read_user(e->cmdline, (__u32)arg_len, (const void *)arg_start);
}

SEC("tracepoint/sched/sched_process_exec")
int eguard_sched_process_exec(void *ctx)
{
    EGUARD_ALLOC_EVENT(process_exec_event, e);
    fill_hdr(&e->hdr, EVENT_PROCESS_EXEC);
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
        fill_cmdline_from_mm(e, task);
    }

    /* filename via __data_loc at tp offset 8 */
    read_tp_data_loc_str(e->path, PATH_SZ, ctx, 8);

    if (!e->cmdline[0])
        bpf_get_current_comm(e->cmdline, CMDLINE_SZ);

    EGUARD_SUBMIT_EVENT(ctx, e);
}
