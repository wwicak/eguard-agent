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
    }

    /* filename via __data_loc at tp offset 8 */
    read_tp_data_loc_str(e->path, PATH_SZ, ctx, 8);

    /* cmdline: best-effort copy of comm */
    bpf_get_current_comm(e->cmdline, CMDLINE_SZ);

    EGUARD_SUBMIT_EVENT(ctx, e);
}
