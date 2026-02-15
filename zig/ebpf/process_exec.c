/* eguard — process exec probe
 *
 * Hook:    tracepoint/sched/sched_process_exec
 * Payload: ppid(4) + cgroup_id(8) + comm(32) + path(160) + cmdline(160)
 */
#include "bpf_helpers.h"

#define COMM_SZ    32
#define PATH_SZ   160
#define CMDLINE_SZ 160

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DEFAULT_RINGBUF_CAPACITY);
} events SEC(".maps");

struct process_exec_event {
    struct event_hdr hdr;
    __u32 ppid;
    __u64 cgroup_id;
    char  comm[COMM_SZ];
    char  path[PATH_SZ];
    char  cmdline[CMDLINE_SZ];
} __attribute__((packed));

SEC("tracepoint/sched/sched_process_exec")
int eguard_sched_process_exec(void *ctx)
{
    struct process_exec_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    bpf_memzero(e, sizeof(*e));
    fill_hdr(&e->hdr, EVENT_PROCESS_EXEC);
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(e->comm, COMM_SZ);

    /* filename via __data_loc at tp offset 8 */
    read_tp_data_loc_str(e->path, PATH_SZ, ctx, 8);

    /* cmdline: best-effort copy of comm */
    bpf_get_current_comm(e->cmdline, CMDLINE_SZ);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
