/* Host-side common-header regression: cc -Wno-attributes -o /tmp/header_generation
 * zig/ebpf/tests/header_generation.c && /tmp/header_generation
 * Mock only BPF helpers; exercise the same fill_hdr used by every producer. */
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "../bpf_helpers.h"

static struct task_struct leader, worker, parent, parent_leader;
static void *current_task(void) { return &worker; }
static __u64 current_pid(void) { return ((__u64)42 << 32) | 43; }
static __u64 current_uid(void) { return 1000; }
static __u64 now(void) { return 999; }
static long read_kernel(void *dst, __u32 n, const void *src)
{
    memcpy(dst, src, n);
    return 0;
}

int main(void)
{
    const unsigned long hz = (unsigned long)sysconf(_SC_CLK_TCK);
    assert(hz > 0);
    leader.start_boottime = 2000000001ULL;
    worker.start_boottime = 3000000000ULL;
    worker.group_leader = &leader;
    worker.real_parent = &parent;
    parent.start_boottime = 4000000000ULL;
    parent.group_leader = &parent_leader;
    parent_leader.start_boottime = 1000000001ULL;
    bpf_get_current_task = current_task;
    bpf_get_current_pid_tgid = current_pid;
    bpf_get_current_uid_gid = current_uid;
    bpf_ktime_get_ns = now;
    bpf_probe_read_kernel = read_kernel;
    struct event_hdr h = {0};
    fill_hdr(&h, EVENT_FILE_OPEN);
    assert(sizeof(h) == 37);
    assert(h.event_type == (0x80 | EVENT_FILE_OPEN));
    assert(h.pid == 42 && h.tid == 43);
    /* A worker's TGID must match the leader's /proc/<tgid>/stat ticks,
     * never the worker's later start or the parent's thread generation. */
    assert(h.pid_start_ns == leader.start_boottime);
    assert(h.ppid_start_ns == parent_leader.start_boottime);
    assert(h.pid_start_ns * hz / 1000000000ULL == 2 * hz);
    assert(h.ppid_start_ns * hz / 1000000000ULL == hz);
    return 0;
}
