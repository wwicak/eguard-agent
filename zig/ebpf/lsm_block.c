/* eguard — LSM blocking probe (optional)
 *
 * Hooks:   lsm/bprm_check_security
 * Payload: reason(1) + pad(3) + subject(128)
 *
 * OPTIONAL — requires CONFIG_BPF_LSM=y and "bpf" in /sys/kernel/security/lsm.
 * If the kernel lacks BPF LSM the agent skips this probe gracefully.
 *
 * V1: audit-only (returns 0 = allow).  Blocking requires a shared
 *     BPF map of deny-listed hashes populated by the agent (future).
 */
#include "bpf_helpers.h"

#define SUBJECT_SZ 128

EGUARD_DEFINE_EVENTS_MAP(events);

struct lsm_block_event {
    struct event_hdr hdr;
    __u8  reason;
    __u8  _pad[3];
    char  subject[SUBJECT_SZ];
} __attribute__((packed));

SEC("lsm/bprm_check_security")
int eguard_bprm_check(void *ctx)
{
    EGUARD_ALLOC_EVENT(lsm_block_event, e);
    fill_hdr(&e->hdr, EVENT_LSM_BLOCK);

    e->reason = 1; /* exec audit */
    bpf_get_current_comm(e->subject, SUBJECT_SZ);

    EGUARD_SUBMIT_EVENT(ctx, e);
}
