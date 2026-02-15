/* eguard — DNS query probe
 *
 * Hook:    kprobe/udp_sendmsg
 * Payload: qtype(2) + qclass(2) + qname(128)
 *
 * This is a coarse probe: it fires on every UDP send, not just DNS.
 * The agent-side parser filters by port / payload heuristics.
 * For V1 we emit the sending process's comm as qname placeholder;
 * real DNS extraction requires skb parsing (TC/XDP, future work).
 */
#include "bpf_helpers.h"

#define QNAME_SZ 128

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DEFAULT_RINGBUF_CAPACITY);
} events SEC(".maps");

struct dns_query_event {
    struct event_hdr hdr;
    __u16 qtype;
    __u16 qclass;
    char  qname[QNAME_SZ];
} __attribute__((packed));

SEC("kprobe/udp_sendmsg")
int eguard_udp_sendmsg(void *ctx)
{
    struct dns_query_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    bpf_memzero(e, sizeof(*e));
    fill_hdr(&e->hdr, EVENT_DNS_QUERY);

    e->qtype  = 1;  /* A */
    e->qclass = 1;  /* IN */
    bpf_get_current_comm(e->qname, QNAME_SZ);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
