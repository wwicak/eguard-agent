/* eguard — DNS query probe
 *
 * Hook:    kprobe/udp_sendmsg
 * Payload: qtype(2) + qclass(2) + qname(128)
 *
 * This is a coarse probe: it fires on every UDP send, not just DNS.
 * The agent-side parser filters by port / payload heuristics.
 * Real DNS extraction requires skb parsing (TC/XDP, future work), so
 * the qname field is left empty unless a future parser populates it.
 */
#include "bpf_helpers.h"

#define QNAME_SZ 128

EGUARD_DEFINE_EVENTS_MAP(events);

struct dns_query_event {
    struct event_hdr hdr;
    __u16 qtype;
    __u16 qclass;
    char  qname[QNAME_SZ];
} __attribute__((packed));

SEC("kprobe/udp_sendmsg")
int eguard_udp_sendmsg(void *ctx)
{
    EGUARD_ALLOC_EVENT(dns_query_event, e);
    fill_hdr(&e->hdr, EVENT_DNS_QUERY);

    e->qtype  = 1;  /* A */
    e->qclass = 1;  /* IN */

    EGUARD_SUBMIT_EVENT(ctx, e);
}
