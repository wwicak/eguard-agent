/* eguard — TCP connect probe
 *
 * Hook:    tracepoint/sock/inet_sock_set_state
 * Fires:   when a socket LEAVES SYN_SENT — i.e. on the resolution of an
 *          outbound connect attempt, whether it established
 *          (SYN_SENT -> ESTABLISHED) or failed (SYN_SENT -> CLOSE via RST or
 *          connect timeout).
 *
 * The old probe fired only on SYN_SENT -> ESTABLISHED, so it silently dropped
 * every beacon to an endpoint that never completed the handshake — exactly the
 * common IOC case (sinkholed, firewalled, offline, or RST'd C2). Widening the
 * trigger to "left SYN_SENT" records the failed attempt too, while the socket's
 * inet_daddr/inet_dport are still populated (they are set before SYN_SENT is
 * entered and are not cleared until the socket is destroyed). Each outbound
 * connect therefore emits exactly one event, at the point its outcome is known.
 *
 * Payload: family(2) + sport(2) + dport(2) + proto(1) + pad(1)
 *        + saddr_v4(4) + daddr_v4(4) + saddr_v6(16) + daddr_v6(16)
 *
 * Tracepoint args (after 8-byte trace_entry):
 *   +8   skaddr     ptr
 *   +16  oldstate   i32
 *   +20  newstate   i32
 *   +24  sport      u16
 *   +26  dport      u16
 *   +28  family     u16
 *   +30  protocol   u16
 *   +32  saddr[4]
 *   +36  daddr[4]
 *   +40  saddr_v6[16]
 *   +56  daddr_v6[16]
 *
 * The destination address/port are populated on the socket before the state is
 * moved to SYN_SENT (tcp_v4_connect/tcp_v6_connect set inet_daddr/inet_dport
 * prior to tcp_connect()->tcp_set_state()), so daddr/dport are valid here.
 */
#include "bpf_helpers.h"

#define TCP_SYN_SENT    2
#define TCP_ESTABLISHED 1

EGUARD_DEFINE_EVENTS_MAP(events);

struct tcp_connect_event {
    struct event_hdr hdr;
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  _pad;
    __u32 saddr_v4;
    __u32 daddr_v4;
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
} __attribute__((packed));

SEC("tracepoint/sock/inet_sock_set_state")
int eguard_inet_sock_set_state(void *ctx)
{
    __s32 oldstate = 0, newstate = 0;
    bpf_probe_read(&oldstate, sizeof(oldstate), (__u8 *)ctx + 16);
    bpf_probe_read(&newstate, sizeof(newstate), (__u8 *)ctx + 20);

    /* Resolution of an outbound connect attempt (success or failure). */
    if (oldstate != TCP_SYN_SENT)
        return 0;

    EGUARD_ALLOC_EVENT(tcp_connect_event, e);
    fill_hdr(&e->hdr, EVENT_TCP_CONNECT);

    bpf_probe_read(&e->sport,    2,  (__u8 *)ctx + 24);
    bpf_probe_read(&e->dport,    2,  (__u8 *)ctx + 26);
    bpf_probe_read(&e->family,   2,  (__u8 *)ctx + 28);
    __u16 proto = 0;
    bpf_probe_read(&proto,       2,  (__u8 *)ctx + 30);
    e->protocol = (__u8)proto;

    /* Record the outcome in the otherwise-spare pad byte (wire layout is
     * unchanged; the userspace codec ignores it): 1 = established,
     * 0 = failed/never-established (dead/sinkholed/firewalled C2 beacon). */
    e->_pad = (newstate == TCP_ESTABLISHED) ? 1 : 0;

    /* Tracepoint sport/dport are already host-order u16; the userspace codec
     * reads them as plain little-endian values, so pass them through unchanged.
     * (The previous bpf_ntohs() here byte-swapped them, turning e.g. dport 443
     * into 47873.) */

    bpf_probe_read(&e->saddr_v4, 4,  (__u8 *)ctx + 32);
    bpf_probe_read(&e->daddr_v4, 4,  (__u8 *)ctx + 36);
    bpf_probe_read(e->saddr_v6,  16, (__u8 *)ctx + 40);
    bpf_probe_read(e->daddr_v6,  16, (__u8 *)ctx + 56);

    EGUARD_SUBMIT_EVENT(ctx, e);
}
