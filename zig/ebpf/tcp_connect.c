/* eguard — TCP connect probe
 *
 * Hook:    tracepoint/sock/inet_sock_set_state
 * Fires:   only on SYN_SENT → ESTABLISHED (outbound connect success)
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
 */
#include "bpf_helpers.h"

#define TCP_SYN_SENT    2
#define TCP_ESTABLISHED 1

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DEFAULT_RINGBUF_CAPACITY);
} events SEC(".maps");

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
    bpf_probe_read(&oldstate, sizeof(oldstate), ctx + 16);
    bpf_probe_read(&newstate, sizeof(newstate), ctx + 20);

    if (oldstate != TCP_SYN_SENT || newstate != TCP_ESTABLISHED)
        return 0;

    struct tcp_connect_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    bpf_memzero(e, sizeof(*e));
    fill_hdr(&e->hdr, EVENT_TCP_CONNECT);

    bpf_probe_read(&e->sport,    2,  (__u8 *)ctx + 24);
    bpf_probe_read(&e->dport,    2,  (__u8 *)ctx + 26);
    bpf_probe_read(&e->family,   2,  (__u8 *)ctx + 28);
    __u16 proto = 0;
    bpf_probe_read(&proto,       2,  (__u8 *)ctx + 30);
    e->protocol = (__u8)proto;

    /* Tracepoint ports are host-order; convert to network order for parser. */
    e->sport = bpf_ntohs(e->sport);
    e->dport = bpf_ntohs(e->dport);

    bpf_probe_read(&e->saddr_v4, 4,  (__u8 *)ctx + 32);
    bpf_probe_read(&e->daddr_v4, 4,  (__u8 *)ctx + 36);
    bpf_probe_read(e->saddr_v6,  16, (__u8 *)ctx + 40);
    bpf_probe_read(e->daddr_v6,  16, (__u8 *)ctx + 56);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
