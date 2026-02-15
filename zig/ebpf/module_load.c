/* eguard — kernel module load probe
 *
 * Hook:    tracepoint/module/module_load
 * Payload: module_name(64)
 *
 * Tracepoint args (after 8-byte trace_entry):
 *   +8   taints     u32
 *   +12  __data_loc name   u32 (len<<16 | offset)
 */
#include "bpf_helpers.h"

#define MOD_NAME_SZ 64

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DEFAULT_RINGBUF_CAPACITY);
} events SEC(".maps");

struct module_load_event {
    struct event_hdr hdr;
    char module_name[MOD_NAME_SZ];
} __attribute__((packed));

SEC("tracepoint/module/module_load")
int eguard_module_load(void *ctx)
{
    struct module_load_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    bpf_memzero(e, sizeof(*e));
    fill_hdr(&e->hdr, EVENT_MODULE_LOAD);

    /* name via __data_loc at tp offset 12 */
    read_tp_data_loc_str(e->module_name, MOD_NAME_SZ, ctx, 12);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
