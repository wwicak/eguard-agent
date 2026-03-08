/* eguard-agent BPF helpers
 *
 * Minimal, self-contained header for eBPF programs compiled with
 * `zig cc -target bpfel`. No kernel-header dependency — builds on
 * any host with Zig >= 0.12.
 *
 * Supports ring-buffer transport on newer kernels and perf-event-array
 * fallback on older kernels that reject BPF_MAP_TYPE_RINGBUF.
 */
#ifndef EGUARD_BPF_HELPERS_H
#define EGUARD_BPF_HELPERS_H

/* ── Scalar types ──────────────────────────────────────────── */
typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
typedef long long           __s64;
typedef int                 __s32;

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#if __has_attribute(preserve_access_index)
#define __preserve_access_index __attribute__((preserve_access_index))
#else
#define __preserve_access_index
#endif

/* Minimal CO-RE-aware task struct subset used for parent process attribution. */
struct task_struct {
    struct task_struct *real_parent;
    __u32 tgid;
    char comm[16];
} __preserve_access_index;

/* ── Section / map macros (libbpf BTF-style) ───────────────── */
#define SEC(name) __attribute__((section(name), used))
#define __uint(field, val) int (*field)[val]

/* ── Map types ─────────────────────────────────────────────── */
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_RINGBUF 27

/* ── Event transport sizing ────────────────────────────────── */
#define DEFAULT_RINGBUF_CAPACITY (8 * 1024 * 1024)
#define PERF_EVENT_ARRAY_MAX_ENTRIES 1024
#define BPF_F_CURRENT_CPU 0xffffffffULL

/* ── BPF helper prototypes (function-pointer-by-ID) ────────── */
static long (*bpf_probe_read)(void *, __u32, const void *) =
    (long (*)(void *, __u32, const void *))(long)4;
static __u64 (*bpf_ktime_get_ns)(void) =
    (__u64 (*)(void))(long)5;
static __u64 (*bpf_get_current_pid_tgid)(void) =
    (__u64 (*)(void))(long)14;
static __u64 (*bpf_get_current_uid_gid)(void) =
    (__u64 (*)(void))(long)15;
static long (*bpf_get_current_comm)(void *, __u32) =
    (long (*)(void *, __u32))(long)16;
static long (*bpf_perf_event_output)(void *, void *, __u64, void *, __u64) =
    (long (*)(void *, void *, __u64, void *, __u64))(long)25;
static void *(*bpf_get_current_task)(void) =
    (void *(*)(void))(long)35;
static __u64 (*bpf_get_current_cgroup_id)(void) =
    (__u64 (*)(void))(long)80;
static long (*bpf_probe_read_user)(void *, __u32, const void *) =
    (long (*)(void *, __u32, const void *))(long)112;
static long (*bpf_probe_read_kernel)(void *, __u32, const void *) =
    (long (*)(void *, __u32, const void *))(long)113;
static long (*bpf_probe_read_user_str)(void *, __u32, const void *) =
    (long (*)(void *, __u32, const void *))(long)114;
static long (*bpf_probe_read_kernel_str)(void *, __u32, const void *) =
    (long (*)(void *, __u32, const void *))(long)115;
static void *(*bpf_ringbuf_reserve)(void *, __u64, __u64) =
    (void *(*)(void *, __u64, __u64))(long)131;
static void (*bpf_ringbuf_submit)(void *, __u64) =
    (void (*)(void *, __u64))(long)132;
static void (*bpf_ringbuf_discard)(void *, __u64) =
    (void (*)(void *, __u64))(long)133;

/* ── Inline zero-fill (verifier-friendly, no memset call) ──── */
static __attribute__((always_inline)) void
bpf_memzero(void *dst, __u32 sz)
{
    __u8 *p = (__u8 *)dst;
    for (__u32 i = 0; i < sz; i++)
        p[i] = 0;
}

static __attribute__((always_inline)) __u16
bpf_ntohs(__u16 v)
{
    return (v >> 8) | (v << 8);
}

/* ── Drop-counter buffer (BSS) ──────────────────────────────── */
#define FALLBACK_LAST_EVENT_DATA_SIZE 512

struct fallback_ringbuf_state {
    __u32 last_event_len;
    __u8  last_event_data[FALLBACK_LAST_EVENT_DATA_SIZE];
    __u64 dropped_events;
};

volatile struct fallback_ringbuf_state fallback_state;

static __attribute__((always_inline)) void
record_drop(void)
{
    fallback_state.dropped_events++;
}

/* Drop-counter BSS buffer is defined in legacy Zig programs; keep C lean. */

/* ── Event transport helpers ───────────────────────────────── */
#ifdef EGUARD_USE_PERFBUF
#define EGUARD_DEFINE_EVENTS_MAP(name)                                    \
    struct {                                                              \
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);                      \
        __uint(key_size, sizeof(__u32));                                  \
        __uint(value_size, sizeof(__u32));                                \
        __uint(max_entries, PERF_EVENT_ARRAY_MAX_ENTRIES);                \
    } name SEC(".maps")

#define EGUARD_ALLOC_EVENT(type, name)                                    \
    struct type name##_storage;                                           \
    struct type *name = &name##_storage;                                  \
    bpf_memzero(name, sizeof(*name))

#define EGUARD_DISCARD_EVENT(name) do { (void)(name); } while (0)

#define EGUARD_SUBMIT_EVENT(ctx, name)                                    \
    do {                                                                  \
        long __eguard_rc = bpf_perf_event_output(                         \
            (ctx), &events, BPF_F_CURRENT_CPU, (name), sizeof(*(name)));  \
        if (__eguard_rc != 0)                                             \
            record_drop();                                                \
        return 0;                                                         \
    } while (0)
#else
#define EGUARD_DEFINE_EVENTS_MAP(name)                                    \
    struct {                                                              \
        __uint(type, BPF_MAP_TYPE_RINGBUF);                               \
        __uint(max_entries, DEFAULT_RINGBUF_CAPACITY);                    \
    } name SEC(".maps")

#define EGUARD_ALLOC_EVENT(type, name)                                    \
    struct type *name = bpf_ringbuf_reserve(&events, sizeof(*name), 0);   \
    if (!(name)) {                                                        \
        record_drop();                                                    \
        return 0;                                                         \
    }                                                                     \
    bpf_memzero(name, sizeof(*name))

#define EGUARD_DISCARD_EVENT(name) do { bpf_ringbuf_discard((name), 0); } while (0)

#define EGUARD_SUBMIT_EVENT(ctx, name)                                    \
    do {                                                                  \
        (void)(ctx);                                                      \
        bpf_ringbuf_submit((name), 0);                                    \
        return 0;                                                         \
    } while (0)
#endif

/* ── Tracepoint __data_loc safety ──────────────────────────── *
 * __data_loc fields encode (len << 16 | offset) in a u32.
 * We clamp both to sane maximums to avoid out-of-bounds reads.
 */
#define TP_DATA_LOC_MAX_OFF  4096  /* tracepoint struct never > 4K */

static __attribute__((always_inline)) void
read_tp_data_loc_str(void *dst, __u32 dst_sz, void *ctx, __u32 loc_offset)
{
    __u32 loc = 0;
    bpf_probe_read(&loc, sizeof(loc), (__u8 *)ctx + loc_offset);

    __u32 off = loc & 0xFFFF;
    __u32 len = loc >> 16;

    /* Clamp to prevent OOB */
    if (off == 0 || off > TP_DATA_LOC_MAX_OFF)
        return;
    if (len == 0)
        return;
    if (len > dst_sz - 1)
        len = dst_sz - 1;

    bpf_probe_read_kernel_str(dst, len + 1, (__u8 *)ctx + off);
}

/* ── Event types (must match crates/platform-linux EventType) ── */
#define EVENT_PROCESS_EXEC   1
#define EVENT_FILE_OPEN      2
#define EVENT_TCP_CONNECT    3
#define EVENT_DNS_QUERY      4
#define EVENT_MODULE_LOAD    5
#define EVENT_LSM_BLOCK      6
#define EVENT_FILE_WRITE     8
#define EVENT_FILE_RENAME    9
#define EVENT_FILE_UNLINK    10

/* ── Event header — 21 bytes packed ────────────────────────── *
 * Matches parse_raw_event() in platform-linux/src/ebpf.rs:
 *   [0]  event_type  u8
 *   [1]  pid         u32 LE
 *   [5]  tid         u32 LE
 *   [9]  uid         u32 LE
 *   [13] timestamp   u64 LE
 */
struct event_hdr {
    __u8  event_type;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u64 timestamp_ns;
} __attribute__((packed));

/* Fill header from current-task context */
static __attribute__((always_inline)) void
fill_hdr(struct event_hdr *h, __u8 etype)
{
    __u64 pt = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();
    h->event_type   = etype;
    h->pid          = (__u32)(pt >> 32);
    h->tid          = (__u32)(pt & 0xFFFFFFFF);
    h->uid          = (__u32)(ug & 0xFFFFFFFF);
    h->timestamp_ns = bpf_ktime_get_ns();
}

/* GPL — required for probe_read*, perf_event_output, and ringbuf helpers */
char LICENSE[] SEC("license") = "GPL";

#endif /* EGUARD_BPF_HELPERS_H */
