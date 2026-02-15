/* eguard-agent BPF helpers
 *
 * Minimal, self-contained header for eBPF programs compiled with
 * `zig cc -target bpfel`.  No kernel-header dependency — builds on
 * any host with Zig >= 0.12.
 *
 * Portable across Linux >= 5.8 (ringbuf support).
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

/* ── Section / map macros (libbpf BTF-style) ───────────────── */
#define SEC(name) __attribute__((section(name), used))
#define __uint(field, val) int (*field)[val]

/* ── Map types ─────────────────────────────────────────────── */
#define BPF_MAP_TYPE_RINGBUF 27

/* ── Ring buffer capacity (bytes) ───────────────────────────── */
#define DEFAULT_RINGBUF_CAPACITY (8 * 1024 * 1024)

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

/* GPL — required for probe_read* and ringbuf helpers */
char LICENSE[] SEC("license") = "GPL";

#endif /* EGUARD_BPF_HELPERS_H */
