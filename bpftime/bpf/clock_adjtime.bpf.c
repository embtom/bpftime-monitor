#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "timex_event.h"

#define ADJ_OFFSET 0x0001
#define ADJ_FREQUENCY 0x0002
#define ADJ_ESTERROR 0x0008
#define ADJ_STATUS 0x0010
#define ADJ_SETOFFSET 0x0100
#define ADJ_TICK 0x4000

#define STA_UNSYNC 0x0040
#define CLOCK_REALTIME 0

/* -------------------- maps -------------------- */
#define KB(x) ((x) * 1024)

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, KB(4));
} clock_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, KB(4));
} status_events SEC(".maps");

/* per-CPU last return value */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, long);
} last_ret SEC(".maps");

/*
 * Tracepoint handler for syscalls:sys_enter_clock_adjtime.
 *
 * The kernel syscall is defined as:
 *   SYSCALL_DEFINE2(clock_adjtime,
 *                   const clockid_t which_clock,
 *                   struct __kernel_timex __user *utx)
 *
 * All syscall tracepoints use the generic
 *   struct trace_event_raw_sys_enter
 * context, where syscall arguments are stored in ctx->args[].
 *
 * Mapping:
 *   ctx->args[0] → which_clock
 *   ctx->args[1] → utx (user-space pointer, must use bpf_probe_read_user)
 *
 * The layout and offsets shown in:
 *   /sys/kernel/tracing/events/syscalls/sys_enter_clock_adjtime/format
 * correspond to this structure
 */
SEC("tracepoint/syscalls/sys_enter_clock_adjtime")
int clock_adjtime_enter(struct trace_event_raw_sys_enter* ctx)
{
    clockid_t which_clock = ctx->args[0];
    struct __kernel_timex* tx = (struct __kernel_timex*)ctx->args[1];

    struct TimexEvent* ev;
    __u32 modes = 0;

    if (which_clock != CLOCK_REALTIME || tx == NULL)
        return 0;

    // tx is a user-space pointer, so we must use bpf_core_read_user() to read its fields.
    bpf_core_read_user(&modes, sizeof(modes), &tx->modes);

    if (!(modes &
          (ADJ_TICK | ADJ_FREQUENCY | ADJ_STATUS | ADJ_OFFSET | ADJ_SETOFFSET | ADJ_ESTERROR)))
        return 0;

    ev = bpf_ringbuf_reserve(&clock_events, sizeof(struct TimexEvent), 0);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(struct TimexEvent));
    ev->modes = modes;

    if (modes & ADJ_ESTERROR)
        bpf_core_read_user(&ev->esterror, sizeof(ev->esterror), &tx->esterror);
    if (modes & ADJ_FREQUENCY)
        bpf_core_read_user(&ev->freq, sizeof(ev->freq), &tx->freq);
    if (modes & ADJ_TICK)
        bpf_core_read_user(&ev->tick, sizeof(ev->tick), &tx->tick);
    if (modes & ADJ_STATUS)
        bpf_core_read_user(&ev->status, sizeof(ev->status), &tx->status);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * Tracepoint handler for syscalls:sys_exit_clock_adjtime.
 *
 * The syscall is defined as:
 *   SYSCALL_DEFINE2(clock_adjtime,
 *                   const clockid_t which_clock,
 *                   struct __kernel_timex __user *utx)
 *
 * Syscall exit tracepoints use the generic
 *   struct trace_event_raw_sys_exit
 * context. It does NOT expose syscall arguments again.
 *
 * Available fields:
 *   ctx->id   → syscall number
 *   ctx->ret  → return value of clock_adjtime()
 *
 * Argument values (which_clock, utx) are only available
 * in the corresponding sys_enter tracepoint.
 */
SEC("tracepoint/syscalls/sys_exit_clock_adjtime")
int clock_adjtime_exit(struct trace_event_raw_sys_exit* ctx)
{
    __u32 key = 0;
    long ret = ctx->ret;
    long* last;
    long* out;

    // Ignore negative return values - errors
    if (ret < 0)
        return 0;

    // Look up per-CPU last return value
    // Skip if map not found (should not happen) or value unchanged
    last = bpf_map_lookup_elem(&last_ret, &key);
    if (!last)
        return 0;

    // if (*last == ret)
    //     return 0;

    *last = ret;

    out = bpf_ringbuf_reserve(&status_events, sizeof(ret), 0);
    if (!out)
        return 0;

    *out = ret;
    bpf_ringbuf_submit(out, 0);
    return 0;
}

/*
 * Tracepoint handler for syscalls:sys_enter_clock_settime.
 *
 * The syscall is defined as:
 *   SYSCALL_DEFINE2(clock_settime,
 *                   const clockid_t which_clock,
 *                   const struct __kernel_timespec __user *tp)
 *
 * All syscall enter tracepoints use the generic
 *   struct trace_event_raw_sys_enter context, where arguments
 *   are stored in ctx->args[].
 *
 * Mapping:
 *   ctx->args[0] → which_clock
 *   ctx->args[1] → tp (user-space pointer, use bpf_probe_read_user)
 *
 * The offsets shown in:
 *   /sys/kernel/tracing/events/syscalls/sys_enter_clock_settime/format
 * reflect this layout with 8-byte alignment on x86_64.
 */
SEC("tracepoint/syscalls/sys_enter_clock_settime")
int clock_settime_enter(struct trace_event_raw_sys_enter* ctx)
{
    clockid_t which_clock = ctx->args[0];
    const struct __kernel_timespec* tp = (const struct __kernel_timespec*)ctx->args[1];

    struct TimexEvent* ev;
    long tv_nsec = 0;

    if (which_clock != CLOCK_REALTIME || !tp)
        return 0;

    bpf_core_read_user(&tv_nsec, sizeof(tv_nsec), &tp->tv_nsec);

    if (tv_nsec < 0 || tv_nsec > 999999999)
        return 0;

    // Reserve space in the ring buffer for this new event
    ev = bpf_ringbuf_reserve(&clock_events, sizeof(struct TimexEvent), 0);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->modes = ADJ_STATUS | ADJ_SETOFFSET;
    ev->status.R = STA_UNSYNC;

    // submit the event to userspace
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
