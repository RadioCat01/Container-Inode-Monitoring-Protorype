#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct event {
    char type[8];
    u64 cgroup;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, u32);
} cgroup_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

#define O_CREAT 0x40

#define FILTER_AND_RESERVE \
    u64 cg = bpf_get_current_cgroup_id(); \
    u32 *val = bpf_map_lookup_elem(&cgroup_filter, &cg); \
    if (!val) return 0; \
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); \
    if (!e) return 0; \
    e->cgroup = cg;

SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_mkdir(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    bpf_probe_read_str(e->type, sizeof(e->type), "mkdir");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int trace_mkdirat(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    bpf_probe_read_str(e->type, sizeof(e->type), "mkdirat");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx) {
    u64 flags = BPF_CORE_READ(ctx, args[1]);
    if (!(flags & O_CREAT)) return 0;
    FILTER_AND_RESERVE
    bpf_probe_read_str(e->type, sizeof(e->type), "open");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 flags = BPF_CORE_READ(ctx, args[2]);
    if (!(flags & O_CREAT)) return 0;
    FILTER_AND_RESERVE
    bpf_probe_read_str(e->type, sizeof(e->type), "openat");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknod")
int trace_mknod(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    bpf_probe_read_str(e->type, sizeof(e->type), "mknod");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int trace_mknodat(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    bpf_probe_read_str(e->type, sizeof(e->type), "mknodat");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_symlink(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    bpf_probe_read_str(e->type, sizeof(e->type), "symlink");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    bpf_probe_read_str(e->type, sizeof(e->type), "symlinkat");
    bpf_ringbuf_submit(e, 0);
    return 0;
}


char LICENSE[] SEC("license") = "GPL";