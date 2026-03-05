#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct event {
    char type[16];
    u64 cgroup;
    s32 delta;
    u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, u32);
} cgroup_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 1024);
} events SEC(".maps");

//#define O_CREAT 0x40

#define FILTER_AND_RESERVE \
    u64 cg = bpf_get_current_cgroup_id(); \
    u32 *val = bpf_map_lookup_elem(&cgroup_filter, &cg); \
    if (!val) return 0; \
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); \
    if (!e) return 0; \
    e->cgroup = cg;

SEC("fentry/vfs_create")
int BPF_PROG(trace_vfs_create, 
    struct mnt_idmap *idmap,
    struct inode *dir, 
    struct dentry *dentry, 
    umode_t mode, 
    bool want_excl)
{
    FILTER_AND_RESERVE
    e->delta = 1;
    bpf_probe_read_str(e->type, sizeof(e->type), "vfs_create");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/vfs_mkdir")
int BPF_PROG(trace_vfs_mkdir, 
    struct mnt_idmap *idmap,
    struct inode *dir, 
    struct dentry *dentry, 
    umode_t mode)
{
    FILTER_AND_RESERVE
    e->delta = 1;
    bpf_probe_read_str(e->type, sizeof(e->type), "vfs_mkdir");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/vfs_mknod")
int BPF_PROG(trace_vfs_mknod, 
    struct mnt_idmap *idmap,
    struct inode *dir, 
    struct dentry *dentry, 
    umode_t mode, 
    dev_t dev)
{
    FILTER_AND_RESERVE
    e->delta = 1;
    bpf_probe_read_str(e->type, sizeof(e->type), "vfs_mknod");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/vfs_symlink")
int BPF_PROG(trace_vfs_symlink, 
    struct mnt_idmap *idmap,
    struct inode *dir, 
    struct dentry *dentry, 
    const char *symname)
{
    FILTER_AND_RESERVE
    e->delta = 1;
    bpf_probe_read_str(e->type, sizeof(e->type), "vfs_symlink");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/vfs_unlink")
int BPF_PROG(trace_vfs_unlink, 
    struct mnt_idmap *idmap,
    struct inode *dir, 
    struct dentry *dentry)
{
    FILTER_AND_RESERVE
    e->delta = -1;
    bpf_probe_read_str(e->type, sizeof(e->type), "vfs_unlink");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/vfs_rmdir")
int BPF_PROG(trace_vfs_rmdir, 
    struct mnt_idmap *idmap,
    struct inode *dir, 
    struct dentry *dentry)
{
    FILTER_AND_RESERVE
    e->delta = -1;
    bpf_probe_read_str(e->type, sizeof(e->type), "vfs_rmdir");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/vfs_link")
int BPF_PROG(trace_vfs_link, 
    struct mnt_idmap *idmap,
    struct inode *old_dir, 
    struct dentry *old_dentry, 
    struct inode *new_dir, 
    struct dentry *new_dentry)
{
    FILTER_AND_RESERVE
    e->delta = 0;
    bpf_probe_read_str(e->type, sizeof(e->type), "vfs_link");
    bpf_ringbuf_submit(e, 0);
    return 0;
}
// SEC("tracepoint/syscalls/sys_enter_mkdir")
// int trace_mkdir(struct trace_event_raw_sys_enter *ctx) {
//     FILTER_AND_RESERVE
//     bpf_probe_read_str(e->type, sizeof(e->type), "mkdir");
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_mkdirat")
// int trace_mkdirat(struct trace_event_raw_sys_enter *ctx) {
//     FILTER_AND_RESERVE
//     bpf_probe_read_str(e->type, sizeof(e->type), "mkdirat");
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_open")
// int trace_open(struct trace_event_raw_sys_enter *ctx) {
//     u64 flags = BPF_CORE_READ(ctx, args[1]);
//     if (!(flags & O_CREAT)) return 0;
//     FILTER_AND_RESERVE
//     bpf_probe_read_str(e->type, sizeof(e->type), "open");
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_openat")
// int trace_openat(struct trace_event_raw_sys_enter *ctx) {
//     u64 flags = BPF_CORE_READ(ctx, args[2]);
//     if (!(flags & O_CREAT)) return 0;
//     FILTER_AND_RESERVE
//     bpf_probe_read_str(e->type, sizeof(e->type), "openat");
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_mknod")
// int trace_mknod(struct trace_event_raw_sys_enter *ctx) {
//     FILTER_AND_RESERVE
//     bpf_probe_read_str(e->type, sizeof(e->type), "mknod");
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_mknodat")
// int trace_mknodat(struct trace_event_raw_sys_enter *ctx) {
//     FILTER_AND_RESERVE
//     bpf_probe_read_str(e->type, sizeof(e->type), "mknodat");
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_symlink")
// int trace_symlink(struct trace_event_raw_sys_enter *ctx) {
//     FILTER_AND_RESERVE
//     bpf_probe_read_str(e->type, sizeof(e->type), "symlink");
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_symlinkat")
// int trace_symlinkat(struct trace_event_raw_sys_enter *ctx) {
//     FILTER_AND_RESERVE
//     bpf_probe_read_str(e->type, sizeof(e->type), "symlinkat");
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }


char LICENSE[] SEC("license") = "GPL";