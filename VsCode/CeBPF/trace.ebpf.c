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

SEC("fentry/vfs_rename")
int BPF_PROG(trace_vfs_rename,
    struct renamedata *rd)
{
    FILTER_AND_RESERVE
    e->delta = 0;
    bpf_probe_read_str(e->type, sizeof(e->type), "vfs_rename");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/ovl_unlink")
int BPF_KPROBE(trace_ovl_unlink)
{
    FILTER_AND_RESERVE

    e->delta = -1;

    const char type[] = "ovl_unlink";
    __builtin_memcpy(e->type, type, sizeof(type));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/ovl_copy_up")
int BPF_KPROBE(trace_ovl_copy_up)
{
    FILTER_AND_RESERVE
    e->delta = 1;
    const char type[] = "ovl_copy_up";
    __builtin_memcpy(e->type, type, sizeof(type));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";