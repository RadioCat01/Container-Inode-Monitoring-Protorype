#!/bin/bash

if [ -d /sys/fs/cgroup/kubepods.slice ]; then
  ROOT=/sys/fs/cgroup/kubepods.slice
elif [ -d /sys/fs/cgroup/unified/kubepods.slice ]; then
  ROOT=/sys/fs/cgroup/unified/kubepods.slice
elif [ -d /sys/fs/cgroup/kubepods ]; then
  ROOT=/sys/fs/cgroup/kubepods
else
  echo "kubepods path not found under /sys/fs/cgroup. Inspect /sys/fs/cgroup manually."; exit 1
fi
echo "Using ROOT = $ROOT"

IDS=$(sudo find "$ROOT" -type d -printf '%i ' 2>/dev/null)

if [ -z "$IDS" ]; then
  echo "No descendant cgroup inodes found under $ROOT"
  echo "Try running: sudo find $ROOT -type d -printf '%i %p\n' to inspect"
  exit 1
fi

PRED=$(echo $IDS | awk '{for(i=1;i<=NF;i++){ if(i>1) printf " || "; printf "cgroup == %s", $i }}')

sudo bpftrace -e "
tracepoint:syscalls:sys_enter_mkdir,
tracepoint:syscalls:sys_enter_mkdirat
/ ($PRED) /
{
    printf(\"[mkdir] cgid=%llu mode=%d\\n\", cgroup, args->mode);
}
tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat
/ ($PRED) && (args->flags & 0x40) /
{
    printf(\"[open] cgid=%llu mode=%d\\n\", cgroup, args->mode);
}
tracepoint:syscalls:sys_enter_mknod,
tracepoint:syscalls:sys_enter_mknodat
/ ($PRED) /
{
    printf(\"[mknod] cgid=%llu mode=%d\\n\", cgroup, args->mode);
}
tracepoint:syscalls:sys_enter_symlink,
tracepoint:syscalls:sys_enter_symlinkat
/ ($PRED) /
{
    printf(\"[symlink] cgid=%llu mode=0\\n\", cgroup);
}
"
