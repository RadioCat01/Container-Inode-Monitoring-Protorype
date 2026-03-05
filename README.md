# Container Inode Monitoring Prototype

## Architecture Overview of the Daemon

This Go program is an **eBPF-powered Kubernetes-aware filesystem activity tracer**.  
It loads an eBPF object (`trace.bpf.o`), attaches multiple syscall tracepoints, and correlates events with Kubernetes pods by resolving cgroup inodes to pod UIDs and pod names.

---

## 1. Compilation Architecture

### eBPF Object (`trace.bpf.o`)
The eBPF code is compiled separately (via Clang) and shipped as a file that the Go daemon loads.
#### vmlinux.h
Auto-generated header created from the running kernel’s BTF (BPF Type Format) **CO-RE**. Allowing the eBPF program to know *how* to read kernel memory safely across different kernel versions.
It contains:
- Full type definitions for kernel structs  
  (e.g., `task_struct`, `cred`, `inode`, `trace_event_raw_sys_enter`, etc.)
- Constants, enums, macros
- Field layout and offsets for the running kernel
```bash
clang -O2 -g -target bpf -c trace.bpf.c -o trace.bpf.o -I.
```

### Go Daemon Compilation
The Go daemon uses CGO to dynamically link against libbpf. So that the image must contain the libraries.
```bash
CGO_CFLAGS="$(pkg-config --cflags libbpf)"
CGO_LDFLAGS="$(pkg-config --libs libbpf)"
go build -v -o daemon .
```
* CGO_CFLAGS → instructs Go compiler where libbpf headers are located
* CGO_LDFLAGS → links the Go binary with the system’s libbpf.so

## 2. Containerization and Deployment

### Docker File
Application is dynamically linked so that the libbpf libraries need to be included in the image's lower layer.
```bash
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      libbpf1 libelf1 zlib1g ca-certificates libzstd1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY daemon trace.bpf.o /app/
RUN chmod +x /app/daemon

CMD ["./daemon"]
```

### DaemonSet Architecture: Mounts & Environment Variables
This DaemonSet runs the eBPF tracer as a **privileged pod** on all nodes.  
To interact with the host kernel and cgroups: **volume mounts** and **environment variables** are used as below.


#### 1. Volume Mounts

The container mounts host filesystems to access kernel and cgroup information:

| Volume Name   | Mount Path (Container)     | Purpose                                                                 |
|---------------|---------------------------|-------------------------------------------------------------------------|
| `sysfs-cgroup` | `/sys/fs/cgroup`          | Provides access to the host’s cgroup filesystem. The daemon reads cgroup directories and inodes to map processes to Kubernetes pods. Mounted read-only to prevent accidental modifications. |
| `tracefs`      | `/sys/kernel/tracing`     | Exposes kernel tracing interfaces (tracepoints, perf events). Required by eBPF to attach programs to syscalls and collect events. Read-only for safety. |

These mounts ensure the container can **observe host kernel events** without interfering with the host system.

---

#### 2. Environment Variable

| Name       | Purpose                                                                 |
|------------|-------------------------------------------------------------------------|
| `NODE_NAME` | Populated automatically with the name of the node the pod is running on. The eBPF daemon uses it to query the Kubernetes API and map pod UIDs to pods running on that specific node. |

The combination of **privileged mode**, **hostPID**, and these mounts allows the daemon to fully inspect the host’s process and filesystem activities.

---

#### 3. Architectural Flow

1. **Daemon runs on each node** (`hostPID: true`)  
2. **Accesses host cgroups** via `/sys/fs/cgroup` → maps inodes to processes/pods  
3. **Attaches eBPF programs to tracepoints** via `/sys/kernel/tracing`  
4. **Uses NODE_NAME** to filter pods relevant to the local node  
---

### RBAC Architecture for eBPF Daemon
Defines **Kubernetes permissions** that allow the eBPF tracer DaemonSet to read pod metadata from the API server while running on all nodes.

#### ServiceAccount
Provides an identity for the DaemonSet pods when communicating with the Kubernetes API.
```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ebpf-tracer-sa
```
#### ClusterRole
This Grants read-only access to all Pods across the cluster. Since the daemon runs on all nodes, a ClusterRole (cluster-wide scope) is required instead of a namespace-scoped Role.
```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```
#### ClusterRoleBinding
Binds the ClusterRole to the ServiceAccount ebpf-tracer-sa. Ensures that any pod using this ServiceAccount inherits the defined cluster-wide permissions.
```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
subjects:
- kind: ServiceAccount
  name: ebpf-tracer-sa
roleRef:
  kind: ClusterRole
  name: ebpf-tracer-role
```

---

## 3. Application Architecture
### 1. eBPF C Program (`trace.bpf.c`)
This file implements the kernel-level tracing logic using **eBPF**. The design focuses on **lightweight, safe, and portable kernel monitoring**.
- eBPF programs run in a **restricted C subset** enforced by the kernel verifier.  
- No loops with unknown bounds, limited pointer arithmetic, and safe memory access are required.  
- Ensures the program cannot crash the kernel.

#### 1. Event Structure 
Captures filesystem events (mkdir, open, symlink, etc.). Type identifies the syscall type, cgroup stores the current cgroup ID.
```c
struct event {
    char type[16];
    u64 cgroup;
    s32 delta;
};
```
#### 2. BPF Maps
- **cgroup_filter** (HASH map):
  - Stores allowed cgroup IDs for filtering events
  - Key: cgroup id (u64), Value: dummy (u32)

- **events** (RINGBUF map):
  - Transfers events from kernel to user-space
  - Efficient, lock-free, supports high-frequency events

Maps are declared with SEC(".maps") and loaded by libbpf/libbpfgo in the Go daemon.

#### 3. FTrace & Filtering
- fentry(ftrace) BPF_PROG (s) are used to do the tracing with minimal overhead.
  - **sudo bpftrace -lv 'fentry:vfs_create'** used to identify the function arguments for each function
  - vfs_create, vfs_mkdir, vfs_mknod, vfs_syslink --> delta +1
  - vfs_unlink, vfs_rmdir --> delta -1
  - vfs_link --> delta 0
- Macro FILTER_AND_RESERVE:
  - Reads current cgroup ID (bpf_get_current_cgroup_id())
  - Filters out irrelevant cgroups using cgroup_filter
  - Reserves an event in the events ring buffer
- bpf_probe_read_str() safely copies the syscall name into the event structure.
- bpf_ringbuf_submit() publishes the event to user-space.

### 2. GO-Lang Daemon (daemon)
This Go program acts as the **user-space companion** to the eBPF kernel program, responsible for **loading, managing, and consuming eBPF events** in a Kubernetes environment.
- **Load eBPF Object:** Uses `libbpfgo` to load the compiled `trace.bpf.o` into the kernel.
- **Manage BPF Maps:** Updates `cgroup_filter` and reads `events` from the eBPF ring buffer.
- **Pod Mapping:** Maps cgroup IDs to Kubernetes pods by querying the cluster API.
- **Event Processing:** Reads events from the ring buffer, correlates them with pod information, and prints structured logs.

### Sample Index Node Stress Workloads (Only for Testing)
```
cd /tmp && mkdir -p inode_data && seq 1 30000 | xargs -n1 -P8 -I{} sh -c 'echo {} > inode_data/f_{}'
cd /tmp && mkdir -p churn && seq 1 20000 | xargs -n1 -P6 -I{} sh -c 'echo x > churn/a_{} && mv churn/a_{} churn/b_{}'

```
