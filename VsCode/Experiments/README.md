# Inode Research Experiments

This directory contains three automated experiments designed to prove the hypotheses in your research paper.

> **CRITICAL ARCHITECTURE NOTE:**
> In your previous tests with `kubectl exec`, events were dropped because the execution terminal opened a new cgroup that your daemon hadn't discovered yet. 
> To guarantee flawless telemetry, each of these experimental pods features a built-in **20-second sleep** on startup. This gives your Go daemon's `refreshCgroupMap` routine (which runs every 15s) time to map the new container to eBPF before the experiment begins to hammer the filesystem.

## How to execute

### Experiment 1: The Whiteout Penalty
Proves that deleting a base-image file *costs* an inode rather than freeing it.
```bash
kubectl apply -f experiment1_whiteout.yaml
```
**What to look for on Grafana:**
- In Panel 2 (Event Velocity), watch `operation="vfs_mknod"` spike by exactly 5,000 for `exp1-whiteout`.
- In Panel 1 (Node Health), watch `node_inode_free` DROP by 5,000 at the exact same moment.
- *Once verified, `kubectl delete pod exp1-whiteout`*

### Experiment 2: The Evasion Attack
Proves that high-velocity workload I/O can cause massive inode turbulence that threshold polling completely misses.
```bash
kubectl apply -f experiment2_evasion.yaml
```
**What to look for on Grafana:**
- Your system disk quota (if you checked via standard k8s polling) would show 0 files created, because they are deleted instantly.
- In Panel 5 (Invisible Workload Velocity), watch the churn rate explode to thousands of operations/sec for `vfs_create` and `vfs_unlink`.
- *Once verified, `kubectl delete pod exp2-evasion`*

### Experiment 3: Performance Benchmark
Proves the efficiency of your ring-buffer tracing architecture under a 30,000 file-per-second concurrency load.
```bash
kubectl apply -f experiment3_benchmark.yaml
```
**What to look for on Grafana:**
- Open a terminal and run `kubectl top pod -n <your-daemonset-namespace>` 
- Watch the CPU and Ram footprint of your eBPF tracer while the spike of 30,000 `vfs_create` hits Panel 2. Wait 30 seconds for Prometheus to digest the metrics.
- Note how the metric scales up cleanly without the eBPF tracer crashing or consuming gigabytes of RAM.
- *Once verified, `kubectl delete pod exp3-benchmark`*
