package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)


type event struct {
	Type   [16]byte 
	Cgroup uint64   
	Delta  int32   
	Pad    uint32  
}

type PodInfo struct {
	Name      string
	Namespace string
}

var (
	mapMutex        sync.RWMutex
	inoToCgroupPath = make(map[uint64]string)  
	uidToPodInfo    = make(map[string]PodInfo) 
	kubeClient      *kubernetes.Clientset

	// Rate-limiter for fallback pod refresh
	podRefreshMu      sync.Mutex
	podRefreshPending bool

	inodeOpTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "container_inode_operation_total",
			Help:      "Cumulative count of filesystem inode operations by type, pod, and namespace.",
			Subsystem: "overlayfs_tracer",
		},
		[]string{"operation", "pod_name", "namespace"},
	)
	containerInodeNetDelta = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "container_inode_net_delta",
			Help:      "Running net total of inode allocations vs deletions tracked by eBPF per pod.",
			Subsystem: "overlayfs_tracer",
		},
		[]string{"operation", "pod_name", "namespace"},
	)
	nodeInodeFree = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "node_inode_free",
			Help:      "Available inode count on the underlying host filesystem.",
			Subsystem: "overlayfs_tracer",
		},
		[]string{"node_name"},
	)
)

//Kube Client initialization
func initKubeClient() error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	kubeClient = client
	return nil
}

// Update Cgroup Map
func refreshCgroupMap(bpfMap *libbpfgo.BPFMap, root, prefix string) error {
	newInfo, err := getCgroupInfo(root, prefix)
	if err != nil {
		return err
	}

	mapMutex.Lock()
	defer mapMutex.Unlock()

	existing := make(map[uint64]struct{})
	iter := bpfMap.Iterator()
	for iter.Next() {
		key := binary.LittleEndian.Uint64(iter.Key())
		existing[key] = struct{}{}
	}

	dummy := uint32(1)

	for id := range newInfo {
		if _, ok := existing[id]; !ok {
			bpfMap.Update(unsafe.Pointer(&id), unsafe.Pointer(&dummy))
		}
		delete(existing, id)
	}

	for id := range existing {
		bpfMap.DeleteKey(unsafe.Pointer(&id))
	}

	inoToCgroupPath = newInfo
	return nil
}

// Map Cgroup Inodes to Paths
func getCgroupInfo(root, prefix string) (map[uint64]string, error) {
	result := make(map[uint64]string)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok {
				rel, _ := filepath.Rel(root, path)
				fullPath := prefix
				if rel != "." {
					fullPath += "/" + rel
				}
				result[stat.Ino] = fullPath
			}
		}
		return nil
	})

	return result, err
}

// Extract Pod UID from Cgroup Path
func extractPodUID(cgroupPath string) string {
	parts := strings.Split(strings.TrimPrefix(cgroupPath, "/"), "/")

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

		if strings.HasPrefix(part, "pod") {
			uid := strings.TrimPrefix(part, "pod")
			return strings.ReplaceAll(uid, "_", "-")
		}

		if strings.HasSuffix(part, ".slice") && strings.Contains(part, "-pod") {
			tmp := strings.SplitN(part, "-pod", 2)
			if len(tmp) == 2 {
				uid := strings.TrimSuffix(tmp[1], ".slice")
				return strings.ReplaceAll(uid, "_", "-")
			}
		}
	}
	return ""
}

// Refresh Pod Map
func refreshPodMap(ctx context.Context) error {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return fmt.Errorf("NODE_NAME not set")
	}

	pods, err := kubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return err
	}

	newMap := make(map[string]PodInfo)
	for _, pod := range pods.Items {
		newMap[string(pod.UID)] = PodInfo{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		}
	}

	mapMutex.Lock()
	defer mapMutex.Unlock()
	uidToPodInfo = newMap
	fmt.Printf("Refreshed Pod Map: found %d pods on node %s\n", len(uidToPodInfo), nodeName)
	return nil
}

// Watch Pods
func watchPods(ctx context.Context) {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		fmt.Println("NODE_NAME not set, watcher disabled")
		return
	}

	for {
		// Initial full list synchronization
		err := refreshPodMap(ctx)
		if err != nil {
			fmt.Printf("Initial pod sync failed: %v, retrying...\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		watcher, err := kubeClient.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + nodeName,
		})
		if err != nil {
			fmt.Printf("Pod watcher failed: %v, retrying...\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		fmt.Printf("Pod watcher started for node %s\n", nodeName)
		for event := range watcher.ResultChan() {
			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				continue
			}

			mapMutex.Lock()
			uid := string(pod.UID)
			switch event.Type {
			case "ADDED", "MODIFIED":
				uidToPodInfo[uid] = PodInfo{
					Name:      pod.Name,
					Namespace: pod.Namespace,
				}
			case "DELETED":
				delete(uidToPodInfo, uid)
				containerInodeNetDelta.DeleteLabelValues(pod.Name, pod.Namespace)
				for _, op := range []string{
					"vfs_create", "vfs_mkdir", "vfs_mknod", "vfs_rename",
					"vfs_symlink", "vfs_link",
					"vfs_unlink", "vfs_rmdir",
				} {
					inodeOpTotal.DeleteLabelValues(op, pod.Name, pod.Namespace)
				}
			}
			mapMutex.Unlock()
		}
		fmt.Println("Pod watcher channel closed, restarting...")
		time.Sleep(1 * time.Second)
	}
}

//Updating node level free inode gauge
func sampleInodes(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var nodeSt syscall.Statfs_t
			if err := syscall.Statfs("/", &nodeSt); err == nil {
				nodeName := os.Getenv("NODE_NAME")
				if nodeName == "" {
					nodeName = "unknown"
				}
				nodeInodeFree.WithLabelValues(nodeName).Set(float64(nodeSt.Ffree))
			}
		}
	}
}


func main() {
	prometheus.MustRegister(inodeOpTotal)
	prometheus.MustRegister(containerInodeNetDelta)
	prometheus.MustRegister(nodeInodeFree)

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(":9091", nil)
	}()

	if err := initKubeClient(); err != nil {
		fmt.Println("Kubernetes client init failed:", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	candidates := []string{
		"/sys/fs/cgroup/kubepods.slice",
		"/sys/fs/cgroup/unified/kubepods.slice",
		"/sys/fs/cgroup/kubepods",
	}

	var root string
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			root = p
			break
		}
	}

	if root == "" {
		fmt.Println("kubepods path not found")
		os.Exit(1)
	}
	prefix := "/" + filepath.Base(root)

	//Loading eBPF object
	module, err := libbpfgo.NewModuleFromFile("trace.bpf.o")
	if err != nil {
		panic(err)
	}
	defer module.Close()

	if err := module.BPFLoadObject(); err != nil {
		panic(err)
	}

	cgroupMap, err := module.GetMap("cgroup_filter")
	if err != nil {
		fmt.Printf("failed to get cgroup_filter map: %v\n", err)
		os.Exit(1)
	}

	refreshCgroupMap(cgroupMap, root, prefix)

	//Routines
	go watchPods(ctx)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for range ticker.C {
			refreshCgroupMap(cgroupMap, root, prefix)
		}
	}()
	go sampleInodes(ctx, 10*time.Second)

	// Attach all fentry probes to kernel VFS functions
	fentryProgs := []string{
		"trace_vfs_create",
		"trace_vfs_mkdir",
		"trace_vfs_mknod",
		"trace_vfs_symlink",
		"trace_vfs_link",
		"trace_vfs_unlink",
		"trace_vfs_rmdir",
		"trace_vfs_rename",
	}

	for _, name := range fentryProgs {
		prog, err := module.GetProgram(name)
		if err != nil {
			fmt.Printf("failed to get prog %s: %v\n", name, err)
			continue
		}

		if _, err := prog.AttachGeneric(); err != nil {
			fmt.Printf("failed to attach %s: %v\n", name, err)
		}
	}

	// Initialize Ring Buffer consumer
	eventsChan := make(chan []byte, 1000000)
	rb, err := module.InitRingBuf("events", eventsChan)
	if err != nil {
		fmt.Printf("failed to init ring buffer: %v\n", err)
		os.Exit(1)
	}
	rb.Start()
	defer rb.Stop()

	// Graceful Shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		cancel()
		rb.Stop()
		os.Exit(0)
	}()


	// Event Loop
	for data := range eventsChan {
		var e event
		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e); err != nil {
			continue
		}

		op := strings.TrimRight(string(e.Type[:]), "\x00")

		// Step 1: Resolve cgroup ID → cgroup path
		mapMutex.RLock()
		cgroupPath, ok := inoToCgroupPath[e.Cgroup]
		mapMutex.RUnlock()

		if !ok {
			continue
		}

		// Step 2: Extract Pod UID from cgroup path
		podUID := extractPodUID(cgroupPath)
		if podUID == "" {
			continue
		}

		// Step 3: Resolve Pod UID → Pod Name/Namespace
		mapMutex.RLock()
		info, ok := uidToPodInfo[podUID]
		mapMutex.RUnlock()

		if !ok {
			// Async, rate-limited fallback: refresh pod map without blocking the event loop
			podRefreshMu.Lock()
			if !podRefreshPending {
				podRefreshPending = true
				go func() {
					refreshPodMap(ctx)
					time.Sleep(5 * time.Second)
					podRefreshMu.Lock()
					podRefreshPending = false
					podRefreshMu.Unlock()
				}()
			}
			podRefreshMu.Unlock()
		}

		podName := "unknown"
		namespace := "unknown"

		if ok {
			podName = info.Name
			namespace = info.Namespace
		}

		// Record Prometheus metrics
		inodeOpTotal.With(prometheus.Labels{
			"operation": op,
			"pod_name":  podName,
			"namespace": namespace,
		}).Inc()

		containerInodeNetDelta.With(prometheus.Labels{
			"operation": op,
			"pod_name":  podName,
			"namespace": namespace,
		}).Add(float64(e.Delta))
	}
}
