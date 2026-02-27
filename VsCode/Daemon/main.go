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
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type event struct {
	Type   [8]byte
	Cgroup uint64
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
	inodeOpTotal    = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "container_inode_operation_total",
			Help:      "Cumulative count of filesystem inode operations by type, pod, and namespace.",
			Subsystem: "overlayfs_tracer",
		},
		[]string{"operation", "pod_name", "namespace"},
	)
)

//////////////////////////////////////////////////////////////
// Inode Measures
//////////////////////////////////////////////////////////////

var (
	// Gauges: current total/free/used inodes per pod
	overlayInodeTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "overlayfs_inode_total",
			Help:      "Total inode count of overlay upperdir per pod.",
			Subsystem: "overlayfs_tracer",
		},
		[]string{"pod_name", "namespace"},
	)

	overlayInodeFree = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "overlayfs_inode_free",
			Help:      "Free inode count of overlay upperdir per pod.",
			Subsystem: "overlayfs_tracer",
		},
		[]string{"pod_name", "namespace"},
	)

	overlayInodeUsed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "overlayfs_inode_used",
			Help:      "Used inode count of overlay upperdir per pod.",
			Subsystem: "overlayfs_tracer",
		},
		[]string{"pod_name", "namespace"},
	)

	// Counter: positive increases in used inodes per sampling (so increase() works)
	overlayInodeUsedDelta = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "overlayfs_inode_used_delta_total",
			Help:      "Accumulated positive delta of used inodes detected per pod (sampling-based).",
			Subsystem: "overlayfs_tracer",
		},
		[]string{"pod_name", "namespace"},
	)

	// Runtime maps
	upperdirMap   = make(map[string]string) // podUID -> upperdir (host path)
	inodePrevUsed = make(map[string]uint64) // podUID -> last used count (Files - Ffree)
)

//////////////////////////////////////////////////////////////
// Kubernetes Client Initialization (only once)
//////////////////////////////////////////////////////////////

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

//////////////////////////////////////////////////////////////
// Cgroup Discovery
//////////////////////////////////////////////////////////////

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

//////////////////////////////////////////////////////////////
// Pod Map Refresh
//////////////////////////////////////////////////////////////

func refreshPodMap(ctx context.Context) error {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return fmt.Errorf("NODE_NAME not set")
	}

	pods, err := kubeClient.CoreV1().Pods("").List(ctx, v1.ListOptions{
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
	uidToPodInfo = newMap
	mapMutex.Unlock()

	return nil
}

//////////////////////////////////////////////////////////////
// Utility: Extract Pod UID
//////////////////////////////////////////////////////////////

func extractPodUID(cgroupPath string) string {
	parts := strings.Split(strings.TrimPrefix(cgroupPath, "/"), "/")

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

		if strings.HasPrefix(part, "pod") {
			return strings.TrimPrefix(part, "pod")
		}

		if strings.HasSuffix(part, ".slice") && strings.Contains(part, "-pod") {
			tmp := strings.SplitN(part, "-pod", 2)
			if len(tmp) == 2 {
				return strings.ReplaceAll(
					strings.TrimSuffix(tmp[1], ".slice"),
					"_",
					"-",
				)
			}
		}
	}
	return ""
}

//////////////////////////////////////////////////////////////
// Utility: Extract Pod PID
//////////////////////////////////////////////////////////////

func findAnyPidForPod(podUID string) (string, error) {
	mapMutex.RLock()
	// snapshot the paths (to avoid holding lock while doing IO)
	paths := make([]string, 0, len(inoToCgroupPath))
	for _, p := range inoToCgroupPath {
		if strings.Contains(p, podUID) {
			paths = append(paths, p)
		}
	}
	mapMutex.RUnlock()

	for _, p := range paths {
		procsPath := filepath.Join("/sys/fs/cgroup", p, "cgroup.procs")
		data, err := os.ReadFile(procsPath)
		if err != nil {
			continue
		}
		lines := strings.Fields(strings.TrimSpace(string(data)))
		if len(lines) > 0 {
			return lines[0], nil // return first PID
		}
	}
	return "", fmt.Errorf("no pid found for podUID %s", podUID)
}

//////////////////////////////////////////////////////////////
// Utility: Extract Upperdir for POD PID
//////////////////////////////////////////////////////////////

func findUpperdirForPid(pid string) (string, error) {
	miPath := filepath.Join("/proc", pid, "mountinfo")
	data, err := os.ReadFile(miPath)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		// mountinfo format: fields ... - fstype source mountopts ...
		// We can search the options part for "upperdir="
		// Simpler: search the whole line for "overlay" and "upperdir="
		if strings.Contains(line, " overlay ") && strings.Contains(line, "upperdir=") {
			// options usually after the 6th field; but just extract upperdir=... portion
			idx := strings.Index(line, "upperdir=")
			if idx >= 0 {
				rest := line[idx+len("upperdir="):]
				// upperdir value ends at comma or space
				end := strings.IndexAny(rest, ", ")
				if end == -1 {
					end = len(rest)
				}
				upper := rest[:end]
				return upper, nil
			}
		}
	}
	return "", fmt.Errorf("upperdir not found in mountinfo for pid %s", pid)
}

//////////////////////////////////////////////////////////////
// Utility: Extract Upperdir for POD
//////////////////////////////////////////////////////////////

func discoverUpperdirForPod(podUID, podName, namespace string) {
	// quickly return if already discovered
	mapMutex.RLock()
	_, ok := upperdirMap[podUID]
	mapMutex.RUnlock()
	if ok {
		return
	}

	// try a few times with small backoff
	for i := 0; i < 4; i++ {
		pid, err := findAnyPidForPod(podUID)
		if err == nil && pid != "" {
			upper, err := findUpperdirForPid(pid)
			if err == nil && upper != "" {
				mapMutex.Lock()
				// store host path; dedupe
				upperdirMap[podUID] = upper
				// initialize prev used to 0 so first sample sets baseline
				inodePrevUsed[podUID] = 0
				mapMutex.Unlock()
				fmt.Printf("Discovered upperdir for pod %s/%s: %s\n", namespace, podName, upper)
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	// failed: keep trying next sample (no tight loop)
	fmt.Printf("Warning: failed to discover upperdir for pod %s\n", podUID)
}

//////////////////////////////////////////////////////////////
// Utility: POD Sampling Main Function
//////////////////////////////////////////////////////////////

func sampleInodes(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// snapshot keys
			mapMutex.RLock()
			pods := make([]struct {
				podUID   string
				upperdir string
			}, 0, len(upperdirMap))
			for podUID, upper := range upperdirMap {
				pods = append(pods, struct {
					podUID   string
					upperdir string
				}{podUID, upper})
			}
			mapMutex.RUnlock()

			for _, p := range pods {
				// do the statfs

				var st syscall.Statfs_t
				err := syscall.Statfs(p.upperdir, &st)
				if err != nil {
					continue
				}

				total := uint64(st.Files)
				free := uint64(st.Ffree)
				used := total - free

				// map podUID -> pod name/namespace for labels
				mapMutex.RLock()
				info, ok := uidToPodInfo[p.podUID]
				mapMutex.RUnlock()

				pn := "unknown"
				ns := "unknown"
				if ok {
					pn = info.Name
					ns = info.Namespace
				}

				// update gauges
				overlayInodeTotal.WithLabelValues(pn, ns).Set(float64(total))
				overlayInodeFree.WithLabelValues(pn, ns).Set(float64(free))
				overlayInodeUsed.WithLabelValues(pn, ns).Set(float64(used))

				// compute delta using prev snapshot
				mapMutex.Lock()
				prev := inodePrevUsed[p.podUID]
				if used > prev {
					delta := used - prev
					overlayInodeUsedDelta.WithLabelValues(pn, ns).Add(float64(delta))
				}
				inodePrevUsed[p.podUID] = used
				mapMutex.Unlock()
			}
		}
	}
}

//////////////////////////////////////////////////////////////
// MAIN
//////////////////////////////////////////////////////////////

func main() {

	//////////////////////////////////////////////////////////////
	// Prometheus Server
	//////////////////////////////////////////////////////////////

	prometheus.MustRegister(inodeOpTotal)
	prometheus.MustRegister(overlayInodeTotal)
	prometheus.MustRegister(overlayInodeFree)
	prometheus.MustRegister(overlayInodeUsed)
	prometheus.MustRegister(overlayInodeUsedDelta)

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(":9091", nil)
	}()

	//////////////////////////////////////////////////////////////
	// Kubernetes Client
	//////////////////////////////////////////////////////////////

	if err := initKubeClient(); err != nil {
		fmt.Println("Kubernetes client init failed:", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//////////////////////////////////////////////////////////////
	// Locate Cgroup Root
	//////////////////////////////////////////////////////////////

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

	//////////////////////////////////////////////////////////////
	// Load eBPF
	//////////////////////////////////////////////////////////////

	module, err := libbpfgo.NewModuleFromFile("trace.bpf.o")
	if err != nil {
		panic(err)
	}
	defer module.Close()

	if err := module.BPFLoadObject(); err != nil {
		panic(err)
	}

	cgroupMap, _ := module.GetMap("cgroup_filter")

	refreshCgroupMap(cgroupMap, root, prefix)
	refreshPodMap(ctx)

	//////////////////////////////////////////////////////////////
	// Background Refresh
	//////////////////////////////////////////////////////////////

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		for range ticker.C {
			refreshCgroupMap(cgroupMap, root, prefix)
		}
	}()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		for range ticker.C {
			refreshPodMap(ctx)
		}
	}()

	go sampleInodes(ctx, 15*time.Second)

	//////////////////////////////////////////////////////////////
	// Attach Tracepoints
	//////////////////////////////////////////////////////////////

	tracepoints := []string{
		"mkdir", "mkdirat",
		"open", "openat",
		"mknod", "mknodat",
		"symlink", "symlinkat",
	}

	for _, tp := range tracepoints {
		prog, err := module.GetProgram("trace_" + tp)
		if err != nil {
			continue
		}
		prog.AttachTracepoint("syscalls", "sys_enter_"+tp)
	}

	//////////////////////////////////////////////////////////////
	// Ring Buffer
	//////////////////////////////////////////////////////////////

	eventsChan := make(chan []byte, 1024)
	rb, _ := module.InitRingBuf("events", eventsChan)
	rb.Start()
	defer rb.Stop()

	//////////////////////////////////////////////////////////////
	// Graceful Shutdown
	//////////////////////////////////////////////////////////////

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		cancel()
		rb.Stop()
		os.Exit(0)
	}()

	//////////////////////////////////////////////////////////////
	// Event Loop
	//////////////////////////////////////////////////////////////

	for data := range eventsChan {
		var e event
		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e); err != nil {
			continue
		}

		op := strings.TrimRight(string(e.Type[:]), "\x00")

		mapMutex.RLock()
		cgroupPath, ok := inoToCgroupPath[e.Cgroup]
		mapMutex.RUnlock()
		if !ok {
			continue
		}

		podUID := extractPodUID(cgroupPath)
		if podUID == "" {
			continue
		}

		mapMutex.RLock()
		info, ok := uidToPodInfo[podUID]
		mapMutex.RUnlock()

		podName := "unknown"
		namespace := "unknown"

		if ok {
			podName = info.Name
			namespace = info.Namespace
		}

		mapMutex.RLock()
		_, exists := upperdirMap[podUID]
		mapMutex.RUnlock()
		if !exists {
			// run discovery async; do not block event loop
			go discoverUpperdirForPod(podUID, podName, namespace)
		}

		inodeOpTotal.With(prometheus.Labels{
			"operation": op,
			"pod_name":  podName,
			"namespace": namespace,
		}).Inc()
	}

}

// CGO_CFLAGS="$(pkg-config --cflags libbpf)" \
// CGO_LDFLAGS="$(pkg-config --libs libbpf)" \
// go build -v -o daemon .
