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
	Type   [16]byte
	Cgroup uint64
	Delta  int32
	Pad uint32
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
	discoveryInProgress = make(map[string]bool)
	discoveryMutex      sync.Mutex

	inodeOpTotal    = prometheus.NewCounterVec(
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
		[]string{"pod_name", "namespace"},
	)
	nodeInodeFree = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "node_inode_free",
			Help:      "Available inode count on the underlying host filesystem.",
			Subsystem: "overlayfs_tracer",
		},
		[]string{"node_name"},
	)
	upperdirMap   = make(map[string]string)
)

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

func refreshPodMap(ctx context.Context) error {
	fmt.Println("Refreshing Pod Map")

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
	defer mapMutex.Unlock()

	oldMap := uidToPodInfo

	for uid, oldInfo := range oldMap {
		if _, stillExists := newMap[uid]; !stillExists {
			fmt.Printf("Pod deleted detected: %s/%s\n", oldInfo.Namespace, oldInfo.Name)
			delete(upperdirMap, uid)
			containerInodeNetDelta.DeleteLabelValues(oldInfo.Name, oldInfo.Namespace)

			for _, op := range []string{
				"mkdir", "mkdirat",
				"open", "openat",
				"mknod", "mknodat",
				"symlink", "symlinkat",
			} {
				inodeOpTotal.DeleteLabelValues(op, oldInfo.Name, oldInfo.Namespace)
			}
		}
	}
	uidToPodInfo = newMap

	return nil
}

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

func findAnyPidForPod(podUID string) (string, error) {
	mapMutex.RLock()
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
			return lines[0], nil
		}
	}
	return "", fmt.Errorf("no pid found for podUID %s", podUID)
}

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
		if strings.Contains(line, " overlay ") && strings.Contains(line, "upperdir=") {
			idx := strings.Index(line, "upperdir=")
			if idx >= 0 {
				rest := line[idx+len("upperdir="):]
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

func discoverUpperdirForPod(podUID, podName, namespace string) {
	mapMutex.RLock()
	_, ok := upperdirMap[podUID]
	mapMutex.RUnlock()
	if ok {
		return
	}

	for i := 0; i < 4; i++ {
		pid, err := findAnyPidForPod(podUID)
		if err == nil && pid != "" {
			upper, err := findUpperdirForPid(pid)
			if err == nil && upper != "" {
				mapMutex.Lock()
				upperdirMap[podUID] = upper
				mapMutex.Unlock()
				fmt.Printf("Discovered upperdir for pod %s/%s: %s\n", namespace, podName, upper)
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Printf("Warning: failed to discover upperdir for pod %s\n", podUID)
}

func sampleInodes(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:			
			var nodeFsPath = "/" 
			mapMutex.RLock()
			for _, upper := range upperdirMap {
				nodeFsPath = upper 
				break 
			}
			mapMutex.RUnlock()
			var nodeSt syscall.Statfs_t
			if err := syscall.Statfs(nodeFsPath, &nodeSt); err == nil {
				nodeName := os.Getenv("NODE_NAME")
				if nodeName == "" {
					nodeName = "unknown"
				}
				nodeFree := float64(nodeSt.Ffree)
				nodeInodeFree.WithLabelValues(nodeName).Set(nodeFree)
			}

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

	fentryProgs := []string{
		"trace_vfs_mkdir",
		"trace_vfs_unlink",
		"trace_vfs_rmdir",
		"trace_vfs_link",
		"trace_vfs_symlink",
		"trace_vfs_create",
		"trace_vfs_mknod",
	}

	for _, name := range fentryProgs {
		prog, err := module.GetProgram(name)
		if err != nil {
			fmt.Printf("failed to get prog %s: %v", name, err)
		}

		if _, err := prog.AttachGeneric(); err != nil {
			fmt.Printf("failed to attach %s: %v", name, err)
		}
	}

	//Ring Buffer
	eventsChan := make(chan []byte, 1000000)
	rb, _ := module.InitRingBuf("events", eventsChan)
	rb.Start()
	defer rb.Stop()

	//Graceful Shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		cancel()
		rb.Stop()
		os.Exit(0)
	}()

	//Event Loop
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
			discoveryMutex.Lock()
			if !discoveryInProgress[podUID] {
				discoveryInProgress[podUID] = true
				go func() {
					discoverUpperdirForPod(podUID, podName, namespace)
					discoveryMutex.Lock()
					delete(discoveryInProgress, podUID)
					discoveryMutex.Unlock()
				}()
			}
			discoveryMutex.Unlock()
		}

		inodeOpTotal.With(prometheus.Labels{
			"operation": op,
			"pod_name":  podName,
			"namespace": namespace,
		}).Inc()

		containerInodeNetDelta.With(prometheus.Labels{
			"pod_name":  podName,
			"namespace": namespace,
		}).Add(float64(e.Delta))

	}

}
