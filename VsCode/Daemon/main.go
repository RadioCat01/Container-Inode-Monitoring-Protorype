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
// MAIN
//////////////////////////////////////////////////////////////

func main() {

	//////////////////////////////////////////////////////////////
	// Prometheus Server
	//////////////////////////////////////////////////////////////

	prometheus.MustRegister(inodeOpTotal)

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
