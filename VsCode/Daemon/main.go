package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type event struct {
	Type   [8]byte
	Cgroup uint64
}

var mapMutex sync.Mutex
var inoToCgroupPath = make(map[uint64]string)
var uidToPodName = make(map[string]string)

func getCgroupInfo(root string, cgroupPrefix string) (map[uint64]string, error) {
	info := make(map[uint64]string)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			finfo, err := d.Info()
			if err != nil {
				return err
			}
			stat, ok := finfo.Sys().(*syscall.Stat_t) //type assertion (returned from d.info)
			if ok {
				rel, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				cgPath := cgroupPrefix
				if rel != "." {
					cgPath += "/" + rel
				}
				info[stat.Ino] = cgPath
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(info) == 0 {
		return nil, fmt.Errorf("no cgroup info found")
	}
	return info, nil
}

func refreshCgroupMap(cgroupMap *libbpfgo.BPFMap, root string, cgroupPrefix string) error {
	newInfo, err := getCgroupInfo(root, cgroupPrefix)
	if err != nil {
		return err
	}
	mapMutex.Lock()
	defer mapMutex.Unlock()

	// Get existing keys
	existing := make(map[uint64]struct{})
	iterator := cgroupMap.Iterator()
	var keyBytes []byte
	for iterator.Next() {
		keyBytes = iterator.Key()
		key := binary.LittleEndian.Uint64(keyBytes)
		existing[key] = struct{}{}
	}
	if iterator.Err() != nil {
		return iterator.Err()
	}
	// Add new, delete old
	dummy := uint32(1)
	added, removed := 0, 0
	for id := range newInfo {
		if _, ok := existing[id]; !ok {
			if err := cgroupMap.Update(unsafe.Pointer(&id), unsafe.Pointer(&dummy)); err == nil {
				added++
			} else {
				fmt.Println("Warning: add failed for ID", id, ":", err)
			}
		}
		delete(existing, id)
	}
	for id := range existing {
		if err := cgroupMap.DeleteKey(unsafe.Pointer(&id)); err == nil {
			removed++
		} else {
			fmt.Println("Warning: delete failed for ID", id, ":", err)
		}
	}
	inoToCgroupPath = newInfo
	if added > 0 || removed > 0 {
		fmt.Printf("Map refreshed: added %d, removed %d\n", added, removed)
	}
	return nil
}

func refreshPodMap() error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	nodeName := os.Getenv("NODE_NAME") //provided at env of the yaml
	if nodeName == "" {
		return fmt.Errorf("NODE_NAME environment variable not set")
	}
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), v1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return err
	}
	newMap := make(map[string]string)
	for _, pod := range pods.Items {
		uid := string(pod.UID)
		name := pod.Name
		newMap[uid] = name
	}
	mapMutex.Lock()
	uidToPodName = newMap
	mapMutex.Unlock()
	return nil
}

func main() {
	candidates := []string{
		"/sys/fs/cgroup/kubepods.slice",
		"/sys/fs/cgroup/unified/kubepods.slice",
		"/sys/fs/cgroup/kubepods",
	}
	var root string
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			root = path
			break
		}
	}
	if root == "" {
		fmt.Println("kubepods path not found under /sys/fs/cgroup. Inspect /sys/fs/cgroup manually.")
		os.Exit(1)
	}
	cgroupPrefix := "/" + filepath.Base(root)
	fmt.Println("Using ROOT =", root, "with cgroup prefix =", cgroupPrefix)

	// Load eBPF module
	module, err := libbpfgo.NewModuleFromFile("trace.bpf.o")
	if err != nil {
		fmt.Println("Error loading eBPF object:", err)
		os.Exit(1)
	}
	defer module.Close()

	// Load the eBPF object into the kernel
	err = module.BPFLoadObject()
	if err != nil {
		fmt.Println("Error loading BPF object into kernel:", err)
		os.Exit(1)
	}

	// Get cgroup map
	cgroupMap, err := module.GetMap("cgroup_filter")
	if err != nil {
		fmt.Println("Error getting map:", err)
		os.Exit(1)
	}

	// Initial refresh
	err = refreshCgroupMap(cgroupMap, root, cgroupPrefix)
	if err != nil {
		fmt.Println("Initial refresh failed:", err)
	}

	// Start background refresh goroutine for cgroups
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			err := refreshCgroupMap(cgroupMap, root, cgroupPrefix)
			if err != nil {
				fmt.Println("Refresh failed:", err)
			}
		}
	}()
	// Initial pod map refresh
	err = refreshPodMap()
	if err != nil {
		fmt.Println("Initial pod map refresh failed (tool may not be running in a pod with appropriate permissions):", err)
	}
	// Start background refresh goroutine for pod map
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			err := refreshPodMap()
			if err != nil {
				fmt.Println("Pod map refresh failed:", err)
			}
		}
	}()
	// Attach to all tracepoints
	tracepoints := []string{
		"mkdir", "mkdirat",
		"open", "openat",
		"mknod", "mknodat",
		"symlink", "symlinkat",
	}
	for _, tp := range tracepoints {
		prog, err := module.GetProgram("trace_" + tp)
		if err != nil {
			fmt.Println("Error getting program:", err)
			continue
		}
		_, err = prog.AttachTracepoint("syscalls", "sys_enter_"+tp)
		if err != nil {
			fmt.Println("Error attaching sys_enter_"+tp+":", err)
		}
	}
	// Initialize ring buffer
	eventsChan := make(chan []byte, 1024)
	rb, err := module.InitRingBuf("events", eventsChan)
	if err != nil {
		fmt.Println("Error initializing ringbuf:", err)
		os.Exit(1)
	}
	rb.Start()
	defer rb.Stop()

	fmt.Println("Tracing started. Press Ctrl+C to stop.")

	for data := range eventsChan {
		var e event
		err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
		if err != nil {
			fmt.Println("Error parsing event:", err)
			continue
		}
		typ := strings.TrimRight(string(e.Type[:]), "\x00")
		mapMutex.Lock()
		cgroupPath, ok := inoToCgroupPath[e.Cgroup]
		mapMutex.Unlock()
		if !ok {
			fmt.Printf("[%s] cgid=%d (no cgroup path found)\n", typ, e.Cgroup)
			continue
		}
		// Parse path to extract pod UID
		var podUID string
		parts := strings.Split(strings.TrimPrefix(cgroupPath, "/"), "/")
		for i := len(parts) - 1; i >= 0; i-- {
			part := parts[i]
			if strings.HasPrefix(part, "pod") {
				podUID = strings.TrimPrefix(part, "pod")
				break
			} else if strings.HasSuffix(part, ".slice") && strings.Contains(part, "-pod") {
				podParts := strings.SplitN(part, "-pod", 2)
				if len(podParts) == 2 {
					podUID = strings.ReplaceAll(strings.TrimSuffix(podParts[1], ".slice"), "_", "-")
					break
				}
			}
		}
		if podUID != "" {
			mapMutex.Lock()
			name, ok := uidToPodName[podUID]
			mapMutex.Unlock()
			if ok {
				fmt.Printf("[%s] pod=%s\n", typ, name)
			} else {
				fmt.Printf("[%s] podUID=%s\n", typ, podUID)
			}
		} else {
			fmt.Printf("[%s] cgid=%d cgroup_path=%s\n", typ, e.Cgroup, cgroupPath)
		}
	}
}

// CGO_CFLAGS="$(pkg-config --cflags libbpf)" \
// CGO_LDFLAGS="$(pkg-config --libs libbpf)" \
// go build -v -o daemon .
