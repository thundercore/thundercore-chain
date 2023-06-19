package rmonitor

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/startstopwaiter"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/thunder/lumberjack"
)

type Monitor interface {
	getMetrics() map[string]interface{}
}

type systemMonitor struct{}

func (monitor *systemMonitor) getMetrics() map[string]interface{} {
	m := make(map[string]interface{})
	loadAvg, err := ioutil.ReadFile("/proc/loadavg")
	if err != nil {
		return m
	}

	fields := strings.Fields(string(loadAvg))
	m["load_avg_1"] = fields[0]
	m["load_avg_5"] = fields[1]
	m["load_avg_15"] = fields[2]

	swaps, err := ioutil.ReadFile("/proc/swaps")
	lines := strings.Split(strings.TrimSuffix(string(swaps), "\n"), "\n")
	if len(lines) > 1 {
		fields = strings.Fields(lines[1])
		size, _ := strconv.ParseUint(fields[2], 10, 64)
		used, _ := strconv.ParseUint(fields[3], 10, 64)
		m["swap_usage"] = float64(used) / float64(size)
	}

	return m
}

type goroutineMonitor struct{}

func (monitor *goroutineMonitor) getMetrics() map[string]interface{} {
	currStacks, _ := GetCurrentStacks()
	m := make(map[string]interface{})
	m["goroutine_number"] = len(currStacks)
	return m
}

type openedFdMonitor struct {
	pid int
}

func (monitor *openedFdMonitor) getMetrics() map[string]interface{} {
	openedFds, _ := ListOpenedFds(monitor.pid)
	m := make(map[string]interface{})
	m["opened_fd_number"] = len(openedFds)
	m["pid"] = monitor.pid
	return m
}

type memoryMonitor struct{}

func (monitor *memoryMonitor) getMetrics() map[string]interface{} {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m := make(map[string]interface{})
	m["heap_alloc"] = ms.Alloc
	m["total_alloc"] = ms.TotalAlloc
	m["gc_number"] = ms.NumGC
	return m
}

type txMonitor struct {
	txPool *core.TxPool
}

func (monitor *txMonitor) getMetrics() map[string]interface{} {
	stats := monitor.txPool.GetStatus()
	m := map[string]interface{}{
		"tx_queue_count":     stats.QueueCount,
		"tx_pending_count":   stats.PendingCount,
		"tx_total_count":     stats.TotalCount,
		"tx_current_max_gas": stats.CurrentMaxGas,
		"tx_available":       stats.Available,
	}
	return m
}

type blockChainMonitor struct {
	bc                 blockchain.BlockChain
	prevFinalizedBlock blockchain.Block
	prevNotarizedBlock blockchain.Block
}

func (monitor *blockChainMonitor) getMetrics() map[string]interface{} {
	fc := monitor.bc.GetFinalizedHead()
	fn := monitor.bc.GetFreshestNotarizedHead()

	var fb_number, fn_number uint64
	if monitor.prevFinalizedBlock != nil && monitor.prevNotarizedBlock != nil {
		fb_number = fc.GetNumber() - monitor.prevFinalizedBlock.GetNumber()
		fn_number = fn.GetNumber() - monitor.prevNotarizedBlock.GetNumber()
	} else {
		fb_number = 0
		fn_number = 0
	}

	nota := monitor.bc.GetNotarization(fn.GetBlockSn())
	nv := uint16(0)
	if nota != nil {
		nv = nota.GetNVote()
	}
	m := map[string]interface{}{
		"new_finalized_block_number": fb_number,
		"new_notarized_block_number": fn_number,
		"number_of_votes":            nv,
		"freshest_notarized_number":  fn.GetNumber(),
	}

	// Update previous block
	monitor.prevFinalizedBlock = fc
	monitor.prevNotarizedBlock = fn
	return m
}

type ResourceMonitor struct {
	startstopwaiter.StartStopWaiterImpl
	monitors []Monitor
	interval time.Duration
	w        io.Writer
	mu       sync.Mutex
	c        io.Closer
	startT   time.Time
}

func (r *ResourceMonitor) Start() error {
	r.startT = time.Now()
	stoppedChan := make(chan interface{})

	action := func(stopChan chan interface{}) error {
		go func() {
			for {
				select {
				case <-stopChan:
					r.c.Close()
					close(stoppedChan)
					return
				case <-time.After(r.interval):
					r.WriteMetrics()
				}
			}
		}()
		return nil
	}
	return r.StartStopWaiterImpl.Start(action, stoppedChan)
}

func (r *ResourceMonitor) WriteMetrics() {
	timestamp := strconv.Itoa(int(time.Now().UTC().Unix()))
	metrics := map[string]interface{}{
		"timestamp":    timestamp,
		"time_elasped": int64(time.Now().Sub(r.startT).Seconds()),
	}

	for _, monitor := range r.monitors {
		for k, v := range monitor.getMetrics() {
			metrics[k] = v
		}
	}

	m, err := json.Marshal(metrics)
	if err != nil {
		panic(err)
	}

	r.mu.Lock()
	fmt.Fprintf(r.w, "%v\n", string(m))
	r.mu.Unlock()
}

func NewResourceMonitor(
	interval time.Duration,
	dirPath string,
	bc blockchain.BlockChain,
	txPool *core.TxPool,
) (*ResourceMonitor, error) {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if err := os.Mkdir(dirPath, 644); err != nil {
			debug.Bug("cannot create directory %s; err=%s", dirPath, err)
		}
	}

	filePath := path.Join(dirPath, "resource.json")
	logWriter := &lumberjack.Logger{
		Filename: filePath,
		// in megabytes, size at which it rotates logfiles.
		// One record is ~0.5K. (24*60*60/10*0.5/1024) * 7 ~= 29.5, so 60M is enough for 2 week data.
		MaxSize: 60,
		// 0 == keep all backup log files.
		// 4 means one current plus 3 backups.
		MaxBackups:     4,
		DoCompression:  true,
		LogfilePrefix:  "",
		RedirectStderr: false,
	}

	monitors := []Monitor{
		&systemMonitor{},
		&memoryMonitor{},
		&openedFdMonitor{pid: os.Getpid()},
		&goroutineMonitor{},
		&blockChainMonitor{bc: bc},
	}

	if txPool != nil {
		monitors = append(monitors, &txMonitor{txPool: txPool})
	}

	return &ResourceMonitor{
		monitors: monitors,
		interval: interval,
		w:        logWriter,
		c:        logWriter,
	}, nil
}
