// This module can be used to enable runtime profiling.
//
// TODO : Future Work - this will be added into most performance
//               application if we verified performance penalty is trivial.
//               There is some articles on internet that strongly support this point.

package profiling

import (
	// Standard imports
	"fmt"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strconv"
	"time"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
)

var PORT = int(config.NewInt64Config("profiling.port",
	"profiling port on http server",
	9999, false, nil).Get())

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s\n", "OK")
}

func Start() {
	// this is to enable pprof/block, we need this get Goroutine
	// blocking info, the golang default setup is to disable it */
	runtime.SetBlockProfileRate(1)

	// Create a new HTTP multiplexer
	mux := http.NewServeMux()

	// Register our handler for the / route
	mux.HandleFunc("/", handler)

	// Add the pprof routes
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	// Start listening.
	go func() {
		profilePort := "127.0.0.1:" + strconv.Itoa(PORT)
		err := http.ListenAndServe(profilePort, mux)
		if err != nil {
			debug.Fatal(fmt.Sprintf("Error when starting or running http server: %v",
				err))
		}
	}()
}

func LogMemoryUsage(interval int64) {
	lgr := lgr.NewLgr("/MemoryUsage")
	go func() {
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			lgr.Info("Sys = %v bytes", m.Sys)             // total bytes of memory obtained from the OS
			lgr.Info("HeapSys = %v bytes", m.HeapSys)     // bytes of heap memory obtained from the OS
			lgr.Info("StackSys = %v bytes", m.StackSys)   // bytes of stack memory obtained from the OS
			lgr.Info("HeapAlloc = %v bytes", m.HeapAlloc) // bytes of allocated heap objects
			lgr.Info("HeapInuse = %v bytes", m.HeapInuse) // bytes in in-use spans
			lgr.Info("HeapObjects = %v", m.HeapObjects)   // number of allocated heap objects
			lgr.Info("NumGoroutine = %v", runtime.NumGoroutine())
			time.Sleep(time.Second * time.Duration(interval))
		}
	}()
}
