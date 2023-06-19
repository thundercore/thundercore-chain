package consensus

import (
	"fmt"
	"os"
	"syscall"
)

type DebugDumper interface {
	GetDebugState() <-chan DebugState
}

func dumpDebugState(ms []DebugDumper) {
	fmt.Println("--- Debug State (begin) ---")
	for _, m := range ms {
		s := m.GetDebugState()
		fmt.Println(<-s)
	}
	fmt.Println("--- Debug State (end)   ---")
}

type DumpDebugStateHandler struct {
	handles map[os.Signal]func([]DebugDumper)
	dumpers []DebugDumper
}

func (h *DumpDebugStateHandler) Call(s os.Signal) {
	if fn, ok := h.handles[s]; ok {
		fn(h.dumpers)
	}
}

func (h *DumpDebugStateHandler) Signals() []os.Signal {
	var signals []os.Signal
	for sig := range h.handles {
		signals = append(signals, sig)
	}
	return signals
}

func NewDumpDebugStateHandler(ms ...DebugDumper) *DumpDebugStateHandler {
	handles := make(map[os.Signal]func([]DebugDumper))
	handles[syscall.SIGUSR1] = dumpDebugState
	handles[syscall.SIGUSR2] = func(ms []DebugDumper) {
		panic("Receive stop")
	}
	return &DumpDebugStateHandler{handles: handles, dumpers: ms}
}

func AsDumpers(mediators []*Mediator) []DebugDumper {
	dumpers := append([]DebugDumper{})
	for _, m := range mediators {
		dumpers = append(dumpers, m)
	}

	return dumpers
}
