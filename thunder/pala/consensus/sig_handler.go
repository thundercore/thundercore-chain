package consensus

import (
	"os"
	"os/signal"
	"syscall"
)

type SignalHandler interface {
	Signals() []os.Signal
	Call(os.Signal)
}

type Stopper interface {
	Stop() error
}

type StopHandler struct {
	stoppers []Stopper
}

func (h *StopHandler) Call(s os.Signal) {
	for _, m := range h.stoppers {
		err := m.Stop()
		if err != nil {
			logger.Error("Error when signal Stopping %q", err)
		}
	}
}

func (h *StopHandler) Signals() []os.Signal {
	return []os.Signal{syscall.SIGTERM, syscall.SIGINT}
}

func NewStopHandler(ms ...Stopper) *StopHandler {
	return &StopHandler{
		stoppers: ms,
	}
}

func RegisterSignalHandlers(handlers ...SignalHandler) chan os.Signal {
	ch := make(chan os.Signal, 1)
	go func() {
		var sigs []os.Signal
		for _, h := range handlers {
			sigs = append(sigs, h.Signals()...)
		}
		signal.Notify(ch, sigs...)
		for {
			s0, ok := <-ch
			if !ok { // channel closed, stopping goroutine
				return
			}
			if sig, ok := s0.(syscall.Signal); ok {
				for _, h := range handlers {
					logger.Info("Calling %T with %s", h, sig)
					h.Call(sig)
				}
			}
		}
	}()
	return ch
}
