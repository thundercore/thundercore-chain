package detector

import (
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	"github.com/ethereum/go-ethereum/thunder/pala/rmonitor"

	"golang.org/x/xerrors"
)

type FdLeakDetector struct {
	pid    int
	initFd []*rmonitor.FileDescriptor
}

func NewFdDetector() *FdLeakDetector {
	return &FdLeakDetector{pid: os.Getpid()}
}

func (d *FdLeakDetector) DumpMetrics(w io.Writer) {
	currFds, _ := rmonitor.ListOpenedFds(d.pid)
	fmt.Fprintf(w, "[DumpMetrics] Current opended fd number: %d\n", len(currFds))
}

func (d *FdLeakDetector) SetTrace() error {
	initFd, err := rmonitor.ListOpenedFds(d.pid)
	if err != nil {
		return xerrors.Errorf("list opened fd failed: %v", err)
	}
	d.initFd = initFd
	return nil
}

func (d *FdLeakDetector) Detect() (leaked []rmonitor.Resource, err error) {
	var fds []*rmonitor.FileDescriptor
	// When race detector is enabled, Go runtime takes more time to release resources
	// and we'll have more false alarms.
	n := 3
	if testutils.RaceEnabled {
		n = 10
	}

	for i := 0; i < n; i++ {
		fds, err = rmonitor.ListOpenedFds(d.pid)
		if err != nil {
			return
		}

		leaked = diff(fds, d.initFd)

		if len(leaked) == 0 {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	return
}

// Verify calls Fatalf if fd leaks are detected
func (d *FdLeakDetector) Verify(t *testing.T) {
	leaked, err := d.Detect()
	if err != nil {
		t.Fatalf("detect fd leak failed: %v", err)
		return
	}

	if len(leaked) > 0 {
		for _, leak := range leaked {
			leak.Dump()
		}
		t.Fatalf("fd leak detected: %v", leaked)
	}
}
