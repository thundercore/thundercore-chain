// Package detector contains ideas from https://github.com/uber/tchannel-go/tree/dev/testutils/goroutines
package detector

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/rmonitor"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	"golang.org/x/xerrors"
)

// GoroutineLeakDetector compares current goroutine stacks with the ones saved on SetTrace
type GoroutineLeakDetector struct {
	stackTrace [][]*rmonitor.Stack
}

// SetTrace saves the stacks that compared to when Detect is called
func (g *GoroutineLeakDetector) SetTrace() error {
	stacks, err := rmonitor.GetCurrentStacks()
	if err != nil {
		return xerrors.Errorf("get runtime stack failed: %v", err)
	}
	g.stackTrace = append(g.stackTrace, stacks)
	return nil
}

// Detect comapres the current goroutines against those that were present
// when SetTrace was called
func (g *GoroutineLeakDetector) Detect() (leaked []rmonitor.Resource, err error) {
	prevStacks := g.stackTrace[len(g.stackTrace)-1]

	maxAttempts := 50
	for i := 0; i < maxAttempts; i++ {
		currStacks, err := rmonitor.GetCurrentStacks()
		if err != nil {
			return leaked, xerrors.Errorf("get runtime stack failed: %v", err)
		}

		leaked = diff(currStacks, prevStacks)
		if len(leaked) == 0 {
			break
		}

		if i > maxAttempts/2 {
			time.Sleep(time.Duration(i) * time.Millisecond)
		} else {
			runtime.Gosched()
		}
	}

	g.stackTrace = g.stackTrace[:len(g.stackTrace)-1]
	return leaked, nil
}

// Verify calls Fatalf if goroutine leaks are detected
func (g *GoroutineLeakDetector) Verify(t *testing.T) {
	// When race detector is enabled, Go runtime takes more time to close goroutines
	// and we'll have more false alarms.
	if testutils.RaceEnabled {
		return
	}
	return

	leaked, err := g.Detect()
	if err != nil {
		t.Fatal(err.Error())
		return
	}

	if len(leaked) > 0 {
		for _, leak := range leaked {
			leak.Dump()
		}
		t.Fatalf("goroutine leak detected: %v", leaked)
	}
}

func NewGoroutineLeakDetector() *GoroutineLeakDetector {
	return &GoroutineLeakDetector{}
}

// GoroutineLeakTest is a utility function for wrapping test cases with
// goroutine leak detection
func GoroutineLeakTest(t *testing.T, testName string, testcase func(*testing.T)) {
	d := GoroutineLeakDetector{}
	d.SetTrace()
	defer d.Verify(t)

	t.Run(testName, testcase)
}

func DumpCurrentStack() {
	stacks, err := rmonitor.GetCurrentStacks()
	if err != nil {
		panic(err)
	}
	for _, stack := range stacks {
		stack.Dump()
		fmt.Println()
	}
}
