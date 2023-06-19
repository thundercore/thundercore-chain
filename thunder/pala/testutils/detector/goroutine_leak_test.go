package detector_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"
)

func TestGoroutineLeak(t *testing.T) {
	d := detector.GoroutineLeakDetector{}
	// For non-closed channel
	d.SetTrace()
	// For closed channel
	d.SetTrace()

	ch := make(chan bool, 1)
	go func() {
		<-ch
	}()

	// ch was not closed, goroutine leak should be detect.
	leaked, err := d.Detect()
	if err != nil {
		t.FailNow()
	}
	if len(leaked) == 0 {
		t.Fatalf("No goroutine leak was detected")
	}

	close(ch)

	// ch was closed, goroutine leak should not be detect.
	leaked, err = d.Detect()
	if err != nil {
		t.FailNow()
	}
	if len(leaked) != 0 {
		t.Fatalf("Goroutine leak was detected")
	}
}
