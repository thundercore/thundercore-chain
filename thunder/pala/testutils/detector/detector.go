package detector

import (
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/pala/rmonitor"
)

type Detector interface {
	SetTrace() error
	// Detect resource leak and return leaked resources.
	Detect() ([]rmonitor.Resource, error)
	// Verify calls Fatalf if resource leaks are detected
	Verify(*testing.T)
}

// diff implements set difference function
// sliceA and sliceB should be `[]*Resource`.
func diff(sliceA, sliceB interface{}) (ret []rmonitor.Resource) {
	a := reflect.ValueOf(sliceA)
	b := reflect.ValueOf(sliceB)

	m := map[string]rmonitor.Resource{}

	for i := 0; i < b.Len(); i++ {
		r := b.Index(i).Interface().(rmonitor.Resource)
		m[r.ID()] = r
	}

	for i := 0; i < a.Len(); i++ {
		r := a.Index(i).Interface().(rmonitor.Resource)
		cached, exist := m[r.ID()]
		// Resource in a but not exists in b.
		if !exist {
			ret = append(ret, r)
			continue
		}

		// Resource in a and b but are not equal.
		if !r.Equal(cached) {
			ret = append(ret, r)
			continue
		}
	}

	return
}

type BundleDetector struct {
	detectors []Detector
}

func (b *BundleDetector) SetTrace() {
	for _, detector := range b.detectors {
		detector.SetTrace()
	}
}

func (b *BundleDetector) Verify(t *testing.T) {
	for _, detector := range b.detectors {
		detector.Verify(t)
	}
}

func NewBundleDetector() *BundleDetector {
	return &BundleDetector{
		detectors: []Detector{
			NewGoroutineLeakDetector(),
			NewFdDetector(),
		},
	}

}
