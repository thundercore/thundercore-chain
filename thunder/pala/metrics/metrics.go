package metrics

import (
	// Standard imports
	"fmt"
)

type BaseMetric interface {
	Name() string
	Reset()
	fmt.Stringer

	// TODO(Peter) since these methods are Pala specific, consider moving them out of these interfaces and expect
	// each implementation of the interface handle this case on their own. In this case, the AdvanceLocalEpoch must
	// use a reflection hack to determine if interface passed in supports copy/difference methods or not.
	//
	// These two methods below are defined separately for each sub-interface of BaseMetric to enforce type constraints
	// These two methods are used specifically for the purpose of computing per epoch metrics inside of Pala
	// Copy returns a deep copy of the metric and is intended to be used as a snapshot
	// Copy() BaseMetric
	// Difference returns the different between the metric and a previous snapshot of the metric taken with Copy()
	// Difference(c BaseMetric) BaseMetric
}

type Counter interface {
	BaseMetric
	Inc()
	Add(value int64)
	Get() int64
	Copy() Counter
	MarshalJSON() ([]byte, error)

	// See comments in Difference() method of Gauge interface to see when to use Counter vs Gauge
	Difference(c Counter) Counter
}

type Gauge interface {
	BaseMetric
	Inc()
	Add(value int64)
	Get() int64
	Set(value int64)
	Copy() Gauge

	// Difference just returns a copy of the instance in the case of Gauge. Use Gauge over Counter when the absolute
	// value is more meaningful than the change between epochs to get better per epoch metrics.
	// example of when to use gauge: number of active connections
	// example of when to use counter: number of connections added/removed
	Difference(g Gauge) Gauge
}

type Histogram interface {
	BaseMetric
	Observe(value float64)
	SampleCount() int64
	SampleAvg() float64
	SampleSum() float64
	SampleVariance() float64
	Copy() Histogram
	Difference(h Histogram) Histogram
}
