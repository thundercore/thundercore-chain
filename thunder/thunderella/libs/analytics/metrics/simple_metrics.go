// Simple in-memory metrics using atomic instructions for updates.

package metrics

import (
	// Standard imports
	"bytes"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

var (
	// Registers all simpleCounter(s) and simpleGauge(s). Used by debug cli.
	metricsLists    = make(map[string][]BaseMetric)
	metricsListLock = &sync.Mutex{}
)

var (
	ErrMetricsNotFound = fmt.Errorf("metrics not found")
)

// Implements counter metric interface
type simpleCounter struct {
	value int64
	name  string
}

func (c *simpleCounter) Name() string {
	return c.name
}

func (c *simpleCounter) Inc() {
	c.Add(1)
}

func (c *simpleCounter) Add(value int64) {
	atomic.AddInt64(&c.value, value)
}

func (c *simpleCounter) Get() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *simpleCounter) String() string {
	return fmt.Sprintf("%s=%d", c.name, c.Get())
}

func newSimpleCounter(namespace string, counterName string) Counter {
	c := &simpleCounter{
		name:  counterName,
		value: 0,
	}
	addSimpleMetric(namespace, c)
	return c
}

// Implements our Gauge interface
type simpleGauge struct {
	simpleCounter
}

// Inc() and Add() functions inherited from simpleCounter

func (g *simpleGauge) Dec() {
	g.Add(-1)
}

func (g *simpleGauge) Sub(value int64) {
	g.Add(value * -1)
}

func (g *simpleGauge) Set(value int64) {
	atomic.StoreInt64(&g.value, value)
}

func (c *simpleGauge) String() string {
	return fmt.Sprintf("%s=%d", c.name, c.Get())
}

func newSimpleGauge(namespace string, gaugeName string) Gauge {
	g := &simpleGauge{
		simpleCounter: simpleCounter{
			name:  gaugeName,
			value: 0.0,
		},
	}
	addSimpleMetric(namespace, g)
	return g
}

// No simple implementation of histogram

func resetSimpleMetrics() {
	metricsListLock.Lock()
	defer metricsListLock.Unlock()
	for l := range metricsLists {
		delete(metricsLists, l)
	}
}

func addSimpleMetric(namespace string, m BaseMetric) {
	metricsListLock.Lock()
	defer metricsListLock.Unlock()
	metricsLists[namespace] = append(metricsLists[namespace], m)
}

// Returns all "Simple" metrics in format "name=value"
func GetMetrics() string {
	metricsListLock.Lock()
	defer metricsListLock.Unlock()
	var namespaces []string
	for key := range metricsLists {
		namespaces = append(namespaces, key)
	}
	sort.Strings(namespaces)
	out := &bytes.Buffer{}
	for _, namespace := range namespaces {
		out.WriteString(getMetricsForNamespaceUnlocked(namespace))
	}
	return out.String()
}

func GetMetricsAsList() []BaseMetric {
	metricsListLock.Lock()
	defer metricsListLock.Unlock()

	ret := make([]BaseMetric, 0)
	for k := range metricsLists {
		for _, m := range metricsLists[k] {
			ret = append(ret, m)
		}
	}
	return ret
}

func getMetric(namespace, name string) (BaseMetric, error) {
	metricsListLock.Lock()
	defer metricsListLock.Unlock()
	list, exists := metricsLists[namespace]
	if !exists {
		return nil, ErrMetricsNotFound
	}

	for _, m := range list {
		if m.Name() == name {
			return m, nil
		}
	}
	return nil, ErrMetricsNotFound
}

// GetMetricsForNamespace iterates over metrics (counters and gauges only) of the given namespace
// and returns string with 'name=value\n' for each metric.
func GetMetricsForNamespace(namespace string) string {
	metricsListLock.Lock()
	defer metricsListLock.Unlock()
	return getMetricsForNamespaceUnlocked(namespace)
}
func getMetricsForNamespaceUnlocked(namespace string) string {
	var metricsStr []string
	for _, m := range metricsLists[namespace] {
		metricsStr = append(metricsStr, fmt.Sprintf("%s=%d\n", m.Name(), m.Get()))
	}
	sort.Strings(metricsStr)
	out := &bytes.Buffer{}
	for _, s := range metricsStr {
		out.WriteString(s)
	}
	return out.String()
}
