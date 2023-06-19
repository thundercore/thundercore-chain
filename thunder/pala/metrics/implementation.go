package metrics

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	// Currently we integrate with the prometheus metrics library in thunder/libs/analytics/metrics rather than
	// integrate with prometheus directly.
	// This is to maintain compatibility with the registry in thunder/libs/analytics/metrics
	// When we stop using thunder/libs/analytics/metrics it should integrate with promtheus directly
	pm "github.com/ethereum/go-ethereum/thunder/thunderella/libs/analytics/metrics"
)

var (
	counterType   = reflect.TypeOf((*Counter)(nil)).Elem()
	gaugeType     = reflect.TypeOf((*Gauge)(nil)).Elem()
	histogramType = reflect.TypeOf((*Histogram)(nil)).Elem()
)

type MetricsWriter interface {
	open() error
	Close() error
	log(datapt string)
}

type FileMetricsWriter struct {
	mutex sync.Mutex
	file  *os.File
	id    string
}

func (fmw *FileMetricsWriter) open() error {
	fmw.mutex.Lock()
	defer fmw.mutex.Unlock()
	var err error
	fmw.file, err = os.Create(fmt.Sprintf("%s_metrics.txt", fmw.id))
	return err
}

func (fmw *FileMetricsWriter) Close() error {
	fmw.mutex.Lock()
	defer fmw.mutex.Unlock()
	return fmw.file.Close()
}

func (fmw *FileMetricsWriter) log(datamsg string) {
	outputString := fmt.Sprintf("%d %s\n", time.Now().Nanosecond(), datamsg)
	fmw.mutex.Lock()
	defer fmw.mutex.Unlock()
	fmw.file.WriteString(outputString)
}

func NewFileMetricsWriter(id string) MetricsWriter {
	r := &FileMetricsWriter{
		id: id,
	}
	return r
}

// Implements counter metric interface
type localCounterOrGaugeBase struct {
	// read-only
	name string

	writer MetricsWriter

	value int64
}

type localCounter struct {
	localCounterOrGaugeBase
}
type localGauge struct {
	localCounterOrGaugeBase
}

func (c *localCounterOrGaugeBase) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.value)
}

func (c *localCounterOrGaugeBase) Name() string {
	return c.name
}

func (c *localCounterOrGaugeBase) Reset() {
	c.Set(0)
}

func (c *localCounterOrGaugeBase) Inc() {
	c.Add(1)
}

func (c *localCounterOrGaugeBase) Add(value int64) {
	c.Set(atomic.LoadInt64(&c.value) + value)
}

func (c *localCounterOrGaugeBase) Set(value int64) {
	atomic.StoreInt64(&c.value, value)
	if c.writer != nil {
		c.writer.log(fmt.Sprintf("%s: %d", c.name, value))
	}
}

func (c *localCounterOrGaugeBase) Get() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *localCounterOrGaugeBase) String() string {
	return fmt.Sprintf("%s=%d", c.name, c.Get())
}

func (c *localCounter) Copy() Counter {
	return newLocalCounterWithStartingValue(c.Name(), nil, c.Get())
}

func (c *localCounter) Difference(o Counter) Counter {
	return newLocalCounterWithStartingValue(c.Name(), nil, c.Get()-o.Get())
}

func (c *localGauge) Copy() Gauge {
	return newLocalGaugeWithStartingValue(c.Name(), nil, c.Get())
}

func (c *localGauge) Difference(o Gauge) Gauge {
	// difference is not meaningful in a Gauge, so simply return a copy of the original gauge
	return c.Copy()
}

func newLocalCounterWithStartingValue(counterName string, writer MetricsWriter, start int64) Counter {
	c := &localCounter{
		localCounterOrGaugeBase{
			name:   counterName,
			writer: writer,
			value:  start,
		},
	}
	return c
}

func newLocalGaugeWithStartingValue(gaugeName string, writer MetricsWriter, start int64) Gauge {
	g := &localGauge{
		localCounterOrGaugeBase{
			name:   gaugeName,
			writer: writer,
			value:  start,
		},
	}
	return g
}

func newLocalCounter(counterName string, writer MetricsWriter) Counter {
	return newLocalCounterWithStartingValue(counterName, writer, 0)
}

func newLocalGauge(gaugeName string, writer MetricsWriter) Gauge {
	return newLocalGaugeWithStartingValue(gaugeName, writer, 0)
}

type localHistogram struct {
	// read-only
	name string

	writer MetricsWriter

	mutex utils.CheckedLock
	count int64
	// sum = Σ X
	sum float64
	// sqSum = Σ X^2
	sqSum float64

	prometheus pm.Histogram
}

func (h *localHistogram) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("count: %d; mean: %f; variance: %f", h.SampleCount(), h.SampleAvg(), h.SampleVariance()))
}

func (h *localHistogram) Name() string {
	return h.name
}

func (h *localHistogram) Reset() {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.count = 0
	h.sum = 0.0
	h.sqSum = 0.0
}

func (h *localHistogram) Observe(value float64) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.count++
	h.sum += value
	h.sqSum += value * value
	if h.prometheus != nil {
		h.prometheus.Observe(value)
	}
	if h.writer != nil {
		h.writer.log(fmt.Sprintf("%s: %f", h.name, value))
	}
}

func (h *localHistogram) mean() float64 {
	h.mutex.CheckIsLocked("lock must be held")
	if h.count == 0 {
		return 0
	}
	return h.sum / float64(h.count)
}

func (h *localHistogram) variance() float64 {
	h.mutex.CheckIsLocked("lock must be held")
	if h.count == 0 {
		return 0
	}
	mean := h.mean()
	return h.sqSum/float64(h.count) - (mean * mean)
}

func (h *localHistogram) SampleCount() int64 {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.count
}

func (h *localHistogram) SampleAvg() float64 {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.mean()
}

func (h *localHistogram) SampleSum() float64 {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.sum
}

func (h *localHistogram) SampleVariance() float64 {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.variance()
}

func (h *localHistogram) String() string {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if h.count == 0 {
		return fmt.Sprintf("%s: n=0", h.name)
	}
	return fmt.Sprintf("%s: n=%d, μ=%f, σ=%f", h.name, h.count, h.mean(), math.Sqrt(h.variance()))
}

func (h *localHistogram) Copy() Histogram {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return newlocalHistogramWithStartingValues(h.name, nil, h.count, h.sum, h.sqSum)
}

func (h *localHistogram) Difference(o Histogram) Histogram {
	oldCount := o.SampleCount()
	oldSum := o.SampleSum()
	oldMean := o.SampleAvg()
	oldSqSum := (o.SampleVariance() + oldMean) * float64(oldCount)
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return newlocalHistogramWithStartingValues(h.name, nil, h.count-oldCount, h.sum-oldSum, h.sqSum-oldSqSum)
}

func newlocalHistogramWithStartingValues(
	histogramName string,
	writer MetricsWriter,
	count int64,
	sum float64,
	sqSum float64,
) Histogram {
	h := &localHistogram{
		name:   histogramName,
		writer: writer,
		count:  count,
		sum:    sum,
		sqSum:  sqSum,
	}
	return h
}

func newlocalHistogram(histogramName string, writer MetricsWriter) Histogram {
	return newlocalHistogramWithStartingValues(histogramName, writer, 0, 0.0, 0.0)
}

func populateMetricsUsingReflection(writer MetricsWriter, obj interface{}, namespace string, enablePromtheus bool) {
	objType := reflect.TypeOf(obj)

	if objType.Kind() != reflect.Ptr || objType.Elem().Kind() != reflect.Struct {
		debug.Bug("reflection expects pointer to a struct")
	}

	structType := objType.Elem()
	structValue := reflect.ValueOf(obj).Elem()
	numFields := structType.NumField()

	// artifact of maintaining compatibility with thunder/libs/analytics/metrics
	// see comment in import section
	if enablePromtheus {
		_, exists := pm.GetRegistry(namespace)
		if !exists {
			pm.ResetPrometheusRegistrar(namespace)
		}
	}

	for i := 0; i < numFields; i++ {
		f := structType.Field(i)
		metricName := f.Name
		description, _ := f.Tag.Lookup("desc")
		if f.Type == counterType {
			c := newLocalCounter(metricName, writer)
			if enablePromtheus {
				if err := pm.RegisterPrometheusCounter(c, namespace, metricName, description); err != nil {
					logger.Error("Failed to register prometheus counter [%s]", err)
				}
			}
			structValue.Field(i).Set(reflect.ValueOf(c))
		} else if f.Type == gaugeType {
			g := newLocalGauge(metricName, writer)
			if enablePromtheus {
				if err := pm.RegisterPrometheusGauge(g, namespace, metricName, description); err != nil {
					logger.Error("Failed to register prometheus gauge [%s]", err)
				}
			}
			structValue.Field(i).Set(reflect.ValueOf(g))
		} else if f.Type == histogramType {
			h := newlocalHistogram(metricName, writer)
			if enablePromtheus {
				h.(*localHistogram).prometheus = pm.AttachOrCreatePrometheusHistogram(namespace, metricName, description)
			}
			structValue.Field(i).Set(reflect.ValueOf(h))
		} else {
			debug.Bug("Metric structs should only contain fields of type"+
				"Counter/Gauge/Histogram. Found '%s' of type '%s'", f.Name, f.Type)
		}
	}
}
