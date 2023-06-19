// Metrics backed by prometheus client.
//
// In future, if we want to switch from one metrics system to another,
// we can simply switch one implementation with another.

package metrics

import (
	// Standard imports
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	// Vendor imports
	"github.com/prometheus/client_golang/prometheus"
	promDto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

var (
	// Map from namespace to set of metrics registered in that namespace
	// For eg. "Accelerator" => set of metrics
	registries     = make(map[string]*prometheus.Registry)
	registriesLock sync.Mutex
)

// To export our simpleCounter and simpleGauge to prometheus
type prometheusMetric struct {
	//lint:ignore U1000 why is name not being used?
	name     string
	desc     *prometheus.Desc
	valType  prometheus.ValueType
	getValue func() int64
}

// FloatValueMetric implements prometheus.Collector
func (m *prometheusMetric) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.desc
}

func (m *prometheusMetric) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(m.desc, m.valType, float64(m.getValue()))
}

// To implement Stringer, SampleCount, etc over prometheus' histogram
type prometheusHistogram struct {
	prometheus.Histogram
}

func (h prometheusHistogram) getDtoMetric() promDto.Metric {
	m := promDto.Metric{}
	h.Histogram.Write(&m)
	return m
}

func (h prometheusHistogram) SampleCount() int64 {
	return int64(*h.getDtoMetric().Histogram.SampleCount)
}

func (h prometheusHistogram) SampleSum() float64 {
	return *h.getDtoMetric().Histogram.SampleSum
}

func (h prometheusHistogram) SampleAvg() float64 {
	m := h.getDtoMetric()
	return (*m.Histogram.SampleSum) / float64(*m.Histogram.SampleCount)
}

func (h prometheusHistogram) String() string {
	return fmt.Sprintf("Avg: %f (Samples = %d)", h.SampleAvg(), h.SampleCount())
}

//////////////////////////
// Metrics factory methods
//////////////////////////

func AttachOrCreatePrometheusCounter(namespace, metricName, description string) Counter {
	counterName := prometheus.BuildFQName(namespace, "", metricName)
	if oldMetric, err := getMetric(namespace, counterName); err == nil {
		if c, ok := oldMetric.(Counter); ok {
			return c
		} else {
			// name collision, get a new one
			logger.Error("Failed to register metric %s with existing name(%s) of %s",
				reflect.TypeOf((*Counter)(nil)), counterName, reflect.TypeOf(oldMetric))
		}
	}
	return newPrometheusCounter(namespace, counterName, description)
}

func newPrometheusCounter(namespace, name, description string) Counter {
	c := newSimpleCounter(namespace, name)
	m := &prometheusMetric{
		desc:     prometheus.NewDesc(name, description, nil, nil),
		valType:  prometheus.CounterValue,
		getValue: c.Get,
	}
	registerPrometheusMetric(namespace, m)
	return c
}

func RegisterPrometheusCounter(c BaseMetric, namespace, metricName, description string) error {
	name := prometheus.BuildFQName(namespace, "", metricName)
	m := &prometheusMetric{
		desc:     prometheus.NewDesc(name, description, nil, nil),
		valType:  prometheus.CounterValue,
		getValue: c.Get,
	}
	return registerPrometheusMetric(namespace, m)
}

func AttachOrCreatePrometheusGauge(namespace, metricName, description string) Gauge {
	gaugeName := prometheus.BuildFQName(namespace, "", metricName)
	if oldMetric, err := getMetric(namespace, gaugeName); err == nil {
		if g, ok := oldMetric.(Gauge); ok {
			return g
		} else {
			// name collision, get a new one
			logger.Error("Failed to register metric %s with existing name(%s) of %s",
				reflect.TypeOf((*Gauge)(nil)), gaugeName, reflect.TypeOf(oldMetric))
		}
	}
	return newPrometheusGauge(namespace, gaugeName, description)
}

func newPrometheusGauge(namespace, name, description string) Gauge {
	g := newSimpleGauge(namespace, name)
	m := &prometheusMetric{
		desc:     prometheus.NewDesc(name, description, nil, nil),
		valType:  prometheus.GaugeValue,
		getValue: g.Get,
	}
	registerPrometheusMetric(namespace, m)
	return g
}

func RegisterPrometheusGauge(g BaseMetric, namespace, metricName, description string) error {
	name := prometheus.BuildFQName(namespace, "", metricName)
	m := &prometheusMetric{
		desc:     prometheus.NewDesc(name, description, nil, nil),
		valType:  prometheus.GaugeValue,
		getValue: g.Get,
	}
	return registerPrometheusMetric(namespace, m)
}

func AttachOrCreatePrometheusHistogram(namespace string, name string, description string) Histogram {
	h := prometheusHistogram{
		prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      name,
			Help:      description,
			// TODO: Should we get buckets from tags?
		}),
	}

	// metricsLists doesn't handle histograms, go with prometheus' own AlreadyRegisteredError
	// to detect already-registered-collectors
	err := registerPrometheusMetric(namespace, h)
	if err == nil {
		return h
	} else if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
		if eCollector, ok := are.ExistingCollector.(prometheusHistogram); ok {
			return eCollector
		}
	}
	// Failed to register metric, the metric can still be used by caller, but will not be collected
	// by prometheus server
	logger.Error("Failed to register Histogram metric %s,%s: %s", namespace, name, err)
	return h
}

func registerPrometheusMetric(namespace string, m prometheus.Collector) error {
	registriesLock.Lock()
	defer registriesLock.Unlock()
	return registries[namespace].Register(m)
}

func ResetPrometheusRegistrar(namespace string) {
	registriesLock.Lock()
	defer registriesLock.Unlock()
	registries[namespace] = prometheus.NewRegistry()
}

func resetPrometheusRegistries() {
	registriesLock.Lock()
	defer registriesLock.Unlock()
	for r := range registries {
		delete(registries, r)
	}
}

func GetRegistry(namespace string) (*prometheus.Registry, bool) {
	registriesLock.Lock()
	defer registriesLock.Unlock()
	list, exists := registries[namespace]
	return list, exists
}

// GetPrometheusMetricsAsText formats metrics as text to serve via http
func GetPrometheusMetricsAsText() (string, error) {
	return GetPrometheusMetricsAsTextWithFilter(nil)
}

func GetPrometheusMetricsAsTextWithFilter(filter map[string]bool) (string, error) {
	registriesLock.Lock()
	defer registriesLock.Unlock()
	out := &bytes.Buffer{}
	for _, registry := range registries {
		gathering, err := registry.Gather()
		if err != nil {
			return "", err
		}
		encoder := expfmt.NewEncoder(out, expfmt.FmtText)
		for _, mf := range gathering {
			// The given pala metrics filter doesn't have the prefix
			name := strings.TrimPrefix(mf.GetName(), fmt.Sprintf("%s_", prefix))
			if filter != nil && filter[name] {
				continue
			}
			if err := encoder.Encode(mf); err != nil {
				debug.Bug(err.Error())
			}
		}
	}
	return out.String(), nil
}
