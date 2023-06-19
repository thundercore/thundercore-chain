package metrics

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	// Thunder imports

	// Vendor imports
	"github.com/stretchr/testify/assert"
)

type counterMetric struct {
	C Counter `tt_desc:"A counter"`
}

type gaugeMetric struct {
	G Gauge `tt_desc:"A gauge"`
}

type histogramMetric struct {
	H Histogram `tt_desc:"A histogram"`
}

type testMetrics struct {
	C Counter   `tt_desc:"A counter"`
	G Gauge     `tt_desc:"A gauge"`
	H Histogram `tt_desc:"A histogram"`
}

type mixedupMetrics struct {
	C Gauge     `tt_desc:"A gauge"`
	G Histogram `tt_desc:"A histogram"`
}

type emptyDescMetric struct {
	C Counter
}

type invalidMetric struct {
	//lint:ignore U1000 it's used by TestInvalidMetricType
	e error
}

const (
	errMsgCounterValue = "Unexpected counter value"
	errMsgGaugeValue   = "Unexpected gauge value"
)

// TestRegister checks that metrics can be registered and that their fields do not have types prior
// to being registered.
func TestRegister(t *testing.T) {
	assert := assert.New(t)

	counterMetric := counterMetric{}
	gaugeMetric := gaugeMetric{}
	histogramMetric := histogramMetric{}

	assert.Nil(reflect.TypeOf(counterMetric.C),
		"Counter field has a type before being registered")
	assert.Nil(reflect.TypeOf(gaugeMetric.G),
		"Gauge field has a type before being registered")

	Register(t.Name(), &counterMetric)
	Register(t.Name(), &gaugeMetric)
	Register(t.Name(), &histogramMetric)

	assert.Equal(reflect.TypeOf(counterMetric.C).String(),
		"*metrics.simpleCounter", "Unexpected type for Counter field")
	assert.Equal(reflect.TypeOf(gaugeMetric.G).String(),
		"*metrics.simpleGauge", "Unexpected type for Gauge field")
	assert.Equal(reflect.TypeOf(histogramMetric.H).String(),
		"metrics.prometheusHistogram", "Unexpected type for Histogram field")
}

func TestCounterInc(t *testing.T) {
	assert := assert.New(t)
	counterMetric := counterMetric{}
	Register(t.Name(), &counterMetric)
	const times int64 = 1000
	for i := int64(0); i < times; i++ {
		counterMetric.C.Inc()
	}
	assert.Equal(counterMetric.C.Get(), times, errMsgCounterValue)
}

func TestCounterAdd(t *testing.T) {
	assert := assert.New(t)
	counterMetric := counterMetric{}
	Register(t.Name(), &counterMetric)
	const delta int64 = 500
	counterMetric.C.Add(delta)
	assert.Equal(counterMetric.C.Get(), delta, errMsgCounterValue)
}

func TestGaugeInc(t *testing.T) {
	assert := assert.New(t)
	gaugeMetric := gaugeMetric{}
	Register(t.Name(), &gaugeMetric)
	const times int64 = 1000
	for i := int64(0); i < times; i++ {
		gaugeMetric.G.Inc()
	}
	assert.Equal(gaugeMetric.G.Get(), times, errMsgGaugeValue)
}

func TestGaugeAdd(t *testing.T) {
	assert := assert.New(t)
	gaugeMetric := gaugeMetric{}
	Register(t.Name(), &gaugeMetric)
	const delta int64 = 500
	gaugeMetric.G.Add(delta)
	assert.Equal(gaugeMetric.G.Get(), delta, errMsgGaugeValue)
}

func TestGaugeDec(t *testing.T) {
	assert := assert.New(t)
	gaugeMetric := gaugeMetric{}
	Register(t.Name(), &gaugeMetric)
	const times int64 = 1000
	for i := int64(0); i < times; i++ {
		gaugeMetric.G.Dec()
	}
	assert.Equal(gaugeMetric.G.Get(), -times, errMsgGaugeValue)
}

func TestGaugeSub(t *testing.T) {
	assert := assert.New(t)
	gaugeMetric := gaugeMetric{}
	Register(t.Name(), &gaugeMetric)
	const delta int64 = 500
	gaugeMetric.G.Sub(delta)
	assert.Equal(gaugeMetric.G.Get(), -delta, errMsgGaugeValue)
}

// TestGetMetricsForNamespace tests that when a metric is registered, its name is added to the
// global metrics list in the appropriate namespace.
func TestGetMetricsForNamespace(t *testing.T) {
	assert := assert.New(t)
	ResetMetrics()

	Register(t.Name(), &testMetrics{})
	metricsStr := GetMetricsForNamespace(t.Name())
	lines := strings.Split(metricsStr, "\n")

	// Expected number of metrics for the current namespace.
	// We have three metrics: one counter, one gauge, one histogram. However, we do not register
	// histograms at the moment so there are only 2 expected registered metrics
	const expectedNumRegisteredMetrics = 2

	numMetricsFound := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		numMetricsFound++
		assert.True(strings.HasPrefix(line, t.Name()))
	}
	assert.Equal(numMetricsFound, expectedNumRegisteredMetrics,
		"Unexpected number of metrics found")
}

// TestGetMetrics tests the same thing as TestGetMetricsForNamespace, but across all registered
// namespaces.
func TestGetMetrics(t *testing.T) {
	assert := assert.New(t)
	ResetMetrics()

	const numCounterMetrics = 100
	const numGaugeMetrics = 150

	numRegisteredMetricsExpected := 0
	numRegisteredMetricsFound := 0

	var counterMetricSlice [numCounterMetrics]counterMetric
	var gaugeMetricSlice [numGaugeMetrics]gaugeMetric

	for i := 0; i < numCounterMetrics; i++ {
		counterMetricSlice[i] = counterMetric{}
		namespace := fmt.Sprintf("%s_counter_%d", t.Name(), i)
		Register(namespace, &counterMetricSlice[i])
		numRegisteredMetricsExpected++
	}

	for i := 0; i < numGaugeMetrics; i++ {
		gaugeMetricSlice[i] = gaugeMetric{}
		namespace := fmt.Sprintf("%s_gauge_%d", t.Name(), i)
		Register(namespace, &gaugeMetricSlice[i])
		numRegisteredMetricsExpected++
	}

	metricsDump := GetMetrics()
	lines := strings.Split(metricsDump, "\n")

	namespaces := make(map[string]bool)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		namespace := strings.Split(line, "=")[0]
		namespaces[namespace] = true
		numRegisteredMetricsFound++
	}

	assert.Equal(numRegisteredMetricsFound, numRegisteredMetricsExpected,
		"Found more/less metrics than expected")

	for i := 0; i < numCounterMetrics; i++ {
		namespace := fmt.Sprintf("%s_counter_%d_C", t.Name(), i)
		_, ok := namespaces[namespace]
		assert.True(ok, "Found a namespace that did not get registered")
	}

	for i := 0; i < numGaugeMetrics; i++ {
		namespace := fmt.Sprintf("%s_gauge_%d_G", t.Name(), i)
		_, ok := namespaces[namespace]
		assert.True(ok, "Found a namespace that did not get registered")
	}
}

func TestAttach(t *testing.T) {
	assert := assert.New(t)
	ResetMetrics()

	metrics := testMetrics{}
	Register(t.Name(), &metrics)
	const delta int64 = 10
	sum := float64(0)

	for i := int64(0); i < delta; i++ {
		metrics.C.Inc()
		metrics.H.Observe(float64(i))
		sum += float64(i)
	}
	metrics.G.Set(delta)

	attachedMetrics := testMetrics{}
	Register(t.Name(), &attachedMetrics)
	assert.Equal(delta, attachedMetrics.C.Get(), "Counter value different after attach")
	assert.Equal(delta, attachedMetrics.G.Get(), "Gauge value different after attach")
	assert.Equal(sum, attachedMetrics.H.SampleSum(), "Histogram sample sum different after attach")
	assert.Equal(delta, attachedMetrics.H.SampleCount(), "Histogram sample count different after attach")
	assert.Equal(sum/float64(delta), attachedMetrics.H.SampleAvg(),
		"Histogram average different after attach")
}

func TestEmptyDescription(t *testing.T) {
	assert := assert.New(t)
	assert.Panics(func() { Register(t.Name(), &emptyDescMetric{}) }, "Accepted metric with empty description")
}

func TestInvalidMetricType(t *testing.T) {
	assert := assert.New(t)
	assert.Panics(func() { Register(t.Name(), &invalidMetric{}) }, "Registered metric with invalid type")
}

func TestNameColission(t *testing.T) {
	assert := assert.New(t)
	ResetMetrics()

	metrics := testMetrics{}
	Register(t.Name(), &metrics)
	metrics.C.Inc()
	metrics.G.Inc()

	// mixedupMetrics contains same names as testMetrics but with different type, causing
	// Register not to attach existing metrics but returning new ones
	attachedMetrics := mixedupMetrics{}
	Register(t.Name(), &attachedMetrics)
	assert.Equal(int64(0), attachedMetrics.C.Get(), "Dirty metric")
	assert.Equal(int64(0), attachedMetrics.G.SampleCount(), "Dirty metric")
}
