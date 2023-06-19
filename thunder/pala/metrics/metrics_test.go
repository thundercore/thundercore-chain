package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCounter(t *testing.T) {
	req := require.New(t)

	c := newLocalCounter("test", nil)
	req.Equal("test", c.Name(), "incorrect value")
	c.Inc()
	req.Equal(int64(1), c.Get(), "incorrect value")
	c.Add(5)
	req.Equal(int64(6), c.Get(), "incorrect value")
	c.Reset()
	req.Equal(int64(0), c.Get(), "incorrect value")
	c.Add(10)
	req.Equal(int64(10), c.Get(), "incorrect value")

	// copy c with value 10
	copyCounter := c.Copy()
	req.Equal("test", copyCounter.Name(), "incorrect value")
	req.Equal(c.Get(), copyCounter.Get(), "incorrect value")
	// increment c to 11 and ensure copy did not change
	c.Inc()
	req.NotEqual(c.Get(), copyCounter.Get(), "copyCounter should not increment")
	diffCounter := c.Difference(copyCounter)
	req.Equal("test", diffCounter.Name(), "incorrect value")
	req.Equal(int64(1), diffCounter.Get(), "incorrect value")
}

func TestGauge(t *testing.T) {
	req := require.New(t)

	c := newLocalGauge("test", nil)
	req.Equal(c.Name(), "test", "incorrect value")
	c.Set(200)
	req.Equal(int64(200), c.Get(), "incorrect value")
	c.Add(5)
	req.Equal(int64(205), c.Get(), "incorrect value")
	c.Reset()
	req.Equal(int64(0), c.Get(), "incorrect value")
	c.Set(10)
	req.Equal(int64(10), c.Get(), "incorrect value")

	// copy c with value 10
	copyGauge := c.Copy()
	req.Equal("test", copyGauge.Name(), "incorrect value")
	req.Equal(c.Get(), copyGauge.Get(), "incorrect value")
	// increment c to 20 and ensure copy did not change
	c.Set(20)
	req.NotEqual(c.Get(), copyGauge.Get(), "copyCounter should not increment")
	diffGauge := c.Difference(copyGauge)
	req.Equal("test", diffGauge.Name(), "incorrect value")
	// diffing a gauge does nothing
	req.Equal(int64(20), diffGauge.Get(), "incorrect value")
}

func TestHistogram(t *testing.T) {
	req := require.New(t)

	h := newlocalHistogram("test", nil)
	req.Equal(h.Name(), "test", "incorrect value")

	values := []float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	for _, e := range values {
		h.Observe(e)
	}
	delta := 0.000001
	req.Equal(int64(10), h.SampleCount(), "incorrect count")
	req.InDelta(45, h.SampleSum(), delta, "incorrect sum")
	req.InDelta(4.5, h.SampleAvg(), delta, "incorrect average")
	req.InDelta(8.25, h.SampleVariance(), delta, "incorrect variance")

	// copy and ensure all values are the same
	copyHistogram := h.Copy()
	req.Equal("test", copyHistogram.Name(), "incorrect value")
	req.Equal(h.SampleCount(), copyHistogram.SampleCount(), "incorrect value")
	req.Equal(h.SampleSum(), copyHistogram.SampleSum(), "incorrect value")
	req.Equal(h.SampleAvg(), copyHistogram.SampleAvg(), "incorrect value")
	req.Equal(h.SampleVariance(), copyHistogram.SampleVariance(), "incorrect value")

	// observe more values and ensure copy did not change
	for _, e := range values {
		h.Observe(e)
	}
	req.NotEqual(h.SampleCount(), copyHistogram.SampleCount(), "incorrect value")
	req.NotEqual(h.SampleSum(), copyHistogram.SampleSum(), "incorrect value")
	// since we added the same values, the average and variance does not change
	req.InDelta(h.SampleAvg(), copyHistogram.SampleAvg(), delta, "incorrect value")
	req.InDelta(h.SampleVariance(), copyHistogram.SampleVariance(), delta, "incorrect value")

	// compute difference and check for expected values
	// since we added the same set of values twice, the difference should be the same as original
	req.Equal(int64(10), copyHistogram.SampleCount(), "incorrect count")
	req.InDelta(45, copyHistogram.SampleSum(), delta, "incorrect sum")
	req.InDelta(4.5, copyHistogram.SampleAvg(), delta, "incorrect average")
	req.InDelta(8.25, copyHistogram.SampleVariance(), delta, "incorrect variance")

	// finally reset and test for expected values
	h.Reset()
	req.Equal(h.Name(), "test", "incorrect name after reset")
	req.Equal(int64(0), h.SampleCount(), "incorrect count after reset")
	req.Equal(float64(0), h.SampleSum(), "incorrect sum after reset")
	req.Equal(float64(0), h.SampleVariance(), "incorrect variance after reset")
	req.Equal(float64(0), h.SampleAvg(), "incorrect count mean reset")
}

type MetricsGroupForTest struct {
	C Counter
	G Gauge
	H Histogram
}

func TestReflection(t *testing.T) {
	req := require.New(t)

	m := &MetricsGroupForTest{}

	populateMetricsUsingReflection(nil, m, "", true)
	req.NotNil(m.C, "expected value")
	req.NotNil(m.G, "expected value")
	req.NotNil(m.H, "expected value")

	m.C.Add(100)
	req.Equal(int64(100), m.C.Get(), "incorrect value")
}
