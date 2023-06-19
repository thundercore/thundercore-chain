package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPalaMetrics(t *testing.T) {
	req := require.New(t)

	// partially test for expected values
	m := &PalaMetrics{}
	populateMetricsUsingReflection(nil, m, "", true)
	req.NotNil(m.LocalEpoch, "expected object")
	req.NotNil(m.NumNotarized, "expected object")
	AddCounter(m.NumNotarized, 10)
	req.Equal(int64(10), m.NumNotarized.Get(), "incorrect value")
	cm := m.AdvanceLocalEpoch(2, 10)
	req.Equal(int64(2), m.LocalSession.Get(), "incorrect value")
	req.Equal(int64(10), m.LocalEpoch.Get(), "incorrect value")

	req.NotNil(cm.LocalSession, "expected object")
	req.NotNil(cm.LocalEpoch, "expected object")
	req.NotNil(cm.NumNotarized, "expected object")
	req.Equal(int64(0), cm.LocalSession.Get(), "incorrect value")
	req.Equal(int64(0), cm.LocalEpoch.Get(), "incorrect value")

	AddCounter(m.NumNotarized, 11)
	req.NotEqual(m.NumNotarized.Get(), cm.NumNotarized.Get())

	// call the logging function to ensure they don't crash
	_, _ = PrintMetricsUsingReflection("", m, cm)
	_, _ = PrintMetricsUsingReflection("", m, nil)

	// ensure it works if fields are nil
	m = &PalaMetrics{}
	cm = &PalaMetrics{}
	_, _ = PrintMetricsUsingReflection("", m, cm)
}
