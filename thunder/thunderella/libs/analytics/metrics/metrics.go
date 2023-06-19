// Simple metrics module to abstract out specifics of metrics client  (prometheus, gokit, etc)
// Metrics have fmt.Stringer to output them in one common format in logs
// We have int64 for both Counter and Gauge despite prometheus' support for float64 because it's
// much more performant to add/subtract int64 atomically. As for tracking non-integral quantities,
// we can track value multiplied by 10^X, where X can be larger/smaller depending on rqequired
// precision.

package metrics

import (
	// Standard imports
	"fmt"
	"reflect"
	"strings"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
)

const prefix = "Thunder"

var (
	logger        = lgr.NewLgr("/metrics")
	counterType   = reflect.TypeOf((*Counter)(nil)).Elem()
	gaugeType     = reflect.TypeOf((*Gauge)(nil)).Elem()
	histogramType = reflect.TypeOf((*Histogram)(nil)).Elem()
)

// Interface to get name and value of Counter or Gauge metric.
// Used by debug cli's metrics command.
type BaseMetric interface {
	Name() string
	Get() int64
}

type Counter interface {
	BaseMetric
	Inc()
	Add(value int64)
	fmt.Stringer
}

type Gauge interface {
	BaseMetric
	Set(value int64)
	Inc()
	Add(value int64)
	Dec() // decrement
	Sub(value int64)
	fmt.Stringer
}

type Histogram interface {
	Observe(value float64)
	SampleCount() int64
	SampleAvg() float64
	SampleSum() float64
	fmt.Stringer
}

func Register(namespace string, obj interface{}) {
	objType := reflect.TypeOf(obj)
	// Need pointer to be able to set Struct's fields' values.
	if objType.Kind() != reflect.Ptr || objType.Elem().Kind() != reflect.Struct {
		debug.Bug("Metrics registration expects pointer to a struct")
	}
	structType := objType.Elem()
	structValue := reflect.ValueOf(obj).Elem()
	numFields := structType.NumField()
	// Create/attach registry for the namespace.
	// Registries will be reused to preserve the metrics' value after each comm-switch
	_, exists := GetRegistry(namespace)
	if !exists {
		ResetPrometheusRegistrar(namespace)
	}
	// Can not use numFields as initial size when resetting simple metrics since histograms are
	// not registered
	// Iterate through all fields and register all counters, gauges and histograms
	for i := 0; i < numFields; i++ {
		f := structType.Field(i)
		//  Expects one of the generic metric interfaces defined above
		if !f.Type.Implements(counterType) && !f.Type.Implements(gaugeType) && f.Type != histogramType {
			debug.Bug("Metric structs should only contain fields of type"+
				"Counter/Gauge/Histogram. Found '%s' of type '%s'", f.Name, f.Type)
		}
		metricName := f.Name
		// Ensure all metrics have descriptions
		description, _ := f.Tag.Lookup("tt_desc")
		if description == "" {
			debug.Bug("No or empty description tag for metric '%v'", metricName)
		}
		if f.Type == counterType {
			c := AttachOrCreatePrometheusCounter(namespace, metricName, description)
			structValue.Field(i).Set(reflect.ValueOf(c))
		} else if f.Type == gaugeType {
			g := AttachOrCreatePrometheusGauge(namespace, metricName, description)
			structValue.Field(i).Set(reflect.ValueOf(g))
		} else if f.Type == histogramType {
			h := AttachOrCreatePrometheusHistogram(namespace, metricName, description)
			structValue.Field(i).Set(reflect.ValueOf(h))
		}
		logger.Debug("Metric registered. Type=%s Name=%s", f.Type.Name(), metricName)
	}
}

func GenerateNamespace(name string) string {
	return strings.Join([]string{prefix, name}, "_")
}

func ResetMetrics() {
	resetSimpleMetrics()
	resetPrometheusRegistries()
}
