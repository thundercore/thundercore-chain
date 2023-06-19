package blockchain

import (
	"testing"
)

type keyValue struct {
	key   []byte
	value []byte
}

type recordingDatabaseWriter struct {
	writeSequence []keyValue
}

func (r *recordingDatabaseWriter) Put(key, value []byte) error {
	r.writeSequence = append(r.writeSequence, keyValue{
		key:   key,
		value: value,
	})
	return nil
}

type dummyDatabaseWriter struct {
}

func (d *dummyDatabaseWriter) Put(key, value []byte) error {
	return nil
}

func TestTracer_tree(t *testing.T) {
	// We use truffle test suite and pala-dev to test the result is the same as call_tracer, see contracts/tracer_test
	t.Skip()
}
