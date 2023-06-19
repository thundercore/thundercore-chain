package benchmark

import (
	"fmt"
	"runtime/debug"
	"testing"

	builtin "errors"

	"golang.org/x/xerrors"
)

func BenchmarkErrorBuiltinNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = builtin.New("hello")
	}
}

func BenchmarkErrorBuiltinErrorf(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = fmt.Errorf("%s", "hello")
	}
}

func BenchmarkErrorXErrorsNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = xerrors.New("hello")
	}
}

func BenchmarkErrorXErrorsErrorf(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = xerrors.Errorf("%s", "hello")
	}
}

func BenchmarkDebugStack(b *testing.B) {
	for i := 0; i < b.N; i++ {
		debug.Stack()
	}
}
