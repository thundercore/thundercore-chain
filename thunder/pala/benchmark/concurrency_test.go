package benchmark

import (
	"sync"
	"sync/atomic"
	"testing"
)

func BenchmarkConcurrencyMutex(b *testing.B) {
	var mutex sync.Mutex
	n := 0
	for i := 0; i < b.N; i++ {
		mutex.Lock()
		n++
		mutex.Unlock()
	}
}

func BenchmarkConcurrencyChannelNProducer(b *testing.B) {
	n := 0
	ch := make(chan int, 1024)
	for i := 0; i < b.N; i++ {
		go func() {
			ch <- 1
		}()
	}
	for i := 0; i < b.N; i++ {
		t := <-ch
		n += t
	}
}

func BenchmarkConcurrencyChannelOneProducer(b *testing.B) {
	n := 0
	ch := make(chan int, 1024)
	go func() {
		for i := 0; i < b.N; i++ {
			ch <- 1
		}
	}()
	for i := 0; i < b.N; i++ {
		t := <-ch
		n += t
	}
}

func BenchmarkConcurrencyCompareAndSwap(b *testing.B) {
	var n int64
	for i := 0; i < b.N; i++ {
		for !atomic.CompareAndSwapInt64(&n, n, n+1) {
		}
	}
}
