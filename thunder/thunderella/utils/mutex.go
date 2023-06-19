// Mutex support.
//
// Wrapper type that tracks sync.Mutex objects to allow
// assertions and debugging.  Use this if you need to
// pass implicit lock state across functions or packages,
// or if you have loops or other complex logic that makes
// reasoning about lock state non-trivial.
//
// If the lock is only used locally and the context is
// obvious, prefer to use sync.Mutex, especially if it
// can follow the standard Lock() / defer Unlock() pattern.
package utils

import (
	// Standard imports
	"sync"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
)

type CheckedLock struct {
	lock   sync.Mutex
	locked bool
}

// Lock locks the CheckedLock, and records that it is locked.
func (c *CheckedLock) Lock() {
	c.lock.Lock()
	c.locked = true
}

// Unlock unlocks the CheckedLock, but debug.Bugs if the check fails.
func (c *CheckedLock) Unlock() {
	if !c.locked {
		debug.Bug("Double unlocking sync.Mutex")
	}
	c.locked = false
	c.lock.Unlock()
}

// CheckIsLocked uses lock.CheckIsLocked("message") to check that a lock is held.
//
// It was legal but broken to use if c.IsLocked() { debug.Bug() }
// because if you don't hold the lock, reading c.locked is actually
// a data race.
//
// In most cases, the reason to use locks in the first place was to
// synchronize with otherwise asynchronous events, so it is also
// legal for the lock to be in a locked state if the object is
// already "live".  If you need to check that an object is not
// in a "live" state, the simplest approach is to use a boolean;
// mutual exclusion is not required - and Go's race detector will
// hopefully catch you if you are not correct.
func (c *CheckedLock) CheckIsLocked(msg string) {
	if !c.locked {
		debug.Bug(msg)
	}
}
