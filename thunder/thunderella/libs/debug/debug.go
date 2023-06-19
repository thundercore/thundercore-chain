// TODO : Future Work - this could eventually be made into a
//     debugger if we set a flag to drop into debug mode.

package debug

import (
	// Standard imports
	"fmt"
	"runtime/debug"
)

func init() {
	// Always collect all goroutine backtraces.
	debug.SetTraceback("all")
}

// This function is used to indicate a logic bug has been found.
// Do not use it for error handling or parse failures, except
// when the result should have been guaranteed to be a success.
//
// Examples: Proper locks are not held, array bounds exceeded,
func Bug(s string, args ...interface{}) {
	panic(fmt.Sprintf("BUG: "+s, args...))
}

// Fatal is used to indicate that a condition or error has been
// encountered that no longer allows making forward progress.
//
// Examples: Filesystem failure, corrupt database, unable to
//           connect or open ports
//
// This is completely different from log.Fatal; do not use log.Fatal
// except in some kind of dire emergency (infinite recursion, deadlock...)
// log.Fatal immediately terminates the process, with no chance for
// clean shutdown.  This is only appropriate during single threaded
// initialization, for simple command line argument parsing, where the
// cause is immediately obvious.
//
// If this is not the case, do not use it.  It terminates without flushing
// logs (even stderr) and gives no goroutine backtrace, making the situation
// complicated to debug.  Bear in mind that many tests use multiple threads
// and initialize things in unexpected ways and so it is unwise to embed
// log.Fatal in deeply nested functions.
func Fatal(s string, args ...interface{}) {
	panic(fmt.Sprintf("FATAL ERROR: "+s, args...))
}

// NotImplemented means the functionality or error handling required
// has not yet been implemented.
//
// Examples: Missing protocol handling, no error handling in caller
//           Possible state transition not yet implemented
func NotImplemented(s string, args ...interface{}) {
	panic(fmt.Sprintf("NOT IMPLEMENTED: "+s, args...))
}
