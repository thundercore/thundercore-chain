//go:build !windows && ((!arm && !arm64) || darwin)
// +build !windows
// +build !arm,!arm64 darwin

package syscall_wrap

import (
	"syscall"
)

func Dup2(oldfd int, newfd int) error {
	return syscall.Dup2(oldfd, newfd)
}
