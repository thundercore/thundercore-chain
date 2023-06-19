package utils

import (
	"syscall"
)

// GetFdLimit returns current file descriptor limit.
// Return -1 if the setting can not be obtained
func GetFdLimit() int {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return -1
	}
	return int(limit.Cur)
}

// SetFdLimit sets the fdlimit to the input value, up to the max allowed
func SetFdLimit(value uint64) error {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return err
	}
	// Update the limit to the max allowed
	// On Darwin, it seems it cannot pass 24576 though it won't report err in that case
	limit.Cur = value
	if value > limit.Max {
		limit.Cur = limit.Max
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return err
	}

	return nil
}
