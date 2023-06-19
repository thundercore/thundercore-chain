package rmonitor_test

import (
	"os"
	"syscall"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/pala/rmonitor"

	"github.com/stretchr/testify/require"
)

func getFdstat(fd int, s *syscall.Stat_t) error {
	return syscall.Fstat(fd, s)
}

func TestListOpenedFds(t *testing.T) {
	req := require.New(t)
	fds, err := rmonitor.ListOpenedFds(os.Getpid())
	if err != nil {
		t.Fatalf("List fds failed: %v", err)
	}

	ids := []string{}
	// Test stdin(0) / stdout(1) / stderr(2) are opened.
	for _, fd := range fds {
		ids = append(ids, fd.ID())
	}
	req.NotEqual(len(ids), 0)
}
