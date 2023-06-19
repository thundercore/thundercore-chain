package detector_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"

	"github.com/stretchr/testify/require"
)

func TestFDLeak(t *testing.T) {
	req := require.New(t)
	d := detector.NewFdDetector()

	if err := d.SetTrace(); err != nil {
		t.Fatalf("FdLeakDetector set trace failed: %v", err)
	}

	leaked, err := d.Detect()
	if err != nil {
		t.Fatalf("detect fd leak failed: %v", err)
	}
	req.Equalf(0, len(leaked), "unexcepted fd leak: %v", leaked)

	// Create a new fd leak.
	file, err := os.Create("test_for_fd_leak") // For read access.
	defer func() {
		_, err := os.Stat(file.Name())
		if !os.IsNotExist(err) {
			os.Remove(file.Name())
		}
	}()
	if err != nil {
		t.Fatalf("open file failed: %v", err)
	}

	// Only detect opened file.
	leaked, err = d.Detect()
	req.Equal(1, len(leaked), "unexcepted fd leak: %v", leaked)
	req.Equal(leaked[0].ID(), strconv.Itoa(int(file.Fd())))

	if err := file.Close(); err != nil {
		t.Fatalf("close file failed: %v", err)
	}

	// After file closed, fd leak should not be detected.
	leaked, err = d.Detect()
	if err != nil {
		t.Fatalf("detect fd leak failed: %v", err)
	}
	req.Equalf(len(leaked), 0, "unexcepted fd leak: %v", leaked)

}
