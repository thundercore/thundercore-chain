package test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/xerrors"
)

func StartPala(args ...string) (*exec.Cmd, error) {
	// Start pala-dev
	pala, err := getPalaDevPath()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(pala, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func StartPalaWithOutput(args ...string) (*exec.Cmd, io.Reader, error) {
	// Start pala-dev
	pala, err := getPalaDevPath()
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(pala, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	stdout, err := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return nil, stdout, err
	}
	return cmd, stdout, nil
}

func StopPala(cmd *exec.Cmd) {
	syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

func GetPalaRootPath() (string, error) {
	s, err := os.Getwd()
	if err != nil {
		return "", xerrors.Errorf("getwd fail: %v", err)
	}
	if idx := strings.LastIndex(s, "thunder"); idx != -1 {
		s = s[0:idx]
	}
	return s, nil
}

func getPalaDevPath() (string, error) {
	s, err := GetPalaRootPath()
	if err != nil {
		return "", xerrors.Errorf("getPalaPath fail: %v", err)
	}
	return filepath.Join(s, "/scripts/test/pala-dev"), nil
}
