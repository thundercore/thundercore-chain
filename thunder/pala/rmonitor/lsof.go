// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package rmonitor

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/xerrors"
)

// Process defines a process using an open file. Properties here are strings
// for compatibility with different platforms.
type Process struct {
	PID             string
	Command         string
	UserID          string
	FileDescriptors []*FileDescriptor
}

// FileType defines the type of file in use by a process
type FileType string

const (
	FileTypeUnknown              FileType = ""
	FileTypeDir                  FileType = "DIR"
	FileTypeFile                 FileType = "REG"
	FileTypeCharacterSpecialFile FileType = "CHR"
)

// FileDescriptor defines a file in use by a process
type FileDescriptor struct {
	FD   string
	Type FileType
	Name string
}

// ExecError is an error running lsof
type ExecError struct {
	command string
	args    []string
	output  string
	err     error
}

func (e ExecError) Error() string {
	return fmt.Sprintf("Error running %s %s: %s (%s)", e.command, e.args, e.err, e.output)
}

// ListProcessStat returns processes stat using command "lsof -p {pid} -w -F pcuftn -X"
// Support file type: DIR, REG
func ListProcessStat(pid int) (Process, error) {
	prcoesses, err := run([]string{"-F", "pcuftnd", "-p", strconv.Itoa(pid), "-X"})
	if err != nil {
		return Process{}, err
	}
	if len(prcoesses) != 1 {
		return Process{}, xerrors.Errorf("lsof can not find pid %d process stat", pid)
	}
	return prcoesses[0], nil
}

func fileTypeFromString(s string) FileType {
	switch s {
	case "DIR":
		return FileTypeDir
	case "REG":
		return FileTypeFile
	case "CHR":
		return FileTypeCharacterSpecialFile
	default:
		return FileTypeUnknown
	}
}

func (p *Process) fillField(s string) error {
	if s == "" {
		return fmt.Errorf("Empty field")
	}
	// See Output for Other Programs at http://linux.die.net/man/8/lsof
	key := s[0]
	value := s[1:]
	switch key {
	case 'p':
		p.PID = value
	case 'c':
		p.Command = value
	case 'u':
		p.UserID = value
	default:
		// Skip unhandled field
	}
	return nil
}

func (f *FileDescriptor) fillField(s string) error {
	// See Output for Other Programs at http://linux.die.net/man/8/lsof
	key := s[0]
	value := s[1:]
	switch key {
	case 't':
		f.Type = fileTypeFromString(value)
	case 'f':
		f.FD = value
	case 'n':
		f.Name = value
	default:
		// Skip unhandled field
	}

	return nil
}

func (f *FileDescriptor) ID() string {
	return f.FD
}

func (f *FileDescriptor) Equal(other Resource) bool {
	otherFd := other.(*FileDescriptor)
	return f.FD == otherFd.FD && f.Type == otherFd.Type && f.Name == otherFd.Name
}

func (f *FileDescriptor) Dump() {
	fmt.Printf("FD: %v, Type: %v, Name: %v\n", f.FD, f.Type, f.Name)
}

func checkIsNumeric(s string) bool {
	if _, err := strconv.Atoi(s); err != nil {
		return false
	}
	return true
}

func (p *Process) parseFileLines(lines []string) error {
	file := &FileDescriptor{}
	for _, line := range lines {
		if strings.HasPrefix(line, "f") && file.FD != "" && checkIsNumeric(file.FD) &&
			(file.Type == FileTypeFile || file.Type == FileTypeDir || file.Type == FileTypeCharacterSpecialFile) {
			// New file
			p.FileDescriptors = append(p.FileDescriptors, file)
			file = &FileDescriptor{}
		}
		err := file.fillField(line)
		if err != nil {
			return err
		}
	}
	if file.FD != "" && checkIsNumeric(file.FD) &&
		(file.Type == FileTypeFile || file.Type == FileTypeDir || file.Type == FileTypeCharacterSpecialFile) {
		p.FileDescriptors = append(p.FileDescriptors, file)
	}
	return nil
}

func parseProcessLines(lines []string) (Process, error) {
	p := Process{}
	for index, line := range lines {
		if strings.HasPrefix(line, "f") {
			err := p.parseFileLines(lines[index:])
			if err != nil {
				return p, err
			}
			break
		} else {
			err := p.fillField(line)
			if err != nil {
				return p, err
			}
		}
	}
	return p, nil
}

func parseAppendProcessLines(processes []Process, linesChunk []string) ([]Process, []string, error) {
	if len(linesChunk) == 0 {
		return processes, linesChunk, nil
	}
	process, err := parseProcessLines(linesChunk)
	if err != nil {
		return processes, linesChunk, err
	}
	processesAfter := processes
	processesAfter = append(processesAfter, process)
	linesChunkAfter := []string{}
	return processesAfter, linesChunkAfter, nil
}

func parse(s string) ([]Process, error) {
	lines := strings.Split(s, "\n")
	linesChunk := []string{}
	processes := []Process{}
	var err error
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// End of process, let's parse those lines
		if strings.HasPrefix(line, "p") && len(linesChunk) > 0 {
			processes, linesChunk, err = parseAppendProcessLines(processes, linesChunk)
			if err != nil {
				return nil, err
			}
		}
		linesChunk = append(linesChunk, line)
	}
	processes, _, err = parseAppendProcessLines(processes, linesChunk)
	if err != nil {
		return nil, err
	}
	return processes, nil
}

func run(args []string) ([]Process, error) {
	// Some systems (Arch, Debian) install lsof in /usr/bin and others (centos)
	// install it in /usr/sbin, even though regular users can use it too. FreeBSD,
	// on the other hand, puts it in /usr/local/sbin. So do not specify absolute path.
	command := "lsof"
	args = append([]string{"-w"}, args...)
	output, err := exec.Command(command, args...).Output()
	if err != nil {
		return nil, ExecError{command: command, args: args, output: string(output), err: err}
	}
	return parse(string(output))
}
