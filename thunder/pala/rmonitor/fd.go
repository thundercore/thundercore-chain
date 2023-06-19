package rmonitor

func ListOpenedFds(pid int) (fds []*FileDescriptor, err error) {
	p, err := ListProcessStat(pid)
	if err != nil {
		return nil, err
	}

	return p.FileDescriptors, err
}
