package startstopwaiter

import (
	"sync"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	"golang.org/x/xerrors"
)

var logger = lgr.NewLgr("/startstopwaiter")

type StartStopWaiter interface {
	Start() error
	Stop() error
	StopAndWait() error
	Wait()
}

type StartStopWaiterImpl struct {
	// mutex protects all members.
	mutex sync.Mutex
	// Notifies the caller of Start() stopping
	stopChan chan interface{}
	// The caller of Start() is responsible to notify the service is stopped via stoppedChan.
	stoppedChan chan interface{}
}

// Start calls action() and enters the running state;
// the caller is responsible to use stoppedChan to notify the service started
// by action() is stopped.
func (s *StartStopWaiterImpl) Start(
	action func(chan interface{}) error, stoppedChan chan interface{},
) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.stoppedChan != nil {
		return xerrors.New("is still running")
	}
	s.stopChan = make(chan interface{})
	if err := action(s.stopChan); err != nil {
		return err
	}
	s.stoppedChan = stoppedChan
	return nil
}

func (s *StartStopWaiterImpl) StopAndWait() error {
	if err := s.Stop(); err != nil {
		return err
	}
	s.Wait()
	return nil
}

func (s *StartStopWaiterImpl) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.stopChan == nil {
		logger.Info("Has called Stop() before; isRunning=%t", s.stoppedChan != nil)
		return nil
	}
	close(s.stopChan)
	s.stopChan = nil
	return nil
}

func (s *StartStopWaiterImpl) Wait() {
	s.mutex.Lock()
	ch := s.stoppedChan
	s.mutex.Unlock()
	if ch != nil {
		<-ch
	}

	s.mutex.Lock()
	s.stoppedChan = nil
	s.mutex.Unlock()
}

func (s *StartStopWaiterImpl) IsRunning() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.stoppedChan != nil
}
