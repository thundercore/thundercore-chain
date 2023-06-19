package network

import (
	"sync"

	"github.com/ethereum/go-ethereum/thunder/pala/msggroup"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	"golang.org/x/xerrors"
)

var (
	ErrNoSubscriber = xerrors.New("Sending message without subscriber")
)

type Blockingness int

const (
	BlockingCall Blockingness = iota
	NonBlockingCall
	PanicIfBlockCall
)

type Multiplexer struct {
	mutex sync.Mutex
	subs  map[msggroup.Group][]chan<- *Message
}

func NewMultiplexer() *Multiplexer {
	return &Multiplexer{
		subs: make(map[msggroup.Group][]chan<- *Message),
	}
}

// Subscribe
func (m *Multiplexer) Subscribe(g msggroup.Group, ch chan<- *Message) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.subs[g] = append(m.subs[g], ch)
	return nil
}

func (m *Multiplexer) Unsubscribe(g msggroup.Group, target chan<- *Message) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	sub, ok := m.subs[g]
	if !ok {
		return
	}
	for i, ch := range sub {
		if ch == target {
			m.subs[g] = append(m.subs[g][:i], m.subs[g][i+1:]...)
			break
		}
	}
}

func (m *Multiplexer) Send(msg *Message, block Blockingness) {
	m.mutex.Lock()
	channels, ok := m.subs[msggroup.GetMessageGroup(msg.GetType())]

	if !ok {
		debug.Bug("(*Multiplexer).Send called with no subscriber")
		return
	}
	channels = append(channels[:0:0], channels...)
	m.mutex.Unlock()

	for _, ch := range channels {
		if block == BlockingCall {
			ch <- msg
		} else {
			select {
			case ch <- msg:
			default:
				if block == NonBlockingCall {
					logger.Warn("Subscriber buffer full. Dropping message.")
				} else { // PanicIfBlockCall
					debug.Bug("(*Multiplexer).Send would have blocked")
				}
			}
		}
	}
}
