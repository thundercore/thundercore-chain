package network

import (
	"testing"

	"github.com/ethereum/go-ethereum/thunder/pala/msggroup"

	"github.com/stretchr/testify/require"
)

func TestMultiplexer_Subscribe(t *testing.T) {
	req := require.New(t)

	m := NewMultiplexer()
	messageGroups := []msggroup.Group{
		msggroup.NetworkMsg,
		msggroup.ConsensusMsg,
		msggroup.ChainSyncMsg,
		msggroup.TxServiceMsg,
	}
	ch := make([]chan *Message, len(messageGroups))
	for i := range ch {
		ch[i] = make(chan *Message, 16)
	}

	for i := range ch {
		m.Subscribe(msggroup.Group(i)<<4, ch[i])
	}

	for i := 0; i < len(messageGroups)*16; i++ {
		msg := NewMessage(uint8(i), uint16(i), []byte{})
		m.Send(msg, BlockingCall)
	}

	msg := NewMessage(uint8(0x40), uint16(0x40), []byte{})
	req.Panics(func() {
		m.Send(msg, BlockingCall)
	})

	for g, c := range ch {
		for i := 0; i < 16; i++ {
			select {
			case msg := <-c:
				req.Equal(messageGroups[g], msggroup.GetMessageGroup(msg.GetType()))
				req.Equal(uint8(i), msg.GetType()&0xf)
			default:
				req.FailNow("Missing msg", "%d didn't get message %d", g, i)
			}
		}
	}

}

func TestMultiplexer_Unsubscribe(t *testing.T) {
	req := require.New(t)

	m := NewMultiplexer()
	messageGroups := []msggroup.Group{
		msggroup.NetworkMsg,
		msggroup.ConsensusMsg,
	}
	ch := make([]chan *Message, len(messageGroups))
	for i := range ch {
		ch[i] = make(chan *Message, 16)
		m.Subscribe(messageGroups[i], ch[i])
	}

	for i := 0; i < len(messageGroups); i++ {
		msg := NewMessage(uint8(messageGroups[i]), uint16(i), []byte{})
		m.Send(msg, BlockingCall)
	}

	for g, c := range ch {
		select {
		case msg := <-c:
			req.Equal(messageGroups[g], msggroup.GetMessageGroup(msg.GetType()))
			req.Equal(uint16(g), msg.GetAttribute())
		default:
			req.FailNow("Missing msg", "%d didn't get message", g)
		}
	}

	m.Unsubscribe(messageGroups[1], ch[1])
	for i := 0; i < len(messageGroups); i++ {
		msg := NewMessage(uint8(messageGroups[i]), uint16(i), []byte{})
		m.Send(msg, BlockingCall)
	}

	select {
	case msg := <-ch[0]:
		req.Equal(messageGroups[messageGroups[0]], msggroup.GetMessageGroup(msg.GetType()))
		req.Equal(uint16(messageGroups[0]), msg.GetAttribute())
	default:
		req.FailNow("Missing msg", "%d didn't get message", messageGroups[0])
	}

	select {
	case <-ch[1]:
		req.FailNow("Recieved unexpected msg")
	default:

	}
}
