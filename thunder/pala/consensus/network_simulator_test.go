package consensus

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"

	"github.com/stretchr/testify/require"
)

var hasTestedDelay = false

func TestNetworkSimulator(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	toType := func(typ blockchain.Type) uint8 {
		return uint8(blockchainTypeToMessageType(typ))
	}

	networkId := uint64(135)

	t.Run("drop connection before sending", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)
		voterSink := network.NewMultiplexer()
		network.MakeChannelForAllMessages(voterSink)
		proposerSink := network.NewMultiplexer()
		proposerCh := network.MakeChannelForAllMessages(proposerSink)
		id := ConsensusId("v1")
		voter := network.NewHost(network.Config{
			LoggingId:          string(id),
			NetworkId:          networkId,
			Role:               network.RoleSpoke,
			ConnectingConfig:   network.DefaultConnectingConfig,
			Authenticator:      &network.AuthenticatorFake{id},
			Sink:               voterSink,
			Clock:              network.NewClock(),
			ClientPuzzleMgrCfg: network.GetClientPuzzleMgrCfgForTest(),
		})
		id = ConsensusId("p1")
		proposer := network.NewHost(network.Config{
			LoggingId:          string(id),
			NetworkId:          networkId,
			Role:               network.RoleHub,
			ConnectingConfig:   network.DefaultConnectingConfig,
			Authenticator:      &network.AuthenticatorFake{id},
			Sink:               proposerSink,
			Clock:              network.NewClock(),
			ClientPuzzleMgrCfg: network.GetClientPuzzleMgrCfgForTest(),
		})
		net := NewNetworkSimulator()
		sn := blockchain.NewBlockSn(1, 1, 1)
		net.AddRule(NetworkSimulatorRule{
			From: MakeConsensusIds("v1"),
			To:   MakeConsensusIds("p1"),
			Type: MessageVote,
			Sn:   sn,
			Action: &network.FilterAction{
				PreCallback: network.ConnectionDropper,
			},
		})
		err := net.Connect(voter, proposer)
		req.NoError(err)

		// Verify the connection is established.
		select {
		case msg := <-proposerCh:
			req.True(msg.GetAttribute()&network.AttrOpen > 0)
		case <-time.NewTimer(time.Second).C:
			req.FailNow("no msg")
		}

		// Expect the first Send() succeeds.
		vote := blockchain.NewVoteFake(sn, "v1")
		msg := network.NewMessage(toType(vote.GetType()), 0, vote.GetBody())
		err = voter.Send("p1", msg)
		req.NoError(err)

		// Expect the connection is closed after Send().
		select {
		case msg := <-proposerCh:
			req.True(msg.GetAttribute()&network.AttrClosed > 0)
		case <-time.NewTimer(time.Second).C:
			req.FailNow("no msg")
		}

		net.Stop()
	})

	t.Run("drop connection after sending", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)
		voterSink := network.NewMultiplexer()
		voterMsgCh := network.MakeChannelForAllMessages(voterSink)
		proposerSink := network.NewMultiplexer()
		proposerCh := network.MakeChannelForAllMessages(proposerSink)
		id := ConsensusId("v1")
		voter := network.NewHost(network.Config{
			LoggingId:          string(id),
			NetworkId:          networkId,
			Role:               network.RoleSpoke,
			ConnectingConfig:   network.DefaultConnectingConfig,
			Authenticator:      &network.AuthenticatorFake{id},
			Sink:               voterSink,
			Clock:              network.NewClock(),
			ClientPuzzleMgrCfg: network.GetClientPuzzleMgrCfgForTest(),
		})
		id = ConsensusId("p1")
		proposer := network.NewHost(network.Config{
			LoggingId:          string(id),
			NetworkId:          networkId,
			Role:               network.RoleHub,
			ConnectingConfig:   network.DefaultConnectingConfig,
			Authenticator:      &network.AuthenticatorFake{id},
			Sink:               proposerSink,
			Clock:              network.NewClock(),
			ClientPuzzleMgrCfg: network.GetClientPuzzleMgrCfgForTest(),
		})
		net := NewNetworkSimulator()
		sn := blockchain.NewBlockSn(1, 1, 1)
		net.AddRule(NetworkSimulatorRule{
			From: MakeConsensusIds("v1"),
			To:   MakeConsensusIds("p1"),
			Type: MessageVote,
			Sn:   sn,
			Action: &network.FilterAction{
				PostCallback: network.ConnectionDropper,
			},
		})
		err := net.Connect(voter, proposer)
		req.NoError(err)

		// Verify the connection is established.
		select {
		case msg := <-proposerCh:
			req.True(msg.GetAttribute()&network.AttrOpen > 0)
		case <-time.NewTimer(time.Second).C:
			req.FailNow("no msg")
		}

		// Expect the first Send() succeeds.
		vote := blockchain.NewVoteFake(sn, "v1")
		msg := network.NewMessage(toType(vote.GetType()), 0, vote.GetBody())
		err = voter.Send("p1", msg)
		req.NoError(err)

		// Verify the proposer received the vote.
		select {
		case msg := <-proposerCh:
			req.Equal(MessageVote, MessageId(msg.GetType()))
		case <-time.NewTimer(time.Second).C:
			req.FailNow("no msg")
		}

		// Expect the second Send() fails because it's already closed by NetworkSimulator.
	ForLoop:
		for {
			select {
			case msg := <-voterMsgCh:
				if msg.GetAttribute() == network.AttrClosed && msg.GetId() == "p1" {
					break ForLoop
				}
			case <-time.After(100 * time.Millisecond):
				req.FailNow("no closed msg")
			}
		}
		err = voter.Send("p1", msg)
		req.Error(err)

		select {
		case msg := <-proposerCh:
			req.True(msg.GetAttribute()&network.AttrClosed > 0)
		case <-time.NewTimer(time.Second).C:
			req.FailNow("no msg")
		}

		net.Stop()
	})

	t.Run("pre and post callbacks", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)
		voterSink := network.NewMultiplexer()
		network.MakeChannelForAllMessages(voterSink)
		proposerSink := network.NewMultiplexer()
		proposerCh := network.MakeChannelForAllMessages(proposerSink)
		id := ConsensusId("v1")
		voter := network.NewHost(network.Config{
			LoggingId:          string(id),
			NetworkId:          networkId,
			Role:               network.RoleSpoke,
			ConnectingConfig:   network.DefaultConnectingConfig,
			Authenticator:      &network.AuthenticatorFake{id},
			Sink:               voterSink,
			Clock:              network.NewClock(),
			ClientPuzzleMgrCfg: network.GetClientPuzzleMgrCfgForTest(),
		})
		id = ConsensusId("p1")
		proposer := network.NewHost(network.Config{
			LoggingId:          string(id),
			NetworkId:          networkId,
			Role:               network.RoleHub,
			ConnectingConfig:   network.DefaultConnectingConfig,
			Authenticator:      &network.AuthenticatorFake{id},
			Sink:               proposerSink,
			Clock:              network.NewClock(),
			ClientPuzzleMgrCfg: network.GetClientPuzzleMgrCfgForTest(),
		})
		net := NewNetworkSimulator()
		sn := blockchain.NewBlockSn(1, 1, 1)

		preDoCalled := false
		postDoCalled := false
		net.AddRule(NetworkSimulatorRule{
			From: MakeConsensusIds("v1"),
			To:   MakeConsensusIds("p1"),
			Type: MessageVote,
			Sn:   sn,
			Action: &network.FilterAction{
				PreCallback: func(from ConsensusId, to ConsensusId, typ uint8, blob []byte) network.PassedOrDropped {
					req.Equal(MessageVote, MessageId(typ))
					req.False(preDoCalled)
					req.False(postDoCalled)
					preDoCalled = true
					return network.Passed
				},
				PostCallback: func(from ConsensusId, to ConsensusId, typ uint8, blob []byte) network.PassedOrDropped {
					req.Equal(MessageVote, MessageId(typ))
					req.True(preDoCalled)
					req.False(postDoCalled)
					postDoCalled = true
					return network.Passed
				},
			},
		})
		err := net.Connect(voter, proposer)
		req.NoError(err)

		// Verify the connection is established.
		select {
		case msg := <-proposerCh:
			req.True(msg.GetAttribute()&network.AttrOpen > 0)
		case <-time.NewTimer(time.Second).C:
			req.FailNow("no msg")
		}

		// Expect the first Send() succeeds.
		vote := blockchain.NewVoteFake(sn, "v1")
		msg := network.NewMessage(toType(vote.GetType()), 0, vote.GetBody())
		err = voter.Send("p1", msg)
		req.NoError(err)

		// Verify the proposer received the vote.
		select {
		case msg := <-proposerCh:
			req.Equal(MessageVote, MessageId(msg.GetType()))
		case <-time.NewTimer(time.Second).C:
			req.FailNow("no msg")
		}

		// Verify both callbacks are called.
		net.Stop()

		req.True(preDoCalled)
		req.True(postDoCalled)
	})

	t.Run("delay", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		if hasTestedDelay {
			return
		}
		hasTestedDelay = true

		req := require.New(t)
		voterSink := network.NewMultiplexer()
		network.MakeChannelForAllMessages(voterSink)
		proposerSink := network.NewMultiplexer()
		proposerCh := network.MakeChannelForAllMessages(proposerSink)
		id := ConsensusId("v1")
		voter := network.NewHost(network.Config{
			LoggingId:          string(id),
			NetworkId:          networkId,
			Role:               network.RoleSpoke,
			ConnectingConfig:   network.DefaultConnectingConfig,
			Authenticator:      &network.AuthenticatorFake{id},
			Sink:               voterSink,
			Clock:              network.NewClock(),
			ClientPuzzleMgrCfg: network.GetClientPuzzleMgrCfgForTest(),
		})
		id = ConsensusId("p1")
		proposer := network.NewHost(network.Config{
			LoggingId:          string(id),
			NetworkId:          networkId,
			Role:               network.RoleHub,
			ConnectingConfig:   network.DefaultConnectingConfig,
			Authenticator:      &network.AuthenticatorFake{id},
			Sink:               proposerSink,
			Clock:              network.NewClock(),
			ClientPuzzleMgrCfg: network.GetClientPuzzleMgrCfgForTest(),
		})
		net := NewNetworkSimulator()
		smallDelay := time.Duration(20 * time.Millisecond)
		delay := time.Duration(200 * time.Millisecond)
		net.SetBaseDelay(network.Delay{
			Mean: delay,
		})
		sn := blockchain.NewBlockSn(1, 1, 1)
		err := net.Connect(voter, proposer)
		req.NoError(err)

		// Verify the connection is established.
		select {
		case msg := <-proposerCh:
			req.True(msg.GetAttribute()&network.AttrOpen > 0)
		case <-time.NewTimer(time.Second).C:
			req.FailNow("no msg")
		}

		// Expect the first Send() succeeds.
		nVote := 10
		for i := 0; i < nVote; i++ {
			vote := blockchain.NewVoteFake(sn, "v1")
			msg := network.NewMessage(toType(vote.GetType()), 0, vote.GetBody())
			err = voter.Send("p1", msg)
			req.NoError(err)
		}

		// Expect the message is delayed.
		select {
		case <-proposerCh:
			req.FailNow("no delay")
		case <-time.NewTimer(smallDelay).C:
		}

		// Verify the proposer received the delayed votes.
		ch := make(chan bool)
		go func() {
			i := 0
			for msg := range proposerCh {
				req.Equal(MessageVote, MessageId(msg.GetType()))
				i++
				if i == nVote {
					break
				}
			}
			req.Equal(nVote, i)
			ch <- true
		}()
		// If the implementation is correct, the votes should arrive in a batch.
		// A wrong implementation may stack the delays.
		select {
		case <-time.NewTimer(delay + smallDelay).C:
			req.FailNow("The delay is too long")
		case <-ch:
		}

		net.Stop()
	})
}
