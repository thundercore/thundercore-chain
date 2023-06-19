package txservice

import (
	"github.com/ethereum/go-ethereum/thunder/pala/msggroup"
	"github.com/ethereum/go-ethereum/thunder/pala/network"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

type MessageId uint8

const (
	MessageTxDistribute       = MessageId(msggroup.TxServiceMsg + 0)
	MessageTxTraceRoutes      = MessageId(msggroup.TxServiceMsg + 1)
	MessageTxTraceRoutesReply = MessageId(msggroup.TxServiceMsg + 2)
)

type txDistributeMessage struct {
	Txs types.Transactions
}

func newTxDistributeMessage(msg *network.Message) (*txDistributeMessage, error) {
	newMsg := &txDistributeMessage{}
	err := rlp.DecodeBytes(msg.GetBlob(), &newMsg.Txs)
	if err != nil {
		return nil, err
	}

	return newMsg, nil
}

func (msg txDistributeMessage) toNetworkMessage() *network.Message {
	typ := uint8(MessageTxDistribute)
	data, err := rlp.EncodeToBytes(msg.Txs)
	if err != nil {
		logger.Info("Cannot encode txs into bytes")
		return nil
	}
	return network.NewMessage(typ, 0, data)
}

type txTraceRoutesMessage struct {
	HopLimit uint8
	Sources  []ConsensusId
}

func newTxTraceRoutesMessage(msg *network.Message) (*txTraceRoutesMessage, error) {
	newMsg := &txTraceRoutesMessage{}
	err := rlp.DecodeBytes(msg.GetBlob(), &newMsg)
	if err != nil {
		return nil, err
	}
	return newMsg, nil
}

func (msg *txTraceRoutesMessage) toNetworkMessage() *network.Message {
	typ := uint8(MessageTxTraceRoutes)
	data, err := rlp.EncodeToBytes(*msg)
	if err != nil {
		logger.Warn("Cannot encode into bytes: %s", err)
		return nil
	}
	return network.NewMessage(typ, 0, data)
}

type txTraceRoutesReplyMessage struct {
	HopLimit uint8
	Sources  []ConsensusId
	Route    []IdAndAddr
}

func newTxTraceRoutesReplyMessage(msg *network.Message) (*txTraceRoutesReplyMessage, error) {
	newMsg := &txTraceRoutesReplyMessage{}
	err := rlp.DecodeBytes(msg.GetBlob(), &newMsg)
	if err != nil {
		return nil, err
	}
	return newMsg, nil
}

func (msg *txTraceRoutesReplyMessage) toNetworkMessage() *network.Message {
	typ := uint8(MessageTxTraceRoutesReply)
	data, err := rlp.EncodeToBytes(*msg)
	if err != nil {
		logger.Warn("Cannot encode into bytes: %s", err)
		return nil
	}
	return network.NewMessage(typ, 0, data)
}
