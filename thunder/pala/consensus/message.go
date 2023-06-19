package consensus

import (
	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/chainsync"
	"github.com/ethereum/go-ethereum/thunder/pala/msggroup"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"golang.org/x/xerrors"
)

// NOTE: Messages used in Thunder Wire Protocol are defined here.
// The values *must* be fixed after Pala release one.
type MessageId uint8

const (
	//
	// Consensus data messages
	//

	ConsensusDataMessageGroup = MessageId(msggroup.ConsensusMsg)
	MessageNil                = MessageId(0x10)
	MessageBlock              = MessageId(0x11)
	MessageProposal           = MessageId(0x12)
	MessageVote               = MessageId(0x13)
	MessageNotarization       = MessageId(0x14)
	MessageClockMsg           = MessageId(0x15)
	MessageClockMsgNota       = MessageId(0x16)

	//
	// Sync messages
	//

	ChainSyncMessageGroup = MessageId(msggroup.ChainSyncMsg)

	// Used by voters.
	MessageUnnotarizedProposals = MessageId(0x20)

	// Used for chain syncing.
	// Reserved 0x9x for the same purpose. This makes code more readable.
	MessageStatus          = MessageId(0x21)
	MessageGetEpoch        = MessageId(0x22)
	MessageEpoch           = MessageId(0x23)
	MessageGetFresherHead  = MessageId(0x24)
	MessageFresherHeadMeta = MessageId(0x25)
	MessageFresherHeadData = MessageId(0x26) // Deprecated. Remove it in R2.

	MessageGetFresherHeadV2  = MessageId(0x27)
	MessageFresherHeadDataV2 = MessageId(0x28)
)

var blockchainTypeToMessageTypeMap = map[blockchain.Type]MessageId{
	blockchain.TypeNil:          MessageNil,
	blockchain.TypeBlock:        MessageBlock,
	blockchain.TypeProposal:     MessageProposal,
	blockchain.TypeVote:         MessageVote,
	blockchain.TypeNotarization: MessageNotarization,
	blockchain.TypeClockMsg:     MessageClockMsg,
	blockchain.TypeClockMsgNota: MessageClockMsgNota,
}

var messageTypeToBlockchainTypeMap = map[MessageId]blockchain.Type{
	MessageNil:          blockchain.TypeNil,
	MessageBlock:        blockchain.TypeBlock,
	MessageProposal:     blockchain.TypeProposal,
	MessageVote:         blockchain.TypeVote,
	MessageNotarization: blockchain.TypeNotarization,
	MessageClockMsg:     blockchain.TypeClockMsg,
	MessageClockMsgNota: blockchain.TypeClockMsgNota,
}

//------------------------------------------------------------------------------

type consensusDataMessage struct {
	msg blockchain.Message
}

type getUnnotarizedProposalsMessage struct {
	sn blockchain.BlockSn
}

type unnotarizedProposalsMessage struct {
	proposals []blockchain.Proposal
}

type getStatusMessage struct {
}

type statusMessage struct {
	status chainsync.Status
}

type getEpochMessage struct {
	clientEpoch blockchain.Epoch
}

type epochMessage struct {
	session blockchain.Session
	existed bool
	isLast  bool
	// (optional) nil if !existed.
	cNota blockchain.ClockMsgNota
}

type getFresherHeadMessage struct {
	head            blockchain.BlockSn
	blockIdentities []chainsync.BlockIdentifier
}

type getFresherHeadV2Message struct {
	head            blockchain.BlockSn
	blockIdentities []chainsync.BlockIdentifier
}

type fresherHeadMetaMessage struct {
	// If we can find a way to extend the peer's freshest notarized chain,
	// set a positive value.
	numNotarizedBlocks uint16
	// Filled when numNotarizedBlocks is 0
	finalizedHead chainsync.BlockInfo
}

type notarizedBlock struct {
	Block blockchain.Block
	Nota  blockchain.Notarization
}

type fresherHeadDataMessage struct {
	notarizedBlock notarizedBlock
}

type fresherHeadDataV2Message struct {
	notarizedBlocks []notarizedBlock
}

//------------------------------------------------------------------------------

func (typ MessageId) String() string {
	switch typ {
	case MessageNil:
		return "blockchain.Nil"
	case MessageBlock:
		return "blockchain.Block"
	case MessageProposal:
		return "blockchain.Proposal"
	case MessageVote:
		return "blockchain.Vote"
	case MessageNotarization:
		return "blockchain.Notarization"
	case MessageClockMsg:
		return "blockchain.ClockMsg"
	case MessageClockMsgNota:
		return "blockchain.ClockMsgNota"
	case MessageUnnotarizedProposals:
		return "UnnotarizedProposals"
	case MessageStatus:
		return "Status"
	case MessageGetEpoch:
		return "GetEpoch"
	case MessageEpoch:
		return "Epoch"
	case MessageGetFresherHead:
		return "MessageGetFresherHead"
	case MessageGetFresherHeadV2:
		return "MessageGetFresherHeadV2"
	case MessageFresherHeadMeta:
		return "MessageFresherHeadMeta"
	case MessageFresherHeadData:
		return "MessageFresherHeadData"
	case MessageFresherHeadDataV2:
		return "MessageFresherHeadDataV2"
	default:
		return "unknown"
	}
}

func blockchainTypeToMessageType(typ blockchain.Type) MessageId {
	if r, ok := blockchainTypeToMessageTypeMap[typ]; ok {
		return r
	}
	debug.Bug("unknown blockchain.Type %d", typ)
	return MessageNil
}

func messageTypeToBlockchainType(typ MessageId) blockchain.Type {
	if r, ok := messageTypeToBlockchainTypeMap[typ]; ok {
		return r
	}
	return blockchain.TypeNil
}

//------------------------------------------------------------------------------

func (msg consensusDataMessage) toNetworkMessage() *network.Message {
	typ := uint8(blockchainTypeToMessageType(msg.msg.GetType()))
	return network.NewMessage(typ, 0, msg.msg.GetBody())
}

func (msg statusMessage) toNetworkMessage() *network.Message {
	return network.NewMessage(uint8(MessageStatus), 0, chainsync.MarshalStatus(msg.status))
}

func newStatusMessage(msg *network.Message) (*statusMessage, error) {
	s, err := chainsync.UnmarshalStatus(msg.GetBlob())
	if err != nil {
		return nil, err
	}
	return &statusMessage{s}, nil
}

func (msg getFresherHeadMessage) toNetworkMessage() *network.Message {
	bytes := msg.head.ToBytes()
	bytes = append(bytes, utils.Uint16ToBytes(uint16(len(msg.blockIdentities)))...)
	for _, id := range msg.blockIdentities {
		bytes = append(bytes, id.ToBytes()...)
	}
	return network.NewMessage(uint8(MessageGetFresherHead), 0, bytes)
}

func newGetFresherHeadMessage(msg *network.Message) (*getFresherHeadMessage, error) {
	expectedType := MessageGetFresherHead
	if MessageId(msg.GetType()) != expectedType {
		return nil, xerrors.Errorf("type mismatched: expect %s but got %s",
			expectedType, MessageId(msg.GetType()))
	}

	head, bytes, err := blockchain.NewBlockSnFromBytes(msg.GetBlob())
	if err != nil {
		return nil, err
	}

	n, bytes, err := utils.BytesToUint16(bytes)
	ids := make([]chainsync.BlockIdentifier, n)
	for i := 0; i < int(n); i++ {
		var id chainsync.BlockIdentifier
		id, bytes, err = chainsync.NewBlockIdentifierFromBytes(bytes)
		if err != nil {
			return nil, err
		}
		ids[i] = id
	}

	return &getFresherHeadMessage{
		head:            head,
		blockIdentities: ids,
	}, nil
}

func (msg getFresherHeadV2Message) toNetworkMessage() *network.Message {
	bytes := msg.head.ToBytes()
	bytes = append(bytes, utils.Uint16ToBytes(uint16(len(msg.blockIdentities)))...)
	for _, id := range msg.blockIdentities {
		bytes = append(bytes, id.ToBytes()...)
	}
	return network.NewMessage(uint8(MessageGetFresherHeadV2), 0, bytes)
}

func newGetFresherHeadV2Message(msg *network.Message) (*getFresherHeadV2Message, error) {
	expectedType := MessageGetFresherHeadV2
	if MessageId(msg.GetType()) != expectedType {
		return nil, xerrors.Errorf("type mismatched: expect %s but got %s",
			expectedType, MessageId(msg.GetType()))
	}

	head, bytes, err := blockchain.NewBlockSnFromBytes(msg.GetBlob())
	if err != nil {
		return nil, err
	}

	n, bytes, err := utils.BytesToUint16(bytes)
	ids := make([]chainsync.BlockIdentifier, n)
	for i := 0; i < int(n); i++ {
		var id chainsync.BlockIdentifier
		id, bytes, err = chainsync.NewBlockIdentifierFromBytes(bytes)
		if err != nil {
			return nil, err
		}
		ids[i] = id
	}

	return &getFresherHeadV2Message{
		head:            head,
		blockIdentities: ids,
	}, nil
}

func (msg *fresherHeadMetaMessage) toNetworkMessage() *network.Message {
	bytes := utils.Uint16ToBytes(msg.numNotarizedBlocks)
	if msg.numNotarizedBlocks == 0 {
		bytes = append(bytes, msg.finalizedHead.ToBytes()...)
	}
	return network.NewMessage(uint8(MessageFresherHeadMeta), 0, bytes)
}

func newFresherHeadMetaMessage(msg *network.Message) (*fresherHeadMetaMessage, error) {
	expectedType := MessageFresherHeadMeta
	if MessageId(msg.GetType()) != expectedType {
		return nil, xerrors.Errorf("type mismatched: expect %s but got %s",
			expectedType, MessageId(msg.GetType()))
	}

	bytes := msg.GetBlob()
	if len(bytes) < 1 {
		return nil, xerrors.Errorf("message length is too small (%d)", len(bytes))
	}

	var err error
	var result fresherHeadMetaMessage
	result.numNotarizedBlocks, bytes, err = utils.BytesToUint16(bytes)
	if err != nil {
		return nil, err
	}
	if result.numNotarizedBlocks == 0 {
		result.finalizedHead, bytes, err = chainsync.NewBlockInfoFromBytes(bytes)
		if err != nil {
			return nil, err
		}
	}

	return &result, nil
}

func appendBytesWithLength(out [][]byte, bytes []byte) [][]byte {
	out = append(out, utils.Uint32ToBytes(uint32(len(bytes))))
	return append(out, bytes)
}

func newFresherHeadDataMessage(
	unmarshaller blockchain.DataUnmarshaller, msg *network.Message,
) (*fresherHeadDataMessage, error) {
	expectedType := MessageFresherHeadData
	if MessageId(msg.GetType()) != expectedType {
		return nil, xerrors.Errorf("type mismatched: expect %s but got %s",
			expectedType, MessageId(msg.GetType()))
	}

	nb, _, err := unmarshalNotarizedBlock(unmarshaller, msg.GetBlob())
	if err != nil {
		return nil, err
	}
	return &fresherHeadDataMessage{*nb}, nil
}

// marshalToNotarizedBlock marshals raw block and nota to fresher head data format.
func marshalToNotarizedBlock(block []byte, nota []byte) []byte {
	var out [][]byte
	out = appendBytesWithLength(out, nota)
	out = appendBytesWithLength(out, block)
	return utils.ConcatCopyPreAllocate(out)
}

func unmarshalNotarizedBlock(unmarshaller blockchain.DataUnmarshaller, bytes []byte,
) (*notarizedBlock, []byte, error) {
	nb, bytes, err := utils.BytesToUint32(bytes)
	if err != nil {
		return nil, nil, err
	}
	if len(bytes) < int(nb) {
		return nil, nil, xerrors.Errorf("short length: %d < %d", len(bytes), nb)
	}
	nota, _, err := unmarshaller.UnmarshalNotarization(bytes[:nb])
	if err != nil {
		return nil, nil, err
	}
	bytes = bytes[nb:]
	nb, bytes, err = utils.BytesToUint32(bytes)
	if err != nil {
		return nil, nil, err
	}
	if len(bytes) < int(nb) {
		return nil, nil, xerrors.Errorf("short length: %d < %d", len(bytes), nb)
	}
	block, _, err := unmarshaller.UnmarshalBlock(bytes[:nb])
	if err != nil {
		return nil, nil, err
	}
	return &notarizedBlock{Nota: nota, Block: block}, bytes[nb:], nil
}

func newFresherHeadDataV2Message(
	unmarshaller blockchain.DataUnmarshaller, msg *network.Message,
) (*fresherHeadDataV2Message, error) {
	expectedType := MessageFresherHeadDataV2
	if MessageId(msg.GetType()) != expectedType {
		return nil, xerrors.Errorf("type mismatched: expect %s but got %s",
			expectedType, MessageId(msg.GetType()))
	}

	bytes := msg.GetBlob()
	var result fresherHeadDataV2Message
	for len(bytes) > 0 {
		var nb *notarizedBlock
		var err error
		nb, bytes, err = unmarshalNotarizedBlock(unmarshaller, bytes)
		if err != nil {
			return nil, err
		}
		result.notarizedBlocks = append(result.notarizedBlocks, *nb)
	}
	return &result, nil
}

func (msg unnotarizedProposalsMessage) toNetworkMessage() *network.Message {
	var out [][]byte
	out = append(out, utils.Uint16ToBytes(uint16(len(msg.proposals))))
	for _, p := range msg.proposals {
		out = append(out, p.GetBody())
	}
	bytes := utils.ConcatCopyPreAllocate(out)

	return network.NewMessage(uint8(MessageUnnotarizedProposals), 0, bytes)
}

func newUnnotarizedProposalsMessage(
	unmarshaller blockchain.DataUnmarshaller, msg *network.Message,
) (*unnotarizedProposalsMessage, error) {
	expectedType := MessageUnnotarizedProposals
	if MessageId(msg.GetType()) != expectedType {
		return nil, xerrors.Errorf("type mismatched: expect %s but got %s",
			expectedType, MessageId(msg.GetType()))
	}

	n, bytes, err := utils.BytesToUint16(msg.GetBlob())
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal a proposal: %w", err)
	}
	var p blockchain.Proposal
	ps := make([]blockchain.Proposal, n)
	for i := 0; i < int(n); i++ {
		if p, bytes, err = unmarshaller.UnmarshalProposal(bytes); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal a proposal: %w", err)
		}
		ps[i] = p
	}
	return &unnotarizedProposalsMessage{ps}, nil
}

func (msg getEpochMessage) toNetworkMessage() *network.Message {
	return network.NewMessage(uint8(MessageGetEpoch), 0, msg.clientEpoch.ToBytes())
}

func newGetEpochMessage(msg *network.Message) (*getEpochMessage, error) {
	epoch, _, err := blockchain.NewEpochFromBytes(msg.GetBlob())
	if err != nil {
		return nil, err
	}
	return &getEpochMessage{epoch}, nil
}

func (msg epochMessage) toNetworkMessage() *network.Message {
	bytes := utils.Uint32ToBytes(uint32(msg.session))

	existed := byte(0)
	if msg.cNota != nil {
		existed = 1
	}
	bytes = append(bytes, existed)

	isLast := byte(0)
	if msg.isLast {
		isLast = 1
	}
	bytes = append(bytes, byte(isLast))

	if msg.cNota != nil {
		bytes = append(bytes, msg.cNota.GetBody()...)
	}

	return network.NewMessage(uint8(MessageEpoch), 0, bytes)
}

func newEpochMessage(unmarshaller blockchain.DataUnmarshaller, msg *network.Message,
) (*epochMessage, error) {
	tmp, bytes, err := utils.BytesToUint32(msg.GetBlob())
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal session: %w", err)
	}
	session := blockchain.Session(tmp)

	var existed, isLast bool
	var cNota blockchain.ClockMsgNota
	if len(bytes) < 2 {
		return nil, xerrors.Errorf("length < 2")
	}
	existed = bytes[0] != 0
	isLast = bytes[1] != 0
	if existed {
		cNota, bytes, err = unmarshaller.UnmarshalClockMsgNota(bytes[2:])
		if err != nil {
			return nil, xerrors.Errorf("failed to unmarshal clock msg nota: %w", err)
		}
	}

	return &epochMessage{
		session: session,
		existed: existed,
		isLast:  isLast,
		cNota:   cNota,
	}, nil
}
