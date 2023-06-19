package blockchain

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm/reward"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/params"
	"github.com/petar/GoLLRB/llrb"
	"golang.org/x/xerrors"
)

var logger = lgr.NewLgr("/blockchain")

type BlockSn struct {
	Epoch Epoch
	// Estimate a rough lower bound: (2**32-1) / (86400*365) == 136.19 (years)
	// uint32 is large enough.
	S uint32
}

type Epoch struct {
	// session in (session, epoch, s),
	// where `session` is the `sid` from the "Reconfigurable Pala" section of the paper.
	Session Session
	// epoch   in (session, epoch, s)
	E uint32
}

type Session uint32

type BlockInfo struct {
	Sn     BlockSn
	Number uint64
	Hash   Hash
}

type BlockSnGetter interface {
	GetBlockSn() BlockSn
}

const HashLength = 32

type Hash [HashLength]byte

// Bytes gets the byte representation of the underlying hash.
func (h Hash) Bytes() []byte { return h[:] }

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

// BytesToHash sets b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

// BlockChain provides API for PaLa and wraps the under implementation such as geth's core.BlockChain.
// All operations must be goroutine-safe.
//
// Requirements:
// * Follow the rule to store notarizations on chain. For block (e,s):
//   * s=1       : contain the notarizations of the previous k blocks
//                 and the clock message notarization of e.
//   * s in [2,k]: contain no notarization.
//   * s>k       : contain the notarization of (e,s-k).
// * The implementation must receive an argument K (outstanding unnotarized proposals)
//   which affect GetFinalizedHead() and StartCreatingNewBlocks().
// * InsertBlock()/AddNotarization() must guarantee the blocks/notarizations are added in order.
//   This constraint simplifies the implementation of managing freshest notarized chain.
type BlockChain interface {
	// ContainsBlock returns true if the block(s) exists.
	// Expect this is more efficient compared to using GetBlock() == nil.
	ContainsBlock(s BlockSn) bool
	// GetBlock returns nil if there is no such value.
	GetBlock(s BlockSn) Block
	GetHeader(s BlockSn) Header
	GetGenesisBlock() Block
	// GetBlockByNumber return the block whose number is `number` from the canonical chain
	// (i.e., the freshest notarized chain).
	GetBlockByNumber(number uint64) Block
	GetHeaderByNumber(number uint64) Header
	GetRawBlockBody(hash Hash) []byte
	// GetNotarization returns nil if there is no such value.
	GetNotarization(s BlockSn) Notarization
	GetRawNotarization(s BlockSn) []byte
	// GetFreshestNotarizedHead() returns the last block of the freshest notarized chain
	// decided by the all received notarizations.
	GetFreshestNotarizedHead() Block
	GetFreshestNotarizedHeadSn() BlockSn
	GetFreshestNotarizedHeadInfo() BlockInfo
	// GetFinalizedHead() returns the last block of the finalized chain.
	// Unlike the freshest notarized chain, we use notarizations in blocks to decide the finalized
	// chain. In other words, notarizations received from AddNotarization() are not used.
	// This constraint makes the finality stronger in practice.
	// When the freshest notarized chain contains 2K consecutive normal blocks,
	// the finalize chain is the one without the last 2k blocks. Note that it is possible
	// that the finalized chain doesn't grow while the freshest notarized chain keeps growing.
	// NOTE: To simplify the implementation, the notarizations in a timeout block doesn't finalize
	// any new block in current design. We can remove this constraint later.
	GetFinalizedHead() Block
	GetFinalizedHeadSn() BlockSn
	// GetLatestFinalizedStopBlock returns the latest finalized stop block.
	// Return nil if there is no finalized stop block yet.
	GetLatestFinalizedStopBlock() Block

	// DecodeBlock decodes a block and returns the notarization and clock-message notarization included in it.
	DecodeBlock(b Block) ([]Notarization, ClockMsgNota)

	// ToRawBlock converts header and block body to block in network format.
	ToRawBlock(header []byte, body []byte) ([]byte, error)

	// InsertBlock returns error if:
	// * |b| already exists and |replaceable| is false
	// * |b|'s parent doesn't exist in the chain.
	// * notarizations in |b| doesn't follow the rules. See rules above BlockChain.
	// * Any other invalid block format based on the implementation definition.
	// The error may support IsTemporary().
	// If the error is temporary, the caller should catch up previous blocks and then insert
	// the block again. During the call, the finalized chain may be updated.
	InsertBlock(b Block, replaceable bool) error

	// StartCreatingNewBlocks returns a channel with buffer size = |K|. This fits the
	// stability-favoring approach in PaLa. The first new block's BlockSn is
	// {|epoch|.Session, |epoch|.E, 1}. Rules:
	// * The first block includes |cNota| if |epoch|.E > 1, i.e., save the proof of entering
	//   the new epoch.
	// * The parent block is the freshest notarized head.
	StartCreatingNewBlocks(epoch Epoch, cNota ClockMsgNota) (chan BlockMadeEvent, error)
	// StopCreatingNewBlocks stops the creation. However, there may be some blocks in the channel returned
	// by StartCreatingNewBlocks(). The call returns after the worker goroutine ends or it already waits
	// |waitingPeriod|. If StartCreatingNewBlocks() is not called before, an error is returned immediately.
	StopCreatingNewBlocks(waitingPeriod time.Duration) error
	// IsCreatingBlock() returns true if the worker goroutine keeps trying to create new blocks.
	IsCreatingBlock() bool
	// AddNotarization may update the freshest notarized chain and/or continue creating a new block
	// if StartCreatingNewBlocks() is called before. Return error if:
	// * the corresponding block does not exist.
	// * the parent block's notarization does not exist.
	// Note that the notarization can be stored anywhere (even in memory) and may be lost
	// after we recreate the BlockChain object.
	AddNotarization(n Notarization) error

	// NewNotificationChannel creates a new channel used to notify events such as
	// FreshestNotarizedChainExtendedEvent and FinalizedChainExtendedEvent.
	NewNotificationChannel() <-chan interface{}
	// RemoveNotificationChannel removes the returned channel from NewNotificationChannel.
	RemoveNotificationChannel(target <-chan interface{})

	// GetProposerAddresses returns the proposers' network addresses in the session.
	// The keys and values of the returned map are the proposer IDs and network addresses.
	GetProposerAddresses(session Session) map[ConsensusId]string

	// GetTxPoolStatus returns
	GetTxPoolStatus() core.TxPoolStatus

	// Get CommInfo
	GetCommInfo(session Session) *committee.CommInfo
	// SetHead rewinds heads back to number
	SetHead(number uint64)

	// Get reward, number has to be a stop block
	GetReward(number uint64) (*reward.Results, error)
}

// ChainReader provides readonly methods from BlockChain
type ChainReader interface {
	ContainsBlock(s BlockSn) bool
	GetBlock(s BlockSn) Block
	GetGenesisBlock() Block
	GetNotarization(s BlockSn) Notarization
	GetFreshestNotarizedHead() Block
	GetFinalizedHead() Block
	DecodeBlock(b Block) ([]Notarization, ClockMsgNota)
	IsCreatingBlock() bool
	GetProposerAddresses(session Session) map[ConsensusId]string
}

type BlockMadeEvent struct {
	Block Block
}

type Type uint8

const (
	TypeNil          = Type(0)
	TypeBlock        = Type(1)
	TypeProposal     = Type(2)
	TypeVote         = Type(3)
	TypeNotarization = Type(4)
	TypeClockMsg     = Type(5)
	TypeClockMsgNota = Type(6)
	TypeHeader       = Type(7)
	TypeBlockBody    = Type(8)
)

// Message is a marshal/unmarshal helper.
type Message interface {
	GetType() Type
	GetBody() []byte
	GetBlockSn() BlockSn
	GetDebugString() string
}

type ByBlockSn []Message

// NOTE: the function ImplementsX() is used to ensure no interface includes another
// interface's methods. For example, assume A and B are interfaces and A includes
// all methods of B. The object implemented A can be converted to B. Adding ImplementsX()
// to ensure these data-type interfaces are exclusive. Otherwise, we may get unexpected
// result after doing a type cast. ImplementsX() does nothing and shouldn't be called.
type Block interface {
	Message

	ImplementsBlock()

	GetParentBlockSn() BlockSn
	GetHash() Hash
	GetParentHash() Hash
	// GetNumber() returns the number (height) of this block.
	GetNumber() uint64

	// GetBodyString() returns a string to represent the block.
	// This is used for logging/testing/debugging.
	GetBodyString() string
}

// TODO(sonic): put this in Block interface
type Header interface {
	Message
	ImplementsHeader()
	GetHash() Hash
	GetNumber() uint64
	GetParentBlockSn() BlockSn
}

type BlockDecoder interface {

	// GetNotarizations() returns the notarizations stored in the block.
	// Return nil if there is none. See comments above BlockChain for more details.
	GetNotarizations(block Block, config *params.ThunderConfig) []Notarization

	// GetClockMsgNota() returns the clock message notarization stored in the block.
	// Note that:
	// * Only the first block at each epoch contains the corresponding clock message notarization.
	// * The first epoch of each session has no clock message notarization.
	GetClockMsgNota(block Block, config *params.ThunderConfig) ClockMsgNota

	// PrehandleBlock() gives a chance to use txpool pre-calculate sender in txs
	PrehandleBlock(block Block)

	// ToRawBlock converts header and block body to block in network format.
	ToRawBlock(header []byte, body []byte) ([]byte, error)
}

type Proposal interface {
	Message

	ImplementsProposal()

	GetBlock() Block
	GetProposerId() ConsensusId
}

type Vote interface {
	Message

	ImplementsVote()

	GetVoterId() ConsensusId
}

type Notarization interface {
	Message

	ImplementsNotarization()

	GetNVote() uint16
	GetMissingVoterIdxs() []uint16
	GetBlockHash() Hash
}

type ClockMsg interface {
	Message

	ImplementsClockMsg()

	GetEpoch() Epoch
	GetVoterId() ConsensusId
}

type ClockMsgNota interface {
	Message

	ImplementsClockMsgNota()

	GetEpoch() Epoch
	GetNVote() uint16
}

// DataUnmarshaller works for the group of data set,
// we should switch all data type between fake and real implementation with DataUnmarshaller switch implementation respectively.
// so that other package don't have to aware the implementation change.
// NOTE: We have three groups of implementation now (all fake implementation, all real implementation, and implementation with real block and other types are fake)
// if we're going to add another real/fake switch, consider add a DataUnmarshallerBuilder.
type DataUnmarshaller interface {
	// UnmarshalBlock receives Block.GetBody() and returns Block and the rest of the bytes.
	UnmarshalBlock([]byte) (Block, []byte, error)
	// UnmarshalProposal receives Proposal.GetBody() and returns Proposal and the rest of the bytes.
	UnmarshalProposal([]byte) (Proposal, []byte, error)
	// UnmarshalVote receives Vote.GetBody() and returns Vote and the rest of the bytes.
	UnmarshalVote([]byte) (Vote, []byte, error)
	// UnmarshalNotarization receives Notarization.GetBody() and returns Notarization and
	// the rest of the bytes.
	UnmarshalNotarization([]byte) (Notarization, []byte, error)
	// UnmarshalClockMsg receives ClockMsg.GetBody() and returns ClockMsg and the rest of the bytes.
	UnmarshalClockMsg([]byte) (ClockMsg, []byte, error)
	// UnmarshalClockMsgNota receives ClockMsgNota.GetBody()
	// and returns ClockMsgNota and the rest of the bytes.
	UnmarshalClockMsgNota([]byte) (ClockMsgNota, []byte, error)
}

// Verifier provides two functions:
// * Create/Verify consensus data.
// * Sign/Verify signature of designated data.
//
// All methods must be goroutine-safe.
type Verifier interface {
	Propose(b Block) (Proposal, error)
	// IsReadyToPropose returns true if votes from `ids` are enough to make a notarization.
	IsReadyToPropose(ids []ConsensusId, session Session) bool
	// VerifyProposal verifies |p| is signed by the eligible proposer
	// and |p|'s block should contain valid notarizations of ancestor blocks.
	// See the rule above BlockChain for details.
	VerifyProposal(p Proposal) error
	Vote(p Proposal) (Vote, error)
	VerifyVote(v Vote, r ChainReader) error
	Notarize(votes []Vote, r ChainReader) (Notarization, error)
	VerifyNotarization(n Notarization, r ChainReader) error
	VerifyNotarizationWithBlock(n Notarization, block Block) error
	NewClockMsg(e Epoch) (ClockMsg, error)
	VerifyClockMsg(c ClockMsg) error
	NewClockMsgNota(clocks []ClockMsg) (ClockMsgNota, error)
	VerifyClockMsgNota(cn ClockMsgNota) error

	// Sign signs |bytes|.
	Sign(bytes []byte) (ConsensusId, []byte, error)
	// VerifySignature verifies |signature| is signed correctly and the signed message
	// equals to |expected|.
	VerifySignature(signature []byte, expected []byte) (id ConsensusId, isConsensusNode bool, err error)
}

// EpochManager manages epoch. All methods must be goroutine-safe.
type EpochManager interface {
	GetEpoch() Epoch
	UpdateByClockMsgNota(cn ClockMsgNota) error
	GetLatestClockMsgNota(session Session) ClockMsgNota
}

type FreshestNotarizedChainExtendedEvent struct {
	Sn BlockSn
}

type FinalizedChainExtendedEvent struct {
	Sn BlockSn
}

//--------------------------------------------------------------------

func (typ Type) String() string {
	switch typ {
	case TypeBlock:
		return "block"
	case TypeProposal:
		return "proposal"
	case TypeVote:
		return "vote"
	case TypeNotarization:
		return "notarization"
	case TypeClockMsg:
		return "clock"
	case TypeClockMsgNota:
		return "clock-nota"
	default:
		return "unknown"
	}
}

func GetGenesisBlockSn() BlockSn {
	return BlockSn{Epoch{}, 1}
}

func GetParentBlock(bc BlockChain, b Block) Block {
	return bc.GetBlock(b.GetParentBlockSn())
}

//--------------------------------------------------------------------

func NewBlockSn(session, epoch, s uint32) BlockSn {
	return BlockSn{
		Epoch: NewEpoch(session, epoch),
		S:     s,
	}
}

// NewBlockSnFromBytes unmarshal the output of BlockSn.ToBytes().
// Return the result and the rest of the bytes.
func NewBlockSnFromBytes(bytes []byte) (BlockSn, []byte, error) {
	if len(bytes) < 12 {
		msg := fmt.Sprintf("Invalid input: the length (%d) is less than 12", len(bytes))
		logger.Warn(msg)
		return BlockSn{}, bytes, xerrors.New(msg)
	}

	e, bytes, err := NewEpochFromBytes(bytes)
	if err != nil {
		return BlockSn{}, nil, err
	}

	s, bytes, err := utils.BytesToUint32(bytes)
	if err != nil {
		return BlockSn{}, nil, err
	}
	return BlockSn{e, s}, bytes, nil
}

func (s BlockSn) String() string {
	return fmt.Sprintf("(%d,%d,%d)", s.Epoch.Session, s.Epoch.E, s.S)
}

func (s BlockSn) IsGenesis() bool {
	return s.Epoch.IsNil() && s.S == 1
}

func (s BlockSn) IsPala() bool {
	return s.Epoch.Session > 0
}

func (s BlockSn) IsNil() bool {
	return s.Epoch.IsNil() && s.S == 0
}

func (s BlockSn) Compare(s2 BlockSn) int {
	r := s.Epoch.Compare(s2.Epoch)
	if r != 0 {
		return r
	}
	if s.S != s2.S {
		if s.S < s2.S {
			return -1
		} else {
			return 1
		}
	}
	return 0
}

func (s BlockSn) GetBlockSn() BlockSn {
	return s
}

func (s BlockSn) Less(s2 llrb.Item) bool {
	return s.Compare(s2.(BlockSnGetter).GetBlockSn()) < 0
}

func (s BlockSn) ToBytes() []byte {
	bytes := make([]byte, 12)
	// Instead of calling Epoch.ToBytes(), write to bytes directly to avoid an unnecessary copy.
	binary.LittleEndian.PutUint32(bytes, uint32(s.Epoch.Session))
	binary.LittleEndian.PutUint32(bytes[4:], s.Epoch.E)
	binary.LittleEndian.PutUint32(bytes[8:], s.S)
	return bytes
}

func (s BlockSn) NextS() BlockSn {
	return BlockSn{
		Epoch: s.Epoch,
		S:     s.S + 1,
	}
}

//--------------------------------------------------------------------

func NewEpoch(session, e uint32) Epoch {
	return Epoch{
		Session: Session(session),
		E:       e,
	}
}

func NewEpochFromBytes(bytes []byte) (Epoch, []byte, error) {
	if len(bytes) < 8 {
		msg := fmt.Sprintf("Invalid input: the length (%d) is less than 8", len(bytes))
		logger.Warn(msg)
		return Epoch{}, bytes, xerrors.New(msg)
	}

	var err error
	var tmp uint32
	tmp, bytes, err = utils.BytesToUint32(bytes)
	if err != nil {
		return Epoch{}, nil, err
	}
	e := Epoch{Session(tmp), 0}
	e.E, bytes, err = utils.BytesToUint32(bytes)
	if err != nil {
		return Epoch{}, nil, err
	}
	return e, bytes, nil
}

func (e Epoch) ToBytes() []byte {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(bytes, uint32(e.Session))
	binary.LittleEndian.PutUint32(bytes[4:], e.E)
	return bytes
}

func (e Epoch) Compare(e2 Epoch) int {
	if e.Session < e2.Session {
		return -1
	} else if e.Session > e2.Session {
		return 1
	}
	if e.E < e2.E {
		return -1
	} else if e.E > e2.E {
		return 1
	}
	return 0
}

func (e Epoch) IsNil() bool {
	return e.Session == 0 && e.E == 0
}

func (e Epoch) String() string {
	return fmt.Sprintf("(%d,%d)", e.Session, e.E)
}

func (e Epoch) NextSession() Epoch {
	return Epoch{e.Session + 1, 1}
}

func (e Epoch) NextEpoch() Epoch {
	return Epoch{e.Session, e.E + 1}
}

func (e Epoch) PreviousEpoch() (Epoch, error) {
	if e.E > 1 {
		return Epoch{e.Session, e.E - 1}, nil
	}
	return Epoch{}, xerrors.Errorf(
		"don't know the last epoch because %s is the first epoch of this session", e)
}

func (s Session) String() string {
	return fmt.Sprintf("%d", s)
}

//--------------------------------------------------------------------

func (s ByBlockSn) Len() int {
	return len(s)
}

func (s ByBlockSn) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s ByBlockSn) Less(i, j int) bool {
	return s[i].GetBlockSn().Compare(s[j].GetBlockSn()) < 0
}
