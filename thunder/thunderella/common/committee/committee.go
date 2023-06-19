package committee

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	// MaxCommSize is the maximum number of committee members.
	MaxCommSize    = 512
	InvalidCommID  = 9999
	InvalidAccelID = 99999

	StakeSize      = 8
	BLSPubKeySize  = 128
	MemberInfoSize = StakeSize + BLSPubKeySize + 2*common.AddressLength
	CommInfoSize   = MaxCommSize*MemberInfoSize + BLSPubKeySize + chain.SeqSize

	// EncodedCommInfoSize is an estimated size which accounts for RLP encoding overhead.
	RLPEncodedCommInfoSize = CommInfoSize * 2

	// JSONEncodedCommInfoSize is an estimated size which accounts for JSON overhead.
	JSONEncodedCommInfoSize = CommInfoSize*2 + // 2 bytes for every bytes
		MaxCommSize*4*30 + // number of fields * field name/ws/encode overhead
		100 // arbitrary JSON top level struct padding
)

var (
	SwitchInterval = config.NewInt64HardforkConfig(
		"committee.switchInterval",
		"interval (in terms of slow blocks) at which new committee is elected")

	// This parameter is used for changing switchInterval ina  hardfork. It's also used to delay first
	// committee switch so that there is enough time for setup steps to run.
	SwitchOffset = config.NewInt64HardforkConfig(
		"committee.switchOffset",
		"expected nonce (in terms of slow blocks) of first committee switch")

	ErrCommIDNotFound         = fmt.Errorf("committee's ID not found")
	ErrAccelIDNotFound        = fmt.Errorf("accelerator's ID not found")
	ErrBadMissingCommIdsOrder = fmt.Errorf(
		"bad ordering of missingCommIds, should be increasing")
)

// MemberInfo holds the information for a specific committee in a specific round.
type MemberInfo struct {
	Stake      *big.Int
	PubVoteKey *bls.PublicKey
	Coinbase   common.Address
	GasPrice   *big.Int
}

func (m *MemberInfo) String() string {
	return fmt.Sprintf("stake: %s, key: %x, coinbase: %x, gasprice: %s",
		m.Stake.String(),
		m.PubVoteKey.ToBytes(),
		m.Coinbase,
		m.GasPrice.String())
}

// AccelInfo mirrors the member info so we can use the same logic where useful.
type AccelInfo struct {
	MemberInfo
	AccelCert  keymanager.AccelCertificate
	URI        string // URI for the accelerator's CDN
	HostPort   string // host:port for this accelerator
	TxPoolAddr string // host:port for this accelerator
}

// CommInfo contains the public voting keys of all committee members
// and the Accel public proposing key
type CommInfo struct {
	Name            string       `json:",omitempty"`
	SlowChainHeight chain.Height // Slow chain height when committee was elected.
	AccelId         uint
	MemberInfo      []MemberInfo // Index equals committee ID.
	AccelInfo       []AccelInfo
}

func (ci *CommInfo) NumCommittee() int {
	return len(ci.MemberInfo)
}

func (ci *CommInfo) Stake() *big.Int {
	stake := big.NewInt(0)
	for i := 0; i < len(ci.MemberInfo); i += 1 {
		stake.Add(stake, ci.MemberInfo[i].Stake)
	}
	return stake
}

func (ci *CommInfo) NumAccel() int {
	return len(ci.AccelInfo)
}

// Check whether two comm info are equals except URI/HostPort/TxPoolAddr in AccelInfo
func (ci *CommInfo) Equals(cc CommInfo) bool {
	if len(ci.AccelInfo) != len(cc.AccelInfo) {
		return false
	}
	for i, ai := range ci.AccelInfo {
		ai0 := ai
		ai0.URI = ""
		ai0.HostPort = ""
		ai0.TxPoolAddr = ""
		ai1 := cc.AccelInfo[i]
		ai1.URI = ""
		ai1.HostPort = ""
		ai1.TxPoolAddr = ""
		if !reflect.DeepEqual(ai0, ai1) {
			return false
		}
	}
	return ci.SlowChainHeight == cc.SlowChainHeight &&
		ci.AccelId == cc.AccelId && reflect.DeepEqual(ci.MemberInfo, cc.MemberInfo)

}

// From bytes decodes a JSON encoded buffer into a fully formed CommInfo struct.
func (ci *CommInfo) FromJSON(buf []byte) error {
	if err := json.Unmarshal(buf, ci); err != nil {
		return err
	}
	return nil
}

// Byte format has proved way too hard to work with and inflexible for this
// struct.  Simpler wrappers for JSON.
func (ci *CommInfo) ToJSON() []byte {
	buf, err := json.MarshalIndent(ci, "", " ")
	if err != nil {
		debug.Bug("Encoding of CommInfo failed: %s (%v)", err, ci)
	}
	return buf
}

// Clone deep copies a CommInfo struct.
func (ci *CommInfo) Clone() *CommInfo {
	bytes := ci.ToJSON()
	newCi := CommInfo{}
	newCi.FromJSON(bytes)
	return &newCi
}

// FindCommId looks up a committee's ID given a public key.
// Returns InvalidCommID if the committee could not be found.
func (ci *CommInfo) FindCommId(pk *bls.PublicKey) (uint, error) {
	pkBytes := pk.ToBytes()
	for i, mi := range ci.MemberInfo {
		mkBytes := mi.PubVoteKey.ToBytes()
		if bytes.Equal(pkBytes, mkBytes) {
			return uint(i), nil
		}
	}
	return InvalidCommID, ErrCommIDNotFound
}

func (ci *CommInfo) ActiveAccel() *AccelInfo {
	return &ci.AccelInfo[ci.AccelId]
}

// FindAccelId looks up a accel's ID given a public key.
// Returns InvalidAccelID if the accelerator could not be found.
func (ci *CommInfo) FindAccelId(pk *bls.PublicKey) (uint, error) {
	pkBytes := pk.ToBytes()
	for i, mi := range ci.AccelInfo {
		mkBytes := mi.PubVoteKey.ToBytes()
		if bytes.Equal(pkBytes, mkBytes) {
			return uint(i), nil
		}
	}
	// In pubvotekeys_comm.json, AccelInfo is null so this case can happen.
	return InvalidAccelID, ErrAccelIDNotFound
}

// ClearingGasPrice returns the max gas price of a committee.
// Returns zero if a committee has no members.
func (ci *CommInfo) ClearingGasPrice() *big.Int {
	c := big.NewInt(0)
	for i := 0; i < len(ci.MemberInfo); i += 1 {
		if c.Cmp(ci.MemberInfo[i].GasPrice) == -1 {
			c.Set(ci.MemberInfo[i].GasPrice)
		}
	}
	return c
}

// AccelGasPrice returns the gas price of the current accelerator.
func (ci *CommInfo) AccelGasPrice() *big.Int {
	return new(big.Int).Set(ci.AccelInfo[ci.AccelId].GasPrice)
}

// GetAggregatedPublicKey fetches the aggregated public key through a cache. Not thread-safe.
func (ci *CommInfo) GetAggregatedPublicKey(missingCommIds []uint) (*bls.PublicKey, error) {
	for i := range missingCommIds {
		if i > 0 && missingCommIds[i] < missingCommIds[i-1] {
			return nil, ErrBadMissingCommIdsOrder
		}
		if missingCommIds[i] >= uint(ci.NumCommittee()) {
			return nil, fmt.Errorf("bad commId %d in missingCommIds (comm size=%d)",
				missingCommIds[i], ci.NumCommittee())
		}
	}

	missingCommIdsLookup := make([]bool, ci.NumCommittee())
	for _, missingCommId := range missingCommIds {
		missingCommIdsLookup[missingCommId] = true
	}

	aggPk := ci.ActiveAccel().PubVoteKey
	for i, MemberInfo := range ci.MemberInfo {
		if missingCommIdsLookup[i] {
			continue
		}
		aggPk = bls.CombinePublicKeys(aggPk, MemberInfo.PubVoteKey)
	}
	return aggPk, nil
}

// NewCommInfoFromKeyManager loads Committee info from key files, as well as Accel's public
// proposing key.
func NewCommInfoFromKeyManager(
	keymgr *keymanager.KeyManager, propKeyIDs []string, voteKeyIDs []string,
) (*CommInfo, error) {
	var commInfo = &CommInfo{
		SlowChainHeight: 0,
	}

	// Update comm member info.
	commKeys, err := keymgr.GetCommPublicVoteKeys(voteKeyIDs, nil)
	if err != nil {
		debug.Fatal("Failed to load committee's public voting keys: %s", err)
	}
	commInfo.MemberInfo = make([]MemberInfo, len(commKeys))
	for i, key := range commKeys {
		commInfo.MemberInfo[i] = newMemberInfo(i, key, 10000000)
	}

	// We also keep certs in commInfo because comm/accel switch dumps this object into
	// TxDB for others to update themselves. Anyone reading commInfo from a random file will
	// need the certs again to verify accel prop keys.
	accelKeys, err := keymgr.GetCommPublicVoteKeys(propKeyIDs, nil)
	if err != nil {
		debug.Fatal("Failed to load Accel public proposing key: %s", err)
	}
	commInfo.AccelInfo = make([]AccelInfo, len(accelKeys))
	webserverPort := 8889
	chainPrefix := "" // empty prefix used for fastpath
	accelPort := 8888
	txPoolPort := 8887
	// Different ports and services name for auxnet/slow-chain
	if len(commKeys) == 0 {
		chainPrefix = "auxnet_"
		accelPort = 8878
		webserverPort = 8879
		txPoolPort = 8877
	}
	for i := 0; i < len(accelKeys); i++ {
		commInfo.AccelInfo[i] = AccelInfo{
			MemberInfo: newMemberInfo(i+100, accelKeys[i], 0),
			HostPort:   fmt.Sprint(chainPrefix, "accel_", i, ":", accelPort),
			URI: fmt.Sprint(chainPrefix, "cdnserver_", i, ":",
				webserverPort+i*10),
			TxPoolAddr: fmt.Sprint(chainPrefix, "accel_", i, ":", txPoolPort+i*10),
		}
	}
	commInfo.AccelId = 0
	return commInfo, nil
}

func newMemberInfo(id int, key *bls.PublicKey, gasPrice int) MemberInfo {
	return MemberInfo{
		Stake:      big.NewInt(int64(id)),
		Coinbase:   common.BigToAddress(big.NewInt(int64(id))),
		GasPrice:   big.NewInt(int64(gasPrice)),
		PubVoteKey: key,
	}
}

// IsBoundary returns true iff the current block is the last block of a committee term.
func IsBoundary(header *types.Header, parentHeader *types.Header) bool {
	if header == nil {
		debug.Fatal("header is nil")
	}

	interval := uint64(0)
	offset := uint64(0)
	if header != nil && header.Number != nil {
		interval = uint64(SwitchInterval.GetValueAt(chain.Seq(header.Number.Int64())))
		offset = uint64(SwitchOffset.GetValueAt(chain.Seq(header.Number.Int64())))
	} else {
		interval = uint64(SwitchInterval.GetValueAt(chain.Seq(0)))
		offset = uint64(SwitchOffset.GetValueAt(chain.Seq(0)))
	}
	offset = offset % interval

	if header.Nonce.Uint64()%interval != offset {
		return false
	}

	// No account would have balance in genesis block to bid
	if parentHeader == nil || parentHeader.Nonce.Uint64() == 0 {
		return false
	}

	return header.Nonce.Uint64() > parentHeader.Nonce.Uint64()
}
