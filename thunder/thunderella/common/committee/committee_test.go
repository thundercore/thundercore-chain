package committee

import (
	// Standard imports
	"math/big"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"

	// Vendor imports
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	config.InitThunderConfig("../../../../config")
	os.Exit(m.Run())
}

func testMemberInfo(assert *assert.Assertions, expected *MemberInfo, actual *MemberInfo) {
	assert.Equal(expected.Stake, actual.Stake, "Stake differerent")
	assert.Equal(expected.PubVoteKey, actual.PubVoteKey, "PubVoteKey different")
	assert.Equal(expected.Coinbase, actual.Coinbase, "Coinbase differerent")

	assert.True(reflect.DeepEqual(*expected, *actual), "Got differences in persisted data")
}

func createRandomMemberInfo(assert *assert.Assertions) MemberInfo {
	var mi MemberInfo
	mi.Stake = big.NewInt(rand.Int63n(100000000000))
	var cb = mi.Coinbase[:]
	rand.Read(cb)
	k, err := bls.NewSigningKey()
	assert.NoError(err, "Got an error creating signing key")
	mi.PubVoteKey = k.GetPublicKey()
	return mi
}

func newCommittee(assert *assert.Assertions) *CommInfo {
	// Make a file locally containing committee info.
	numComm := rand.Intn(10)
	ci := CommInfo{
		SlowChainHeight: chain.Height(rand.Int63n(10000000000)),
		AccelId:         0,
		MemberInfo:      make([]MemberInfo, numComm),
		AccelInfo:       make([]AccelInfo, 1),
	}
	ci.AccelInfo[0].MemberInfo = createRandomMemberInfo(assert)
	for i := 0; i < numComm; i++ {
		ci.MemberInfo[i] = createRandomMemberInfo(assert)
	}
	ci.AccelInfo = nil
	return &ci
}

func testCommInfo(assert *assert.Assertions, expected *CommInfo, actual *CommInfo) {
	assert.Equal(expected.SlowChainHeight, actual.SlowChainHeight, "SlowChainHeight different")
	assert.Equal(expected.AccelId, actual.AccelId, "AccelPropKey different")

	// Deeper inspection
	assert.Equal(len(expected.MemberInfo), len(actual.MemberInfo), "Wrong member size")
	for i, mi := range expected.MemberInfo {
		testMemberInfo(assert, &mi, &actual.MemberInfo[i])
	}
	for i, mi := range expected.AccelInfo {
		testMemberInfo(assert, &mi.MemberInfo, &actual.AccelInfo[i].MemberInfo)
	}
}

func TestCommInfoToJSON(t *testing.T) {
	assert := assert.New(t)
	ci := newCommittee(assert)
	t.Logf("%v", ci)

	buf := ci.ToJSON()
	newCi := &CommInfo{}
	newCi.FromJSON(buf)

	testCommInfo(assert, ci, newCi)
}

func TestCommitteeInfoClone(t *testing.T) {
	assert := assert.New(t)
	ci := newCommittee(assert)
	clone := ci.Clone()
	testCommInfo(assert, ci, clone)
}

func generateCommInfo(t *testing.T) *CommInfo {
	// Test loading all committee keys and Accel key
	voteKeyIDs := keymanager.GetKeyIDsForFS(5, keymanager.VotingKeyType, 0)
	propKeyIDs := voteKeyIDs[:1]
	memKeystore := keymanager.SetupTestingKeystore(
		keymanager.MemKeyStoreConfig{
			AccelIDs:   propKeyIDs,
			VoteKeyIDs: voteKeyIDs,
		})
	keymgr := keymanager.NewKeyManagerFromMemKeystore(memKeystore)
	commInfo, err := NewCommInfoFromKeyManager(keymgr, propKeyIDs, voteKeyIDs)
	assert.Nil(t, err, "cannot load committee info")
	assert.NotNil(t, commInfo, "Incorrect committee info")
	return commInfo
}

func TestNonSortedMissingCommIds(t *testing.T) {
	cInfo := generateCommInfo(t)
	_, err := cInfo.GetAggregatedPublicKey([]uint{3, 2})
	assert.Equal(t, err, ErrBadMissingCommIdsOrder, "expected error")
}

func TestWrongIdInMissingCommIds(t *testing.T) {
	cInfo := generateCommInfo(t)
	_, err := cInfo.GetAggregatedPublicKey([]uint{3, 5})
	assert.True(t, strings.HasPrefix(err.Error(), "bad commId 5"))
}

func TestGetAggPubKey(t *testing.T) {
	cInfo := generateCommInfo(t)
	missingCommIds := []uint{3, 4}
	_, err := cInfo.GetAggregatedPublicKey(missingCommIds)
	assert.Nil(t, err, "unexpected error")
}

// XXX The following aren't used anywhere other than the test.  Are they actually useful?

// Helper functions for working with comm switch interval
// IsFirstBlockOfInterval returns true if height is first block of the interval
// Must have interval > 0, height >= 0
func IsFirstHeightOfInterval(interval int64, height chain.Height) bool {
	return int64(height)%interval == 0
}

// IsLastBlockOfInterval returns true if height is last block of the interval
// Must have interval > 0, height >= 0
func IsLastHeightOfInterval(interval int64, height chain.Height) bool {
	return (int64(height)+1)%interval == 0
}

// GetFirstBlockOfInterval returns the first block of the interval of the given height
// Must have interval > 0, height >= 0
func GetFirstHeightOfInterval(interval int64, height chain.Height) chain.Height {
	return chain.Height(int64(height) - (int64(height) % interval))
}

// GetFirstHeightOfNextInterval returns the first block of the next interval of the given height
// Must have interval > 0, height >= 0
func GetFirstHeightOfNextInterval(interval int64, height chain.Height) chain.Height {
	return chain.Height(int64(height) - (int64(height) % interval) + interval)
}

func TestIntervalHelpers(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(true, IsFirstHeightOfInterval(100, 10100), "unexpected result")
	assert.Equal(false, IsFirstHeightOfInterval(100, 10101), "unexpected result")
	assert.Equal(true, IsLastHeightOfInterval(100, 1099), "unexpected result")
	assert.Equal(false, IsLastHeightOfInterval(100, 10100), "unexpected result")

	assert.Equal(chain.Height(10000), GetFirstHeightOfInterval(100, 10001), "unexpected result")
	assert.Equal(chain.Height(10000), GetFirstHeightOfInterval(100, 10099), "unexpected result")
	assert.Equal(chain.Height(10100), GetFirstHeightOfNextInterval(100, 10000),
		"unexpected result")
	assert.Equal(chain.Height(10100), GetFirstHeightOfNextInterval(100, 10050),
		"unexpected result")
	assert.Equal(chain.Height(10100), GetFirstHeightOfNextInterval(100, 10099),
		"unexpected result")
	assert.Equal(chain.Height(10200), GetFirstHeightOfNextInterval(100, 10100),
		"unexpected result")

	// TODO set interval to something random
	var interval int64 = 23
	var firstBlock int64 = 0
	var lastBlock int64 = 0
	var nextBlock int64 = 0
	for i := int64(0); i <= 10000; i++ {
		if IsFirstHeightOfInterval(interval, chain.Height(i)) {
			firstBlock = i
			lastBlock = firstBlock + interval - 1
			nextBlock = firstBlock + interval
		}
		if IsLastHeightOfInterval(interval, chain.Height(i)) {
			assert.Equal(lastBlock, i)
		}
		assert.Equal(chain.Height(firstBlock),
			GetFirstHeightOfInterval(interval, chain.Height(i)))
		assert.Equal(chain.Height(nextBlock),
			GetFirstHeightOfNextInterval(interval, chain.Height(i)))
	}
}

func TestIsBoundary(t *testing.T) {
	assert := assert.New(t)

	oldCommSwitchInterval := SwitchInterval.GetValueAt(config.InitialBlockNum)
	// these tests don't work if switchinterval is too small due to wrap around
	SwitchInterval.SetTestValueAt(100, config.InitialBlockNum)
	SwitchOffset.SetTestValueAt(0, config.InitialBlockNum)
	defer func() {
		SwitchInterval.SetTestValueAt(oldCommSwitchInterval, config.InitialBlockNum)
	}()

	isBoundaryTests := []struct {
		headerNonce       int64
		parentHeaderNonce int64
		expected          bool
	}{
		{2, -1, false},
		{SwitchInterval.GetValueAt(config.InitialBlockNum), -1, false},
		{2, 1, false},
		{2, 2, false},
		{0, 1, false},
		{SwitchInterval.GetValueAt(config.InitialBlockNum) * 3, SwitchInterval.GetValueAt(config.InitialBlockNum)*3 + 1, false},
		{SwitchInterval.GetValueAt(config.InitialBlockNum) * 10, SwitchInterval.GetValueAt(config.InitialBlockNum) * 10, false},
		{SwitchInterval.GetValueAt(config.InitialBlockNum) * 10, SwitchInterval.GetValueAt(config.InitialBlockNum) - 1, true},
		{SwitchInterval.GetValueAt(config.InitialBlockNum) * 10, SwitchInterval.GetValueAt(config.InitialBlockNum) * 9, true},
	}

	for _, test := range isBoundaryTests {
		header := &types.Header{
			Nonce: types.EncodeNonce(uint64(test.headerNonce)),
		}
		if test.headerNonce < 0 {
			header = nil
		}
		parentHeader := &types.Header{
			Nonce: types.EncodeNonce(uint64(test.parentHeaderNonce)),
		}
		if test.parentHeaderNonce < 0 {
			parentHeader = nil
		}
		actual := IsBoundary(header, parentHeader)
		assert.Equal(test.expected, actual, "incorrect boundary")
	}
}
