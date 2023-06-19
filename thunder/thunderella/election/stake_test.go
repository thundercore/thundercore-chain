package election

import (
	// Standard imports
	"math/big"
	"os"
	"reflect"
	"testing"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	config.InitThunderConfig("../../../config/thunderella_stake_config")
	code := m.Run()
	os.Exit(code)
}

func newStake(req *require.Assertions, StakingAddr common.Address, Stake *big.Int) *StakeInfo {
	k, err := bls.NewSigningKey()
	req.Equal(nil, err, "Got an error creating signing key: %s", err)

	return newStakeWithKey(StakingAddr, Stake, k.GetPublicKey())
}

func newStakeWithKey(StakingAddr common.Address, Stake *big.Int, pubKey *bls.PublicKey) *StakeInfo {
	return &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      new(big.Int).Set(Stake),
			PubVoteKey: pubKey,
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(20),
		},
		StakingAddr: StakingAddr,
		RefundID:    []byte{},
	}
}

//lint:ignore U1000 need to confirm this one
func testStake(require *require.Assertions, expected *StakeInfo, actual *StakeInfo) {
	if expected == nil {
		require.Nil(actual, "actual is not nil")
		// parsing failed as expected
		return
	}
	require.NotNilf(actual, "actual is nil")
	require.Equal(expected.Stake, actual.Stake, "Stake differerent %v %v", expected.Stake,
		actual.Stake)
	require.Equal(expected.PubVoteKey, actual.PubVoteKey, "PubVoteKey different")
	require.Equal(expected.StakingAddr, actual.StakingAddr, "StakingAddr differerent")
	require.Equal(expected.Coinbase, actual.Coinbase, "Coinbase differerent")
	require.True(reflect.DeepEqual(*expected, *actual), "Got differences")
}

func testStakeInfo(require *require.Assertions, expected *StakeInfo, actual *StakeInfo) {
	require.Equal(expected.Stake, actual.Stake, "Stake differerent")
	require.Equal(expected.PubVoteKey, actual.PubVoteKey, "PubVoteKey different")
	require.Equal(expected.StakingAddr, actual.StakingAddr, "StakingAddr differerent")
	require.Equal(expected.Coinbase, actual.Coinbase, "Coinbase differerent")
	require.Equal(expected.GasPrice, actual.GasPrice, "GasPrice differerent")
	require.Equal(expected.RefundID, actual.RefundID, "RefundID different")
	require.True(reflect.DeepEqual(*expected, *actual), "Got differences in persisted data")
}

func TestStakeInfoToBytes(t *testing.T) {
	require := require.New(t)
	si := newStake(require, common.HexToAddress("0x2"), big.NewInt(10))
	t.Logf("%v", si)

	buf := si.ToBytes()
	t.Logf("%v", buf)

	newSi := &StakeInfo{}
	err := newSi.FromBytes(buf)
	require.Equal(err, nil, "Got an error calling FromBytes: %s", err)
	t.Logf("%v", newSi)

	testStakeInfo(require, si, newSi)
}

func TestToMemberInfo(t *testing.T) {
	require := require.New(t)
	si := newStake(require, common.HexToAddress("0x2"), big.NewInt(10))
	t.Logf("%v", si)

	actual := si.ToMemberInfo()

	expected := &committee.MemberInfo{
		Stake:      si.Stake,
		PubVoteKey: si.PubVoteKey,
		Coinbase:   si.Coinbase,
		GasPrice:   si.GasPrice,
	}

	require.True(reflect.DeepEqual(*expected, *actual), "Got differences in MemberInfo")
}
