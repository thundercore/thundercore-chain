package chainconfig

import (

	// Standard imports
	"crypto/sha256"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
)

var (
	TestnetSecureAddr = common.HexToAddress("0xb1C8bD0db1ED341303f2346Ad3Fcd8Bc53BB086E")
	TestnetTxnFeeAddr = common.HexToAddress("0xc4F3c85Bb93F33A485344959CF03002B63D7c4E3")

	// This is a testing address.
	TestnetTestingAddr = common.HexToAddress("0x9A78d67096bA0c7C1bCdc0a8742649Bc399119c0")

	// This is a testing address.
	TestnetLowValueAddr = common.HexToAddress("0xCD1191CAe116bDCBB24657c15C10aDfdb506aD85")

	// The testing address for Web3JS tests. Do not use it in Go tests.
	// This is required to run tests in parallel. See Thunder-444.
	TestnetTestingWeb3JSAddr = common.HexToAddress("0xbb8718be30d331a9d98e74c0fe92391dc2b437c3")

	// The testing address for TxStress tests. Do not use it in Go tests except txstress.
	// This is required to run tests in parallel. See Thunder-444.
	TestnetTestingTxStressAddr = common.HexToAddress("0x4bc87b58cfd96a4627a76c3da5a8a26486ee7fc9")

	// This is a testing Thunder Foundation address.
	// This use to be 0x6519d6Dfd11363CF0821809b919B55F794fe0cb5 but we changed it.
	TestnetThunderFoundationAddr = common.HexToAddress("0x0000000000000000000000000000001234567989")

	// GenesisConfigPath is the file that contains Genesis block config
	GenesisConfigPath = config.NewStringConfig("chain.genesisConfig",
		"Genesis Config file path", "", false, nil)

	commElectionTPCHash = sha256.Sum256([]byte("Thunder_CommitteeElection"))
	// CommElectionTPCAddress is 0x30d87bd4D1769437880c64A543bB649a693EB348
	CommElectionTPCAddress = common.BytesToAddress(commElectionTPCHash[:20])

	vaultTPCHash = sha256.Sum256([]byte("Thunder_Vault"))
	// VaultTPCAddress is 0xEC45c94322EaFEEB2Cf441Cd1aB9e81E58901a08
	VaultTPCAddress = common.BytesToAddress(vaultTPCHash[:20])

	randomTPCHash = sha256.Sum256([]byte("Thunder_Random"))
	// RandomTPCAddress is 0x8cC9C2e145d3AA946502964B1B69CE3cD066A9C7
	RandomTPCAddress = common.BytesToAddress(randomTPCHash[:20])

	blockSnTPCHash = sha256.Sum256([]byte("Thunder_BlockSn"))
	// BlockSnTPCAddress is 0xd5891E5D906480f4215c78778B9FCEc909B04235
	BlockSnTPCAddress = common.BytesToAddress(blockSnTPCHash[:20])
)

const (
	// MainnetChainID is Mainnet's chain ID, which equals to network ID now.
	MainnetChainID = 108
	// TestnetChainID is Testnet's chain ID, which equals to network ID now.
	TestnetChainID = 19
)

var (
	chainId = int64(TestnetChainID)
)

// TODO(scottt): better way to reconcile:
// 1. chainId and other chain parameters in config file (Thunder's preferred style)
// 2. chainConfig hard-coded constants (go-ethereum's)

func SetChainId(id int64) {
	chainId = id
}

func ChainID() int64 {
	return chainId
}
