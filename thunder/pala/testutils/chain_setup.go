package testutils

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager"
	oTestutils "github.com/ethereum/go-ethereum/thunder/thunderella/testutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/xerrors"
)

type ChainDataConfig struct {
	HighValueAddr common.Address
	HighValueKey  *ecdsa.PrivateKey
	LowValueAddr  common.Address
	LowValueKey   *ecdsa.PrivateKey
	RandomTPCAddr common.Address

	LowValueBalance               *big.Int
	ValuePerComm                  *big.Int
	StakeinValue                  *big.Int
	AdditionalStakeinForDirectBid *big.Int

	TxGas      uint64
	TxGasPrice *big.Int

	DefaultGas      uint64
	DefaultGasPrice int64
}

func GetDefaultChainDataConfig() *ChainDataConfig {
	return &ChainDataConfig{
		HighValueAddr: oTestutils.TestingAddr,
		HighValueKey:  oTestutils.TestingKey,
		LowValueAddr:  oTestutils.TestingLowValueAddr,
		LowValueKey:   oTestutils.TestingLowValueKey,
		RandomTPCAddr: chainconfig.RandomTPCAddress,

		// copied from LocalChainCommand.setup_chain_data
		LowValueBalance:               bigNum(1, 20),
		ValuePerComm:                  bigNum(1, 24),
		StakeinValue:                  bigNum(1, 18),
		AdditionalStakeinForDirectBid: bigNum(1, 18),

		TxGas:      uint64(50000000), // 50M
		TxGasPrice: bigNum(15, 9),    // 15gewi

		// copied from transfer.py
		DefaultGas:      uint64(2000000),
		DefaultGasPrice: int64(21000),
	}
}

type ChainDataDeployer struct {
	config               *ChainDataConfig
	wsHostname           string
	operators            []common.Address
	votingKeys           [][32]byte
	numOfVoters          int64
	timePerBlock         time.Duration
	additionalOperators  []common.Address
	additionalVotingKeys [][32]byte

	// initialized during every setup
	genesisAllocator *GenesisAllocator
	client           *ethclient.Client
}

func (c *ChainDataDeployer) GetOriginalVotingKeys() [][32]byte {
	return c.votingKeys
}

func (c *ChainDataDeployer) GetAdditionalVotingKeys() [][32]byte {
	return c.additionalVotingKeys
}

func (c *ChainDataDeployer) GetOriginalVotingOperators() []common.Address {
	return c.operators
}

func (c *ChainDataDeployer) GetAdditionalVotingOperators() []common.Address {
	return c.additionalOperators
}

func NewChainDataDeployer(config *ChainDataConfig, numOfVoters int, keymgr *keymanager.KeyManager, keyIds map[string][]string, wsHostname string, timePerBlock time.Duration) (*ChainDataDeployer, error) {
	operators := make([]common.Address, numOfVoters)
	votingKeyHashes := make([][32]byte, numOfVoters)
	for i := 0; i < numOfVoters; i++ {
		stakeinKey, err := keymgr.GetAccountKey(keyIds["accountKeyIds"][i], "", "", false)
		if err != nil {
			return nil, err
		}
		operators[i] = crypto.PubkeyToAddress(stakeinKey.PublicKey)

		votingKey, err := keymgr.GetCommPrivateVoteKey(keyIds["votingKeyIds"][i], "")
		if err != nil {
			return nil, err
		}
		votingKeyHashes[i] = sha256.Sum256(votingKey.GetPublicKey().ToBytes())
	}

	return &ChainDataDeployer{
		config:       config,
		wsHostname:   wsHostname,
		operators:    operators,
		votingKeys:   votingKeyHashes,
		numOfVoters:  int64(numOfVoters),
		timePerBlock: timePerBlock,
	}, nil
}

func (c *ChainDataDeployer) AddAdditionalStakeins(keymgr *keymanager.KeyManager, keyIds map[string][]string, numOfVoters int) error {
	// AdditionalStakins are used during transferToStakeinAccounts
	operators := make([]common.Address, numOfVoters)
	votingKeyHashes := make([][32]byte, numOfVoters)
	for i := 0; i < numOfVoters; i++ {
		stakeinKey, err := keymgr.GetAccountKey(keyIds["accountKeyIds"][i], "", "", false)
		if err != nil {
			return err
		}
		operators[i] = crypto.PubkeyToAddress(stakeinKey.PublicKey)

		votingKey, err := keymgr.GetCommPrivateVoteKey(keyIds["votingKeyIds"][i], "")
		if err != nil {
			return err
		}
		votingKeyHashes[i] = sha256.Sum256(votingKey.GetPublicKey().ToBytes())
	}
	c.additionalOperators = operators
	c.additionalVotingKeys = votingKeyHashes
	return nil
}

func (c *ChainDataDeployer) SetupVault() error {
	_, err := c.setupVault(false)
	return err
}

func (c *ChainDataDeployer) SetupDirectBid() error {
	_, err := c.setupDirectBid(false)
	return err
}

func (c *ChainDataDeployer) SetupVaultGenesis() (*core.Genesis, error) {
	return nil, xerrors.New("Not implemented")
}

func (c *ChainDataDeployer) SetupDirectBidGenesis() (*core.Genesis, error) {
	return c.setupDirectBid(true)
}

func (c *ChainDataDeployer) prepareClient(genesis bool) error {
	if genesis {
		c.genesisAllocator = NewGenesisAllocator()
	} else {
		client, err := ethclient.Dial(fmt.Sprintf("ws://%s", c.wsHostname))
		if err != nil {
			return err
		}
		c.client = client
	}
	return nil
}

func (c *ChainDataDeployer) cleanup(genesis bool) (*core.Genesis, error) {
	if genesis {
		g := core.DefaultThunderGenesisBlock()
		c.genesisAllocator.PopulateGenesis(g)
		return g, nil
	}
	return nil, nil
}

func (c *ChainDataDeployer) Close() {
	if c.client != nil {
		c.client.Close()
	}
}

func (c *ChainDataDeployer) setupVault(genesis bool) (*core.Genesis, error) {
	defer timeTrace(time.Now(), "preparing vault")
	if genesis {
		return nil, xerrors.New("Not implemented")
	}

	if err := c.prepareClient(genesis); err != nil {
		return nil, err
	}
	if err := c.transferRandomTPC(genesis); err != nil {
		return nil, err
	}
	if err := c.transferLowValueAccount(genesis); err != nil {
		return nil, err
	}
	if err := c.deployVault(genesis); err != nil {
		return nil, err
	}
	if err := c.transferToStakeinAccounts(genesis, c.config.LowValueKey, c.config.LowValueAddr, c.config.StakeinValue); err != nil {
		return nil, err
	}
	return c.cleanup(genesis)
}

func (c *ChainDataDeployer) setupDirectBid(genesis bool) (*core.Genesis, error) {
	defer timeTrace(time.Now(), "preparing direct bid")
	if err := c.prepareClient(genesis); err != nil {
		return nil, err
	}
	if err := c.transferRandomTPC(genesis); err != nil {
		return nil, err
	}
	if err := c.transferLowValueAccount(genesis); err != nil {
		return nil, err
	}
	dbStakeinValue := new(big.Int).Add(c.config.ValuePerComm, c.config.AdditionalStakeinForDirectBid)
	if err := c.transferToStakeinAccounts(genesis, c.config.HighValueKey, c.config.HighValueAddr, dbStakeinValue); err != nil {
		return nil, err
	}
	return c.cleanup(genesis)
}

func (c *ChainDataDeployer) transfer(genesis bool, fromKey *ecdsa.PrivateKey, fromAddr, toAddr common.Address, value *big.Int) error {
	if genesis {
		c.genesisAllocator.AddEntry(toAddr, value)
		c.genesisAllocator.AddEntry(fromAddr, new(big.Int).Neg(value))
		return nil
	}

	nonce, err := c.nonceAt(fromAddr)
	if err != nil {
		return err
	}
	tx := oTestutils.MakeTxact(fromKey, &toAddr, nonce, value, nil, nil)
	_, err = c.sendTx(tx)
	if err != nil {
		return err
	}
	return nil
}

func (c *ChainDataDeployer) transferRandomTPC(genesis bool) error {
	value := big.NewInt(1)
	return c.transfer(genesis, c.config.HighValueKey, c.config.HighValueAddr, c.config.RandomTPCAddr, value)
}

func (c *ChainDataDeployer) transferLowValueAccount(genesis bool) error {
	return c.transfer(genesis, c.config.HighValueKey, c.config.HighValueAddr, c.config.LowValueAddr, c.config.LowValueBalance)
}

func (c *ChainDataDeployer) nonceAt(addr common.Address) (uint64, error) {
	return c.client.NonceAt(context.Background(), addr, nil)
}

func (c *ChainDataDeployer) sendTx(tx *types.Transaction) (*types.Receipt, error) {
	err := c.client.SendTransaction(context.Background(), tx)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 20; i++ {
		r, err := c.client.TransactionReceipt(context.Background(), tx.Hash())
		if err != nil {
			time.Sleep(c.timePerBlock / 2)
			continue
		}
		return r, nil
	}
	return nil, xerrors.New("exceeded retry limit")
}

func (c *ChainDataDeployer) createBiddingAccountToVaultContract(voteKeyHash [32]byte, operator common.Address) error {
	// only called after VaultR2P5 hardfork
	method := "createAccount"

	n, err := c.nonceAt(c.config.HighValueAddr)
	if err != nil {
		return err
	}

	// function createAccount(address operator, bytes32 keyHash)
	data, err := thundervm.VaultR3ABI.Pack(method, operator, voteKeyHash)
	if err != nil {
		return xerrors.Errorf("faield to pack createAccount: %w", err)
	}

	// requires higher gas
	tx := types.NewTransaction(n, chainconfig.VaultTPCAddress, big.NewInt(0), c.config.TxGas, c.config.TxGasPrice, data)
	signer := types.NewEIP155Signer(params.ThunderChainConfig().ChainID)
	tx, err = types.SignTx(tx, signer, c.config.HighValueKey)
	if err != nil {
		return err
	}
	r, err := c.sendTx(tx)
	if err != nil {
		return err
	}
	if r.Status != 1 {
		return xerrors.New("Failed to createAccount with vault contract")
	}
	return nil
}

func (c *ChainDataDeployer) SetBiddingAmountToVaultContract(voteKeyHash [32]byte, amount *big.Int) error {
	// only called after VaultR2P5 hardfork
	method := "setBidAmount"

	n, err := c.nonceAt(c.config.HighValueAddr)
	if err != nil {
		return err
	}

	data, err := thundervm.VaultR3ABI.Pack(method, voteKeyHash, amount)
	if err != nil {
		return xerrors.Errorf("faield to pack setBiddingAmount: %w", err)
	}

	// requires higher gas
	tx := types.NewTransaction(n, chainconfig.VaultTPCAddress, big.NewInt(0), c.config.TxGas, c.config.TxGasPrice, data)
	signer := types.NewEIP155Signer(params.ThunderChainConfig().ChainID)
	tx, err = types.SignTx(tx, signer, c.config.HighValueKey)
	if err != nil {
		return err
	}
	r, err := c.sendTx(tx)
	if err != nil {
		return err
	}
	if r.Status != 1 {
		return xerrors.New("Failed to setBidAmount with vault contract")
	}
	return nil
}

func (c *ChainDataDeployer) depositToVaultContract(voteKeyHash [32]byte, amount *big.Int) error {
	// only called after VaultR2P5 hardfork
	method := "deposit"

	n, err := c.nonceAt(c.config.HighValueAddr)
	if err != nil {
		return err
	}

	data, err := thundervm.VaultR3ABI.Pack(method, voteKeyHash)
	if err != nil {
		return xerrors.Errorf("faield to pack setBiddingAmount: %w", err)
	}

	// requires higher gas
	tx := types.NewTransaction(n, chainconfig.VaultTPCAddress, amount, c.config.TxGas, c.config.TxGasPrice, data)
	signer := types.NewEIP155Signer(params.ThunderChainConfig().ChainID)
	tx, err = types.SignTx(tx, signer, c.config.HighValueKey)
	if err != nil {
		return err
	}
	r, err := c.sendTx(tx)
	if err != nil {
		return err
	}
	if r.Status != 1 {
		return xerrors.New("Failed to setBidAmount with vault contract")
	}
	return nil
}

func (c *ChainDataDeployer) GetAvailableBalanceFromVaultContract(voteKeyHash [32]byte) (*big.Int, error) {
	method := "getAvailableBalance"
	data, err := thundervm.VaultR3ABI.Pack(method, voteKeyHash)
	if err != nil {
		return nil, xerrors.Errorf("failed to pack VaultR3ABI getAvailableBalance: %w", err)
	}
	msg := ethereum.CallMsg{
		From: c.config.HighValueAddr,
		To:   &chainconfig.VaultTPCAddress,
		Data: data,
	}
	res, err := c.client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to call contract method '%s': %w", method, err)
	}
	availableStake := big.NewInt(0)
	availableStake.SetBytes(res)
	return availableStake, nil
}

func (c *ChainDataDeployer) GetBalanceFromVaultContract(voteKeyHash [32]byte) (*big.Int, error) {
	method := "getBalance"
	data, err := thundervm.VaultR3ABI.Pack(method, voteKeyHash)
	if err != nil {
		return nil, xerrors.Errorf("failed to pack VaultR3ABI getBalance: %w", err)
	}
	msg := ethereum.CallMsg{
		From: c.config.HighValueAddr,
		To:   &chainconfig.VaultTPCAddress,
		Data: data,
	}
	res, err := c.client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to call contract method '%s': %w", method, err)
	}
	balance := big.NewInt(0)
	balance.SetBytes(res)
	return balance, nil
}

func (c *ChainDataDeployer) GetBidAmountFromVaultContract(voteKeyHash [32]byte) (*big.Int, error) {
	method := "getBidAmount"
	data, err := thundervm.VaultR3ABI.Pack(method, voteKeyHash)
	if err != nil {
		return nil, xerrors.Errorf("failed to pack VaultR3ABI getBidAmount: %w", err)
	}
	msg := ethereum.CallMsg{
		From: c.config.HighValueAddr,
		To:   &chainconfig.VaultTPCAddress,
		Data: data,
	}
	res, err := c.client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to call contract method '%s': %w", method, err)
	}
	bidAmount := big.NewInt(0)
	bidAmount.SetBytes(res)
	return bidAmount, nil
}

func (c *ChainDataDeployer) deployVault(genesis bool) error {

	if len(c.votingKeys) != len(c.operators) {
		return xerrors.New("voter keys size is not the same as operations size")
	}

	if len(c.additionalVotingKeys) != len(c.additionalOperators) {
		return xerrors.New("additional voter keys size is not the same as additional operations size")
	}
	for idx := range c.votingKeys {
		keyHash := c.votingKeys[idx]
		operator := c.operators[idx]
		if err := c.createBiddingAccountToVaultContract(keyHash, operator); err != nil {
			return err
		}
		if err := c.depositToVaultContract(keyHash, c.config.ValuePerComm); err != nil {
			return err
		}
	}
	for idx := range c.additionalVotingKeys {
		keyHash := c.additionalVotingKeys[idx]
		operator := c.additionalOperators[idx]
		if err := c.createBiddingAccountToVaultContract(keyHash, operator); err != nil {
			return err
		}
		if err := c.depositToVaultContract(keyHash, c.config.ValuePerComm); err != nil {
			return err
		}
	}
	return nil
}

func (c *ChainDataDeployer) transferToStakeinAccounts(genesis bool, fromKey *ecdsa.PrivateKey, fromAddr common.Address, value *big.Int) error {
	operators := append(c.operators[:0:0], c.operators...)
	operators = append(operators, c.additionalOperators...)
	if genesis {
		for _, o := range operators {
			c.genesisAllocator.AddEntry(o, value)
		}
		totalStakein := new(big.Int).Mul(value, big.NewInt(c.numOfVoters))
		c.genesisAllocator.AddEntry(fromAddr, totalStakein.Neg(totalStakein))
		return nil
	}
	n, err := c.nonceAt(fromAddr)
	if err != nil {
		return err
	}
	wg := sync.WaitGroup{}
	errChan := make(chan error)
	for _, o := range operators {
		wg.Add(1)
		go func(addr common.Address, nonce uint64) {
			defer wg.Done()
			tx := oTestutils.MakeTxact(fromKey, &addr, nonce, value, nil, nil)
			_, err := c.sendTx(tx)
			if err != nil {
				select {
				case errChan <- err:
				default:
				}
			}
		}(o, n)
		n++
	}
	wg.Wait()
	select {
	case err := <-errChan:
		return err
	default:
		return nil
	}
}

// bigNum returns n * 10**zeros
func bigNum(n int64, zeros int64) *big.Int {
	v := big.NewInt(10)
	v = v.Exp(v, big.NewInt(zeros), nil)
	return v.Mul(v, big.NewInt(n))
}

// genesis related
type Account struct {
	Address common.Address
	Value   *big.Int
}

type GenesisAllocator struct {
	expenses []Account
}

func (g *GenesisAllocator) AddEntry(addr common.Address, value *big.Int) {
	g.expenses = append(g.expenses, Account{addr, new(big.Int).Set(value)})
}

func (g *GenesisAllocator) PopulateGenesis(genesis *core.Genesis) {
	alloc := genesis.Alloc
	for _, v := range g.expenses {
		if _, ok := alloc[v.Address]; ok {
			alloc[v.Address].Balance.Add(alloc[v.Address].Balance, v.Value)
		} else {
			alloc[v.Address] = core.GenesisAccount{Balance: v.Value}
		}
	}
}

func NewGenesisAllocator() *GenesisAllocator {
	return &GenesisAllocator{make([]Account, 0)}
}

func timeTrace(start time.Time, msg string) {
	fmt.Printf("Spent %s on %s\n", time.Since(start), msg)
}
