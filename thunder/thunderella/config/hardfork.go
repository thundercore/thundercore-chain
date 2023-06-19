package config

import (
	// Standard imports
	"bytes"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

type Hardfork struct {
	BlockNum chain.Seq
	Value    interface{}
}

type SessionHardfork struct {
	Session int64
	Value   interface{}
}

type SessionHardforks []SessionHardfork

func (s SessionHardforks) Len() int {
	return len(s)
}

func (s SessionHardforks) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s SessionHardforks) Less(i, j int) bool {
	return s[i].Session < s[j].Session
}

type HardforkConfig []Hardfork

func (h HardforkConfig) Len() int {
	return len(h)
}

func (h HardforkConfig) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h HardforkConfig) Less(i, j int) bool {
	return h[i].BlockNum < h[j].BlockNum
}

type rawConfig struct {
	configs []map[string]interface{}
}

var (
	hardforkConfigFile = "hardfork.yaml"

	// map of all hardfork configurations
	hardforkMap map[string]HardforkConfig
	sessionMap  map[string]SessionHardforks

	// map of description for configs
	hardforkDescMap = make(map[string]string)

	InitialBlockNum = chain.Seq(0)
)

type RequiredSettings struct {
	BlockGasLimit int64
}

type Setting struct {
	Key   string
	Value interface{}
}

type BlockNumSetting struct {
	Setting
	BlockNum chain.Seq
}

func NewBlockNumSetting(key string, value interface{}, blkNum chain.Seq) BlockNumSetting {
	return BlockNumSetting{Setting{key, value}, blkNum}
}

type SessionSetting struct {
	Setting
	Session int64
}

func NewSessionSetting(key string, value interface{}, s int64) SessionSetting {
	return SessionSetting{Setting{key, value}, s}
}

func setInitialHardforkSetting(key string, v interface{}) {
	hardforkMap[strings.ToLower(key)] = HardforkConfig{Hardfork{
		BlockNum: 0, Value: v}}
}

func setHardfork(settings RequiredSettings,
	bSettings []BlockNumSetting, sSettings []SessionSetting) {
	hardforkMap = make(map[string]HardforkConfig)
	sessionMap = make(map[string]SessionHardforks)

	setInitialHardforkSetting("protocol.BlockGasLimit", settings.BlockGasLimit)

	for _, b := range bSettings {
		k := strings.ToLower(b.Key)
		hardforkMap[k] = append(hardforkMap[k], Hardfork{BlockNum: b.BlockNum, Value: b.Value})
	}

	for _, s := range sSettings {
		k := strings.ToLower(s.Key)
		sessionMap[k] = append(sessionMap[k], SessionHardfork{Session: s.Session, Value: s.Value})
	}
}

// readHardfork populates the map from hardfork.yaml
func readHardfork(configPath string) {
	hardforkMap = make(map[string]HardforkConfig)
	sessionMap = make(map[string]SessionHardforks)

	configFileName := filepath.Join(configPath, "hardfork.yaml")
	content, err := ioutil.ReadFile(configFileName)

	if err != nil {
		if perr, ok := err.(*os.PathError); ok {
			if perr.Err == syscall.ENOENT {
				logger.Warn("Hardfork config file not found at %s", configFileName)
				return
			}
		}
		debug.Fatal("Cannot read hardfork config file. %v", err)
	}

	rawConf := &rawConfig{}
	yaml.Unmarshal(content, &rawConf.configs)

	// If default values of hardfork configs are missing
	if len(rawConf.configs) < 1 {
		// debug.Fatal("configs length %v", len(rawConf.configs))
		debug.Fatal("Need default config in %s",
			configFileName)
	}

	// Check hardfork_test.go for sample input hardfork.yaml
	for index, val := range rawConf.configs {
		block, hasNumber := val["blocknum"]
		session, hasSession := val["session"]
		if !hasNumber && !hasSession {
			debug.Fatal("No block number is defined in hardfork config, index %d", index)
		}

		// Get the blocknum and discard desc which is only for description purpose
		delete(val, "blocknum")
		delete(val, "desc")
		delete(val, "session")

		viperCfg := viper.New()
		viperCfg.SetConfigType("yaml")

		out, err := yaml.Marshal(val)
		if err != nil {
			debug.Fatal("Cannot marshal hardfork config, index %d", index)
		}
		viperCfg.ReadConfig(bytes.NewBuffer(out))

		if hasNumber {
			parseHardforkConfig(viperCfg, chain.Seq(getInt64Value(block)))
		}

		if hasSession {
			parseSessionConfig(viperCfg, getInt64Value(session))
		}

	}

	// Sort the hardfork history for each config variable by block number
	for key, hardforks := range hardforkMap {
		sort.Stable(hardforks)
		if hardforks[0].BlockNum != 0 {
			debug.Fatal("Hardfork config %s does not have default value! (please specify at blockNum 0)", key)
		}
	}

	logger.Note("Hardfork configuration is:\n%s", prettyPrintSettings(hardforkMap, 0))
	logger.Note("SessionHardfork configuration is:\n%s", prettyPrintSettings(sessionMap, 0))
}

func parseHardforkConfig(viperCfg *viper.Viper, blockNum chain.Seq) {
	for _, key := range viperCfg.AllKeys() {
		value := viperCfg.Get(key)
		hardforkMap[key] = append(hardforkMap[key], Hardfork{BlockNum: blockNum, Value: value})
	}
}

func parseSessionConfig(viperCfg *viper.Viper, session int64) {
	for _, key := range viperCfg.AllKeys() {
		value := viperCfg.Get(key)
		sessionMap[key] = append(sessionMap[key], SessionHardfork{Session: session, Value: value})
	}
}

// getHardforkValue get the value of hardfork based on block number
func getHardforkValue(hardforks HardforkConfig, block chain.Seq) (interface{}, bool) {
	if hardforks == nil {
		return nil, false
	}

	length := len(hardforks)
	if length == 0 {
		return nil, false
	}

	lower := sort.Search(length, func(i int) bool {
		return hardforks[i].BlockNum > block
	})

	return hardforks[lower-1].Value, true
}

func getSessionHardforkValue(hardforks SessionHardforks, session int64) (interface{}, bool) {
	if hardforks == nil {
		return nil, false
	}

	length := len(hardforks)
	if length == 0 {
		return nil, false
	}

	lower := sort.Search(length, func(i int) bool {
		return hardforks[i].Session > session
	})

	return hardforks[lower-1].Value, true
}

var hardforkMapMutex = sync.RWMutex{}
var sessionMapMutex = sync.RWMutex{}

// getValueAt get the value for either genesis config or hardfork config
func getValueAt(name string, block chain.Seq) (interface{}, bool) {
	// if the maps are not initialized
	// might happen in tests
	// Please do: config.InitThunderConfig("../../../config")
	//			  or: config.InitThunderConfig("../../../../config")
	// (depending on the directory level of the test package)
	// in TestMain(m *test.M)
	// to load hardfork.yaml in config directory

	// Get value from hardfork map
	hardforkMapMutex.RLock()
	defer hardforkMapMutex.RUnlock()

	if hardforkValue, found := getHardforkValue(hardforkMap[name], block); found {
		return hardforkValue, true
	}

	// If not found
	logger.Warn("hardforkMap: %v", hardforkMap)
	debug.Fatal("config '%s' is not a genesis/hardfork config", name)
	return nil, false
}

func getValueAtSession(name string, session int64) (interface{}, bool) {
	sessionMapMutex.RLock()
	defer sessionMapMutex.RUnlock()

	if hardforkValue, found := getSessionHardforkValue(sessionMap[name], session); found {
		return hardforkValue, true
	}

	// If not found
	logger.Warn("hardforkMap: %v", hardforkMap)
	debug.Fatal("config '%s' is not a genesis/hardfork config", name)
	return nil, false
}

// getEnabledBlockNum(name) returns the block number where `name` is set in `hardforkMap[name]`
// assuming `name` is either never set or only set once.
// TODO: validate `name` is set at most once at hardfork.yaml parse time
func getEnabledBlockNum(name string) chain.Seq {
	for _, h := range hardforkMap[name] {
		if h.Value.(bool) == true {
			return h.BlockNum
		}
	}
	return -1
}

// getEnabledSession(name) returns the session where `name` is set in `sessionMap[name]`
// assuming `name` is either never set or only set once.
// TODO: validate `name` is set at most once at hardfork.yaml parse time
func getEnabledSession(name string) int64 {
	for _, s := range sessionMap[name] {
		if s.Value.(bool) == true {
			return s.Session
		}
	}
	return -1
}

//======================================
//    Exported functions for testing
// (Should only be called in unit test)
//======================================
// To Use:
//   SetTestValueAt should only be called in unit tests.
func setTestValueAt(name string, value interface{}, blockNum chain.Seq) {
	utils.EnsureRunningInTestCode()

	hardforkMapMutex.Lock()
	defer hardforkMapMutex.Unlock()

	logger.Info("setTestValueAt(%s, %v, %v)", name, value, blockNum)

	// If maps has not been initialized in test
	// refer to comments in getValueAt(blockNum)
	config, found := hardforkMap[name]
	if found {
		logger.Info("config %s found, old value: %v", name, config)
		for i, hardfork := range config {
			if hardfork.BlockNum == blockNum {
				config[i].Value = value
				logger.Info("config %s found, new value: %v", name, hardforkMap[name])
				return
			}
		}
	}

	hardforkMap[name] = append(hardforkMap[name], Hardfork{BlockNum: blockNum, Value: value})
	sort.Stable(hardforkMap[name])
}

func setTestValueAtSession(name string, value interface{}, session int64) {
	utils.EnsureRunningInTestCode()

	sessionMapMutex.Lock()
	defer sessionMapMutex.Unlock()

	logger.Info("setTestValueAtSession(%s, %v, %v)", name, value, session)

	config, found := sessionMap[name]
	if found {
		s := sort.Search(len(config), func(i int) bool { return config[i].Session >= session })
		if s < len(config) && config[s].Session == session {
			config[s].Value = value
			return
		}
	}

	sessionMap[name] = append(sessionMap[name], SessionHardfork{Session: session, Value: value})
	sort.Sort(sessionMap[name])
}

//======================================
//      Hardfork configs Interfaces
//======================================

type baseHardforkConfig struct {
	_name       string
	_prettyName string
}

func newBaseHardforkConfig(name string, desc string) *baseHardforkConfig {
	b := baseHardforkConfig{
		_name:       strings.ToLower(name),
		_prettyName: name,
	}
	hardforkDescMap[strings.ToLower(name)] = desc
	return &b
}

func (c *baseHardforkConfig) name() string {
	return c._name
}

// int64 configuration type
type Int64HardforkConfig struct {
	baseHardforkConfig
}

func NewInt64HardforkConfig(name string, desc string) *Int64HardforkConfig {
	c := &Int64HardforkConfig{
		baseHardforkConfig: *newBaseHardforkConfig(name, desc),
	}
	return c
}

func (c *Int64HardforkConfig) GetValueAt(block chain.Seq) int64 {
	if value, found := getValueAt(c.name(), block); found {
		return getInt64Value(value)
	}
	return -1
}

func (c *Int64HardforkConfig) GetValueAtSession(session int64) int64 {
	if value, found := getValueAtSession(c.name(), session); found {
		return getInt64Value(value)
	}

	return -1
}

func (c *Int64HardforkConfig) GetValueAtU64(block chain.Seq) uint64 {
	return uint64(c.GetValueAt(block))
}

func (c *Int64HardforkConfig) SetTestValueAt(value int64, block chain.Seq) {
	setTestValueAt(c.name(), value, block)
}

func (c *Int64HardforkConfig) SetTestValueAtSession(value int64, session int64) {
	setTestValueAtSession(c.name(), value, session)
}

// float 64 configuration type
type Float64HardforkConfig struct {
	baseHardforkConfig
}

func NewFloat64HardforkConfig(name string, desc string) *Float64HardforkConfig {
	c := &Float64HardforkConfig{
		baseHardforkConfig: *newBaseHardforkConfig(name, desc),
	}
	return c
}

func (c *Float64HardforkConfig) GetValueAt(block chain.Seq) float64 {
	if value, found := getValueAt(c.name(), block); found {
		return value.(float64)
	}
	return -1
}

func (c *Float64HardforkConfig) GetValueAtSession(session int64) float64 {
	if value, found := getValueAtSession(c.name(), session); found {
		return value.(float64)
	}

	return -1
}

type HardforkMapBackuper struct {
	backupMap map[string]HardforkConfig
}

func (c *HardforkMapBackuper) Backup() {
	c.backupMap = make(map[string]HardforkConfig)
	for k, v := range hardforkMap {
		b := make([]Hardfork, len(v))
		copy(b, v)
		c.backupMap[k] = b
	}
}

func (c *HardforkMapBackuper) Restore() {
	for k, v := range c.backupMap {
		hardforkMap[k] = v
	}
}

func DumpHardforkConfigMap() {
	for k, v := range hardforkMap {
		fmt.Printf("%v %v\n", k, v)
	}
}

// bool configuration type
type BoolHardforkConfig struct {
	baseHardforkConfig
}

func NewBoolHardforkConfig(name string, desc string) *BoolHardforkConfig {
	c := &BoolHardforkConfig{
		baseHardforkConfig: *newBaseHardforkConfig(name, desc),
	}
	return c
}

func (c *BoolHardforkConfig) GetValueAt(block chain.Seq) bool {
	if value, found := getValueAt(c.name(), block); found {
		return value.(bool)
	}
	return false
}

func (c *BoolHardforkConfig) GetValueAtSession(session int64) bool {
	if value, found := getValueAtSession(c.name(), session); found {
		return value.(bool)
	}

	return false
}

// TODO: use new type for PalaHardfork instead of BoolHardforkConfig
func (c *BoolHardforkConfig) GetEnabledBlockNum() chain.Seq {
	return getEnabledBlockNum(c.name())
}

func (c *BoolHardforkConfig) GetEnabledSession() int64 {
	return getEnabledSession(c.name())
}

func (c *BoolHardforkConfig) SetTestValueAt(value bool, block chain.Seq) {
	setTestValueAt(c.name(), value, block)
}

func (c *BoolHardforkConfig) SetTestValueAtSession(value bool, session int64) {
	setTestValueAtSession(c.name(), value, session)
}

// string configuration type
type StringHardforkConfig struct {
	baseHardforkConfig
}

func NewStringHardforkConfig(name string, desc string) *StringHardforkConfig {
	c := &StringHardforkConfig{
		baseHardforkConfig: *newBaseHardforkConfig(name, desc),
	}
	return c
}

func (c *StringHardforkConfig) SetTestValueAt(value string, block chain.Seq) {
	setTestValueAt(c.name(), value, block)
}

func (c *StringHardforkConfig) SetTestValueAtSession(value string, session int64) {
	setTestValueAtSession(c.name(), value, session)
}

func (c *StringHardforkConfig) GetValueAt(block chain.Seq) string {
	if value, found := getValueAt(c.name(), block); found {
		return value.(string)
	}
	return ""
}

func (c *StringHardforkConfig) GetValueAtSession(session int64) string {
	if value, found := getValueAtSession(c.name(), session); found {
		return value.(string)
	}

	return ""
}

// big.Int configuration type
type BigIntHardforkConfig struct {
	baseHardforkConfig
}

func NewBigIntHardforkConfig(name string, desc string) *BigIntHardforkConfig {
	c := &BigIntHardforkConfig{
		baseHardforkConfig: *newBaseHardforkConfig(name, desc),
	}
	return c
}

func (c *BigIntHardforkConfig) GetValueAt(block chain.Seq) *big.Int {
	if value, found := getValueAt(c.name(), block); found {
		// 	logger.Info("type of value of %s: %t", c.name(), value)
		bi, err := SimpleScientificBigIntParse(cast.ToString(value))
		if err != nil {
			debug.Fatal("Cannot get big Int value at block %d. %v", block, err)
		}
		return bi
	}
	bi, _ := SimpleScientificBigIntParse("-1")
	return bi
}

func (c *BigIntHardforkConfig) GetValueAtSession(session int64) *big.Int {
	if value, found := getValueAtSession(c.name(), session); found {
		bi, err := SimpleScientificBigIntParse(cast.ToString(value))
		if err != nil {
			debug.Fatal("Cannot get big Int value at block %d. %v", session, err)
		}
		return bi
	}

	bi, _ := SimpleScientificBigIntParse("-1")
	return bi
}

func (c *BigIntHardforkConfig) SetTestValueAt(value *big.Int, block chain.Seq) {
	setTestValueAt(c.name(), new(big.Int).Set(value), block)
}

func (c *BigIntHardforkConfig) SetTestValueAtSession(value *big.Int, session int64) {
	setTestValueAtSession(c.name(), new(big.Int).Set(value), session)
}

func (c *BigIntHardforkConfig) String() string {
	return fmt.Sprintf("hardfork %s: %v", c.name(), sessionMap[c.name()])
}

// time.Duration configuration type
type AddressHardforkConfig struct {
	baseHardforkConfig
}

func NewAddressHardforkConfig(name string, desc string) *AddressHardforkConfig {
	c := &AddressHardforkConfig{
		baseHardforkConfig: *newBaseHardforkConfig(name, desc),
	}
	return c
}

func (c *AddressHardforkConfig) GetValueAt(block chain.Seq) common.Address {
	if value, found := getValueAt(c.name(), block); found {
		return common.HexToAddress(cast.ToString(value))
	}
	return common.HexToAddress("0")
}

func (c *AddressHardforkConfig) getValueAtSession(session int64) common.Address {
	if value, found := getValueAtSession(c.name(), session); found {
		return common.HexToAddress(cast.ToString(value))
	}
	return common.HexToAddress("0")
}

//=====================================
//      Hardfork configs debugCLI
//=====================================

// format for printing
func getPrettyHardforkLeaf() string {
	prettyHardforkLeaf := "%%-%ds %%s"
	for hardforkParamName := range hardforkMap {
		if len(hardforkParamName) > longestKey {
			longestKey = len(hardforkParamName)
		}
	}
	return fmt.Sprintf(prettyHardforkLeaf, longestKey)
}

// print all hardfork configuration parameters
// grouped by name, in the order of block num
func printHardforkConfigByName() (string, error) {
	var list []string
	var prettyString string
	prettyHardforkLeaf := getPrettyHardforkLeaf()
	for name, hardforkCfg := range hardforkMap {
		prettyString = fmt.Sprintf(
			prettyHardforkLeaf, name,
			": "+hardforkDescMap[name]+"\n")
		var sublist []string
		for _, hardfork := range hardforkCfg {
			sublist = append(sublist,
				fmt.Sprintf("        Block %-20d - %v",
					hardfork.BlockNum, hardfork.Value))
		}
		prettyString += strings.Join(sublist, "\r\n")
		list = append(list, prettyString)
	}

	for name, hardforkCfg := range sessionMap {
		prettyString = fmt.Sprintf(
			prettyHardforkLeaf, name,
			": "+hardforkDescMap[name]+"\n")
		var sublist []string
		for _, hardfork := range hardforkCfg {
			sublist = append(sublist,
				fmt.Sprintf("        Session %-20d - %v",
					hardfork.Session, hardfork.Value))
		}
		prettyString += strings.Join(sublist, "\r\n")
		list = append(list, prettyString)
	}
	sort.Strings(list)
	output := strings.Join(list, "\r\n")
	return output, nil
}

// print all hardfork configuration parameters
// grouped by blockNum
func printHardforkConfigByBlockNum() (string, error) {
	var blockNums []chain.Seq
	type snapshotItem struct {
		Name  string
		Value interface{}
	}
	type hardforkSnapshot = []snapshotItem
	hfMapByBlockNum := make(map[chain.Seq]*hardforkSnapshot)
	for name, hardforkCfg := range hardforkMap {
		for _, hardfork := range hardforkCfg {
			si := &snapshotItem{}
			si.Name = name
			si.Value = hardfork.Value
			snapshot, found := hfMapByBlockNum[hardfork.BlockNum]
			if found {
				*snapshot = append(*snapshot, *si)
			} else {
				blockNums = append(blockNums, hardfork.BlockNum)
				currConfig := &hardforkSnapshot{}
				*currConfig = append(*currConfig, *si)
				hfMapByBlockNum[hardfork.BlockNum] = currConfig
			}
		}
	}
	// sort the hardfork history by block num
	sort.SliceStable(blockNums, func(i, j int) bool {
		return blockNums[i] < blockNums[j]
	})
	// generate the pretty print string
	var list []string
	prettyHardforkLeaf := getPrettyHardforkLeaf()
	for _, blockNum := range blockNums {
		list = append(list, fmt.Sprintf(
			prettyHardforkLeaf, fmt.Sprintf("Block %d", blockNum), ""))
		var sublist []string
		for _, snapshotItem := range *hfMapByBlockNum[blockNum] {
			sublist = append(sublist, fmt.Sprintf(prettyHardforkLeaf,
				"        "+snapshotItem.Name, fmt.Sprintf(" : %v",
					snapshotItem.Value)))
		}
		sort.Strings(sublist)
		list = append(list, sublist...)
	}
	output := strings.Join(list, "\r\n")
	return output, nil
}
