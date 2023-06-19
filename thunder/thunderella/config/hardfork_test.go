package config

import (
	// Standard imports
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cast"
	"github.com/stretchr/testify/require"
)

var (
	yamlData = `
- blocknum: 0
  desc: "default value"
  accel:
      paramfoo: 1
  fullnode:
      parambar: "orange"
  committee:
      AuctionStakeThreshold: "5000000000"
  vault:
      burnReward: true
  bidder:
      rewardAddress: "0x0"
  auxnet:
      parambaz: "canada"

- blocknum: 100
  desc: "hardfork alpha"
  accel:
      paramfoo: 50
  fullnode:
      parambar: "apple"
  committee:
      AuctionStakeThreshold: "500000000000000000000000"

- blocknum: 200
  desc: "hardfork beta"
  accel:
      paramfoo: 80
  fullnode:
      parambar: "banana"
  committee:
      AuctionStakeThreshold: "5000000000000000000000000"
  vault:
      burnReward: false
  bidder:
      rewardAddress: "0x7956dAAe22AE04d47B8116C0C3a577a31D9673aE"

- blocknum: 77777777777
  desc: "hardfork gamma"
  accel:
      paramfoo: 150
  auxnet:
      parambaz: "mercury"
`

	yamlDataWithoutDefault = `
- blocknum: -1
  desc: "genesis"
  accel:
    paramcat: false

- blocknum: 100
  desc: "hardfork alpha"
  accel:
    paramfoo: 50
`

	origBigValue, _ = big.NewInt(0).SetString("5000000000", 10)
	oldBigValue, _  = big.NewInt(0).SetString("500000000000000000000000", 10)
	newBigValue, _  = big.NewInt(0).SetString("5000000000000000000000000", 10)
)

// For unit tests to setup temporary hardfork.yaml
func HardforkConfigTestFileSetup(t *testing.T, data []byte) (tmpDir string) {
	tmpDir, err := ioutil.TempDir("", "hardfork")
	if err != nil {
		t.Fatal("can't create temporary dir")
	}
	fileName := filepath.Join(tmpDir, hardforkConfigFile)

	if err = ioutil.WriteFile(fileName, data, 0644); err != nil {
		t.Fatal("can't create temporary hardfork config yaml file")
	}

	return tmpDir
}

func TestNoHardforkConfig(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "hardfork")
	if err != nil {
		t.Fatal("can't create temporary dir")
	}
	defer os.RemoveAll(tmpDir)

	require.NotPanics(t, func() { readHardfork(tmpDir) })
}

//=========================================================================
// Should panic if:
//	1. No genesis / default config provided in hardfork.yaml (testcase 1,2)
//	2. Genesis configs are rewritten in later hardforks
//=========================================================================
func TestInvalidHardforkConfig(t *testing.T) {

	tmpDir2 := HardforkConfigTestFileSetup(t, []byte(yamlDataWithoutDefault))
	defer os.RemoveAll(tmpDir2)

	// readHardfork(tmpDir2)
	require.Panics(t, func() { readHardfork(tmpDir2) })

}

func TestInitGenesisAndHardforkConfig(t *testing.T) {

	tmpDir := HardforkConfigTestFileSetup(t, []byte(yamlData))
	defer os.RemoveAll(tmpDir)

	readHardfork(tmpDir)

	var keys []string
	for _, v := range reflect.ValueOf(hardforkMap).MapKeys() {
		keys = append(keys, v.String())
	}

	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	require.Equal(t,
		[]string{"accel.paramfoo",
			"auxnet.parambaz",
			"bidder.rewardaddress",
			"committee.auctionstakethreshold",
			"fullnode.parambar",
			"vault.burnreward",
		},
		keys)
}

func TestInternalGetValueAt(t *testing.T) {
	tmpDir := HardforkConfigTestFileSetup(t, []byte(yamlData))
	defer os.RemoveAll(tmpDir)

	readHardfork(tmpDir)

	tests := []struct {
		key   string
		attrs []struct {
			blockNum chain.Seq
			found    bool
			value    interface{}
		}
	}{
		{
			key: "accel.paramfoo",
			attrs: []struct {
				blockNum chain.Seq
				found    bool
				value    interface{}
			}{
				{99, true, 1},
				{100, true, 50},
				{101, true, 50},
				{199, true, 50},
				{200, true, 80},
				{77777777777, true, 150},
			},
		},
		{
			key: "auxnet.parambaz",
			attrs: []struct {
				blockNum chain.Seq
				found    bool
				value    interface{}
			}{
				{99, true, "canada"},
				{77777777776, true, "canada"},
				{77777777777, true, "mercury"},
			},
		},
		{
			key: "fullnode.parambar",
			attrs: []struct {
				blockNum chain.Seq
				found    bool
				value    interface{}
			}{
				{99, true, "orange"},
				{100, true, "apple"},
				{101, true, "apple"},
				{199, true, "apple"},
				{200, true, "banana"},
				{100000, true, "banana"},
			},
		},
	}

	for _, tt := range tests {
		for _, attr := range tt.attrs {
			result, found := getValueAt(tt.key, attr.blockNum)
			require.Equal(t, attr.found, found)
			if attr.found {
				require.Equal(t, attr.value, result)
			}
		}
	}

	bigIntTests := []struct {
		blockNum chain.Seq
		found    bool
		value    interface{}
	}{
		{99, true, origBigValue},
		{100, true, oldBigValue},
		{101, true, oldBigValue},
		{199, true, oldBigValue},
		{200, true, newBigValue},
		{77777777777, true, newBigValue},
	}
	hardforkCfgs := hardforkMap["committee.auctionstakethreshold"]
	for _, tt := range bigIntTests {
		result, found := getHardforkValue(hardforkCfgs, tt.blockNum)
		require.Equal(t, tt.found, found)
		if tt.found {
			bi, err := SimpleScientificBigIntParse(cast.ToString(result))
			require.NoError(t, err)
			require.Equal(t, tt.value, bi)
		}

	}
}

func TestGetInt64HardforkConfig(t *testing.T) {
	tmpDir := HardforkConfigTestFileSetup(t, []byte(yamlData))
	defer os.RemoveAll(tmpDir)

	ResetThunderConfig()
	c1 := NewInt64HardforkConfig("accel.paramfoo", "")
	c2 := NewInt64Config("foo.bar", "", 1, false, nil)
	InitThunderConfig(tmpDir)

	require.Equal(t, int64(1), c2.Get())

	tests := []struct {
		blockNum      chain.Seq
		signedValue   int64
		unsignedValue uint64
	}{
		{99, int64(1), uint64(1)},
		{100, int64(50), uint64(50)},
		{101, int64(50), uint64(50)},
		{199, int64(50), uint64(50)},
		{200, int64(80), uint64(80)},
		{1000, int64(80), uint64(80)},
		{77777777777, int64(150), uint64(150)},
	}

	for _, tt := range tests {
		require.Equal(t, tt.signedValue, c1.GetValueAt(tt.blockNum))
		require.Equal(t, tt.unsignedValue, c1.GetValueAtU64(tt.blockNum))
	}
}

func TestGetStringHardforkConfig(t *testing.T) {
	tmpDir := HardforkConfigTestFileSetup(t, []byte(yamlData))
	defer os.RemoveAll(tmpDir)

	ResetThunderConfig()
	c1 := NewStringHardforkConfig("fullnode.parambar", "")
	c2 := NewStringConfig("foo.bar", "", "orange", false, nil)
	InitThunderConfig(tmpDir)

	require.Equal(t, "orange", c2.Get())

	tests := []struct {
		blockNum chain.Seq
		value    string
	}{
		{99, "orange"},
		{100, "apple"},
		{101, "apple"},
		{199, "apple"},
		{200, "banana"},
		{77777777777, "banana"},
	}

	for _, tt := range tests {
		require.Equal(t, tt.value, c1.GetValueAt(tt.blockNum))
	}
}

func TestGetBoolHardforkConfig(t *testing.T) {
	tmpDir := HardforkConfigTestFileSetup(t, []byte(yamlData))
	defer os.RemoveAll(tmpDir)

	ResetThunderConfig()
	c1 := NewBoolHardforkConfig("vault.burnreward", "")
	c2 := NewBoolConfig("foo.bar", "", false, false, nil)
	InitThunderConfig(tmpDir)

	require.Equal(t, false, c2.Get())

	tests := []struct {
		blockNum chain.Seq
		value    bool
	}{
		{99, true},
		{100, true},
		{101, true},
		{199, true},
		{200, false},
		{77777777777, false},
	}

	for _, tt := range tests {
		require.Equal(t, tt.value, c1.GetValueAt(tt.blockNum))
	}
}

func TestGetBigIntHardforkConfig(t *testing.T) {
	tmpDir := HardforkConfigTestFileSetup(t, []byte(yamlData))
	defer os.RemoveAll(tmpDir)

	ResetThunderConfig()
	c1 := NewBigIntHardforkConfig("committee.auctionstakethreshold", "")
	c2 := NewBigIntConfig("foo.bar", "", origBigValue, false, nil)
	InitThunderConfig(tmpDir)

	require.Equal(t, origBigValue, c2.Get())

	tests := []struct {
		blockNum chain.Seq
		value    *big.Int
	}{
		{99, origBigValue},
		{100, oldBigValue},
		{101, oldBigValue},
		{199, oldBigValue},
		{200, newBigValue},
		{77777777777, newBigValue},
	}

	for _, tt := range tests {
		require.Equal(t, tt.value, c1.GetValueAt(tt.blockNum))
	}
}

func TestGetAddressHardforkConfig(t *testing.T) {
	tmpDir := HardforkConfigTestFileSetup(t, []byte(yamlData))
	defer os.RemoveAll(tmpDir)

	ResetThunderConfig()
	origAddr := common.Address{}
	newAddr := common.HexToAddress("0x7956dAAe22AE04d47B8116C0C3a577a31D9673aE")

	c1 := NewAddressHardforkConfig("bidder.rewardaddress", "")
	c2 := NewAddressConfig("foo.bar", "", origAddr, false, nil)
	InitThunderConfig(tmpDir)

	require.Equal(t, origAddr, c2.Get())

	tests := []struct {
		blockNum chain.Seq
		value    common.Address
	}{
		{99, origAddr},
		{100, origAddr},
		{101, origAddr},
		{199, origAddr},
		{200, newAddr},
		{77777777777, newAddr},
	}

	for _, tt := range tests {
		require.Equal(t, tt.value, c1.GetValueAt(tt.blockNum))
	}
}

func getYamlData(strs ...string) []byte {
	var sb strings.Builder
	for _, str := range strs {
		sb.WriteString(str)
	}
	return []byte(sb.String())
}

type TestAttr struct {
	blockNum chain.Seq
	found    bool
	value    interface{}
}
type TestStruct struct {
	key       string
	isSession bool
	attrs     []TestAttr
}

func runTest(t *testing.T, yamlData []byte, tests []TestStruct, negTest bool) {
	tmpDir := HardforkConfigTestFileSetup(t, yamlData)
	fmt.Println(string(yamlData))
	defer os.RemoveAll(tmpDir)

	if negTest {
		require.Panics(t, func() { readHardfork(tmpDir) })
	} else {
		readHardfork(tmpDir)
	}

	for _, tt := range tests {
		key := strings.ToLower(tt.key)
		if tt.isSession {
			sessionHardforkCfgs := sessionMap[key]
			t.Log(sessionHardforkCfgs)
			for _, attr := range tt.attrs {
				result, found := getSessionHardforkValue(sessionHardforkCfgs, int64(attr.blockNum))
				t.Log(key, attr.blockNum, attr.found, attr.value, " Expect:", found, result)
				require.Equal(t, attr.found, found)
				if attr.found {
					require.Equal(t, attr.value, result)
				}
			}
		} else {
			hardforkCfgs := hardforkMap[key]
			t.Log(hardforkCfgs)
			for _, attr := range tt.attrs {
				result, found := getHardforkValue(hardforkCfgs, attr.blockNum)
				t.Log(key, attr.blockNum, attr.found, attr.value, " Expect:", found, result)
				require.Equal(t, attr.found, found)
				if attr.found {
					require.Equal(t, attr.value, result)
				}
			}
		}
	}
}

func TestOneBlockOneParam(t *testing.T) {
	yamlData := `
- blocknum: 0
  desc: "default value"
  accel:
      para1: 5

- blocknum: 100
  desc: "hardfork 100"
  accel:
      para1: 50
`
	tests := []TestStruct{
		{
			key: "accel.para1",
			attrs: []TestAttr{
				{99, true, 5},
				{100, true, 50},
				{101, true, 50},
			},
		},
	}
	runTest(t, getYamlData(yamlData), tests, false)
}

func TestOneBlockTwoParam(t *testing.T) {
	yamlData := `
- blocknum: 0
  desc: "default value"
  accel:
      para1: 5
  comm:
      para1: 5

- blocknum: 100
  desc: "hardfork 100"
  accel:
      para1: 50
  comm:
      para1: 50
`
	tests := []TestStruct{
		{
			key: "accel.para1",
			attrs: []TestAttr{
				{99, true, 5},
				{100, true, 50},
				{101, true, 50},
			},
		},
		{
			key: "comm.para1",
			attrs: []TestAttr{
				{99, true, 5},
				{100, true, 50},
				{101, true, 50},
			},
		},
	}
	runTest(t, getYamlData(yamlData), tests, false)
}

func TestTwoBlockFourParam(t *testing.T) {
	yamlData := `
- blocknum: 0
  desc: "default value"
  accel:
      para1: 5
  comm:
      para1: 5
  full:
      para1: 5
  auxnet:
      para1: 5

- blocknum: 100
  desc: "hardfork 100"
  accel:
      para1: 50
  comm:
      para1: 50

- blocknum: 200
  desc: "hardfork 200"
  full:
      para1: 55
  auxnet:
      para1: 55
`
	tests := []TestStruct{
		{
			key: "accel.para1",
			attrs: []TestAttr{
				{99, true, 5},
				{100, true, 50},
				{101, true, 50},
			},
		},
		{
			key: "comm.para1",
			attrs: []TestAttr{
				{99, true, 5},
				{100, true, 50},
				{101, true, 50},
			},
		},
		{
			key: "full.para1",
			attrs: []TestAttr{
				{99, true, 5},
				{100, true, 5},
				{101, true, 5},
				{199, true, 5},
				{200, true, 55},
				{201, true, 55},
			},
		},
		{
			key: "auxnet.para1",
			attrs: []TestAttr{
				{99, true, 5},
				{100, true, 5},
				{101, true, 5},
				{199, true, 5},
				{200, true, 55},
				{201, true, 55},
			},
		},
	}
	runTest(t, getYamlData(yamlData), tests, false)
}

func TestThreeBlockFourParam(t *testing.T) {
	yamlData := `
- blocknum: 0
  desc: "default value"
  accel:
      para1: 5
  comm:
      para1: false
  full:
      para1: 5
  auxnet:
      para1: 5

- blocknum: 100
  desc: "hardfork 100"
  accel:
      para1: 100
  comm:
      para1: true
  full:
      para1: 100
  auxnet:
      para1: 100

- blocknum: 200
  desc: "hardfork 200"
  accel:
      para1: 200
  comm:
      para1: false
  full:
      para1: 200
  auxnet:
      para1: 200

- blocknum: 99999999999999999
  desc: "hardfork 99999999999999999"
  accel:
      para1: 300
  comm:
      para1: true
  full:
      para1: 300
  auxnet:
      para1: 300
`
	tests := []TestStruct{
		{
			key: "accel.para1",
			attrs: []TestAttr{
				{99, true, 5},
				{100, true, 100},
				{101, true, 100},
				{199, true, 100},
				{200, true, 200},
				{201, true, 200},
				{99999999999999998, true, 200},
				{99999999999999999, true, 300},
				{100000000000000000, true, 300},
			},
		},
		{
			key: "comm.para1",
			attrs: []TestAttr{
				{99, true, false},
				{100, true, true},
				{101, true, true},
				{199, true, true},
				{200, true, false},
				{201, true, false},
				{99999999999999998, true, false},
				{99999999999999999, true, true},
				{100000000000000000, true, true},
			},
		},
		{
			key: "full.para1",
			attrs: []TestAttr{
				{99, true, 5},
				{100, true, 100},
				{101, true, 100},
				{199, true, 100},
				{200, true, 200},
				{201, true, 200},
				{99999999999999998, true, 200},
				{99999999999999999, true, 300},
				{100000000000000000, true, 300},
			},
		},
		{
			key: "auxnet.para1",
			attrs: []TestAttr{
				{99, true, 5},
				{100, true, 100},
				{101, true, 100},
				{199, true, 100},
				{200, true, 200},
				{201, true, 200},
				{99999999999999998, true, 200},
				{99999999999999999, true, 300},
				{100000000000000000, true, 300},
			},
		},
	}
	runTest(t, getYamlData(yamlData), tests, false)
}

func TestBlockNumOne(t *testing.T) {
	yamlTest := `
- blocknum: 0
  desc: "default value"
  accel:
      para1: 5

- blocknum: 1
  desc: "hardfork 100"
  accel:
      para1: 50
`
	tests := []TestStruct{
		{
			key: "accel.para1",
			attrs: []TestAttr{
				{0, true, 5},
				{1, true, 50},
				{2, true, 50},
			},
		},
	}
	runTest(t, getYamlData(yamlTest), tests, false)
}

func TestSessionZero(t *testing.T) {
	yamlTest := `
- blocknum: 0
  session: 0
  desc: "default value"
  accel:
      para1: 5

- session: 1
  desc: "hardfork 100"
  accel:
      para1: 50
`
	tmpDir := HardforkConfigTestFileSetup(t, getYamlData(yamlTest))
	fmt.Println(string(yamlTest))
	defer os.RemoveAll(tmpDir)
	readHardfork(tmpDir)
}

func TestEnabledBlockNumAndSession(t *testing.T) {
	req := require.New(t)
	yamlTest := `
- blocknum: 0
  session: 0
  desc: "default value"
  pala:
      enableByBlock: false
      enableBySession: false
- session: 4
  desc: "hardfork session"
  pala:
      enableBySession: true
- blocknum: 60
  desc: "hardfork block"
  pala:
      enableByBlock: true

`
	tests := []TestStruct{
		{
			key:       "pala.enableBySession",
			isSession: true,
			attrs: []TestAttr{
				{0, true, false},
				{1, true, false},
				{2, true, false},
				{3, true, false},
				{4, true, true},
				{5, true, true},
			},
		}, {
			key: "pala.enableByBlock",
			attrs: []TestAttr{
				{0, true, false},
				{30, true, false},
				{58, true, false},
				{59, true, false},
				{60, true, true},
				{61, true, true},
			},
		},
	}
	runTest(t, getYamlData(yamlTest), tests, false)
	s := NewBoolHardforkConfig("pala.enableBySession", "")
	req.Equal(s.GetEnabledSession(), int64(4))
	b := NewBoolHardforkConfig("pala.enableByBlock", "")
	req.Equal(b.GetEnabledBlockNum(), chain.Seq(60))
}

// func TestRepeatedBlockNum(t *testing.T) {
// 	yamlTest := `
// - blocknum: 0
//   desc: "default value"
//   accel:
//       para1: 5

// - blocknum: 100
//   desc: "hardfork 100"
//   accel:
//       para1: 50

// - blocknum: 100
//   desc: "hardfork 100"
//   accel:
//       para1: 55
// `
// 	tests := []TestStruct{}
// 	runTest(t, getYamlData(yamlTest), tests, true)
// }

func TestNegativeBlockNum(t *testing.T) {
	yamlTest := `
- blocknum: 0
  desc: "default value"
  accel:
      para1: 5

- blocknum: 100
  desc: "hardfork 100"
  accel:
      para1: 50

- blocknum: -100
  desc: "hardfork 100"
  accel:
      para1: 55
`
	tests := []TestStruct{}
	runTest(t, getYamlData(yamlTest), tests, true)
}

func TestNonNumericalBlockNum(t *testing.T) {
	yamlTest := `
- blocknum: 0
  desc: "default value"
  accel:
      para1: 5

- blocknum: 100
  desc: "hardfork 100"
  accel:
      para1: 50

- blocknum: chars
  desc: "hardfork 100"
  accel:
      para1: 55
`
	tests := []TestStruct{}
	runTest(t, getYamlData(yamlTest), tests, true)
}

func TestBlockNumZero(t *testing.T) {
	yamlTest := `
- blocknum: 100
  desc: "hardfork 100"
  accel:
      para1: 50

- blocknum: 0
  desc: "default value"
  accel:
      para1: 5
`
	tests := []TestStruct{}
	runTest(t, getYamlData(yamlTest), tests, false)
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
