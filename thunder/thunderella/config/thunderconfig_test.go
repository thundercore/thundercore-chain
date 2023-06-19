package config

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// configuration
var (
	defInt64                  = int64(0)
	defFloat64                = 0.0
	defString                 = "boop"
	defBool                   = false
	defBigInt                 = big.NewInt(123)
	defDuration               = time.Duration(0)
	defTime                   = time.Time{}
	defAddress                = common.Address{}
	defStringMapString        map[string]string
	testInt64Config           *Int64Config
	testFloat64Config         *Float64Config
	testStringConfig          *StringConfig
	testBoolConfig            *BoolConfig
	testTimeConfig            *TimeConfig
	testDurationConfig        *DurationConfig
	testBigIntConfig          *BigIntConfig
	testAddressConfig         *AddressConfig
	testStringMapStringConfig *StringMapStringConfig

	testChangeableConfig *Int64Config
	wasCfgChanged        bool
)

func onCfgChange(string, interface{}) {
	wasCfgChanged = true
}

func thunderTestSetup(t *testing.T) string {
	// reset everything from previous run
	ResetThunderConfig()

	// Test config var for onSet callback
	testChangeableConfig = NewInt64Config("config.test.changeable", "test changeable config",
		0, true, onCfgChange)
	wasCfgChanged = false

	testInt64Config = NewInt64Config("config.test.int", "test int config",
		defInt64, true, nil)
	testFloat64Config = NewFloat64Config("config.test.float", "test float config",
		defFloat64, true, nil)
	testStringConfig = NewStringConfig("config.test.string", "test string config",
		defString, true, nil)
	testBoolConfig = NewBoolConfig("config.test.bool", "test bool config",
		defBool, true, nil)
	testTimeConfig = NewTimeConfig("config.test.time", "test time config",
		defTime, true, nil)
	testDurationConfig = NewDurationConfig("config.test.duration", "test duration config",
		defDuration, true, nil)
	testBigIntConfig = NewBigIntConfig("config.test.bigint", "test bigint config",
		defBigInt, true, nil)
	testAddressConfig = NewAddressConfig("config.test.address", "test address config",
		defAddress, true, nil)
	testStringMapStringConfig = NewStringMapStringConfig("config.test.netAddr", "test map[string]string config",
		defStringMapString)

	// Create new tmp dir and write initial configs
	configDir, err := ioutil.TempDir("", "")
	require.NoError(t, err)

	testConfig := `# Testing config
config:
        test:
                changeable: 100
                int: 100
                float: 100
                string: "not boop"
                bool: true
                time: 324234
                duration: 321s
                bigint: 242392e20
                address: 0x01234567
                netaddr:
                        abc: 1.2.3.4
                        def: 5.6.7.8
`
	err = ioutil.WriteFile(path.Join(configDir, "thunder.yaml"), []byte(testConfig), 0644)
	require.NoError(t, err)
	return configDir
}

func TestThunderConfigTypes(t *testing.T) {
	assert := assert.New(t)

	// load defaults
	configDir := thunderTestSetup(t)
	defer os.RemoveAll(configDir)
	assert.Equal(defInt64, testInt64Config.Get(), "default value does not match")
	assert.Equal(defFloat64, testFloat64Config.Get(), "default value does not match")
	assert.Equal(defString, testStringConfig.Get(), "default value does not match")
	assert.Equal(defBool, testBoolConfig.Get(), "default value does not match")
	assert.Equal(defTime, testTimeConfig.Get(), "default value does not match")
	assert.Equal(defDuration, testDurationConfig.Get(), "default value does not match")
	assert.Equal(defBigInt, testBigIntConfig.Get(), "default value does not match")
	assert.Equal(defAddress, testAddressConfig.Get(), "default value does not match")
	assert.Equal(defStringMapString, testStringMapStringConfig.Get(), "default value does not match")

	// test that we can't domain shadow
	assert.Panics(func() { NewInt64Config("config.test.int", "", defInt64, false, nil) },
		"must panic with overlapping domains")
	assert.Panics(func() { NewInt64Config("config.test.int.aoe", "", defInt64, false, nil) },
		"must panic with overlapping domains")
	assert.Panics(func() { NewInt64Config("config", "", defInt64, false, nil) },
		"must panic with overlapping domains")

	// test that setting the defaults doesn't change the live config.  save them first.
	oi := defInt64
	of := defFloat64
	os := defString
	ob := defBool
	ot := defTime
	od := defDuration
	oB := new(big.Int).Set(defBigInt)
	oA := defAddress
	oS := defStringMapString
	defInt64++
	defFloat64 += 3
	defString = defString + "HOAX"
	defBool = !defBool
	defTime = defTime.Add(1 * time.Hour)
	defDuration = 3 * time.Hour
	defBigInt.Add(defBigInt, big.NewInt(11000))
	defAddress = common.HexToAddress("0x30d87bd4D1769437880c64A543bB649a693EB348")
	defStringMapString = map[string]string{}

	assert.NotEqual(defInt64, testInt64Config.Get(), "live configuration was modified")
	assert.NotEqual(defFloat64, testFloat64Config.Get(), "live configuration was modified")
	assert.NotEqual(defString, testStringConfig.Get(), "live configuration was modified")
	assert.NotEqual(defBool, testBoolConfig.Get(), "live configuration was modified")
	assert.NotEqual(defTime, testTimeConfig.Get(), "live configuration was modified")
	assert.NotEqual(defDuration, testDurationConfig.Get(), "live configuration was modified")
	assert.NotEqual(defBigInt, testBigIntConfig.Get(), "live configuration was modified")
	assert.NotEqual(defAddress, testAddressConfig.Get(), "live configuration was modified")
	assert.NotEqual(defStringMapString, testStringMapStringConfig.Get(), "live configuration was modified")

	// restore the original defaults
	defInt64 = oi
	defFloat64 = of
	defString = os
	defBool = ob
	defTime = ot
	defDuration = od
	defBigInt = oB
	defAddress = oA
	defStringMapString = oS

	// now load up from config file
	InitThunderConfig(configDir)

	assert.NotEqual(defInt64, testInt64Config.Get(), "value default after loading config")
	assert.NotEqual(defFloat64, testFloat64Config.Get(), "value default after loading config")
	assert.NotEqual(defString, testStringConfig.Get(), "value default after loading config")
	assert.NotEqual(defBool, testBoolConfig.Get(), "value default after loading config")
	assert.NotEqual(defTime, testTimeConfig.Get(), "value default after loading config")
	assert.NotEqual(defDuration, testDurationConfig.Get(), "value default after loading config")
	assert.NotEqual(defBigInt, testBigIntConfig.Get(), "value default after loading config")
	assert.NotEqual(defAddress, testAddressConfig.Get(), "value default after loading config")
	assert.NotEqual(defStringMapString, testStringMapStringConfig.Get(), "value default after loading config")
	assert.Equal("1.2.3.4", testStringMapStringConfig.Get()["abc"])
	assert.Equal("5.6.7.8", testStringMapStringConfig.Get()["def"])

	// test that the value returned by .Get() can't be written to
	i := testInt64Config.Get()
	f := testFloat64Config.Get()
	s := testStringConfig.Get()
	b := testBoolConfig.Get()
	T := testTimeConfig.Get()
	d := time.Microsecond
	B := testBigIntConfig.Get()
	a := testAddressConfig.Get()
	m := testStringMapStringConfig.Get()
	i++
	f += 3
	s += "XAOH"
	b = !b
	T = T.Add(3 * time.Hour)
	B.Add(B, big.NewInt(11000000))
	a = common.BytesToAddress([]byte("aoeu"))
	mOldLength := len(m)
	m["invalid"] = "8.8.8.8"
	assert.NotEqual(i, testInt64Config.Get(), "live configuration was modified")
	assert.NotEqual(f, testFloat64Config.Get(), "live configuration was modified")
	assert.NotEqual(s, testStringConfig.Get(), "live configuration was modified")
	assert.NotEqual(b, testBoolConfig.Get(), "live configuration was modified")
	assert.NotEqual(T, testTimeConfig.Get(), "live configuration was modified")
	assert.NotEqual(d, testDurationConfig.Get(), "live configuration was modified")
	assert.NotEqual(B, testBigIntConfig.Get(), "live configuration was modified")
	assert.NotEqual(a, testAddressConfig.Get(), "live configuration was modified")
	assert.Equal(mOldLength, len(testStringMapStringConfig.Get()), "live configuration was modified")

	// test that the value passed to .Set() can't be used to manipulate the live value
	testInt64Config.Set(i)
	testFloat64Config.Set(f)
	testStringConfig.Set(s)
	testBoolConfig.Set(b)
	testTimeConfig.Set(T)
	testDurationConfig.Set(d)
	testBigIntConfig.Set(B)
	testAddressConfig.Set(a)
	i++
	f += 3
	s += "BAOH"
	b = !b
	T = T.Add(3 * time.Hour)
	d = time.Millisecond
	B.Add(B, big.NewInt(22000000))
	a = common.Address{}
	assert.NotEqual(i, testInt64Config.Get(), "live configuration was modified")
	assert.NotEqual(f, testFloat64Config.Get(), "live configuration was modified")
	assert.NotEqual(s, testStringConfig.Get(), "live configuration was modified")
	assert.NotEqual(b, testBoolConfig.Get(), "live configuration was modified")
	assert.NotEqual(T, testTimeConfig.Get(), "live configuration was modified")
	assert.NotEqual(d, testDurationConfig.Get(), "live configuration was modified")
	assert.NotEqual(B, testBigIntConfig.Get(), "live configuration was modified")
	assert.NotEqual(a, testAddressConfig.Get(), "live configuration was modified")

	// now manually set back to defaults
	testInt64Config.Set(defInt64)
	testFloat64Config.Set(defFloat64)
	testStringConfig.Set(defString)
	testBoolConfig.Set(defBool)
	testTimeConfig.Set(defTime)
	testDurationConfig.Set(defDuration)
	testBigIntConfig.Set(defBigInt)
	testAddressConfig.Set(defAddress)

	// and test they are defaults
	assert.Equal(defInt64, testInt64Config.Get(), "default value does not match")
	assert.Equal(defFloat64, testFloat64Config.Get(), "default value does not match")
	assert.Equal(defString, testStringConfig.Get(), "default value does not match")
	assert.Equal(defBool, testBoolConfig.Get(), "default value does not match")
	assert.Equal(defTime, testTimeConfig.Get(), "default value does not match")
	assert.Equal(defDuration, testDurationConfig.Get(), "default value does not match")
	assert.Equal(defBigInt, testBigIntConfig.Get(), "default value does not match")
	assert.Equal(defAddress, testAddressConfig.Get(), "default value does not match")
}

func TestThunderConfigOnSetCallback(t *testing.T) {
	assert := assert.New(t)
	configDir := thunderTestSetup(t)
	InitThunderConfig(configDir)
	testChangeableConfig.Set(defInt64)
	assert.Equal(true, wasCfgChanged, "expected cfg callback to have been triggered")
}

// Micro-benchmarking support
//
// New results show a slight regression:
//
// BenchmarkInt64Get-8      	1000000000	         1.82 ns/op
// BenchmarkFloat64Get-8    	2000000000	         1.75 ns/op
// BenchmarkStringGet-8     	1000000000	         1.92 ns/op
// BenchmarkBoolGet-8       	1000000000	         1.83 ns/op
// BenchmarkTimeGet-8       	1000000000	         2.16 ns/op
// BenchmarkDurationGet-8   	2000000000	         1.88 ns/op
// BenchmarkBigIntGet-8     	20000000	        77.6 ns/op
//
// Old results:
//
// BenchmarkInt64Get-8      	2000000000	         0.42 ns/op
// BenchmarkFloat64Get-8    	2000000000	         0.43 ns/op
// BenchmarkStringGet-8     	2000000000	         0.58 ns/op
// BenchmarkBoolGet-8       	2000000000	         0.56 ns/op
// BenchmarkTimeGet-8       	2000000000	         0.72 ns/op
// BenchmarkDurationGet-8   	2000000000	         0.58 ns/op
// BenchmarkBigIntGet-8     	20000000	        75.5 ns/op

// Store results in globals to prevent optimizer eliding the calls to Config.Get()
var (
	rint64    int64
	rfloat64  float64
	rstring   string
	rbool     bool
	rtime     time.Time
	rduration time.Duration
	rbigint   *big.Int
	raddress  common.Address
)

func BenchmarkInt64Get(b *testing.B) {
	var r int64
	for i := 0; i < b.N; i++ {
		r = testInt64Config.Get()
	}
	rint64 = r
}

func BenchmarkFloat64Get(b *testing.B) {
	var r float64
	for i := 0; i < b.N; i++ {
		r = testFloat64Config.Get()
	}
	rfloat64 = r
}

func BenchmarkStringGet(b *testing.B) {
	var r string
	for i := 0; i < b.N; i++ {
		r = testStringConfig.Get()
	}
	rstring = r
}

func BenchmarkBoolGet(b *testing.B) {
	var r bool
	for i := 0; i < b.N; i++ {
		r = testBoolConfig.Get()
	}
	rbool = r
}

func BenchmarkTimeGet(b *testing.B) {
	var r time.Time
	for i := 0; i < b.N; i++ {
		r = testTimeConfig.Get()
	}
	rtime = r
}

func BenchmarkDurationGet(b *testing.B) {
	var r time.Duration
	for i := 0; i < b.N; i++ {
		r = testDurationConfig.Get()
	}
	rduration = r
}

func BenchmarkBigIntGet(b *testing.B) {
	var r *big.Int
	for i := 0; i < b.N; i++ {
		r = testBigIntConfig.Get()
	}
	rbigint = r
}

func BenchmarkAddressGet(b *testing.B) {
	var r common.Address
	for i := 0; i < b.N; i++ {
		r = testAddressConfig.Get()
	}
	raddress = r
}

var toLgrKeyTests = []struct {
	in       string
	expected string
}{
	{"loglevel./", "/"},
	{"loglevel./bouncer", "/bouncer"},
	{"loglevel./bouncer/client", "/bouncer/client"},
	{"loglevel./Bouncer", "/Bouncer"},
	{"loglevel./Bouncer/Client", "/Bouncer/Client"},
}

func TestToLgrKey(t *testing.T) {
	for _, test := range toLgrKeyTests {
		actual := toLgrKey(test.in)
		if actual != test.expected {
			t.Errorf("toLgrKey(%s) got %s, want %s", test.in, actual, test.expected)
		}
	}
}

func TestLgrOtherDomainsCliHandler(t *testing.T) {
	assert := assert.New(t)

	domain := "/x/y"
	err := lgr.SetLogLevel(domain, lgr.LvlInfo)
	assert.NoError(err, "error from set log level")

	args := []string{logLevelPrefix + domain, "WARN"}
	_, err = setHandler(args)
	assert.NoError(err, "got error from SetHandler")
	lvl, err := lgr.GetLogLevel(domain)
	assert.NoError(err, "level from string")
	assert.Equal(lgr.LvlWarning, lvl, "didn't set log domain to expected level")
}

func TestLgrOtherDomainsSetManual(t *testing.T) {
	assert := assert.New(t)

	domain := "/x/y"
	err := lgr.SetLogLevel(domain, lgr.LvlInfo)
	assert.NoError(err, "error from set log level")

	err = SetManual(logLevelPrefix+domain, "WARN")
	assert.NoError(err, "got error from SetHandler")
	lvl, err := lgr.GetLogLevel(domain)
	assert.NoError(err, "level from string")
	assert.Equal(lgr.LvlWarning, lvl, "didn't set log domain to expected level")
}

// this test requires "loglevel./x/y: WARN" to be set in unittest.yaml.  Would be nice if
// thunder config function could take an array of io.Readers to init from, then could use a
// string reader to do this test
/*
func TestLgrOtherDomainsViaConfig(t *testing.T) {
	assert := assert.New(t)

	domain := "/x/y"
	//err := lgr.SetLogLevel(domain, lgr.LvlInfo)
	//assert.NoError(err, "error from set log level")
	ResetThunderConfig()
	InitTestingConfig()

	lvl, err := lgr.GetLogLevel(domain)
	assert.NoError(err, "level from string")
	assert.Equal(lgr.LvlWarning, lvl, "didn't set log domain to expected level")
}
*/

// TestThunderConfigSetManual tests config.SetManual
// Note this also tests parseAndSetFromString
func TestThunderConfigSetManual(t *testing.T) {
	assert := assert.New(t)
	thunderTestSetup(t)

	i := int64(1 << 60)
	SetManual(testInt64Config.name(), fmt.Sprint(i))
	assert.Equal(i, testInt64Config.Get())

	f := float64(1 << 100)
	SetManual(testFloat64Config.name(), fmt.Sprint(f))
	assert.Equal(f, testFloat64Config.Get())

	s := "abc"
	SetManual(testStringConfig.name(), s)
	assert.Equal(s, testStringConfig.Get())

	b := true
	SetManual(testBoolConfig.name(), fmt.Sprint(b))
	assert.Equal(b, testBoolConfig.Get())

	now := time.Now()
	durations := []time.Duration{
		time.Nanosecond,
		time.Microsecond,
		time.Millisecond,
		time.Second,
		time.Minute,
		time.Hour,
		-time.Nanosecond,
		-time.Microsecond,
		-time.Millisecond,
		-time.Second,
		-time.Minute,
		-time.Hour,
	}
	for _, d := range durations {
		tim := now.Add(d)
		SetManual(testTimeConfig.name(), fmt.Sprint(tim))
		withoutMonotonicClock := "2006-01-02 15:04:05.999999999 -0700 MST"
		assert.Equal(tim.Format(withoutMonotonicClock),
			testTimeConfig.Get().Format(withoutMonotonicClock))
	}

	d := time.Duration(123)
	SetManual(testDurationConfig.name(), fmt.Sprint(d))
	assert.Equal(d, testDurationConfig.Get())

	B := big.NewInt(456)
	SetManual(testBigIntConfig.name(), fmt.Sprint(B))
	assert.EqualValues(B, testBigIntConfig.Get())

	a := common.HexToAddress("0x30d87bd4D1769437880c64A543bB649a693EB348")
	SetManual(testAddressConfig.name(), a.Hex())
	assert.Equal(a, testAddressConfig.Get())
}

func assertDynamicConfigValues(t *testing.T, configDir string, intVal int, boolVal bool, strVal string) {
	ResetThunderConfig()
	c1 := NewInt64Config("foo.int", "", 1, true, nil)
	c2 := NewBoolConfig("foo.bool", "", true, true, nil)
	c3 := NewStringConfig("foo.string", "", "abc", true, nil)
	InitThunderConfig(configDir)
	assert.EqualValues(t, intVal, c1.Get())
	assert.EqualValues(t, boolVal, c2.Get())
	assert.EqualValues(t, strVal, c3.Get())
}

func testGoodScientificParsing(t *testing.T, str string, expected *big.Int) {
	actual, err := SimpleScientificBigIntParse(str)
	assert.NoError(t, err)
	assert.EqualValues(t, expected, actual)
}

func TestScientificBigIntParse_GoodCases(t *testing.T) {
	testGoodScientificParsing(t, "0", big.NewInt(0))
	testGoodScientificParsing(t, "23", big.NewInt(23))
	testGoodScientificParsing(t, "-23", big.NewInt(-23))
	// Test xxe0 for +ve/-ve
	testGoodScientificParsing(t, "11e0", big.NewInt(11))
	testGoodScientificParsing(t, "-11e0", big.NewInt(-11))
	// Test with >0 power for 'e'
	testGoodScientificParsing(t, "22e5", big.NewInt(2200000))
	testGoodScientificParsing(t, "22e+5", big.NewInt(2200000))
	testGoodScientificParsing(t, "+22e+5", big.NewInt(2200000))
	testGoodScientificParsing(t, "-22e+5", big.NewInt(-2200000))
	// big ints
	expected, _ := big.NewInt(0).SetString("1234500000000000000000000", 0)
	testGoodScientificParsing(t, "12345e+20", expected)
	expected, _ = big.NewInt(0).SetString("-100000000000000000000", 0)
	testGoodScientificParsing(t, "-1e+20", expected)
}

func TestScientificBigIntParse_BadCases(t *testing.T) {
	_, err := SimpleScientificBigIntParse("asdfa")
	assert.NotNil(t, err)
	_, err = SimpleScientificBigIntParse("-132e")
	assert.NotNil(t, err)
	_, err = SimpleScientificBigIntParse("-132e-1")
	assert.NotNil(t, err)
	_, err = SimpleScientificBigIntParse("-132e+")
	assert.NotNil(t, err)
	_, err = SimpleScientificBigIntParse("-132e10e20")
	assert.NotNil(t, err)
	_, err = SimpleScientificBigIntParse("e20")
	assert.NotNil(t, err)
}

func TestSetHandlerOnHardforkedConf(t *testing.T) {
	require := require.New(t)

	var hardforkData = `
- blocknum: 0
  desc: "default value"
  config:
    test:
      int: 1

- blocknum: 100
  desc: "test set config"
  config:
    test:
      int: 101
`

	// load defaults
	configDir := thunderTestSetup(t)
	defer os.RemoveAll(configDir)

	hardForkFile := filepath.Join(configDir, hardforkConfigFile)
	if err := ioutil.WriteFile(hardForkFile, []byte(hardforkData), 0644); err != nil {
		t.Fatal("can't create temporary hardfork config yaml file")
	}
	InitThunderConfig(configDir)

	result, _ := setHandler([]string{"config.test.int", "102"})
	require.Equal("Cannot change config.test.int which has been hardforked", result)

	result, _ = setHandler([]string{"config.test.string", "foo"})
	require.Equal("Set config.test.string from not boop to foo", result)
}
