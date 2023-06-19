package configreader

import (
	"bytes"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func Test_simpleScientificBigIntParse(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		want    *big.Int
		wantErr bool
	}{
		{name: "empty string", arg: "", want: nil, wantErr: true},
		{name: "base", arg: "0", want: big.NewInt(0), wantErr: false},
		{name: "digit-space-digit", arg: "1 2", want: nil, wantErr: true},
		{name: "native-base", arg: "-23", want: big.NewInt(-23), wantErr: false},
		{name: "base-plus", arg: "1+", want: nil, wantErr: true},
		{name: "base-E", arg: "45E", want: nil, wantErr: true},
		{name: "base-e", arg: "123e", want: nil, wantErr: true},
		{name: "base-e-exponent", arg: "123e3", want: big.NewInt(123000), wantErr: false},
		{name: "base-e-exponent", arg: "123e3", want: big.NewInt(123000), wantErr: false},
		{name: "leading-zeros-base", arg: "0078e0", want: big.NewInt(78), wantErr: false},
		{name: "leading-zeros-exponent", arg: "1e01", want: big.NewInt(10), wantErr: false},
		{name: "large-number", arg: "1e21", want: big.NewInt(0).Exp(big.NewInt(10), big.NewInt(21), nil),
			wantErr: false},
		{name: "negative-exponent", arg: "1e-17", want: nil, wantErr: true},
		{name: "large-negative-number", arg: "-1e+21", want: big.NewInt(0).Mul(
			big.NewInt(-1),
			big.NewInt(0).Exp(big.NewInt(10), big.NewInt(21), nil)),
			wantErr: false},
		{name: "23", arg: "23", want: big.NewInt(23), wantErr: false},
		{name: "11e0", arg: "11e0", want: big.NewInt(11), wantErr: false},
		{name: "-11e0", arg: "-11e0", want: big.NewInt(-11), wantErr: false},
		{name: "12345e+20", arg: "12345e+20", want: big.NewInt(0).Mul(big.NewInt(12345), big.NewInt(0).Exp(big.NewInt(10), big.NewInt(20), nil)),
			wantErr: false},
		{name: "garbage", arg: "garbage", want: nil, wantErr: true},
		{name: "-132e+", arg: "-132e+", want: nil, wantErr: true},
		{name: "-132e10e20", arg: "-132e10e20", want: nil, wantErr: true},
		{name: "e20", arg: "e20", want: nil, wantErr: true},
	}
	req := require.New(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SimpleScientificBigIntParse(tt.arg)
			if tt.wantErr {
				req.Error(err)
			} else {
				req.NoError(err)
				req.Equal(tt.want, got)
			}
		})
	}
}

func TestReader_ParsedKeys(t *testing.T) {
	t.Run("ethereum-address", func(t *testing.T) {
		addr1Str := "0xa82b90ceb8e1cce20cb849bc0f78aa12bc28f9f6"
		addr1 := common.HexToAddress(addr1Str)
		tests := []struct {
			name        string
			c           Config
			val         interface{} // nil means "not set in configMap"
			want        interface{} // nil means expect `parseAddress(val)``
			wantErr     bool
			panicsOnNew bool
		}{
			{name: "valid-value-set", c: Config{Key: "some-address"}, val: "0xad23b02673214973e354d41e19999d9e01f3be58"},
			{name: "no-0x-prefix", c: Config{Key: "some-address"}, val: "ad23b02673214973e354d41e19999d9e01f3be58"},
			{name: "not-set-and-without-default-value", c: Config{Key: "NON-EXISTENT"}, want: common.Address{}},
			{name: "not-set-but-with-default-value", c: Config{Key: "NON-EXISTENT", Default: common.HexToAddress(addr1Str)}, want: addr1},
			{name: "with-default-value-of-wrong-type", c: Config{Key: "NON-EXISTENT", Default: 17}, panicsOnNew: true},
			{name: "set-as-empty-string", c: Config{Key: "empty-string"}, val: "", wantErr: true},
			{name: "bad-value", c: Config{Key: "bad-address"}, val: "?", wantErr: true},
			{name: "bad-value1", c: Config{Key: "bad-address"}, val: "0x1", wantErr: true},
		}

		req := require.New(t)
		reader := New()
		ks := make([]*AddressKey, 0, len(tests))
		for i, tt := range tests {
			a := viper.New()
			appendNewKey := func() {
				ks = append(ks, reader.NewAddress(tt.c))
			}
			if tt.panicsOnNew {
				req.Panics(appendNewKey, tt.name)
				continue
			} else {
				req.NotPanics(appendNewKey, tt.name)
			}
			if tt.val != nil {
				a.Set(tt.c.Key, tt.val.(string))
			}
			err := reader.parse(a)
			if tt.wantErr {
				req.Error(err, tt.name)
				continue
			}
			req.NoError(err, tt.name)
			actual := ks[i].Get()
			if tt.want == nil {
				expected, err := parseAddress(tt.val.(string))
				req.NoError(err, tt.name)
				req.Equal(expected, actual, tt.name)
			} else {
				req.Equal(tt.want.(common.Address), actual, tt.name)
			}
		}
	})
	t.Run("big.Int", func(t *testing.T) {
		tests := []struct {
			name        string
			c           Config
			val         interface{} // nil means "not set in configMap"
			want        *big.Int    // nil means expect `parseBigInt(val)`
			wantErr     bool
			panicsOnNew bool
		}{
			{name: "valid-value-set", c: Config{Key: "some-price"}, val: "1e+18"},
			{name: "not-set-and-without-default-value", c: Config{Key: "NON-EXISTENT"}, want: big.NewInt(0)},
			{name: "not-set-but-with-default-value", c: Config{Key: "NON-EXISTENT", Default: big.NewInt(87)}, want: big.NewInt(87)},
			{name: "with-int-default-value", c: Config{Key: "NON-EXISTENT", Default: 17}, want: big.NewInt(17)},
			{name: "with-int64-default-value", c: Config{Key: "NON-EXISTENT", Default: int64(17)}, want: big.NewInt(17)},
			{name: "with-default-value-of-wrong-type", c: Config{Key: "NON-EXISTENT", Default: ""}, panicsOnNew: true},
			{name: "with-default-value-of-wrong-type1", c: Config{Key: "NON-EXISTENT", Default: []string{}}, panicsOnNew: true},
			{name: "set-as-empty-string", c: Config{Key: "empty-string"}, val: "", wantErr: true},
			{name: "bad-value", c: Config{Key: "bad-value"}, val: "?", wantErr: true},
			{name: "bad-value1", c: Config{Key: "bad-value"}, val: "RaNd0m", wantErr: true},
		}

		req := require.New(t)
		reader := New()
		ks := make([]*BigIntKey, 0, len(tests))
		for i, tt := range tests {
			a := viper.New()
			appendNewKey := func() {
				ks = append(ks, reader.NewBigInt(tt.c))
			}
			if tt.panicsOnNew {
				req.Panics(appendNewKey, tt.name)
				continue
			} else {
				req.NotPanics(appendNewKey, tt.name)
			}
			if tt.val != nil {
				a.Set(tt.c.Key, tt.val.(string))
			}
			err := reader.parse(a)
			if tt.wantErr {
				req.Error(err, tt.name)
				continue
			}
			req.NoError(err, tt.name)
			actual := ks[i].Get()
			if tt.want == nil {
				expected, err := parseBigInt(tt.val.(string))
				req.NoError(err, tt.name)
				req.Equal(expected, actual, tt.name, tt.name)
			} else {
				req.Equal(tt.want, actual, tt.name)
			}
		}
	})
	t.Run("bool", func(t *testing.T) {
		tests := []struct {
			name        string
			c           Config
			val         interface{} // nil means "not set in configMap"
			want        interface{} // nil means expect `strconv.ParseBool(val)``
			wantErr     bool
			panicsOnNew bool
		}{
			{name: "valid-value-set", c: Config{Key: "profling.enable"}, val: "true"},
			{name: "valid-value-set1", c: Config{Key: "x-enable"}, val: "false"},
			{name: "valid-value-set2", c: Config{Key: "x-enable"}, val: "1"},
			{name: "valid-value-set3", c: Config{Key: "x-enable"}, val: "0"},
			{name: "not-set-and-without-default-value", c: Config{Key: "NON-EXISTENT"}, want: false},
			{name: "not-set-but-with-default-value", c: Config{Key: "NON-EXISTENT", Default: true}, want: true},
			{name: "with-default-value-of-wrong-type", c: Config{Key: "NON-EXISTENT", Default: ""}, panicsOnNew: true},
			{name: "with-default-value-of-wrong-type1", c: Config{Key: "NON-EXISTENT", Default: 'X'}, panicsOnNew: true},
			{name: "with-default-value-of-wrong-type2", c: Config{Key: "NON-EXISTENT", Default: map[string]string{}}, panicsOnNew: true},
			{name: "set-as-empty-string", c: Config{Key: "empty-string"}, val: "", wantErr: true},
			{name: "bad-value", c: Config{Key: "bad-value"}, val: "?", wantErr: true},
			{name: "bad-value1", c: Config{Key: "bad-value"}, val: "0x1", wantErr: true},
		}

		req := require.New(t)
		reader := New()
		ks := make([]*BoolKey, 0, len(tests))
		for i, tt := range tests {
			a := viper.New()
			appendNewKey := func() {
				ks = append(ks, reader.NewBool(tt.c))
			}
			if tt.panicsOnNew {
				req.Panics(appendNewKey, tt.name)
				continue
			} else {
				req.NotPanics(appendNewKey, tt.name)
			}
			if tt.val != nil {
				a.Set(tt.c.Key, tt.val.(string))
			}
			err := reader.parse(a)
			if tt.wantErr {
				req.Error(err, tt.name)
				continue
			}
			req.NoError(err, tt.name)
			actual := ks[i].Get()
			if tt.want == nil {
				expected, err := strconv.ParseBool(tt.val.(string))
				req.NoError(err, tt.name)
				req.Equal(expected, actual, tt.name)
			} else {
				req.Equal(tt.want.(bool), actual, tt.name)
			}
		}
	})
	t.Run("int", func(t *testing.T) {
		tests := []struct {
			name        string
			c           Config
			val         interface{} // nil means "not set in configMap"
			want        interface{} // nil means expect `parseInt(val)``
			wantErr     bool
			panicsOnNew bool
		}{
			{name: "valid-value-set", c: Config{Key: "profiling.port"}, val: "9999"},
			{name: "valid-value-set1", c: Config{Key: "profiling.port"}, val: "-1"},
			{name: "valid-value-set2", c: Config{Key: "profiling.port"}, val: "0x3"},
			{name: "valid-value-set2", c: Config{Key: "file.perm"}, val: "0644"},
			{name: "not-set-and-without-default-value", c: Config{Key: "NON-EXISTENT"}, want: 0},
			{name: "not-set-but-with-default-value", c: Config{Key: "NON-EXISTENT", Default: 1337}, want: 1337},
			{name: "not-set-but-with-default-value1", c: Config{Key: "NON-EXISTENT", Default: 'A'}, want: 65},
			{name: "not-set-but-with-default-value2", c: Config{Key: "NON-EXISTENT", Default: true}, want: 1},
			{name: "with-default-value-of-wrong-type", c: Config{Key: "NON-EXISTENT", Default: ""}, panicsOnNew: true},
			{name: "with-default-value-of-wrong-type1", c: Config{Key: "NON-EXISTENT", Default: map[string]string{}}, panicsOnNew: true},
			{name: "set-as-empty-string", c: Config{Key: "empty-string"}, val: "", wantErr: true},
			{name: "bad-value", c: Config{Key: "bad-value"}, val: "?", wantErr: true},
			{name: "bad-value1", c: Config{Key: "bad-value"}, val: "deadbeef", wantErr: true},
		}

		req := require.New(t)
		reader := New()
		ks := make([]*IntKey, 0, len(tests))
		for i, tt := range tests {
			a := viper.New()
			appendNewKey := func() {
				ks = append(ks, reader.NewInt(tt.c))
			}
			if tt.panicsOnNew {
				req.Panics(appendNewKey, tt.name)
				continue
			} else {
				req.NotPanics(appendNewKey, tt.name)
			}
			if tt.val != nil {
				a.Set(tt.c.Key, tt.val.(string))
			}
			err := reader.parse(a)
			if tt.wantErr {
				req.Error(err, tt.name)
				continue
			}
			req.NoError(err, tt.name)
			actual := ks[i].Get()
			if tt.want == nil {
				expected, err := parseInt(tt.val.(string))
				req.NoError(err, tt.name)
				req.Equal(expected.(int64), actual, tt.name)
			} else {
				req.Equal(cast.ToInt64(tt.want), actual, tt.name)
			}
		}
	})
	t.Run("duration", func(t *testing.T) {
		tests := []struct {
			name        string
			c           Config
			val         interface{} // nil means "not set in configMap"
			want        interface{} // nil means expect `parseDuration(val)``
			wantErr     bool
			panicsOnNew bool
		}{
			{name: "valid-value-set", c: Config{Key: "time-per-block"}, val: "1s"},
			{name: "valid-value-set", c: Config{Key: "time-per-block"}, val: "15m"},
			{name: "valid-value-set", c: Config{Key: "time-per-block"}, val: "3h"},
			{name: "not-set-and-without-default-value", c: Config{Key: "NON-EXISTENT"}, want: time.Duration(0)},
			{name: "not-set-but-with-default-value", c: Config{Key: "NON-EXISTENT", Default: 7 * time.Second}, want: 7 * time.Second},
			{name: "with-default-value-of-wrong-type", c: Config{Key: "NON-EXISTENT", Default: ""}, panicsOnNew: true},
			{name: "with-default-value-of-wrong-type1", c: Config{Key: "NON-EXISTENT", Default: map[string]string{}}, panicsOnNew: true},
			{name: "with-default-value-of-wrong-type2", c: Config{Key: "NON-EXISTENT", Default: false}, panicsOnNew: true},
			{name: "set-as-empty-string", c: Config{Key: "empty-string"}, val: "", wantErr: true},
			{name: "bad-value", c: Config{Key: "bad-value"}, val: "?", wantErr: true},
			{name: "bad-value1", c: Config{Key: "bad-value"}, val: "deadbeef", wantErr: true},
		}

		req := require.New(t)
		reader := New()
		ks := make([]*DurationKey, 0, len(tests))
		for i, tt := range tests {
			a := viper.New()
			appendNewKey := func() {
				ks = append(ks, reader.NewDuration(tt.c))
			}
			if tt.panicsOnNew {
				req.Panics(appendNewKey, tt.name)
				continue
			} else {
				req.NotPanics(appendNewKey, tt.name)
			}
			if tt.val != nil {
				a.Set(tt.c.Key, tt.val.(string))
			}
			err := reader.parse(a)
			if tt.wantErr {
				req.Error(err, tt.name)
				continue
			}
			req.NoError(err, tt.name)
			actual := ks[i].Get()
			if tt.want == nil {
				expected, err := parseDuration(tt.val.(string))
				req.NoError(err, tt.name)
				req.Equal(expected.(time.Duration), actual, tt.name)
			} else {
				req.Equal(tt.want.(time.Duration), actual, tt.name)
			}
		}
	})
}

func TestReader_BaseKeys(t *testing.T) {
	reader := New()
	newString := func(c Config) interface{} {
		return reader.NewString(c)
	}
	newStringSlice := func(c Config) interface{} {
		return reader.NewStringSlice(c)
	}
	newStringMapStringSlice := func(c Config) interface{} {
		return reader.NewStringMapStringSlice(c)
	}
	tests := []struct {
		name        string
		new         (func(Config) interface{})
		c           Config
		want        interface{} // nil means expect `parseDuration(val)``
		panicsOnNew bool
	}{
		{name: "string-set-in-config", new: newString, c: Config{Key: "loglevel./network"}, want: "info"},
		{name: "string-user-default", new: newString, c: Config{Key: "loglevel./", Default: "warn"}, want: "warn"},
		{name: "string-zero-value", new: newString, c: Config{Key: "loglevel./consensus"}, want: ""},
		{name: "string-slice-set-in-config", new: newStringSlice, c: Config{Key: "pala.bootnode.addresses"},
			want: []string{"bootname0", "bootname1", "bootname2"}},
		{name: "string-slice-with-default", new: newStringSlice, c: Config{Key: "hello-world",
			Default: []string{"hi", "world"}}, want: []string{"hi", "world"}},
		{name: "string-slice-zero-value", new: newStringSlice, c: Config{Key: "NON-EXISTENT"}, want: make([]string, 0)},
		{name: "string-map-string-slice-set-in-config", new: newStringMapStringSlice, c: Config{Key: "profiling"},
			want: map[string][]string{"enable": []string{"true"}, "port": []string{"9997"}}},
		{name: "string-map-string-slice-with-default", new: newStringMapStringSlice, c: Config{Key: "etc-hosts",
			Default: map[string][]string{"localhost": []string{"127.0.0.1", "::1"}}},
			want: map[string][]string{"localhost": []string{"127.0.0.1", "::1"}}},
		{name: "string-map-string-slice-zero-value", new: newStringMapStringSlice, c: Config{Key: "some-other-map"},
			want: make(map[string][]string)},
	}

	yamlBytes := []byte(`
loglevel./network: info
loggingId: bootnode_0
# debug | info | note | warning | error
dataDir: pala-dev/dataDir/bootnode
key:
  GenesisCommPath: pala-dev/keys/fastpath/keystore/genesis_comm_info.json
pala:
  fromGenesis: true
  bootnode:
    addresses:
      bootname0 bootname1 bootname2
rpc:
  http:
    hostname: 0.0.0.0
    port: 8645
  ws:
    hostname: 0.0.0.0
    origins: '*'
    port: 8646
chain:
  genesis: pala-dev/common/genesis.json
proposer:
  bindingIPPort: 0.0.0.0:8888
  rewardAddress: '0x9A78d67096bA0c7C1bCdc0a8742649Bc399119c0'
metrics:
  address: 0.0.0.0:9203
profiling:
   enable: true
   port: 9997`)
	req := require.New(t)
	reader.v.SetConfigType("yaml")
	err := reader.v.ReadConfig(bytes.NewBuffer(yamlBytes))
	req.NoError(err)
	req.NotEmpty(reader.v.AllSettings())

	ks := make([]interface{}, 0, len(tests))
	for i, tt := range tests {
		appendNewKey := func() {
			ks = append(ks, tt.new(tt.c))
		}
		if tt.panicsOnNew {
			req.Panics(appendNewKey, tt.name)
			continue
		} else {
			req.NotPanics(appendNewKey, tt.name)
		}
		var actual interface{}
		switch k := ks[i].(type) {
		case *StringKey:
			actual = k.Get()
		case *StringSliceKey:
			actual = k.Get()
		case *StringMapStringSliceKey:
			actual = k.Get()
		default:
			req.Fail(tt.name)
		}
		req.Equal(tt.want, actual, tt.name)
	}
}

func TestReader_Read(t *testing.T) {
	req := require.New(t)

	dirPath, err := ioutil.TempDir("" /*dir*/, "config.Reader.Read-")
	req.NoError(err)
	defer os.RemoveAll(dirPath)

	yaml0 := []byte(`
PaLa:
  Key0: A
  Key1: D
`)
	yaml1 := []byte(`
PaLa:
  Key0: B
  Key2: E
`)
	yaml2 := []byte(`
PaLa:
  Key0: C
  Key3: F
`)
	thunderYaml := filepath.Join(dirPath, "thunder.yaml")
	err = ioutil.WriteFile(thunderYaml, yaml0, 0600)
	req.NoError(err)
	overrideYaml := filepath.Join(dirPath, "override.yaml")
	err = ioutil.WriteFile(overrideYaml, yaml1, 0600)
	req.NoError(err)
	extraYaml := filepath.Join(dirPath, "extra_config.yaml")
	err = ioutil.WriteFile(extraYaml, yaml2, 0600)
	req.NoError(err)

	reader := New()
	a, err := reader.Read(dirPath)
	req.NoError(err)
	req.Equal("C", a.GetString("pala.key0"))
	req.Equal("D", a.GetString("pala.key1"))
	req.Equal("E", a.GetString("pala.key2"))
	req.Equal("F", a.GetString("pala.key3"))
}
