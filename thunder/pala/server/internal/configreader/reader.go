package configreader

import (
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

var (
	logger = lgr.NewLgr("/Config")
)

// Helper function for printing config file content -- Begin
func appendIdent(b *strings.Builder, ident int) {
	for i := 0; i < ident; i++ {
		b.WriteString("\t")
	}
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k, _ := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func prettyPrintSettings(settings interface{}, indent int) string {
	var b strings.Builder
	switch v := settings.(type) {
	case map[string]interface{}:
		if len(v) == 0 {
			b.WriteString("{}")
		}
		b.WriteRune('\n')
		for _, k := range mapKeys(v) {
			appendIdent(&b, indent)
			p := prettyPrintSettings(v[k], indent+1)
			b.WriteString(fmt.Sprintf("%s: %v", k, p))
		}
	case []string:
		if len(v) == 0 {
			b.WriteString("[]")
		}
		b.WriteRune('\n')
		for _, i := range v {
			appendIdent(&b, indent)
			b.WriteString(fmt.Sprintf("- %q\n", i))
		}
	case common.Address:
		b.WriteString(v.String())
		b.WriteRune('\n')
	case string:
		b.WriteString(fmt.Sprintf("%q", v))
		b.WriteRune('\n')
	default:
		b.WriteString(fmt.Sprintf("%v", v))
		b.WriteRune('\n')
	}
	return b.String()
}

// Helper functions for printing config file content -- End

func mergeOptionalFile(v *viper.Viper, filename string) error {
	v.SetConfigName(filename) // changes value reported by `v.ConfigFileUsed` by setting a member field
	if err := v.MergeInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
		logger.Note("Could not find config file %q", filename)
		return nil
	}
	logger.Note("Merging config from %q", v.ConfigFileUsed())
	return nil
}

// AllKeysGetStringer when given this YAML fragment:
// ```
//pala
//  isProposer: true
// ```
// would return:
// AllKeys() -> []string{strings.ToLower("pala.isProposer")}
// GetString("pala.isProposer") -> "true"
type AllKeysGetStringer interface {
	AllKeys() []string
	GetString(string) string
}

func read(v *viper.Viper, configPath string) (AllKeysGetStringer, error) {
	v.AddConfigPath(configPath)
	err := mergeOptionalFile(v, "thunder")
	if err != nil {
		return nil, err
	}
	err = mergeOptionalFile(v, "override")
	if err != nil {
		return nil, err
	}
	err = mergeOptionalFile(v, "extra_config")
	if err != nil {
		return nil, err
	}
	return v, nil
}

type Reader struct {
	v      *viper.Viper
	parsed map[string]*ParsedKey
}

func New() *Reader {
	return &Reader{v: viper.New(), parsed: make(map[string]*ParsedKey)}
}

type keyChecker regexp.Regexp

func newKeyChecker() *keyChecker {
	re, err := regexp.Compile("[A-Z]")
	if err != nil {
		debug.Bug("re.Compile failed: %s", err)
	}
	return (*keyChecker)(re)
}

func (k *keyChecker) hasCapitalLetters(s string) bool {
	return ((*regexp.Regexp)(k)).MatchString(s)
}

// parse parses the values in `c` into `r.parsed`
func (r *Reader) parse(a AllKeysGetStringer) error {
	kc := newKeyChecker()
	for _, key := range a.AllKeys() {
		if kc.hasCapitalLetters(key) {
			debug.Bug("AllKeys should not have returned key with capital letters: %q", key)
		}
		parsedKey, ok := r.parsed[key]
		if !ok {
			continue
		}
		val := a.GetString(key)
		v, err := parsedKey.parse(val)
		//fmt.Fprintf(os.Stderr, "Reader.parse: key: %q, val: %q, v: %#v\n", key, val, v)
		if err != nil {
			return err
		}
		parsedKey.x = v
	}
	return nil
}

// Read sets the values of the config variables and also returns the config map
func (r *Reader) Read(configPath string) (AllKeysGetStringer, error) {
	a, err := read(r.v, configPath)
	if err != nil {
		return nil, err
	}
	logger.Note("Configuration is:\n%s", prettyPrintSettings(r.v.AllSettings(), 0))
	r.parse(a)
	return a, nil
}

type Config struct {
	Key         string
	Description string
	Default     interface{}
}

type BaseKey struct {
	r   *Reader
	key string
}

func newKey(r *Reader, key string) *BaseKey {
	return &BaseKey{r, key}
}

type parseFunc func(string) (interface{}, error) // string from config file -> value

// defaultValidateFunc validates user specified default values for config variables
type defaultValidateFunc func(interface{}) (interface{}, error)

type ParsedKey struct { // types that use custom `parseFunc`s
	BaseKey
	parse parseFunc
	x     interface{} // holds the default or the value parsed from string
}

func (r *Reader) newParsedKey(parse parseFunc,
	defaultValidate defaultValidateFunc,
	zeroVal interface{}, c Config) *ParsedKey {
	k := &ParsedKey{BaseKey: *newKey(r, c.Key), parse: parse}
	if c.Default == nil {
		k.x = zeroVal
	} else {
		// `c.default_` is what the user passed in while declaring the config variable
		// `default_` is what the config variable will return on `.Get()`
		default_, err := defaultValidate(c.Default)
		if err != nil {
			// Panic if the default value is the wrong type to catch
			// config variable declaration errors relatively early in program execution
			debug.Bug("invalid default value specified while adding new config variable %q: %s",
				c.Key, err)
		}
		k.x = default_
	}
	r.parsed[strings.ToLower(c.Key)] = k
	r.v.SetDefault(c.Key, k.x)
	return k
}

type BoolKey ParsedKey

func parseBool(s string) (interface{}, error) {
	return strconv.ParseBool(s)
}

func validateBool(d interface{}) (interface{}, error) {
	return cast.ToBoolE(d)
}

func (r *Reader) NewBool(c Config) *BoolKey {
	return (*BoolKey)(r.newParsedKey(parseBool, validateBool, false /*zero value*/, c))
}

func (k *BoolKey) Get() bool {
	return k.x.(bool)
}

type IntKey ParsedKey

func parseInt(s string) (interface{}, error) {
	return strconv.ParseInt(s, 0, 64)
}

func validateInt(d interface{}) (interface{}, error) {
	return cast.ToInt64E(d)
}

func (r *Reader) NewInt(c Config) *IntKey {
	return (*IntKey)(r.newParsedKey(parseInt, validateInt, int64(0) /*zero value*/, c))
}

func (k *IntKey) Get() int64 {
	return k.x.(int64)
}

type DurationKey ParsedKey

func parseDuration(s string) (interface{}, error) {
	return time.ParseDuration(s)
}

func validateDuration(d interface{}) (interface{}, error) {
	return cast.ToDurationE(d)
}

func (r *Reader) NewDuration(c Config) *DurationKey {
	return (*DurationKey)(r.newParsedKey(parseDuration, validateDuration, time.Duration(0) /* zero value */, c))
}

func (k *DurationKey) Get() time.Duration {
	return k.x.(time.Duration)
}

type AddressKey ParsedKey // Ethereum address

func parseAddress(s string) (interface{}, error) {
	if !common.IsHexAddress(s) {
		return nil, xerrors.Errorf("invalid address: %q", s)
	}
	return common.HexToAddress(s), nil
}

func validateAddress(d interface{}) (interface{}, error) {
	if _, ok := d.(common.Address); !ok {
		return nil, xerrors.Errorf("unable to cast %#v of type %T to common.Address", d, d)
	}
	return d, nil
}

func (r *Reader) NewAddress(c Config) *AddressKey {
	return (*AddressKey)(r.newParsedKey(parseAddress, validateAddress, common.Address{} /* zero value */, c))
}

func (k *AddressKey) Get() common.Address {
	return k.x.(common.Address)
}

type BigIntKey ParsedKey

func SimpleScientificBigIntParse(s string) (*big.Int, error) {
	// Only allowed values in *simple* parsing are [0-9], 'e',
	// optional '-/+' at the start, and an optional '+' after 'e'.
	// No '-' allowed after 'e' since we are parsing Ints not Floats.
	errBadFormat := xerrors.Errorf("failed to parse %q as big.Int in scientific notation", s)
	matched, err := regexp.MatchString(`^[-+]?[0-9]+([e][+]?[0-9]+)?$`, s)
	if err != nil {
		debug.Fatal("SimpleScientificBigIntParse regex failed to compile: %s", err)
		return nil, err
	}
	if !matched {
		return nil, errBadFormat
	}
	indexOfE := strings.Index(s, "e")
	var firstPart, secondPart string
	if indexOfE == -1 { // no 'e' present
		firstPart = s
		secondPart = "0"
	} else {
		firstPart = s[0:indexOfE]
		secondPart = s[indexOfE+1:] // regex above ensures there are chars after 'e'
	}
	base, ok0 := big.NewInt(0).SetString(firstPart, 10)
	exp10, ok1 := big.NewInt(0).SetString(secondPart, 10)
	if !ok0 || !ok1 {
		return nil, errBadFormat
	}
	// return firstPart * 10^secondPart
	t := big.NewInt(10)
	return base.Mul(base, t.Exp(t, exp10, nil)), nil
}

func parseBigInt(s string) (interface{}, error) {
	return SimpleScientificBigIntParse(s)
}

func validateBigInt(d interface{}) (interface{}, error) {
	if _, ok := d.(*big.Int); !ok {
		//cast.ToInt64E would accept nil, 'X' (int32) and false
		i, err := cast.ToInt64E(d)
		if err == nil {
			return big.NewInt(i), nil
		}
		return nil, xerrors.Errorf("unable to cast %#v of type %T to *big.Int", d, d)
	}
	return d, nil
}

func (r *Reader) NewBigInt(c Config) *BigIntKey {
	return (*BigIntKey)(r.newParsedKey(parseBigInt, validateBigInt, big.NewInt(0) /* zero value */, c))
}

func (k *BigIntKey) Get() *big.Int {
	return k.x.(*big.Int)
}

// Types with no `parseFunc` and thus no config file content validation define their types as `BaseKey`
// When fetching the actual values of config variables, `X.Get()` would behave the same as
// `viper.GetX()` , which typically returns the zero value of the type on invalid input.
type StringKey BaseKey

func (r *Reader) NewString(c Config) *StringKey {
	var d string
	if c.Default == nil {
		d = ""
	} else {
		d = c.Default.(string)
	}
	r.v.SetDefault(c.Key, d)
	return (*StringKey)(newKey(r, c.Key))
}

func (k *StringKey) Get() string {
	return k.r.v.GetString(k.key)
}

type StringSliceKey BaseKey

func (r *Reader) NewStringSlice(c Config) *StringSliceKey {
	if c.Default == nil { // special case to make zero value consistent with StringMapStringSlice
		// `viper.GetStringSlice(key)` returns `([]string)(nil)` when `key` is not set
		r.v.SetDefault(c.Key, make([]string, 0))
	} else {
		r.v.SetDefault(c.Key, c.Default)
	}
	return (*StringSliceKey)(newKey(r, c.Key))
}

func (k *StringSliceKey) Get() []string {
	return k.r.v.GetStringSlice(k.key)
}

type StringMapStringSliceKey BaseKey

func (r *Reader) NewStringMapStringSlice(c Config) *StringMapStringSliceKey {
	if c.Default != nil {
		r.v.SetDefault(c.Key, c.Default)
	}
	return (*StringMapStringSliceKey)(newKey(r, c.Key))
}

func (k *StringMapStringSliceKey) Get() map[string][]string {
	return k.r.v.GetStringMapStringSlice(k.key)
}
