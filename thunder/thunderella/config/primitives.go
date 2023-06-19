// This file implements thunder configuration config
// types for various primitives

package config

import (
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	// thunder packages
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	// vendor
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cast"
)

// int64 configuration type
type Int64Config struct {
	baseConfig
}

func isHardforked(name string) bool {
	return hardforkMap[name] != nil
}

func requireNotHardforked(name string) {
	if isHardforked(name) {
		debug.Fatal("config %s has been hardforked. Use GetValueAt instead", name)
	}
}

// Create a new int64 configuration with given name description and default value
// if generateDebugCLISet is true, the configuration can be set via debug CLI
// onSetCb:	optional callback called after the config changes (e.g. via Set or debugCLI)
func NewInt64Config(
	name string,
	desc string,
	dflt int64,
	generateDebugCLISet bool,
	onSetCb OnSetCb,
) *Int64Config {
	c := &Int64Config{
		baseConfig: *newBaseConfig(name, desc, dflt, generateDebugCLISet, onSetCb),
	}
	addConfig(c)
	return c
}

func getInt64Value(value interface{}) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	case string:
		ret, err := strconv.ParseInt(v, 0, 64)
		if err != nil {
			debug.Fatal("Cannot parse value %s. %v", value, err)
		}
		return ret
	default:
		debug.Fatal("Unexpect value type")
	}
	return 0
}

func (c *Int64Config) Get() int64 {
	requireNotHardforked(c.name())
	return c.value.Load().(int64)
}

func (c *Int64Config) GetU64() uint64 {
	requireNotHardforked(c.name())
	return uint64(c.value.Load().(int64))
}

func (c *Int64Config) initFromViperConfig(v interface{}) {
	i := cast.ToInt64(v)
	c.value.Store(i)
}

func (c *Int64Config) parseAndSetFromString(arg string) (err error) {
	value, err := strconv.ParseInt(arg, 0, 64)
	if err == nil {
		c.Set(value)
	}
	return
}

func (c *Int64Config) Set(v int64) {
	c.set(v, v)
}

type IntToStringCallback func(int64) (string, error)
type StringToIntCallback func(arg string) (int64, error)

type EnumConfig struct {
	Int64Config
	strToIntCb StringToIntCallback
	intToStrCb IntToStringCallback
}

// Create a new enum configuration with given name description and default value
// Internally it is stored as an int64. Accepts both string enums and integers
// stored as strings.  Will perform all default integer conversion for users,
// taking in any base for the usual hexadecimal, decimal and octal bases, output
// is in base 10.
//
// if generateDebugCLISet is true, the configuration can be set via debug CLI
// onSetCb:	optional callback called after the config changes (e.g. via Set or debugCLI)
// strToIntCb:	required callback for manually parsing and verifying string arg
// 		passed in from debug CLI interface and from viper configs.
// intToStrCb: required callback to format enums into enum values.
//      callee is not required to format outlier values.
func NewEnumConfig(
	name string,
	desc string,
	dflt int64,
	generateDebugCLISet bool,
	onSetCb OnSetCb,
	strToIntCb StringToIntCallback,
	intToStrCb IntToStringCallback,
) *EnumConfig {
	if strToIntCb == nil || intToStrCb == nil {
		debug.Bug("need pretty print and parse callback for reading / writing configs")
	}
	c := &EnumConfig{
		Int64Config: Int64Config{
			baseConfig: *newBaseConfig(name, desc, dflt, generateDebugCLISet, onSetCb),
		},
		strToIntCb: strToIntCb,
		intToStrCb: intToStrCb,
	}
	addConfig(c)
	return c
}

func (c *EnumConfig) parseAndSetFromString(arg string) (err error) {
	var intValue int64
	if c.strToIntCb != nil {
		intValue, err = c.strToIntCb(arg)
	} else {
		intValue, err = strconv.ParseInt(arg, 0, 64)
	}
	if err == nil {
		c.Set(intValue)
	}
	return
}

func (c *EnumConfig) initFromViperConfig(v interface{}) {
	s, ok := v.(string)
	if ok {
		n, err := c.strToIntCb(s)
		if err != nil {
			n, err = strconv.ParseInt(s, 0, 64)
			if err != nil {
				// Can't convert or parse as an int, bail
				return
			}
		}
		c.value.Store(n)
	} else {
		c.value.Store(cast.ToInt64(v))
	}
	// Don't reset viper to non-string value
}

func (c *EnumConfig) Set(v int64) {
	str, err := c.intToStrCb(v)
	if err != nil {
		str = strconv.FormatInt(v, 10)
	}
	c.set(v, str)
}

func (c *EnumConfig) PrettyPrint() string {
	v := c.value.Load().(int64)
	str, err := c.intToStrCb(v)
	if err != nil {
		str = strconv.FormatInt(v, 10)
	}
	return str
}

// float64 configuration type
type Float64Config struct {
	baseConfig
}

// Create a new float64 configuration with given name description and default value
// if generateDebugCLISet is true, the configuration can be set via debug CLI
// onSetCb:	optional callback called after the config changes (e.g. via Set or debugCLI)
func NewFloat64Config(
	name string,
	desc string,
	dflt float64,
	generateDebugCLISet bool,
	onSetCb OnSetCb,
) *Float64Config {
	c := &Float64Config{
		baseConfig: *newBaseConfig(name, desc, dflt, generateDebugCLISet, onSetCb),
	}
	addConfig(c)
	return c
}

func (c *Float64Config) Get() float64 {
	requireNotHardforked(c.name())
	return c.value.Load().(float64)
}

func (c *Float64Config) initFromViperConfig(v interface{}) {
	f := cast.ToFloat64(v)
	c.value.Store(f)
}

func (c *Float64Config) parseAndSetFromString(arg string) (err error) {
	value, err := strconv.ParseFloat(arg, 64)
	if err == nil {
		c.Set(value)
	}
	return
}

func (c *Float64Config) Set(v float64) {
	c.set(v, v)
}

// bool configuration type
type BoolConfig struct {
	baseConfig
}

// Create a new bool configuration with given name description and default value
// if generateDebugCLISet is true, the configuration can be set via debug CLI
// onSetCb:	optional callback called after the config changes (e.g. via Set or debugCLI)
func NewBoolConfig(
	name string,
	desc string,
	dflt bool,
	generateDebugCLISet bool,
	onSetCb OnSetCb,
) *BoolConfig {
	c := &BoolConfig{
		baseConfig: *newBaseConfig(name, desc, dflt, generateDebugCLISet, onSetCb),
	}
	addConfig(c)
	return c
}

func (c *BoolConfig) Get() bool {
	requireNotHardforked(c.name())
	return c.value.Load().(bool)
}

func (c *BoolConfig) initFromViperConfig(v interface{}) {
	b := cast.ToBool(v)
	c.value.Store(b)
}

func (c *BoolConfig) parseAndSetFromString(arg string) (err error) {
	value, err := strconv.ParseBool(arg)
	if err == nil {
		c.Set(value)
	}
	return
}

func (c *BoolConfig) Set(v bool) {
	c.set(v, v)
}

// string configuration type
type StringConfig struct {
	baseConfig
}

// Create a new string configuration with given name description and default value
// if generateDebugCLISet is true, the configuration can be set via debug CLI
// onSetCb:	optional callback called after the config changes (e.g. via Set or debugCLI)
func NewStringConfig(
	name string,
	desc string,
	dflt string,
	generateDebugCLISet bool,
	onSetCb OnSetCb,
) *StringConfig {
	c := &StringConfig{
		baseConfig: *newBaseConfig(name, desc, dflt, generateDebugCLISet, onSetCb),
	}
	addConfig(c)
	return c
}

func (c *StringConfig) Get() string {
	requireNotHardforked(c.name())
	return c.value.Load().(string)
}

func (c *StringConfig) initFromViperConfig(v interface{}) {
	s := cast.ToString(v)
	c.value.Store(s)
}

func (c *StringConfig) parseAndSetFromString(arg string) error {
	c.Set(arg)
	return nil
}

func (c *StringConfig) Set(v string) {
	c.set(v, v)
}

// time.Time configuration type
type TimeConfig struct {
	baseConfig
}

// Create a new time.Time configuration with given name description and default value
// if generateDebugCLISet is true, the configuration can be set via debug CLI
// onSetCb:	optional callback called after the config changes (e.g. via Set or debugCLI)
func NewTimeConfig(
	name string,
	desc string,
	dflt time.Time,
	generateDebugCLISet bool,
	onSetCb OnSetCb,
) *TimeConfig {
	c := &TimeConfig{
		baseConfig: *newBaseConfig(name, desc, dflt, generateDebugCLISet, onSetCb),
	}
	addConfig(c)
	return c
}

func (c *TimeConfig) Get() time.Time {
	requireNotHardforked(c.name())
	return c.value.Load().(time.Time)
}

func (c *TimeConfig) initFromViperConfig(v interface{}) {
	t := cast.ToTime(v)
	c.value.Store(t)
}

func (c *TimeConfig) parseAndSetFromString(arg string) (err error) {
	// Trim the monotonic clock part if exists;
	// otherwise, the parser will fail.
	re := regexp.MustCompile(`(.*) m=[+-][0-9]+\.[0-9]+$`)
	if re.MatchString(arg) {
		arg = re.ReplaceAllString(arg, "${1}")
	}

	time, err := cast.ToTimeE(arg)
	if err == nil {
		c.Set(time)
	}
	return
}

func (c *TimeConfig) Set(v time.Time) {
	c.set(v, v)
}

// time.Duration configuration type
type DurationConfig struct {
	baseConfig
}

// Create a new time.Duration configuration with given name description and default value
// if generateDebugCLISet is true, the configuration can be set via debug CLI
// onSetCb:	optional callback called after the config changes (e.g. via Set or debugCLI)
func NewDurationConfig(
	name string,
	desc string,
	dflt time.Duration,
	generateDebugCLISet bool,
	onSetCb OnSetCb,
) *DurationConfig {
	c := &DurationConfig{
		baseConfig: *newBaseConfig(name, desc, dflt, generateDebugCLISet, onSetCb),
	}
	addConfig(c)
	return c
}

func (c *DurationConfig) Get() time.Duration {
	requireNotHardforked(c.name())
	return c.value.Load().(time.Duration)
}

func (c *DurationConfig) initFromViperConfig(v interface{}) {
	d := cast.ToDuration(v)
	c.value.Store(d)
}

func (c *DurationConfig) parseAndSetFromString(arg string) (err error) {
	duration, err := time.ParseDuration(arg)
	if err == nil {
		c.Set(duration)
	}
	return
}

func (c *DurationConfig) Set(v time.Duration) {
	c.set(v, v)
}

// big.Int configuration type
type BigIntConfig struct {
	baseConfig
}

// Create a new big.Int configuration with given name description and default value
//
// XXX N.B. - be careful with this type. Internally it is implemented as a
//            slice of integers, which is just a pointer, and it is often
//            passed around as a pointer.  Effectively, this just passes a reference
//            to the original value, and when creating new values, we want copy
//            semantics instead.
//
// if generateDebugCLISet is true, the configuration can be set via debug CLI
// onSetCb:	optional callback called after the config changes (e.g. via Set or debugCLI)
func NewBigIntConfig(
	name string,
	desc string,
	dflt *big.Int,
	generateDebugCLISet bool,
	onSetCb OnSetCb,
) *BigIntConfig {
	c := &BigIntConfig{
		// Make copy of default value object
		baseConfig: *newBaseConfig(name, desc, new(big.Int).Set(dflt), generateDebugCLISet, onSetCb),
	}
	addConfig(c)
	return c
}

func (c *BigIntConfig) Get() *big.Int {
	requireNotHardforked(c.name())
	// Deep copy so caller can't manipulate it.
	return new(big.Int).Set(c.value.Load().(*big.Int))
}

func (c *BigIntConfig) initFromViperConfig(v interface{}) {
	if bi, err := SimpleScientificBigIntParse(cast.ToString(v)); err != nil {
		debug.Bug("Error parsing config '%s' : %s", c.name(), err)
	} else {
		c.value.Store(bi)
	}
}

func SimpleScientificBigIntParse(val string) (*big.Int, error) {
	// Only allowed values in *simple* parsing are [0-9], 'e/E',
	// optional '-/+' in the start, and a optional '+' after 'e/E'.
	// No '-' allowed after 'e' since we are parsing Ints not Floats.
	badFormatErr := fmt.Errorf("error parsing BigInt value '%s' : bad format", val)
	if matched, err := regexp.MatchString(`^[-+]?[0-9]+([e][+]?[0-9]+)?$`, val); err != nil {
		return nil, fmt.Errorf("error parsing BigInt value '%s' : %s", val, err)
	} else if !matched {
		return nil, badFormatErr
	}
	indexOfE := strings.Index(val, "e")
	var firstPart, secondPart string
	if indexOfE == -1 { // no 'e' present
		firstPart = val
		secondPart = "0"
	} else {
		firstPart = val[0:indexOfE]
		secondPart = val[indexOfE+1:] // regular exp above ensures there are chars after 'e'
	}
	base, success1 := big.NewInt(0).SetString(cast.ToString(firstPart), 0)
	exp10, success2 := big.NewInt(0).SetString(cast.ToString(secondPart), 0)
	if !success1 || !success2 {
		return nil, badFormatErr
	}
	// return firstPart * 10^secondPart
	return base.Mul(base, big.NewInt(0).Exp(big.NewInt(10), exp10, nil)), nil
}

func (c *BigIntConfig) parseAndSetFromString(arg string) error {
	if bi, err := SimpleScientificBigIntParse(arg); err != nil {
		return fmt.Errorf("error parsing config '%s' : %s", c.name(), err)
	} else {
		c.Set(bi)
	}
	return nil
}

func (c *BigIntConfig) Set(v *big.Int) {
	// Deep copy so caller can't manipulate it.
	value := new(big.Int).Set(v)
	c.set(value, value)
}

// time.Duration configuration type
type AddressConfig struct {
	baseConfig
}

// Create a new time.Duration configuration with given name description and default value
// if generateDebugCLISet is true, the configuration can be set via debug CLI
// onSetCb:	optional callback called after the config changes (e.g. via Set or debugCLI)
func NewAddressConfig(
	name string,
	desc string,
	dflt common.Address,
	generateDebugCLISet bool,
	onSetCb OnSetCb,
) *AddressConfig {
	c := &AddressConfig{
		baseConfig: *newBaseConfig(name, desc, dflt, generateDebugCLISet, onSetCb),
	}
	addConfig(c)
	return c
}

func (c *AddressConfig) Get() common.Address {
	requireNotHardforked(c.name())
	return c.value.Load().(common.Address)
}

func (c *AddressConfig) initFromViperConfig(v interface{}) {
	addr := common.HexToAddress(cast.ToString(v))
	c.value.Store(addr)
}

func (c *AddressConfig) parseAndSetFromString(arg string) (err error) {
	c.Set(common.HexToAddress(arg))
	return
}

func (c *AddressConfig) Set(v common.Address) {
	c.set(v, v)
}

// map[string]string configuration type
type StringMapStringConfig struct {
	baseConfig
}

func NewStringMapStringConfig(
	name string,
	desc string,
	dflt map[string]string,
) *StringMapStringConfig {
	c := &StringMapStringConfig{
		baseConfig: *newBaseConfig(name, desc, dflt, false, nil),
	}
	addConfig(c)
	return c
}

func (c *StringMapStringConfig) Get() map[string]string {
	requireNotHardforked(c.name())
	value := c.value.Load().(map[string]string)
	if len(value) == 0 {
		// Get the value from the raw config object.
		tmp, ok := viperCfg.Get(c.name()).(map[string]interface{})
		if !ok {
			return nil
		}
		if sms := cast.ToStringMapString(tmp); sms != nil {
			c.value.Store(sms)
			value = sms
		} else {
			return nil
		}
	}
	// Create a copy.
	newValue := map[string]string{}
	for k, v := range value {
		newValue[k] = v
	}
	return newValue
}

func (c *StringMapStringConfig) initFromViperConfig(v interface{}) {
	debug.NotImplemented("not supported")
}

func (c *StringMapStringConfig) parseAndSetFromString(arg string) error {
	debug.NotImplemented("not supported")
	return nil
}
