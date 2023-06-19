// This file implements thunder configuration using viper
// and also contains helper methods for auto generating
// debug cli commands for modifying configurations
//
// We piggy back on top of viper config system.
// Viper has the following precedence on configuration files:
// explicit call to Set
// flag (unused)
// env (unused)
// config
// key/value store (unused)
// default
//
// user set default config values will be reflected in viper at "default" level
// settings loaded from config file will be reflected in viper at "config" level
// user set allowDebugCLISet config vars via CLI or explicit calls to Set() will be reflected at
// "explicit call to Set" level.
//
// Please read comments thoroughly to understand non-trivial viper interfacing details.

package config

import (
	// Standard imports

	"fmt"
	"path"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	// Thunder imports

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/spf13/viper"
)

var (
	// map of all configurations
	configMap = map[string]IConfig{}

	// the raw data of all configurations from files.
	viperCfg = viper.New()

	// longest key in config, used for pretty printing
	longestKey    int
	curPrettyLeaf string

	// Keep track of dynamically overridden config values i.e. using debugcli.
	// We use Viper instance to keep track of them instead of our own map since Viper provides
	// a convenient function to write configs to file.
	dynamicOverrides         = viper.New()
	dynamicOverridesFilePath string

	logger = lgr.NewLgr("/Config")
)

const (
	prettyLeaf                = "%%-%ds : %%v - %%s%%s"
	logLevelPrefix            = "loglevel."
	verboseLogFileLevelPrefix = "verboseLogFileLevel"
)

func isLogLevelConfig(key string) bool {
	return strings.HasPrefix(strings.ToLower(key), logLevelPrefix)
}

func isVerboseLogLevelConfig(key string) bool {
	return strings.ToLower(key) == strings.ToLower(verboseLogFileLevelPrefix)
}

// handleLogLevelConfig implements the ability to set log levels for loggers.
// Loggers are not registered with config system since log domains are very fluid and can be created
// anytime by anything. So to keep configs framework - logger framework integration simple, setting
// log levels is handled in this one-way push manner.
func handleLogLevelConfig(lowerCaseKey string, levelStr string) (string, error) {
	if isLogLevelConfig(lowerCaseKey) {
		domain := toLgrKey(lowerCaseKey)
		level, err := lgr.LevelFromString(levelStr)
		if err != nil {
			return "", fmt.Errorf("cannot get log level from %s: %s", domain, err)
		}
		err = lgr.SetLogLevel(domain, level)
		if err != nil {
			return "", fmt.Errorf("cannot set log level for %s: %s", domain, err)
		}
		return fmt.Sprintf("Set log level %d for %s", level, domain), nil
	} else if isVerboseLogLevelConfig(lowerCaseKey) {
		level, err := lgr.LevelFromString(levelStr)
		if err != nil {
			return "", fmt.Errorf("invalid verbose log file level: %s", err)
		}
		err = lgr.SetVerboseLogFileLevel(level)
		if err != nil {
			return "", fmt.Errorf("cannot set verbose log level: %s", err)
		}
		return fmt.Sprintf("Set verbose log level %d", level), nil
	}
	return "", fmt.Errorf("config %s does not exist", lowerCaseKey)
}

func toLgrKey(k string) string {
	return strings.TrimPrefix(k, logLevelPrefix)
}

// Reset configuration.  Exposed for testing.
func ResetThunderConfig() {
	dynamicOverrides = viper.New()
	viperCfg = viper.New()
	configMap = map[string]IConfig{}
}

// check if domain string A shadows domain string B or vice versa
func checkDomainShadowing(A string, B string) bool {
	as := strings.Split(A, ".")
	bs := strings.Split(B, ".")
	min := utils.Min(len(as), len(bs))
	for i := 0; i < min; i++ {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// Add configuration from an IConfig
//
// Must be called before InitThunderConfig(..)
func addConfig(cfg IConfig) {
	// check for domain shadowing
	for k := range configMap {
		if checkDomainShadowing(cfg.name(), k) {
			debug.Fatal("domain shadowing found with %s and %s", cfg.name(), k)
		}
	}

	// store inside of map for faster lookup
	configMap[cfg.name()] = cfg
	if len(cfg.name()) > longestKey {
		longestKey = len(cfg.name())
		curPrettyLeaf = fmt.Sprintf(prettyLeaf, longestKey)
	}
}

// Configuration interface
type IConfig interface {
	// get the normalized name of the configuration (matches viper configuration keys)
	name() string

	// get the pretty name of the configuration
	prettyName() string

	// get the description of the configuration
	desc() string

	// Initialize the configuration with viper configuration value. This function may silently
	// fail if viper config value can not be converted into the internal storage type.
	// This function is for typed caching of viper configuration values.
	// This function is only used during initialization and should not call onSet()
	initFromViperConfig(interface{})

	// This function is used by InitThunderConfig to synchronize viper config state.
	// After InitThunderConfig(..) has been called, this function should return always return
	// the same result as "viper.Get(this.name())" i.e. our configuration should always be in
	// sync with the viper ones. This way we can do stuff like viper.WriteConfig if we want to
	// dump our modified configurations to a yaml file :).
	get() interface{}

	// returns true if configuration can be changed via debugCLI
	AllowDebugCLISet() bool

	// parse string for configuration value, and make it new value.
	// Returns an error if type mismatch
	// this should call onSet()
	parseAndSetFromString(arg string) error

	// called after configuration(s) have been changed by set(..)
	// this should not be called on the initialization of configuration system
	onSet(string, interface{})
}

type PrettyPrinter interface {
	// pretty print as a string
	PrettyPrint() string
}

// Callback type for when a config value changes after initialization.
// Arguments are (name, value).
type OnSetCb func(string, interface{})

type baseConfig struct {
	_name            string
	_prettyName      string
	_desc            string
	value            atomic.Value
	allowDebugCLISet bool
	onSetCb          OnSetCb
	lock             sync.Mutex
}

func newBaseConfig(name string, desc string, defaultValue interface{}, allowDebugCLISet bool,
	onSetCb OnSetCb,
) *baseConfig {
	b := baseConfig{
		_name:            strings.ToLower(name),
		_prettyName:      name,
		_desc:            desc,
		allowDebugCLISet: allowDebugCLISet,
		onSetCb:          onSetCb,
	}
	b.value.Store(defaultValue)
	return &b
}

func (c *baseConfig) name() string {
	return c._name
}

func (c *baseConfig) desc() string {
	return c._desc
}

func (c *baseConfig) prettyName() string {
	return c._prettyName
}

func (c *baseConfig) AllowDebugCLISet() bool {
	return bool(c.allowDebugCLISet)
}

func (c *baseConfig) get() interface{} {
	return c.value.Load()
}

func (c *baseConfig) set(internalValue interface{}, viperValue interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.value.Store(internalValue)
	c.onSet(c.name(), internalValue)
}

func (c *baseConfig) onSet(k string, v interface{}) {
	if c.onSetCb != nil {
		c.onSetCb(k, v)
	}
}

func appendIdent(r string, ident int) string {
	for i := 0; i < ident; i++ {
		r += "\t"
	}
	return r
}

// Helper function for printing viper configurations
func prettyPrintSettings(settings interface{}, ident int) string {
	var r string
	val := reflect.ValueOf(settings)

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Map:
		r += "\n"
		for _, k := range val.MapKeys() {
			r = appendIdent(r, ident)
			v := val.MapIndex(k)
			r += fmt.Sprintf("%s: %v", k.Interface(), prettyPrintSettings(v.Interface(), ident+1))
		}
	case reflect.Struct:
		r += "\n"
		for i := 0; i < val.NumField(); i++ {
			r = appendIdent(r, ident)
			v := val.Field(i)
			r += fmt.Sprintf("%s: %v", val.Type().Field(i).Name, prettyPrintSettings(v.Interface(), ident+1))
		}
	case reflect.Slice:
		for i := 0; i < val.Len(); i++ {
			v := val.Index(i)
			r += fmt.Sprintf("%v", prettyPrintSettings(v.Interface(), ident+1))
		}
	default:
		r += fmt.Sprintf("%v\n", val.Interface())
	}
	return r
}

func prettyPrintValue(c interface{}) string {
	var s string
	pp, ok := c.(PrettyPrinter)
	if ok {
		s = pp.PrettyPrint()
	}
	if !ok {
		cv := c.(IConfig).get()
		st, ok := cv.(fmt.Stringer)
		if ok {
			s = st.String()
		} else {
			s = fmt.Sprintf("%v", cv)
		}
	}
	return s
}

// Helper for loading viper cfg files
func loadViperCfg(v *viper.Viper, filename string, required bool) {
	v.SetConfigName(filename)
	err := v.MergeInConfig()
	if err != nil {
		logger.Note("Could not load config file: %s", filename)
		if required {
			debug.Fatal("could not read config %s", err)
		}
		return
	}
	logger.Note("Loaded config file %s", v.ConfigFileUsed())
}

func initDynamicOverrides(configPath string) {
	const filename = "dynamic_overrides"
	dynamicOverrides.AddConfigPath(configPath)
	dynamicOverrides.SetConfigName(filename)
	dynamicOverridesFilePath = path.Join(configPath, filename+".yaml")
	err := dynamicOverrides.ReadInConfig()
	if err != nil {
		// It's okay if file was not found, but fail for any other kind of error, for eg
		// bad config value, error in reading, etc. Since this file is programatically
		// written, such errors are not acceptable and we should fail the process in start
		// itself.
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Note("No %s file found", filename)
		} else {
			debug.Fatal("could not read %s : %s", filename, err)
		}
	}
}

func setIConfigValuesFromViper(v *viper.Viper) {
	// Iterate over configs read from the files, and update the values of IConfig objects
	// (which are the ones which get used all over thunder code).
	for _, key := range v.AllKeys() {
		if cfg, exists := configMap[key]; exists {
			logger.Note("setting %s from %v to %v", cfg.name(), cfg.get(), v.Get(key))
			cfg.initFromViperConfig(v.Get(key))
		}
	}
}

// Initialize the thunder configuration system. Does the following:
// - loads correct viper configuration from yaml file
// - Use them to override corresponding thunder configurations' values.
// - sets up the debug CLI to get/set our configurations
// We use viper only during initialization (as yaml reader), it's not needed after that.
func InitThunderConfig(configPath string) {
	logger.Note("Config path: %q", configPath)
	viperCfg.AddConfigPath(configPath)

	loadViperCfg(viperCfg, "thunder", false)
	loadViperCfg(viperCfg, "override", false)
	loadViperCfg(viperCfg, "extra_config", false)
	logger.Note("Configuration is:\n%s", prettyPrintSettings(viperCfg.AllSettings(), 0))
	setIConfigValuesFromViper(viperCfg)

	// If dynamic overrides file exists, then read values from it override existing ones.
	initDynamicOverrides(configPath)
	setIConfigValuesFromViper(dynamicOverrides)

	// initialize hardfork config
	readHardfork(configPath)

	// configMap contains only New*Config() flags defined in our *.go files. viperCfg is a
	// subset of that map containing only those flags which get set in config file. To get all
	// flags being set in config files, neither of the map is sufficient and we need
	// AllSettings().
	for _, key := range viperCfg.AllKeys() {
		if isLogLevelConfig(key) {
			_, err := handleLogLevelConfig(
				strings.ToLower(key), viperCfg.Get(key).(string))
			// Since handing configs is first order of business on startup of any
			// process, crashing when bad configs are detected is better than continuing
			// with wrong ones. We can only do this in InitThunderConfigs(), but not in
			// setHandler() since a typo in hotfix command shouldn't crash a live
			// process.
			if err != nil {
				debug.Fatal("Error in loglevel config %s : %s", key, err)
			}
		}
	}
}

func SetHardfork(settings RequiredSettings,
	bSettings []BlockNumSetting, sSettings []SessionSetting) {
	setHardfork(settings, bSettings, sSettings)
}

func InitHardforkConfig(configPath string) {
	readHardfork(configPath)
}

func InitDefaultHardforkConfigForTesting() {
	hardforkMap = make(map[string]HardforkConfig)
	sessionMap = make(map[string]SessionHardforks)
}

func SetManual(configVar string, value string) error {
	setting := strings.ToLower(configVar)
	if cfg, ok := configMap[setting]; ok {
		oldv := cfg.get()
		if err := cfg.parseAndSetFromString(value); err != nil {
			return fmt.Errorf("error %s", err.Error())
		}
		logger.Info(fmt.Sprintf("Set %s from %v to %v", cfg.name(), oldv, cfg.get()))
		return nil
	}
	_, err := handleLogLevelConfig(setting, value)
	return err
}

var setCmdName = "set"
var setCmdHelp = fmt.Sprintf("%s <var name> <value> - set the value of a config var", setCmdName)

// setCmd handler, also used by setManyCmd
func setHandler(args []string) (string, error) {
	if len(args) < 2 {
		return setCmdHelp, nil
	}
	configName := strings.ToLower(args[0])

	// Block changing config that's been forked
	if _, ok := hardforkMap[configName]; ok {
		return fmt.Sprintf("Cannot change %s which has been hardforked", configName), nil
	}

	if cfg, ok := configMap[configName]; ok {
		if !cfg.AllowDebugCLISet() {
			return fmt.Sprintf("%s can not be set",
				configName), nil
		}
		oldv := cfg.get()
		value := strings.Join(args[1:], " ")
		if err := cfg.parseAndSetFromString(value); err != nil {
			return fmt.Sprintf("error %s", err.Error()), nil
		}
		// Ideally it should be - persist the value first and then set internally - but
		// then case where a value might be wrong (failing parseAndSetFromString) becomes
		// hard because we can't un-persisting something (without having complicated tmp
		// file, move and recovery mechanisms). So we simply write the file after
		// everything has succeeded.
		dynamicOverrides.Set(configName, value)
		err := dynamicOverrides.WriteConfigAs(dynamicOverridesFilePath)
		if err != nil {
			return fmt.Sprintf(
				"ERROR: Config changed internally but failed to persist to dynamic" +
					"overrides file. WRITE IT MANUALLY!!"), nil
		}
		return fmt.Sprintf("Set %s from %v to %v", cfg.name(), oldv, cfg.get()), nil
	}
	// does not exist
	output, err := handleLogLevelConfig(configName, args[1])
	if err != nil {
		// be consistent with weird error handling already in this function
		return err.Error(), nil
	}
	return output, nil
}
