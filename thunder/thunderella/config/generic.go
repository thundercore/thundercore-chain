// This file implements thunder configuration config
// types for generic type

package config

import (
	"errors"
	"sync"
	"time"

	// vendor
	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

// mutex to prevent concurrent reading of viper configs
var viperLock sync.Mutex

// Interface for generic configuration type
type ConfigNode struct {
	value interface{}
}

// GetString returns the value associated with the key as a string.
func (cfgNode ConfigNode) GetString() (string, error) {
	return cast.ToStringE(cfgNode.value)
}

// GetBool returns the value associated with the key as a boolean.
func (cfgNode ConfigNode) GetBool() (bool, error) {
	return cast.ToBoolE(cfgNode.value)
}

// GetInt64 returns the value associated with the key as an integer.
func (cfgNode ConfigNode) GetInt64() (int64, error) {
	return cast.ToInt64E(cfgNode.value)
}

// GetFloat64 returns the value associated with the key as a float64.
func (cfgNode ConfigNode) GetFloat64() (float64, error) {
	return cast.ToFloat64E(cfgNode.value)
}

// GetTime returns the value associated with the key as time.
func (cfgNode ConfigNode) GetTime() (time.Time, error) {
	return cast.ToTimeE(cfgNode.value)
}

// GetDuration returns the value associated with the key as a duration.
func (cfgNode ConfigNode) GetDuration() (time.Duration, error) {
	return cast.ToDurationE(cfgNode.value)
}

// GetSlice returns the value associated with the key as a slice of ConfigNodes.
func (cfgNode ConfigNode) GetSlice() ([]ConfigNode, error) {
	r_, err := cast.ToSliceE(cfgNode.value)
	if err != nil {
		return nil, err
	}
	r := make([]ConfigNode, len(r_))
	for i, v := range r_ {
		r[i] = ConfigNode{v}
	}
	return r, err
}

// GetMap returns the value associated with the key as a map of ConfigNodes.
func (cfgNode ConfigNode) GetMap() (map[string]ConfigNode, error) {
	r_, err := cast.ToStringMapE(cfgNode.value)
	if err != nil {
		return nil, err
	}
	r := map[string]ConfigNode{}
	for k, v := range r_ {
		r[k] = ConfigNode{v}
	}
	return r, err
}

// Configuration type for any type.
// This configuration type does no caching and pulls values directly out of viper.
type GenericConfig struct {
	baseConfig
}

// Create a new generic configuration with given name description and default value
// dflt:	default value of the configuration. If there are child configurations
// 		their default values will override this one. It's normal to set this to nil.
//		TODO (lu): consider removing dflt value all together. It's unintuitive and
//		IMO it's uses are limited.
func NewGenericConfig(
	name string,
	desc string,
	dflt interface{},
) *GenericConfig {
	c := &GenericConfig{
		baseConfig: *newBaseConfig(name, desc, dflt, false, nil),
	}
	addConfig(c)
	return c
}

// N.B. (lu): I'm 99 percent sure viper returns a deep copy of the object.
func (c *GenericConfig) get() interface{} {
	if !viper.IsSet(c.name()) {
		return c.value.Load()
	}
	viperLock.Lock()
	defer viperLock.Unlock()
	return viper.Get(c.name())
}

// Get the generic config value (interface{}) wrapped in ConfigNode
// note, internally, everything is stored as interface{}
func (c *GenericConfig) Get() ConfigNode {
	// wrap the internal interface{} for ease of use
	return ConfigNode{c.get()}
}

func (c *GenericConfig) initFromViperConfig(v interface{}) {
	// no caching on GenericConfig
}

func (c *GenericConfig) parseAndSetFromString(arg string) (err error) {
	return errors.New("GenericConfigs can not be parsed/set")
}
