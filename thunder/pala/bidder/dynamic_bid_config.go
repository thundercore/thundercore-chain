package bidder

import (
	"log"
	"math/big"
	"sync"

	// vendor
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// mutex to prevent concurrent reading of viper configs
var (
	viperLock sync.Mutex

	// Dirty solution
	// Record the config's location
	ConfigPath = ""
)

func (b *Bidder) setupConfig(bidAmountCh chan *big.Int) {
	v := viper.New()
	if ConfigPath == "" {
		log.Println("config path can not be empty")
		return
	}
	v.AddConfigPath(ConfigPath)
	v.SetConfigName("override")
	v.ReadInConfig()
	logger.Info("[%s] Initial bid amount value: %s", b.loggingId, v.GetString("bidder.amount"))
	b.loadConfigDynamically(bidAmountCh, &viperLock, v)
}

func (b *Bidder) loadConfigDynamically(bidAmountCh chan *big.Int, viperLock *sync.Mutex, vipe *viper.Viper) {
	viperLock.Lock()
	vipe.OnConfigChange(func(e fsnotify.Event) {
		viperLock.Lock()
		defer viperLock.Unlock()
		logger.Info("[%s] config file changed: %s", b.loggingId, e.Name)
		sAmount := vipe.GetString("bidder.amount")
		amount, success := new(big.Int).SetString(sAmount, 10)
		if success {
			bidAmountCh <- amount
		}
	})
	viperLock.Unlock()
	vipe.WatchConfig()
}
