// fntool: a tool to stress-test fullnodes
// to monitor a fullnode see cmd/bovine

package main

import (
	// Standard imports
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/web3"
)

// note: simulated auxnet fullnode on localchain uses port 8536, thunder fullnode uses port 8546
// for ws://...

var (
	// fullnode to talk to
	targetNodeFlag = flag.String("target", "",
		"ws://... url for destination fullnode")

	// misc options
	verboseFlag = flag.Bool("v", false, "more verbose logging")
	txDelayFlag = flag.Duration("txDelay", 0*time.Millisecond,
		"amount of time to wait between transactions")
	numSocketsFlag = flag.Int64("numSockets", 1, "number of sockets to use")
	durationFlag   = flag.Duration("duration", 24*time.Hour,
		"time to run spam tests")

	logger = lgr.NewLgr("/Fntool")
)

func spamGeneric(name string, f func(conn *web3.Web3Connector) bool) {
	logger.Info("sending %s", name)
	conns := make([]*web3.Web3Connector, *numSocketsFlag)
	defer func() {
		for _, c := range conns {
			if c != nil {
				c.Close()
			}
		}
	}()

	for x := 0; x < int(*numSocketsFlag); x++ {
		// the name passed in is used as the logger tag
		c, err := web3.NewWeb3Connector(*targetNodeFlag, "Conn"+strconv.Itoa(x), logger)
		if err != nil {
			return
		}
		conns[x] = c
	}

	var wg sync.WaitGroup
	// set the wait group here so that the wg.Wait() blocks; otherwise there's a race condition
	// if we.Wait get called before the goroutines start executing
	wg.Add(len(conns))
	var reqCount int64
	var done int64
	for _, c := range conns {
		go func(conn *web3.Web3Connector) {
			defer wg.Done()
			for atomic.LoadInt64(&done) == 0 {
				ok := f(conn)
				if !ok {
					break
				}
				atomic.AddInt64(&reqCount, 1)
				time.Sleep(*txDelayFlag)
			}
		}(c)
	}

	const reportInterval = 1 * time.Second
	termination := time.Now().Add(*durationFlag)
	nextReport := time.Now().Add(reportInterval)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for atomic.LoadInt64(&done) == 0 {
			if time.Now().After(nextReport) {
				logger.Info("sent %d requests", atomic.LoadInt64(&reqCount))
				nextReport = time.Now().Add(reportInterval)
				time.Sleep(reportInterval / 5)
			}
			if time.Now().After(termination) {
				atomic.StoreInt64(&done, 1)
				logger.Info("time's up; terminating")
			}
		}
	}()
	wg.Wait()
}

func spamBlock() {
	fcn := func(conn *web3.Web3Connector) bool {
		_, err := conn.GetBlock(1)
		if err != nil {
			logger.Error("error from GetBlock(): %s", err)
			return false
		}
		return true
	}
	spamGeneric("block requests", fcn)
}

func spamRandBlock(conn *web3.Web3Connector) {
	maxBlock, err := conn.GetLatestBlocknum()
	if err != nil {
		logger.Error("error from GetLatestBlocknum(): %s", err)
		return
	}
	fcn := func(conn *web3.Web3Connector) bool {
		blockNum := rand.Int63n(maxBlock.Int64())
		_, err := conn.GetBlock(blockNum)
		if err != nil {
			logger.Error("error from GetBlock(%d): %s", blockNum, err)
			if err.Error() == "EOF" {
				return false
			}
		} else {
			logger.Debug("got block %d", blockNum)
		}
		return true
	}
	spamGeneric("random block requests", fcn)
}

func spamSequentialBlock(conn *web3.Web3Connector) {
	maxBlock, err := conn.GetLatestBlocknum()
	if err != nil {
		logger.Error("error from GetLatestBlocknum(): %s", err)
		return
	}
	fcn := func(conn *web3.Web3Connector) bool {
		for blockNum := int64(0); blockNum < maxBlock.Int64(); blockNum++ {
			_, err := conn.GetBlock(blockNum)
			if err != nil {
				logger.Error("error from GetBlock(%d): %s", blockNum, err)
				if err.Error() == "EOF" {
					return false
				}
			} else {
				logger.Debug("got block %d", blockNum)
			}
		}
		return true
	}
	spamGeneric("sequential block requests", fcn)
}

func spamChainId() {
	fcn := func(conn *web3.Web3Connector) bool {
		_, err := conn.GetChainID()
		if err != nil {
			logger.Error("error from GetChainId(): %s", err)
			if err.Error() == "EOF" {
				return false
			}
		}
		return true
	}
	spamGeneric("chain id requests", fcn)
}

func help() {
	errorMsg("")
}

func errorMsg(format string, args ...interface{}) {
	if format != "" {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
	}
	fmt.Fprint(os.Stderr, "Usage:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nCommands are:\n")
	fmt.Fprintf(os.Stderr, "  chainid (sends rapid requests to fullnode)\n")
	fmt.Fprintf(os.Stderr, "  block (sends rapid requests for the same block to fullnode)\n")
	fmt.Fprintf(os.Stderr, "  randblock (sends rapid requests for random blocks to fullnode)\n")
	fmt.Fprintf(os.Stderr, "  seqblock (sends rapid requests for sequential blocks to fullnode)\n")
}

func main() {
	lgr.SetWriter(os.Stderr)
	flag.CommandLine.Usage = help
	flag.Parse()
	if *verboseFlag {
		lgr.SetLogLevel("/", lgr.LvlDebug)
	}
	logger.Debug("Invoked with %s", os.Args)

	if *targetNodeFlag == "" {
		errorMsg("Target fullnode must be specified")
		return
	}

	argList := flag.Args()
	var cmdName string
	if len(argList) == 0 {
		errorMsg("command must be specified")
		return
	} else {
		cmdName = argList[0]
	}

	conn, err := web3.NewWeb3Connector(*targetNodeFlag, "Conn", logger)
	if err != nil {
		logger.Error("Cannot connect to %s: %s", *targetNodeFlag, err)
		return
	}
	defer conn.Close()

	switch cmdName {
	case "chainid":
		spamChainId()
	case "block":
		spamBlock()
	case "randblock":
		spamRandBlock(conn)
	case "seqblock":
		spamSequentialBlock(conn)
	default:
		errorMsg("Unrecognized command name: '%s'", cmdName)
		return
	}

	logger.Info("Done")
}
