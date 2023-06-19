// A tools for running single process Pala tests
//
// e.g. simulate a thunder deployment for 10 seconds and write metrics
// ./bin/benchmark --blockDelayInMS 1000 --k 1 --packetDelayInMS 200 --nProposers 5 --nVoters 32 --runningTimeInS 10 --enableMetrics

package main

import (
	"flag"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/thunder/pala/consensus"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils"

	"github.com/spf13/cobra"

	"github.com/ethereum/go-ethereum/params"
)

// Prepare arguments.
var (
	// root cmd vars
	times          int
	runningTimeInS int

	enableMetrics bool

	nVoters    int
	nProposers int
	nBootnodes int

	k int

	packetDelayInMS int
	blockDelayInMS  int
)

func run() {

	if nProposers < 1 || nVoters < 1 {
		debug.Bug("expected at least one proposer and voter")
	}

	// create honest nodes
	proposerIds := testutils.MakeIds("p", nProposers)
	voterIds := testutils.MakeIds("v", nVoters)
	bootnodeIds := testutils.MakeIds("b", nBootnodes)

	palaParams := consensus.DefaultPalaParams
	palaParams.K = params.MaxUnnotarizedProposals

	utils.RunningTest = true
	params.MaxUnnotarizedProposals.SetTestValueAtSession(int64(k), 0)

	cfg := testutils.PalaNodeClusterConfig{
		ProposerIds:     proposerIds,
		VoterIds:        voterIds,
		BootnodesITrust: bootnodeIds,
		Params:          palaParams,
		BlockDelayInMs:  uint64(blockDelayInMS),
		UseMetrics:      enableMetrics,
	}
	nodes := testutils.NewPalaNodeCluster(cfg)

	firstProposer := nodes.Proposers[0]
	proposerChain := firstProposer.GetBlockChainForTest()

	// connect everyone
	cfm := testutils.NewConnectionFakeMap()
	wg := sync.WaitGroup{}
	stopCh := make(chan interface{})
	testutils.ConnectAllWithFilter(testutils.ConcatMediatorSlices(nodes.Proposers, nodes.Bootnodes), nodes.Voters, cfm,
		network.Delay{Mean: time.Duration(packetDelayInMS) * time.Millisecond},
		&wg, stopCh, network.EmptyFilter)

	// start all nodes
	nodes.StartAllNodes()

	// Warm up.
	proposerNotificationChan := firstProposer.NewNotificationChannel()
WarmUpLoop:
	for e := range proposerNotificationChan {
		switch e.(type) {
		case consensus.FreshestNotarizedChainExtendedEvent:
		case consensus.FinalizedChainExtendedEvent:
			break WarmUpLoop
		}
	}
	firstProposer.RemoveNotificationChannel(proposerNotificationChan)

	// Wait a while to have stable results.
	time.Sleep(time.Second)

	// Wait the designated time.
	begin := proposerChain.GetFinalizedHead()
	time.Sleep(time.Duration(runningTimeInS) * time.Second)
	end := proposerChain.GetFinalizedHead()
	nBlock := end.GetNumber() - begin.GetNumber()

	// stop all nodes
	err := nodes.Stop()
	if err != nil {
		fmt.Printf("error stopping nodes %s", err)
	}

	// Note that the metrics record data from before the timer starts so the numbers recorded by the metrics
	// do not match the numbers printed below.
	//firstProposer.PrintMetrics()

	fmt.Printf("----------------------\nblocks\ttime\tblocks per second\n")
	fmt.Printf("%d\t%d\t%.1f\n", nBlock, runningTimeInS, float64(nBlock)/float64(runningTimeInS))
}

func main() {

	dontCare := false
	flag.BoolVar(&dontCare, "test.v", false, "required flag to use testing helper functions; the value doesn't matter")

	var rootCmd = &cobra.Command{
		Use:   "cmd",
		Short: "use to benchmark pala with various configuration parameters",
		Run: func(cmd *cobra.Command, args []string) {
			for i := 0; i < times; i++ {
				run()
			}
		},
	}

	// Use a higher log level to avoid overheads.
	_ = lgr.SetLogLevel("/", lgr.LvlError)

	rootCmd.Flags().IntVar(&times, "times", 1, "number of running trials")
	rootCmd.Flags().IntVar(&runningTimeInS, "runningTimeInS", 1, "running trial time in second")

	rootCmd.Flags().BoolVar(&enableMetrics, "enableMetrics", false, "enable metrics output")

	rootCmd.Flags().IntVar(&nVoters, "nVoters", 1, "number of voters")
	rootCmd.Flags().IntVar(&nProposers, "nProposers", 1, "number of proposers")
	rootCmd.Flags().IntVar(&nBootnodes, "nBootnodes", 0, "number of bootnodes")

	rootCmd.Flags().IntVar(&k, "k", 1, "outstanding unnotarized proposal")

	rootCmd.Flags().IntVar(&packetDelayInMS, "packetDelayInMS", 0, "packet delay time in millisecond")
	rootCmd.Flags().IntVar(&blockDelayInMS, "blockDelayInMS", 0, "block time in millisecond")

	rootCmd.Execute()
}
