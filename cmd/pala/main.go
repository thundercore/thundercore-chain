package main

import (
	"fmt"
	_ "net/http/pprof"
	"os"
	"syscall"

	// Thunder imports.

	"github.com/ethereum/go-ethereum/thunder/pala/server"
	"github.com/ethereum/go-ethereum/thunder/pala/types"

	thunderconfig "github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/commitsha1"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	// Vendor imports

	"github.com/ethereum/go-ethereum/node"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
)

type ConsensusId = types.ConsensusId

const SemanticVersion = "0.8.2"

const MaxAllowedOpenFd = 640 * 1024

var (
	ThunderVersionSpec = SemanticVersion + ":" + commitsha1.CommitSha1
	dataDir            string
	configPath         string
	printVersion       bool
	logToConsole       bool
	noFdCheck          bool
	ethMetrics         bool
	setHead            uint64
)

func run(cmd *cobra.Command) error {
	cmd.SilenceUsage = true
	if printVersion {
		fmt.Println(ThunderVersionSpec)
		return nil
	}

	if utils.InTest() {
		debug.Bug("the binary pala should not run in the testing mode")
	}

	var err error
	if !noFdCheck {
		var rLimit syscall.Rlimit
		err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		if err != nil {
			debug.Bug("Failed to get RLIMIT_NOFILE: err: %s", err)
		}
		if rLimit.Max < MaxAllowedOpenFd {
			orig := rLimit
			rLimit.Cur = MaxAllowedOpenFd
			rLimit.Max = MaxAllowedOpenFd
			err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
			if err != nil {
				fmt.Printf("Failed to increase RLIMIT_NOFILE from %v to %v: err: %s\n",
					orig, rLimit, err)
				os.Exit(1)
			}
		}
	}

	a, err := server.ReadConfigFiles(configPath)
	if err != nil {
		return err
	}
	err = server.SetLogLevelFromConfig(a)
	thunderconfig.InitHardforkConfig(configPath)
	if logToConsole {
		err = server.SetupLogging(server.StdoutLogOutputMode, "", "")
	} else {
		err = server.SetupRotatingLogging()
	}
	if err != nil {
		return err
	}

	server.StartPprofServer()

	if dataDir == node.DefaultDataDir() {
		dataDir = server.DataDirFromConfig()
	}

	if setHead > 0 {
		palaChain, ethBackend, err := server.NewPalaChainFromConfig(ThunderVersionSpec, dataDir)
		if err != nil {
			return err
		}
		defer ethBackend.Stop()
		palaChain.SetHead(setHead)
		return nil
	}

	pala, err := server.NewPalaNodeFromConfig(ThunderVersionSpec, dataDir)
	if err != nil {
		return xerrors.Errorf("NewPalaNodeFromConfig failed: %s", err)
	}
	if err := pala.Start(); err != nil {
		return xerrors.Errorf("Start pala node failed: %s", err)
	}
	defer utils.StopSignalHandler(pala.Signal())

	pala.Wait()
	return pala.Stop()
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "pala",
		Short: "Pala binary runs with config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd)
		},
	}

	rootCmd.Flags().StringVar(&dataDir, "datadir", node.DefaultDataDir(), "Blockchain data directory")
	rootCmd.Flags().StringVar(&configPath, "configPath", "", "Configuration file(s) path")
	rootCmd.Flags().BoolVar(&ethMetrics, "metrics", false, "Enable ETH metrics")
	rootCmd.Flags().BoolVar(&printVersion, "version", false, "Print the version and exit")
	rootCmd.Flags().BoolVar(&logToConsole, "logToConsole", false, "Whether to log to the console")
	rootCmd.Flags().BoolVar(&noFdCheck, "noFdCheck", false, "Whether to check max allowed open fd")
	rootCmd.Flags().Uint64Var(&setHead, "setHead", 0, "Set blockchain head to the given number for an emergency and testing")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
