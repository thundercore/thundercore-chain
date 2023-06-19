// ThunderTool
//
// CLI app for maintain, configure and support Thunder in Prod.

package main

import (
	// Standard imports.
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/commitsha1"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	// Vendor imports.
	cli "gopkg.in/urfave/cli.v1"
)

var (
	app = cli.NewApp()
)

var ThunderToolVersionSpec = SemanticVersion + "-" + commitsha1.CommitSha1

func init() {
	// Initialize the CLI app and start ThunderTool.
	app.Name = "thundertool"
	app.Version = ThunderToolVersionSpec
	app.Usage = "a helper of configuring, operating and maintaining thunder token network"
	app.Copyright = "Copyright 2019 Team Thunder"
	app.Commands = []cli.Command{
		genAuxNetKeyCommand,
		genVotingKeyCommand,
		genStakeInKeyCommand,
		getKeyCommand,
		genCommInfoCommand,
		verifyCommInfoCommand,
	}
	app.Flags = append(app.Flags, thunderToolFlags...)
}

func main() {
	lgr.SetLogLevel("/", lgr.LvlWarning)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
