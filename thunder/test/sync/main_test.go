//go:build !skipe2etest
// +build !skipe2etest

package sync

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/test"

	"github.com/stretchr/testify/require"
)

// What does the test do?
// (1) Run a node which is the proposer and voter to generate some blocks.
//     ( command: tools/pala-dev -g -d sync )
// (2) Run a bootnode which uses the generated data in (1) and a fullnode with empty data.
//     ( command: tools/pala-dev -r bootnode -d sync
//                tools/pala-dev -r fullnode -d sync )
// Expect the fullnode catchs up soon.
//
// If the test fails, manually run the tests to check whether the configuration is correct.
func TestSync(t *testing.T) {
	flag.Parse()
	if testing.Short() {
		fmt.Println("skipping sync tests in short mode")
		os.Exit(0)
	}

	req := require.New(t)
	var timeout int = 30

	fmt.Println("Starting proposer", time.Now())
	//log: 2019/11/26 00:27:32.157534 UTC INFO : [/PST]: thunder.go:184: process block 34 txs 1 receipts 1 committee 1 blocktime 2019-11-25 16:27:19 -0800 PST
	re := regexp.MustCompile(`^(\d+/\d+/\d+ \d+:\d+:\d+.\d+).*process block (\d+) txs (\d+).*$`)
	// clear chain data
	cmd, stdout, err := test.StartPalaWithOutput("-c")
	if err != nil {
		fmt.Println("Failed to clear chain pala-dev data", err)
		os.Exit(1)
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
	if err := cmd.Wait(); err != nil {
		fmt.Println("Failed to clear chain pala-dev data", err)
		os.Exit(1)
	}

	cmd, stdout, err = test.StartPalaWithOutput("-g", "-d", "sync")
	if err != nil {
		fmt.Println("Failed to start Pala", err)
		os.Exit(1)
	}
	var gblocks = 0
	go func(blocks *int) {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if ret := re.FindAllStringSubmatch(scanner.Text(), -1); ret != nil {
				fmt.Println("[proposer]>", ret)
				*blocks += 1
			}
		}
	}(&gblocks)
	time.Sleep(time.Duration(timeout) * time.Second)

	fmt.Println("Stopping proposer", time.Now())
	test.StopPala(cmd)
	cmd.Wait()
	fmt.Println("Generated blocks: ", gblocks)
	req.True(gblocks > 0, "there is no generated block")

	//start bootnode
	cmdBoot, err := test.StartPala("-d", "sync", "-r", "bootnode")
	if err != nil {
		fmt.Println("Failed to start Pala bootnode", err)
		os.Exit(1)
	}

	cmdFull, stdout, err := test.StartPalaWithOutput("-d", "sync", "-r", "fullnode")
	if err != nil {
		fmt.Println("Failed to start Pala fullnode", err)
		os.Exit(1)
	}

	var speed float64 = 0
	go func(pSpeed *float64) {
		scanner := bufio.NewScanner(stdout)
		var blocks = 0
		var txs = 0
		var startTime *time.Time
		var endTime *time.Time

		for scanner.Scan() {
			if ret := re.FindAllStringSubmatch(scanner.Text(), -1); ret != nil {
				fmt.Println("[fullnode]>", ret)
				blocks += 1
				if txNum, err := strconv.Atoi(ret[0][3]); err == nil {
					txs += txNum
				}

				if t, err := time.Parse("2006/01/02 15:04:05.000000", ret[0][1]); err == nil {
					if startTime == nil {
						startTime = &t
					} else {
						if endTime != nil && t.Sub(*endTime).Seconds() > 5 {
							test.StopPala(cmdFull)
						}
						endTime = &t
					}
				}
				if gblocks-1 <= blocks {
					test.StopPala(cmdFull)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			consumedSeconds := endTime.Sub(*startTime).Seconds()
			*pSpeed = float64(blocks) / consumedSeconds
			fmt.Printf("Total synced blocks %v, total TXs %v, time consumed %.2f\n", blocks, txs, consumedSeconds)
			fmt.Printf("Sync speed: %.2f blocks/second\n", *pSpeed)
		}
	}(&speed)
	cmdFull.Wait()
	fmt.Println("wait fullnode closed ", time.Now())
	test.StopPala(cmdBoot)
	cmdBoot.Wait()
	fmt.Println("wait bootnode closed ", time.Now())

	var expSpeed float64 = 10
	req.GreaterOrEqualf(speed, expSpeed, "Sync speed: %.2f, expect speed >= %.2f", speed, expSpeed)
}
