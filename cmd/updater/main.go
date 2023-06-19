package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

const fullnodeDir = "/config/fastpath/fullnode"
const palaDir = "/config/fastpath/pala"

type nodeStatus struct {
	Identity              string
	Epoch                 string
	FreshestNotarizedHead string
	Address               string
}

type chainStatusResp struct {
	JsonRPC string
	Result  struct {
		MyEpoch                 string
		MyFreshestNotarizedHead string
		MyFinalizedHead         string
		MyHeight                int64
		NVoteInLastBlock        int64
		Proposers               map[string]nodeStatus
		Voters                  map[string]nodeStatus
		Bootnodes               map[string]nodeStatus
	}
}

// Parse "(81,1,8)" -> 81
func (c *chainStatusResp) getCurrentSession() int64 {
	s := strings.TrimPrefix(c.Result.MyEpoch, "(")
	s = strings.TrimSuffix(s, ")")
	if e, err := strconv.Atoi(strings.Split(s, ",")[0]); err == nil {
		return int64(e)
	}
	return 0
}

type overrideConfig struct {
	path string
}

func (c *overrideConfig) readInViper() (*viper.Viper, error) {
	b, err := ioutil.ReadFile(c.path)
	if err != nil {
		return nil, err
	}

	v := viper.New()
	v.SetConfigType("yaml")
	if err = v.ReadConfig(bytes.NewBuffer(b)); err != nil {
		return nil, err
	}

	return v, nil
}

func (c *overrideConfig) writeConfig(configMap interface{}) error {
	b, err := yaml.Marshal(configMap)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(c.path, b, 0644); err != nil {
		return err
	}

	return nil
}

func (c *overrideConfig) setIsFullNode() error {
	v, err := c.readInViper()
	if err != nil {
		return err
	}

	pala := v.Sub("pala").AllSettings()
	delete(pala, "isvoter")
	delete(pala, "isproposer")
	pala["isfullnode"] = true

	configMap := v.AllSettings()
	configMap["pala"] = pala

	if err = c.writeConfig(configMap); err != nil {
		return err
	}

	return nil
}

func (c *overrideConfig) overwriteTrustedBootnodes(bootnodes []string) error {
	v, err := c.readInViper()
	if err != nil {
		return err
	}

	// Set configMap['pala']['bootnode']['trusted'] = bootnodes
	var bootnodeMap map[string]interface{}
	pala := v.Sub("pala").AllSettings()
	if bootnode := v.Sub("pala.bootnode"); bootnode == nil {
		bootnodeMap = map[string]interface{}{
			"trusted": bootnodes,
		}
	} else {
		bootnodeMap = bootnode.AllSettings()
		bootnodeMap["trusted"] = bootnodes
	}

	pala["bootnode"] = bootnodeMap

	configMap := v.AllSettings()
	configMap["pala"] = pala
	if err = c.writeConfig(configMap); err != nil {
		return err
	}

	return nil
}

func NewFullnodeRunner(bootnodes []string) *FullnodeRunner {
	if _, err := os.Stat("/pala"); err != nil {
		exitOnError(err)
	}

	// Copy fullnode directory if not existed
	if _, err := os.Stat(fullnodeDir); os.IsNotExist(err) {
		cmd := exec.Command("cp", "-r", palaDir, fullnodeDir)
		if err := cmd.Run(); err != nil {
			exitOnError(err)
		}
	}

	override := overrideConfig{
		path: filepath.Join(fullnodeDir, "override.yaml"),
	}
	// Run override.yaml as a fullnode
	if err := override.setIsFullNode(); err != nil {
		exitOnError(err)
	}
	if err := override.overwriteTrustedBootnodes(bootnodes); err != nil {
		exitOnError(err)
	}

	return &FullnodeRunner{
		stoppedCh: make(chan struct{}),
	}
}

type FullnodeRunner struct {
	stoppedCh chan struct{}
	process   *os.Process
}

func (c *FullnodeRunner) Stopped() bool {
	opening := false
	select {
	case <-c.stoppedCh:
	default:
		opening = true
	}

	return !opening
}

func (c *FullnodeRunner) Stop() {
	if c.Stopped() {
		fmt.Println("fullnode runner was stopped")
		return
	}

	fmt.Println("fullnode runner is stopping")
	c.process.Kill()
	c.process.Wait()
	close(c.stoppedCh)
	fmt.Println("fullnode runner is stopped")
}

func (c *FullnodeRunner) Start() {
	cmd := exec.Command("/pala", "--configPath", "/config/fastpath/fullnode")
	if err := cmd.Start(); err != nil {
		fmt.Printf("Run pala in fullnode mode failed: %v\n", err)
		exitOnError(err)
		return
	}

	c.process = cmd.Process
	fmt.Printf("pala is running in fullnode mode, pid=%d\n", c.process.Pid)
}

func getChainStatus() (*chainStatusResp, error) {
	output, err := exec.Command("ipc", "dev_getStatus").Output()
	if err != nil {
		return nil, err
	}

	var status chainStatusResp
	if err := json.Unmarshal(output, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

func getR2HardforkSession() (int64, error) {
	configPath := "/config/fastpath/pala/hardfork.yaml"
	b, err := ioutil.ReadFile(configPath)
	if err != nil {
		return 0, err
	}

	rawConfs := []interface{}{}
	yaml.Unmarshal(b, &rawConfs)

	for _, rawConf := range rawConfs {
		v := viper.New()
		v.SetConfigType("yaml")
		b, err := yaml.Marshal(rawConf)
		if err != nil {
			return 0, err
		}

		if err = v.ReadConfig(bytes.NewBuffer(b)); err != nil {
			return 0, err
		}

		if v.GetString("committee.proposerList") == "r2" {
			return v.GetInt64("session"), nil
		}
	}

	return 0, fmt.Errorf("Cannot find committee.proposerList")
}

func exitOnError(err error) {
	if err != nil {
		fmt.Printf("%v\n", err)
		panic(err)
	}
}

func checkSessionReach(r2Session int64) bool {
	status, err := getChainStatus()
	exitOnError(err)
	s := status.getCurrentSession()
	fmt.Printf("current session: %v, hardfork session: %v\n", s, r2Session)
	return s >= r2Session
}

func Run() bool {
	bootnodes := flag.Args()

	runner := NewFullnodeRunner(bootnodes)
	go runner.Start()

	r2Session, err := getR2HardforkSession()
	exitOnError(err)

	syncSuccess := false
LOOP:
	for {
		select {
		case <-time.After(time.Second):
			if checkSessionReach(r2Session) {
				runner.Stop()
				<-runner.stoppedCh
				syncSuccess = true
				break LOOP
			}

		case <-runner.stoppedCh:
			break LOOP
		}
	}

	return syncSuccess
}

func main() {
	flag.Parse()

	if ret := Run(); ret {
		os.Exit(0)
	}
	os.Exit(1)
}
