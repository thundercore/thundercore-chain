package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
)

type CommitteeV1 struct {
	CommID    uint
	PublicKey bls.PublicKey
}

// Arguments for this function are: Root directory to traverse, and the number of committee members
func main() {
	// Add help
	flag.String("h", "", "Args: 1: Path to keystore dirs on local file system. "+
		"2: # of committee members")
	flag.Parse()

	if len(os.Args) != 3 {
		debug.Fatal("Incorrect number of required arguments.")
	}
	directory := os.Args[1]
	numberCommittee, err := strconv.Atoi(os.Args[2])
	if err != nil {
		debug.Fatal("Unable to convert committee number.", err)
	}

	// Accel directory.
	accelFilePath := filepath.Join(directory, "accel")

	// Merge for each committee member.
	commKeys := &[]bls.PublicKey{}
	for i := 0; i < numberCommittee; i++ {
		comm := fmt.Sprintf("pubvotekey_comm_%d.json", i)
		commFilePath := filepath.Join(accelFilePath, comm)

		// Read file into new struct.
		commV1 := &CommitteeV1{}
		bytes, err := ioutil.ReadFile(commFilePath)
		if err != nil {
			debug.Fatal("Unable to read file: ", err)
		}
		json.Unmarshal(bytes, commV1)

		// Update to new struct. Using
		*commKeys = append(*commKeys, commV1.PublicKey)
	}

	// Output file directory/name
	accelOutputFilePath := filepath.Join(accelFilePath, "pubvotekeys_comm.json")

	// Write to accel and all committee members.
	buf, err := json.MarshalIndent(commKeys, "", " ")
	if err != nil {
		debug.Fatal("Failed to marshal keys to bytes.")
	}
	err = ioutil.WriteFile(accelOutputFilePath, buf, 0644)
	if err != nil {
		debug.Fatal("Failed to write file. ", err)
	}

	// Write to committee members.
	for i := 0; i < numberCommittee; i++ {
		temp := fmt.Sprintf("comm_%d", i)
		outputFilePath := filepath.Join(directory, temp, "pubvotekeys_comm.json")

		err = ioutil.WriteFile(outputFilePath, buf, 0644)
		if err != nil {
			debug.Fatal("Failed to write file. ", err)
		}
	}
}
