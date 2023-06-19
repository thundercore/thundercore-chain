package rmonitor_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/thunder/pala/rmonitor"
)

func TestGetStacks(t *testing.T) {
	getStackBuffer := "github.com/ethereum/go-ethereum/thunder/pala/rmonitor.getStackBuffer"

	stacks, _ := rmonitor.GetCurrentStacks()
	if stacks[0].LastFunction() != getStackBuffer {
		t.Fatalf(
			"Get current stack failed: %v != %v",
			stacks[0].LastFunction(),
			getStackBuffer,
		)
	}
}
