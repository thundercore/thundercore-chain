package testutils

import (
	// Standard imports
	"testing"
	"time"

	// Vendor imports
	"github.com/stretchr/testify/require"
)

func TestPredicates(t *testing.T) {
	require := require.New(t)

	result := WaitForPredicate(
		func() PredResult {
			return PredAbort()
		}, 1*time.Second, 50*time.Millisecond)
	require.Equal(result, false, "didn't handle abort")
	result = WaitForPredicate(
		func() PredResult {
			return PredFail()
		}, 1*time.Second, 50*time.Millisecond)
	require.Equal(result, false, "didn't handle fail")
	result = WaitForPredicate(
		func() PredResult {
			return PredOk()
		}, 1*time.Second, 50*time.Millisecond)
	require.Equal(result, true, "didn't handle ok")

	r1 := PredOk()
	r2 := PredFail()
	require.NotEqual(r1, r2, "didn't find unequality")
	r3 := PredOk()
	require.Equal(r1, r3, "didn't detect equality")
	r4 := PredResult{}
	require.NotEqual(r1, r4, "bogus constant not detected")
	require.NotEqual(r2, r4, "bogus constant not detected")
	require.NotEqual(r3, r4, "bogus constant not detected")
}
