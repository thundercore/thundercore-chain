package utils

import (
	// Standard imports
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"

	// Vendor imports
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringUtils(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("0", TrimLeadingZeroes("00000"))
	assert.Equal("120", TrimLeadingZeroes("00120"))
	assert.Equal("", TrimLeadingZeroes(""))
}

func TestIntUtils(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(8, IntDivCeil(3*10, 4), "Ceil incorrect.")
}

func TestJsonUtils(t *testing.T) {
	assert := assert.New(t)

	dir, err := ioutil.TempDir("", "utils_test_")
	assert.Nil(err)
	defer os.RemoveAll(dir)

	t.Log(dir)
	f := filepath.Join(dir, "test.json")
	key := "key"
	val := []byte("value")
	BytesToJSONFile(&f, 0666, &key, val)
	back, err := BytesFromJSONFile(&f, &key)
	assert.Nil(err)
	assert.Equal(val, *back, "incorrect value")

	tm := time.Now().Unix()
	rand.Seed(tm)
	t.Log("random seed: ", tm)
	dict := make(map[string]string)
	var k, v [20]byte
	for i := 0; i < 10; i++ {
		rand.Read(k[:])
		rand.Read(v[:])
		key := hex.EncodeToString(k[:])
		val := hex.EncodeToString(v[:])
		dict[key] = val
	}
	f = filepath.Join(dir, "test2.json")
	MapToJSONFile(&f, 0666, dict)
	nm, _ := MapFromJSONFile(&f)
	assert.True(reflect.DeepEqual(dict, nm))

	// MapFromJSONFile: non existent file
	f = filepath.Join(dir, "NON-EXISTENT")
	_, err = MapFromJSONFile(&f)
	assert.NotNil(err)

	// MapFromJSONFile: invalid JSON content
	tempfile, err := ioutil.TempFile(dir, "invalid.json")
	assert.Nil(err)
	s := tempfile.Name()
	_, err = MapFromJSONFile(&s)
	assert.NotNil(err)

	// BytesFromJSONFile: invalid JSON content
	key = ""
	_, err = BytesFromJSONFile(&s, &key)
	assert.NotNil(err)

	// BytesFromJSONFile: trigger hex string decode failure
	key = "K"
	tempfile, err = ioutil.TempFile(dir, "non-hex-str-value.json")
	assert.Nil(err)
	s = tempfile.Name()
	tempfile.Write([]byte("{\"K\": \"V\"}\n"))
	tempfile.Seek(0, 0)
	_, err = BytesFromJSONFile(&s, &key)
	assert.NotNil(err)
}

var minTests = []struct {
	a        int
	b        int
	expected int
}{
	{0, 0, 0},
	{1, 1, 1},
	{-1, -1, -1},
	{-1, 0, -1},
	{0, 100, 0},
	{10, 54, 10},
}

func TestMin(t *testing.T) {
	assert := assert.New(t)

	for _, test := range minTests {
		actual := Min(test.a, test.b)
		actual64 := MinInt64(int64(test.a), int64(test.b))
		assert.Equal(test.expected, actual,
			fmt.Sprintf("Min(%d, %d) incorrect", test.a, test.b))
		assert.Equal(int64(test.expected), actual64,
			fmt.Sprintf("Min(%d, %d) incorrect", test.a, test.b))
	}
}

var maxTests = []struct {
	a        int
	b        int
	expected int
}{
	{0, 0, 0},
	{1, 1, 1},
	{-1, -1, -1},
	{-1, 0, 0},
	{0, 100, 100},
	{10, 54, 54},
}

func TestMax(t *testing.T) {
	assert := assert.New(t)

	for _, test := range maxTests {
		actual := Max(test.a, test.b)
		actual64 := MaxInt64(int64(test.a), int64(test.b))
		assert.Equal(test.expected, actual,
			fmt.Sprintf("Max(%d, %d) incorrect", test.a, test.b))
		assert.Equal(int64(test.expected), actual64,
			fmt.Sprintf("MaxInt64(%d, %d) incorrect", test.a, test.b))
	}
	assert.Equal(10, MaxAll(10, 9, 8), "MaxAll failed for first val")
	assert.Equal(10, MaxAll(8, 9, 10), "MaxAll failed for last val")
	assert.Equal(-10, MaxAll(-80, -10, -80), "MaxAll failed for mid val")
}

func TestMutex(t *testing.T) {
	c := CheckedLock{}

	assert.PanicsWithValue(t,
		fmt.Sprint("BUG: Double unlocking sync.Mutex"),
		func() {
			c.Unlock()
		})

	notLockedMsg := "mutex is not locked"
	assert.PanicsWithValue(t,
		fmt.Sprintf("BUG: %s", notLockedMsg),
		func() {
			c.CheckIsLocked(notLockedMsg)
		})

	assert.NotPanics(t,
		func() {
			c.Lock()
			//lint:ignore SA2001 why do we have empty critical section
			c.Unlock()
		})
}

type typeForTestingToString struct {
	s string
	i int
}

func (t typeForTestingToString) String() string {
	return "0xdeadbeef"
}

func TestToString(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("<nil>", ToString(nil))

	tmp := typeForTestingToString{"", 0}
	assert.Equal("0xdeadbeef", ToString(&tmp))
}

func TestTimerReset(t *testing.T) {
	assert := assert.New(t)

	// The time.NewTimer API is quite hard to test against.
	//
	// To know whether a timer has stopped, one can use:
	// 1. The return value of Timer.Stop()
	// 2. The receive only channel Timer.C
	// but both have the potential side effect of draining Timer.C,
	// which would cause SafeTimerReset() to block when it tries to drain the same
	// channel again.

	timer := time.NewTimer(0)
	// This Sleep(1) call looks wrong and indeed the timer may or may not have
	// expired after the Sleep(1) returns but as long as we don't drain timer.C,
	// SafeTimerReset() can work correctly.
	time.Sleep(time.Nanosecond)
	SafeTimerReset(timer, 0)
	assert.NotNil(<-timer.C)

	timer = time.NewTimer(10 * time.Second)
	SafeTimerReset(timer, 0)
	assert.NotNil(<-timer.C)
}

func TestFetch(t *testing.T) {
	assert := assert.New(t)

	// fileURI: non-existent file
	tempdir, err := ioutil.TempDir("", "utils_fetch_test_")
	assert.Nil(err)
	defer os.RemoveAll(tempdir)
	f := filepath.Join(tempdir, "NON-EXISTENT")
	buf, err := Fetch(fmt.Sprintf("file://%s", f), 10)
	assert.NotNil(err)
	assert.Nil(buf)

	// fileURI: successful content retrieval
	test_bytes := []byte("TEST")
	tempfile, err := ioutil.TempFile("", "utils_fetch_test_")
	assert.Nil(err)
	defer os.Remove(tempfile.Name())
	tempfile.Write(test_bytes)
	buf, err = Fetch(fmt.Sprintf("file://%s", tempfile.Name()), len(test_bytes))
	assert.Nil(err)
	assert.Equal(buf, test_bytes)

	// fileURI: intentionally provide too much data
	buf, err = Fetch(fmt.Sprintf("file://%s", tempfile.Name()), len(test_bytes)-1)
	assert.NotNil(err)
	assert.Nil(buf)
}

func TestMoveToNewDir(t *testing.T) {
	require := require.New(t)

	tmpDir, err := ioutil.TempDir("", "utils_move_to_tmp_dir_test_")
	require.NoError(err)
	defer os.RemoveAll(tmpDir)

	f, err := os.OpenFile(filepath.Join(tmpDir, "F"), os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(err)

	destDir, err := MoveToNewDir(tmpDir, "archive", []string{f.Name()})
	require.NoError(err)
	fInfo, err := os.Stat(filepath.Join(destDir, filepath.Base(f.Name())))
	require.NoError(err)
	require.NotNil(fInfo)
}

func TestNilCheckWithTypedNil(t *testing.T) {
	require := require.New(t)

	defer func() {
		//lint:ignore SA9003 should it be removed
		if r := recover(); r != nil {
		}
	}()

	var foo *CheckedLock
	CheckNotNil(foo, "should not be nil")
	require.Fail("didn't panic when it should have")
}

func TestFdLimit(t *testing.T) {
	require := require.New(t)

	orig := GetFdLimit()
	require.NotEqual(-1, orig)

	var limit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit)
	require.NoError(err)
	require.Equal(orig, int(limit.Cur))

	newValue := limit.Max
	if runtime.GOOS == "darwin" {
		newValue = uint64(24576)
	}
	err = SetFdLimit(newValue)
	require.NoError(err)
	require.Equal(newValue, uint64(GetFdLimit()))

	err = SetFdLimit(uint64(orig))
	require.NoError(err)
	require.Equal(orig, GetFdLimit())
}
