// Basic utilities.
//
// Since these functions are used by other thunder modules,
// don't import thunder modules here to avoid circular dependencies.
package utils

import (
	// Standard imports
	"archive/zip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	// Vendor imports

	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/ssh/terminal"
)

var RunningTest bool = false

// Used by errors.
type TemporaryError interface {
	Error() string
	IsTemporary() bool
}

type TemporaryErrorImpl struct {
	// Use error instead of string to hold the flexibility to do more things when needed.
	err       error
	temporary bool
}

//------------------------------------------------------------------------------

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// InBenchmark returns true iff the code is being run as part of a Go benchmark.
func InBenchmark() bool {
	x := flag.Lookup("test.bench")
	if x == nil {
		return false
	}
	v := x.Value.String()
	return v != ""
}

func InTest() bool {
	return flag.Lookup("test.v") != nil || RunningTest
}

func EnsureRunningInTestCode() {
	if !InTest() {
		debug.Bug("called in non-test code")
	}
}

// TrimLeadingZeroes removes leading zeros for numerical conversion.
// Useful for fixed width strings that we don't want
// to accidentally interpret as octal.
func TrimLeadingZeroes(s string) string {
	if s == "" {
		return s
	}
	r := strings.TrimLeft(s, "0")
	if r == "" {
		return "0"
	}
	return r
}

// IntDivCeil rounds-up for integer divide.
func IntDivCeil(numerator int, denominator int) int {
	return (numerator + denominator - 1) / denominator
}

// Min returns the min value of two integers.
func Min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max returns the max value of two integers.
func Max(a int, b int) int {
	if a < b {
		return b
	}
	return a
}

// MaxAll returns the max value of a series of integers.
func MaxAll(vals ...int) int {
	max := int(math.MinInt64)
	for _, num := range vals {
		if num > max {
			max = num
		}
	}
	return max
}

// MinInt64 returns the min value of two int64s.
func MinInt64(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// MaxInt64 returns the max value of two int64s.
func MaxInt64(a int64, b int64) int64 {
	if a < b {
		return b
	}
	return a
}

// MapToJSONFile writes a string->string map to a file
func MapToJSONFile(filename *string, perm os.FileMode,
	data map[string]string) error {
	bytes, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		debug.Bug("JSON convertion error: %s (%v)", err, data)
	}
	return ioutil.WriteFile(*filename, bytes, perm)
}

// BytesToJSONFile writes []bytes to json with a key.
func BytesToJSONFile(filename *string, perm os.FileMode,
	key *string, val []byte,
) error {
	data := map[string]string{
		*key: hex.EncodeToString(val),
	}
	return MapToJSONFile(filename, perm, data)
}

// MapFromJSONBytes reads a string->string map from a slice of bytes
// of JSON data
func MapFromJSONBytes(bytes []byte) (map[string]string, error) {
	data := map[string]string{}
	err := json.Unmarshal(bytes, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// MapFromJSONFile reads a string->string map from a JSON file
func MapFromJSONFile(filename *string) (map[string]string, error) {
	bytes, err := ioutil.ReadFile(*filename)
	if err != nil {
		return nil, err
	}
	return MapFromJSONBytes(bytes)
}

// BytesFromJSONFile reads from a json file into []bytes with a key.
func BytesFromJSONFile(filename, key *string) (*[]byte, error) {
	data, err := MapFromJSONFile(filename)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(data[*key])
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ReadPassword reads in a password from stdin while not echoing keystrokes.
func ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := terminal.ReadPassword(0)
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// ReadVerifiedPassword asks user to type password twice to make sure the two passwords
// are identical. It is used for password based secret protection.
func ReadVerifiedPassword(prompt string) (string, error) {
	pwd, err := ReadPassword(prompt)
	if err != nil {
		return "", nil
	}

	verifyingPwd, err := ReadPassword("Verifying - " + prompt)
	if err != nil {
		return "", nil
	}

	if pwd != verifyingPwd {
		return "", fmt.Errorf("the typed passwords do not match")
	}
	return pwd, nil
}

// Safely resets timer by doing exactly what time.Timer.Reset godoc says.
func SafeTimerReset(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		<-t.C
	}
	t.Reset(d)
}

// ToString converts any Stringer-compliant *struct to a string.  If the ptr is nil, "<nil>"
// is returned
func ToString(s fmt.Stringer) string {
	if s == nil || reflect.ValueOf(s).IsNil() {
		return "<nil>"
	}
	return s.String()
}

func CheckNotNil(val interface{}, msg string) {
	if val == nil || reflect.ValueOf(val).IsNil() {
		debug.Fatal(msg)
	}
}

func CheckNotEmpty(val string, msg string) {
	if len(val) == 0 {
		debug.Fatal(msg)
	}
}

// MergeErrors merge multiple errors into one error. The error message
// begins with the message and each error is appended as a new line.
// If there is no error, return nil.
func MergeErrors(message string, errors []error) error {
	var builder strings.Builder
	builder.WriteString(message + "\n")
	hasError := false
	for _, err := range errors {
		if err != nil {
			hasError = true
			builder.WriteString(err.Error() + "\n")
		}
	}
	if hasError {
		return fmt.Errorf(builder.String())
	}
	return nil
}

// MoveToNewDir moves files "out of the way" by moving the files
// to a newly created  directory under `dir`,
// whose name starts with `newDirPrefix`
// MoveToNewDir will move the files one by one in the exact order specified by fileNames
func MoveToNewDir(dir string, newDirPrefix string, fileNames []string) (dirName string, err error) {
	// The newly created dir is meant to keep files that need to be moved
	// "out of the way" and is not removed.
	dirName, err = ioutil.TempDir(dir, newDirPrefix)
	if err != nil {
		return "", err
	}
	errRet := error(nil)
	for _, fileName := range fileNames {
		destName := filepath.Join(dirName, filepath.Base(fileName))
		err = os.Rename(fileName, destName)
		if err != nil {
			errRet = err
		}
	}
	if errRet != nil {
		return "", errRet
	}
	return dirName, nil
}

// ZipFiles compresses one or many files into a single zip archive file.
// Param 1: filename is the output zip file's name.
// Param 2: files is a list of files to add to the zip.
// this function does not handle any directory as input element.
func ZipFiles(filename string, files []string) error {

	newZipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

	// Add files to zip
	for _, file := range files {
		zipfile, err := os.Open(file)
		if err != nil {
			return err
		}

		// Get the file information
		info, err := zipfile.Stat()
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		// Using FileInfoHeader() above only uses the basename of the file. If we want
		// to preserve the folder structure we can overwrite this with the full path.
		//header.Name = file

		// Change to deflate to gain better compression
		// see http://golang.org/pkg/archive/zip/#pkg-constants
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		if _, err = io.Copy(writer, zipfile); err != nil {
			return err
		}
		zipfile.Close()
	}
	return nil
}

func UnZipFile(zipfile string, dir string) (*[]string, error) {
	zipReader, err := zip.OpenReader(zipfile)
	if err != nil {
		return nil, err
	}
	out := new([]string)
	for _, file := range zipReader.Reader.File {

		zippedFile, err := file.Open()
		if err != nil {
			//log.Fatal(err)
			return nil, err
		}
		defer zippedFile.Close()

		//targetDir := "./"
		targetDir := dir
		extractedFilePath := filepath.Join(
			targetDir,
			file.Name,
		)

		if file.FileInfo().IsDir() {
			//log.Println("Directory Created:", extractedFilePath)
			err = os.MkdirAll(extractedFilePath, file.Mode())
			if err != nil {
				return nil, err
			}
		} else {
			//log.Println("File extracted:", file.Name)

			outputFile, err := os.OpenFile(
				extractedFilePath,
				os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
				file.Mode(),
			)
			if err != nil {
				//log.Fatal(err)
				return nil, err
			}
			defer outputFile.Close()

			_, err = io.Copy(outputFile, zippedFile)
			if err != nil {
				//log.Fatal(err)
				return nil, err
			}
			*out = append(*out, file.Name)
		}
	}
	return out, nil
}

func CopyFile(src string, dst string) error {
	from, err := os.Open(src)
	if err != nil {
		return err
	}
	defer from.Close()

	to, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE, 0750)
	if err != nil {
		return err
	}
	defer to.Close()

	_, err = io.Copy(to, from)
	return err
}

// Wei to ether
func WeiToEther(value *big.Int) *big.Int {
	return new(big.Int).Div(value, big.NewInt(1e18))
}

// This is more efficient than append().
// See https://stackoverflow.com/a/40678026/278456
func ConcatCopyPreAllocate(slices [][]byte) []byte {
	var totalLen int
	for _, s := range slices {
		totalLen += len(s)
	}
	tmp := make([]byte, totalLen)
	var i int
	for _, s := range slices {
		i += copy(tmp[i:], s)
	}
	return tmp
}

func Uint64ToBytes(n uint64) []byte {
	var result [8]byte
	binary.LittleEndian.PutUint64(result[:], n)
	return result[:]
}

func BytesToUint64(bytes []byte) (uint64, []byte, error) {
	if len(bytes) < 8 {
		return 0, nil, fmt.Errorf("len(bytes) = %d < 4", len(bytes))
	}
	v := binary.LittleEndian.Uint64(bytes)
	return v, bytes[8:], nil
}

func Uint32ToBytes(n uint32) []byte {
	var result [4]byte
	binary.LittleEndian.PutUint32(result[:], n)
	return result[:]
}

func BytesToUint32(bytes []byte) (uint32, []byte, error) {
	if len(bytes) < 4 {
		return 0, nil, fmt.Errorf("len(bytes) = %d < 4", len(bytes))
	}
	v := binary.LittleEndian.Uint32(bytes)
	return v, bytes[4:], nil
}

func Uint16ToBytes(n uint16) []byte {
	var result [2]byte
	binary.LittleEndian.PutUint16(result[:], n)
	return result[:]
}

func BytesToUint16(bytes []byte) (uint16, []byte, error) {
	if len(bytes) < 2 {
		return 0, nil, fmt.Errorf("len(bytes) = %d < 2", len(bytes))
	}
	return binary.LittleEndian.Uint16(bytes), bytes[2:], nil
}

func StringToBytes(s string) []byte {
	bytes := []byte(s)
	return append(Uint16ToBytes(uint16(len(bytes))), bytes...)
}

func BytesToString(bytes []byte) (string, []byte, error) {
	n, bytes, err := BytesToUint16(bytes)
	if err != nil {
		return "", nil, err
	}
	if len(bytes) < int(n) {
		return "", nil, fmt.Errorf("len(bytes) = %d < %d", len(bytes), n)
	}
	s := string(bytes[:n])
	return s, bytes[n:], nil
}

func NewTemporaryError(err error, temporary bool) error {
	return TemporaryErrorImpl{err, temporary}
}

func (e TemporaryErrorImpl) Error() string {
	return e.err.Error()
}

func (e TemporaryErrorImpl) IsTemporary() bool {
	return e.temporary
}

func IsTemporaryError(err error) bool {
	if te, ok := err.(TemporaryError); ok && te.IsTemporary() {
		return true
	}
	return false
}

func StopSignalHandler(ch chan os.Signal) {
	signal.Stop(ch)
	close(ch)
}

func SliceContains(haystack []string, needle string) bool {
	return FindIndex(haystack, needle) < len(haystack)
}

func FindIndex(haystack []string, needle string) int {
	for i, v := range haystack {
		if v == needle {
			return i
		}
	}
	return len(haystack)
}

func Abs(n int) int {
	if n >= 0 {
		return n
	}
	return -n
}

// Helper function so we don't need this debug.Bug everywhere.
func MustEncodeToBytes(val interface{}) []byte {
	buf, err := rlp.EncodeToBytes(val)
	if err != nil {
		debug.Bug("Encoding failed: err %s, val: (%v)", err, val)
	}
	return buf
}
