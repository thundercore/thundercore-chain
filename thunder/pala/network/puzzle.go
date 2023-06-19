package network

import (
	"bytes"
	cryptoRand "crypto/rand"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/xerrors"
)

var supportedPuzzles map[string]Puzzle

const (
	Keccak256CPUReversePuzzleName = "Keccak256CPUReversePuzzle"
	CookieClientPuzzleName        = "CookieClientPuzzle"
	FailingPuzzleName             = "FailingPuzzle"
)

func init() {
	supportedPuzzles = make(map[string]Puzzle)
	supportedPuzzles[Keccak256CPUReversePuzzleName] = &Keccak256CPUReversePuzzle{}
	supportedPuzzles[CookieClientPuzzleName] = &CookieClientPuzzle{}
	supportedPuzzles[FailingPuzzleName] = &FailingPuzzle{}

	rand.Seed(time.Now().UnixNano())
}

func GetPreferenceForTest() []string {
	utils.EnsureRunningInTestCode()
	return []string{CookieClientPuzzleName}
}

func GetClientPuzzleMgrCfgForTest() *ClientPuzzleMgrCfg {
	utils.EnsureRunningInTestCode()
	return &ClientPuzzleMgrCfg{
		Preference: GetPreferenceForTest(),
		Difficulty: 32,
	}
}

type ClientPuzzleMgrCfg struct {
	Preference []string
	Difficulty uint32
}

type ClientPuzzleMgr struct {
	puzzles    map[string]Puzzle
	preference []string
	difficulty uint32
}

func (m *ClientPuzzleMgr) GetSupportedPuzzles() []string {
	return m.preference
}

func (m *ClientPuzzleMgr) SelectPuzzle(puzzles []string) (Puzzle, error) {
	puzzleMap := make(map[string]bool)
	for _, v := range puzzles {
		puzzleMap[v] = true
	}
	for _, v := range m.preference {
		if _, ok := puzzleMap[v]; ok {
			return m.GetPuzzle(v)
		}
	}
	return nil, xerrors.New("No supported puzzle found")
}

func (m *ClientPuzzleMgr) GetPuzzle(name string) (Puzzle, error) {
	if p, ok := m.puzzles[name]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("puzzle(%s) not supported", name)
}

func (m *ClientPuzzleMgr) GetDifficulty() uint32 {
	return m.difficulty
}

func NewClientPuzzleMgr(cfg *ClientPuzzleMgrCfg) *ClientPuzzleMgr {
	puzzles := make(map[string]Puzzle)
	validPuzzles := make([]string, 0)
	for _, v := range cfg.Preference {
		p, ok := supportedPuzzles[v]
		if !ok {
			logger.Warn("Invalid puzzel type: %s", v)
			continue
		}
		puzzles[v] = p
		validPuzzles = append(validPuzzles, v)
	}
	return &ClientPuzzleMgr{
		puzzles:    puzzles,
		preference: validPuzzles,
		difficulty: cfg.Difficulty,
	}
}

type ClientPuzzleExtension struct {
	puzzleTypes       []string
	challengeResponse []byte
}

func (e *ClientPuzzleExtension) ToBytes() []byte {
	var out [][]byte
	out = append(out, utils.Uint16ToBytes(uint16(len(e.puzzleTypes))))
	for _, v := range e.puzzleTypes {
		out = append(out, utils.StringToBytes(v))
	}
	out = append(out, e.challengeResponse)
	return utils.ConcatCopyPreAllocate(out)
}

func (e *ClientPuzzleExtension) FromBytes(bytes []byte) error {
	nTypes, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return err
	}

	var puzzleType []string
	for i := 0; i < int(nTypes); i++ {
		var t string
		t, bytes, err = utils.BytesToString(bytes)
		if err != nil {
			return err
		}
		puzzleType = append(puzzleType, t)
	}

	e.puzzleTypes = puzzleType
	e.challengeResponse = bytes
	return nil
}

type Puzzle interface {
	GeneratePuzzle(uint32) ([]byte, []byte)
	SolvePuzzle([]byte) ([]byte, error)
	VerifyPuzzle([]byte, []byte, []byte) error
	Name() string
}

type keccak256CPUReversePuzzleMsg struct {
	challengeMax    uint32
	salt            uint16
	keccak256Result []byte
}

func (m *keccak256CPUReversePuzzleMsg) ToBytes() []byte {
	out := utils.Uint32ToBytes(m.challengeMax)
	out = append(out, utils.Uint16ToBytes(m.salt)...)
	return append(out, m.keccak256Result...)
}

func (m *keccak256CPUReversePuzzleMsg) FromBytes(bytes []byte) error {
	challengeMax, bytes, err := utils.BytesToUint32(bytes)
	if err != nil {
		return err
	}

	salt, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return err
	}

	if len(bytes) != 32 {
		return fmt.Errorf("len(remainingBytes) = %d != %d", len(bytes), 32)
	}

	m.challengeMax = challengeMax
	m.salt = salt
	m.keccak256Result = bytes
	return nil
}

type Keccak256CPUReversePuzzle struct {
}

func (p *Keccak256CPUReversePuzzle) GeneratePuzzle(challengeMax uint32) ([]byte, []byte) {
	saltBN, err := cryptoRand.Int(cryptoRand.Reader, big.NewInt(math.MaxUint16))
	if err != nil {
		debug.Bug("Cannot generate salt for puzzle.")
	}
	solutionBN, err := cryptoRand.Int(cryptoRand.Reader, big.NewInt(int64(challengeMax)))
	if err != nil {
		debug.Bug("Cannot generate challenge for puzzle.")
	}
	salt := uint16(saltBN.Uint64())
	solution := uint32(solutionBN.Uint64())
	puzzle := keccak256CPUReversePuzzleMsg{
		challengeMax:    challengeMax,
		salt:            salt,
		keccak256Result: crypto.Keccak256(p.hashingBytes(solution, salt)),
	}
	return puzzle.ToBytes(), utils.Uint32ToBytes(solution)
}

func (p *Keccak256CPUReversePuzzle) SolvePuzzle(puzzleBytes []byte) ([]byte, error) {
	var puzzle keccak256CPUReversePuzzleMsg
	if err := puzzle.FromBytes(puzzleBytes); err != nil {
		return nil, err
	}

	for _, v := range rand.Perm(int(puzzle.challengeMax)) {
		solution := uint32(v)
		hash := crypto.Keccak256(p.hashingBytes(solution, puzzle.salt))
		if bytes.Compare(hash, puzzle.keccak256Result) == 0 {
			return utils.Uint32ToBytes(solution), nil
		}
	}

	return nil, xerrors.New("Failed to find solution")
}

func (p *Keccak256CPUReversePuzzle) VerifyPuzzle(puzzle, solution, clientSolution []byte) error {
	if bytes.Compare(solution, clientSolution) != 0 {
		return xerrors.New("Wrong solution")
	}
	return nil
}

func (p *Keccak256CPUReversePuzzle) hashingBytes(solution uint32, salt uint16) []byte {
	out := append(utils.Uint32ToBytes(solution), utils.Uint16ToBytes(salt)...)
	return append(out, []byte("Keccak256CPUReversePuzzle")...)
}

func (p *Keccak256CPUReversePuzzle) Name() string {
	return Keccak256CPUReversePuzzleName
}

type CookieClientPuzzle struct {
}

func (p *CookieClientPuzzle) GeneratePuzzle(dataSize uint32) ([]byte, []byte) {
	var input []byte
	for i := uint32(0); i < dataSize; i++ {
		input = append(input, byte(rand.Int()%256))
	}
	return input, input
}

func (p *CookieClientPuzzle) SolvePuzzle(puzzle []byte) ([]byte, error) {
	return puzzle, nil
}

func (p *CookieClientPuzzle) VerifyPuzzle(_, solution, clientSolution []byte) error {
	if bytes.Compare(solution, clientSolution) == 0 {
		return nil
	}
	return xerrors.New("Wrong solution")
}

func (p *CookieClientPuzzle) Name() string {
	return CookieClientPuzzleName
}

type FailingPuzzle struct {
}

func (p *FailingPuzzle) GeneratePuzzle(_ uint32) ([]byte, []byte) {
	return []byte{}, []byte{}
}

func (p *FailingPuzzle) SolvePuzzle(_ []byte) ([]byte, error) {
	return []byte{}, nil
}

func (p *FailingPuzzle) VerifyPuzzle(_ []byte, _ []byte, _ []byte) error {
	return xerrors.New("Wrong solution")
}

func (p *FailingPuzzle) Name() string {
	return FailingPuzzleName
}
