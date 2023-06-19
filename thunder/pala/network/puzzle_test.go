package network

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestKeccak256CPUReversePuzzle(t *testing.T) {
	req := require.New(t)
	p := Keccak256CPUReversePuzzle{}
	challengeMax := uint32(500000)
	puzzle, solution := p.GeneratePuzzle(challengeMax)

	t.Run("invalid case", func(t *testing.T) {
		invalidSol := []byte("invalidSol")
		err := p.VerifyPuzzle(puzzle, solution, invalidSol)
		req.Error(err)
	})

	t.Run("normal case", func(t *testing.T) {
		sol, err := p.SolvePuzzle(puzzle)
		req.NoError(err)
		err = p.VerifyPuzzle(puzzle, solution, sol)
		req.NoError(err)
	})

	t.Run("msgMarshalling", func(t *testing.T) {
		req := require.New(t)
		msg := keccak256CPUReversePuzzleMsg{
			challengeMax:    500000,
			salt:            1111,
			keccak256Result: crypto.Keccak256([]byte("data")),
		}
		bytes := msg.ToBytes()

		var unmarshalled keccak256CPUReversePuzzleMsg
		err := unmarshalled.FromBytes(append(bytes, []byte("invalidTrailingData")...))
		req.Error(err)

		err = unmarshalled.FromBytes(bytes)
		req.NoError(err)
		req.Equal(msg.challengeMax, unmarshalled.challengeMax)
		req.Equal(msg.salt, unmarshalled.salt)
		req.Equal(msg.keccak256Result, unmarshalled.keccak256Result)
	})
}

func TestCookieClientPuzzle(t *testing.T) {
	req := require.New(t)
	p := CookieClientPuzzle{}
	dataSize := uint32(1024)
	puzzle, solution := p.GeneratePuzzle(dataSize)
	req.Equal(dataSize, uint32(len(puzzle)))

	t.Run("invalid case", func(t *testing.T) {
		invalidSol := []byte("invalidSol")
		err := p.VerifyPuzzle(puzzle, solution, invalidSol)
		req.Error(err)
	})

	t.Run("normal case", func(t *testing.T) {
		sol, err := p.SolvePuzzle(puzzle)
		req.NoError(err)
		err = p.VerifyPuzzle(puzzle, solution, sol)
		req.NoError(err)
	})
}

func TestFailingPuzzle(t *testing.T) {
	req := require.New(t)
	p := FailingPuzzle{}
	puzzle, solution := p.GeneratePuzzle(0)
	sol, err := p.SolvePuzzle(puzzle)
	req.NoError(err)
	err = p.VerifyPuzzle(puzzle, solution, sol)
	req.Error(err)
}

func TestClientPuzzleExtension(t *testing.T) {
	req := require.New(t)
	e := ClientPuzzleExtension{
		puzzleTypes:       []string{"type1", "type2"},
		challengeResponse: []byte("challengeResponse"),
	}
	bytes := e.ToBytes()

	var unmarshalled ClientPuzzleExtension
	err := unmarshalled.FromBytes(bytes)
	req.NoError(err)
	req.Equal(e.puzzleTypes, unmarshalled.puzzleTypes)
	req.Equal(e.challengeResponse, unmarshalled.challengeResponse)
}

func TestClientPuzzleMgr(t *testing.T) {
	invalidPuzzle := "invalidType"
	validPuzzles := []string{Keccak256CPUReversePuzzleName, CookieClientPuzzleName}
	mgr := NewClientPuzzleMgr(&ClientPuzzleMgrCfg{
		Preference: append(validPuzzles, invalidPuzzle),
	})

	t.Run("get puzzle", func(t *testing.T) {
		req := require.New(t)
		_, err := mgr.GetPuzzle(invalidPuzzle)
		req.Error(err)

		p, err := mgr.GetPuzzle(Keccak256CPUReversePuzzleName)
		req.NoError(err)
		req.IsType(&Keccak256CPUReversePuzzle{}, p)

		p, err = mgr.GetPuzzle(CookieClientPuzzleName)
		req.NoError(err)
		req.IsType(&CookieClientPuzzle{}, p)
	})

	t.Run("get supported puzzles", func(t *testing.T) {
		req := require.New(t)
		puzzles := mgr.GetSupportedPuzzles()
		req.Equal(puzzles, validPuzzles)
	})

	t.Run("preference", func(t *testing.T) {
		req := require.New(t)
		p, err := mgr.SelectPuzzle(validPuzzles)
		req.NoError(err)
		req.Equal(validPuzzles[0], p.Name())

		p, err = mgr.SelectPuzzle([]string{CookieClientPuzzleName, Keccak256CPUReversePuzzleName})
		req.NoError(err)
		req.Equal(validPuzzles[0], p.Name())

		p, err = mgr.SelectPuzzle([]string{CookieClientPuzzleName})
		req.NoError(err)
		req.Equal(CookieClientPuzzleName, p.Name())

		_, err = mgr.SelectPuzzle([]string{"some", "not", "supported", "puzzles"})
		req.Error(err)
	})
}

func BenchmarkKeccak256CPUReversePuzzle(b *testing.B) {
	p := Keccak256CPUReversePuzzle{}
	for difficulty := uint32(20000); difficulty < 1500000; difficulty *= 2 {
		puzzle, solution := p.GeneratePuzzle(difficulty)
		name := fmt.Sprintf("SolvePuzzle-%d", difficulty)
		b.Run(name, func(b *testing.B) {
			req := require.New(b)
			for i := 0; i < b.N; i++ {
				sol, err := p.SolvePuzzle(puzzle)
				req.NoError(err)
				err = p.VerifyPuzzle(puzzle, solution, sol)
				req.NoError(err)
			}
		})
	}
}
