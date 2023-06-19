package benchmark

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/golang/snappy"
	"github.com/stretchr/testify/require"
)

const dataSize = 1e6 // 1 MB

func getSameData() []byte {
	var input []byte
	for i := 0; i < dataSize; i++ {
		input = append(input, 0)
	}
	return input
}

func getPatternedData() []byte {
	var input []byte
	for i := 0; i < dataSize; i++ {
		input = append(input, byte(i%256))
	}
	return input
}

func getRandomData() []byte {
	r := rand.New(rand.NewSource(0))
	var input []byte
	for i := 0; i < dataSize; i++ {
		input = append(input, byte(r.Int()%256))
	}
	return input
}

func TestSnappy(t *testing.T) {
	req := require.New(t)

	inputs := map[string][]byte{
		"same":      getSameData(),
		"patterned": getPatternedData(),
		"random":    getRandomData(),
	}

	for name, input := range inputs {
		output := snappy.Encode(nil, input)
		tmp, err := snappy.Decode(nil, output)
		req.NoError(err)
		req.Equal(input, tmp)

		fmt.Printf("Data Rate Savings (%s): %.2f\n",
			name, float64(len(input)-len(output))/float64(len(input))*100.0)
	}
}

func BenchmarkSnappyEncode(b *testing.B) {
	b.Run("same", func(b *testing.B) {
		input := getSameData()
		for i := 0; i < b.N; i++ {
			snappy.Encode(nil, input)
		}
	})

	b.Run("patterned", func(b *testing.B) {
		input := getPatternedData()
		for i := 0; i < b.N; i++ {
			snappy.Encode(nil, input)
		}
	})

	b.Run("random", func(b *testing.B) {
		input := getRandomData()
		for i := 0; i < b.N; i++ {
			snappy.Encode(nil, input)
		}
	})
}

func BenchmarkSnappyDecode(b *testing.B) {
	b.Run("same", func(b *testing.B) {
		input := getSameData()
		output := snappy.Encode(nil, input)
		for i := 0; i < b.N; i++ {
			snappy.Decode(nil, output)
		}
	})

	b.Run("patterned", func(b *testing.B) {
		input := getPatternedData()
		output := snappy.Encode(nil, input)
		for i := 0; i < b.N; i++ {
			snappy.Decode(nil, output)
		}
	})

	b.Run("random", func(b *testing.B) {
		input := getRandomData()
		output := snappy.Encode(nil, input)
		for i := 0; i < b.N; i++ {
			snappy.Decode(nil, output)
		}
	})
}
