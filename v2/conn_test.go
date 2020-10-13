package krach

import (
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConcurrentConnAccess(t *testing.T) {
	conn, err := NewConn(nil)
	require.NoError(t, err)

	conn.testBuf = []byte{}

	streamWriteSize := 4096

	wg := &sync.WaitGroup{}

	streamCount := 100

	for i := 0; i < streamCount; i++ {
		wg.Add(1)
		buf := make([]byte, streamWriteSize)
		n, err := rand.Read(buf)
		require.NoError(t, err)
		assert.EqualValues(t, streamWriteSize, n)
		s, _ := conn.newStream(uint8(i))
		go func(i int, s *Stream, buf []byte) {

			s.Write(buf)
			wg.Done()
		}(i, s, buf)
	}
	wg.Wait()

	assert.EqualValues(t, streamWriteSize*streamCount, len(conn.testBuf))
}
