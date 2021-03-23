package krach

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufResize(t *testing.T) {
	b := &buf{
		index: 1,
		data:  make([]byte, defaultBufSize),
	}
	require.Len(t, b.data, defaultBufSize)

	b.resize(8192)
	assert.EqualValues(t, 8192, b.size())

	b.resize(64)
	assert.EqualValues(t, 64, b.size())
}
