package krach

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockConn(t *testing.T) {
	conn := newMockConnection()

	clientAddr := &net.UDPAddr{
		IP:   net.ParseIP("fe80::10"),
		Port: 1500,
	}
	serverAddr := &net.UDPAddr{
		IP:   net.ParseIP("fe80:20"),
		Port: 1800,
	}

	clientSock, err := conn.Listen(clientAddr)
	require.NoError(t, err)
	serverSock, err := conn.Listen(serverAddr)
	require.NoError(t, err)

	testMsg := []byte("Hello connection")
	n1, err := clientSock.WriteTo(testMsg, serverAddr)
	require.NoError(t, err)

	pktBuf := make([]byte, 1500)
	n2, addr, err := serverSock.ReadFrom(pktBuf)
	require.NoError(t, err)

	assert.EqualValues(t, n1, n2)
	assert.EqualValues(t, testMsg, pktBuf[:n2])
	assert.EqualValues(t, addr, clientAddr)

	testMsg = []byte("Hello back")
	n1, err = serverSock.WriteTo(testMsg, clientAddr)

	n2, addr, err = clientSock.ReadFrom(pktBuf)
	require.NoError(t, err)

	assert.EqualValues(t, n1, n2)
	assert.EqualValues(t, testMsg, pktBuf[:n2])
	assert.EqualValues(t, serverAddr, addr)
}
