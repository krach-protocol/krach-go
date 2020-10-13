package krach

import (
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/smolcert/smolcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConcurrentConnAccess(t *testing.T) {
	t.Skip("Need to finish handshake first")
	conn, err := NewConn(DefaultConnectionConfig())
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

func TestHandshake(t *testing.T) {
	rootCert, rootKey, err := smolcert.SelfSignedCertificate("root", time.Now(), time.Now().Add(time.Minute*5), nil)
	require.NoError(t, err)
	clientCert, clientKey, err := smolcert.ClientCertificate("client", 1, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(t, err)
	serverCert, serverKey, err := smolcert.ClientCertificate("server", 2, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(t, err)

	clientNetConn, serverNetConn := net.Pipe()
	clientConf := DefaultConnectionConfig()
	clientConf.isClient = true
	clientConf.LocalIdentity = NewPrivateIdentity(clientCert, clientKey)

	serverConf := DefaultConnectionConfig()
	serverConf.isClient = false
	serverConf.LocalIdentity = NewPrivateIdentity(serverCert, serverKey)

	clientConn, _ := NewConn(clientConf)
	clientConn.netConn = clientNetConn

	serverConn, _ := NewConn(serverConf)
	serverConn.netConn = serverNetConn

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		err := clientConn.runClientHandshake()
		assert.NoError(t, err, "Client handshake failed")
		wg.Done()
	}()

	go func() {
		err := serverConn.runServerHandshake()
		assert.NoError(t, err, "Server handshake failed")
		wg.Done()
	}()

	wg.Wait()
}
