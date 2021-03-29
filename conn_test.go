// +build !multiplexing

package krach

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/smolcert/smolcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNonMultiplexedConnection(t *testing.T) {
	rootCert, rootKey, err := smolcert.SelfSignedCertificate("root", time.Now(), time.Now().Add(time.Minute*5), nil)
	require.NoError(t, err)
	clientCert, clientKey, err := smolcert.ClientCertificate("client", 1, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(t, err)
	serverCert, serverKey, err := smolcert.ClientCertificate("server", 2, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(t, err)

	clientNetConn, serverNetConn := net.Pipe()
	clientConf := DefaultConnectionConfig()
	clientConf.IsClient = true
	clientConf.LocalIdentity = NewPrivateIdentity(clientCert, clientKey)

	serverConf := DefaultConnectionConfig()
	serverConf.IsClient = false
	serverConf.LocalIdentity = NewPrivateIdentity(serverCert, serverKey)

	clientConn, _ := newConn(clientConf, clientNetConn)

	serverConn, _ := newConn(serverConf, serverNetConn)

	wg := &sync.WaitGroup{}
	wg.Add(1)

	var clientErr, serverErr error

	go func() {
		defer wg.Done()
		fmt.Println("Running server handshake")
		serverErr = serverConn.runServerHandshake()
	}()

	fmt.Println("Running client handshake")
	clientErr = clientConn.runClientHandshake()
	fmt.Println("Finished client handshake")

	fmt.Println("Waiting for handshake to finish")
	require.NoError(t, clientErr, "Client handshake failed")
	wg.Wait()
	require.NoError(t, serverErr, "Server handshake failed")

	fmt.Println("Handshake finished, testing cipher states")
	// we should now have valid cipher states on both sides
	testMsg := []byte(`Well, all information looks like noise until you break the code.`)

	encMsg := clientConn.hcOut.cs.Encrypt([]byte{}, nil, testMsg)
	assert.EqualValues(t, len(testMsg)+16, len(encMsg)) // Ensure that the message has a correct mac
	decrMsg, err := serverConn.hcIn.cs.Decrypt([]byte{}, nil, encMsg)
	require.NoError(t, err)

	assert.EqualValues(t, testMsg, decrMsg)
}

func BenchmarkNonMultiplexedConnection(b *testing.B) {
	rootCert, rootKey, err := smolcert.SelfSignedCertificate("root", time.Now(), time.Now().Add(time.Minute*5), nil)
	require.NoError(b, err)
	clientCert, clientKey, err := smolcert.ClientCertificate("client", 1, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(b, err)
	serverCert, serverKey, err := smolcert.ClientCertificate("server", 2, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(b, err)

	clientNetConn, serverNetConn := net.Pipe()
	clientConf := DefaultConnectionConfig()
	clientConf.IsClient = true
	clientConf.LocalIdentity = NewPrivateIdentity(clientCert, clientKey)

	serverConf := DefaultConnectionConfig()
	serverConf.IsClient = false
	serverConf.LocalIdentity = NewPrivateIdentity(serverCert, serverKey)

	clientConn, _ := newConn(clientConf, clientNetConn)

	serverConn, _ := newConn(serverConf, serverNetConn)

	wg := &sync.WaitGroup{}
	wg.Add(1)

	var clientErr, serverErr error

	go func() {
		defer wg.Done()
		serverErr = serverConn.runServerHandshake()
	}()

	clientErr = clientConn.runClientHandshake()
	require.NoError(b, clientErr, "Client handshake failed")
	wg.Wait()
	require.NoError(b, serverErr, "Server handshake failed")

	payloadLen := 8192
	randPayload := make([]byte, payloadLen)
	n := 0
	for n < payloadLen {
		n1, err := rand.Read(randPayload)
		require.NoError(b, err)
		n = n + n1
	}

	wg = &sync.WaitGroup{}
	wg.Add(2)
	b.ResetTimer()
	go func() {
		var totalBytes int64
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			clientConn.SetDeadline(time.Now().Add(time.Second * 10))
			n, err := clientConn.Write(randPayload)
			assert.NoError(b, err)
			assert.EqualValues(b, payloadLen, n)
			totalBytes = totalBytes + int64(n)
		}
		b.SetBytes(totalBytes)
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, payloadLen)
		for i := 0; i < b.N; i++ {
			serverConn.SetDeadline(time.Now().Add(time.Second * 10))
			n, err := serverConn.Read(buf)
			assert.NoError(b, err)
			assert.EqualValues(b, payloadLen, n)
			assert.EqualValues(b, randPayload, buf[:n])
		}
	}()
	wg.Wait()
}
