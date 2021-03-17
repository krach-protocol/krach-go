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

func TestConcurrentConnAccess(t *testing.T) {
	t.Skip("Need to finish handshake first")
	conn, err := NewConn(DefaultConnectionConfig(), nil)
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
		s, _ := conn.NewStream(uint8(i))
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
	clientConf.IsClient = true
	clientConf.LocalIdentity = NewPrivateIdentity(clientCert, clientKey)

	serverConf := DefaultConnectionConfig()
	serverConf.IsClient = false
	serverConf.LocalIdentity = NewPrivateIdentity(serverCert, serverKey)

	clientConn, _ := NewConn(clientConf, clientNetConn)

	serverConn, _ := NewConn(serverConf, serverNetConn)

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

	encMsg := clientConn.csOut.Encrypt([]byte{}, nil, testMsg)
	assert.EqualValues(t, len(testMsg)+16, len(encMsg)) // Ensure that the message has a correct mac
	decrMsg, err := serverConn.csIn.Decrypt([]byte{}, nil, encMsg)
	require.NoError(t, err)

	assert.EqualValues(t, testMsg, decrMsg)
}

func TestOverallConnection(t *testing.T) {
	t.Skip("Skip until streams are figured out")
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

	clientConn, _ := NewConn(clientConf, clientNetConn)

	serverConn, _ := NewConn(serverConf, serverNetConn)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		fmt.Println("Running client handshake")
		err := clientConn.runClientHandshake()
		fmt.Println("Finished client handshake")
		assert.NoError(t, err, "Client handshake failed")
	}()

	go func() {
		defer wg.Done()
		fmt.Println("Running server handshake")
		err := serverConn.runServerHandshake()
		fmt.Println("Finished server handshake")
		assert.NoError(t, err, "Server handshake failed")
	}()

	fmt.Println("Waiting for handshake to finish")
	wg.Wait()

	fmt.Println("Handshake finished, testing cipher states")
	// we should now have valid cipher states on both sides
	testMsg := []byte(`Well, all information looks like noise until you break the code.`)

	encMsg := clientConn.csOut.Encrypt([]byte{}, nil, testMsg)
	assert.EqualValues(t, len(testMsg)+16, len(encMsg)) // Ensure that the message has a correct mac
	decrMsg, err := serverConn.csIn.Decrypt([]byte{}, nil, encMsg)
	require.NoError(t, err)

	assert.EqualValues(t, testMsg, decrMsg)

	fmt.Println("Verified cipher states, testing streams")

	// We have established that the cipherstates are valid

	streamCount := 1

	clientStreams := make([]*Stream, streamCount)
	serverStreams := make([]*Stream, streamCount)

	for i := 10; i < 10+streamCount; i++ {
		cs, err := clientConn.NewStream(uint8(i))
		require.NoError(t, err, "Failed to create client stream %d", i)
		clientStreams[i-10] = cs

		ss, err := serverConn.NewStream(uint8(i))
		require.NoError(t, err)
		serverStreams[i-10] = ss
	}

	wg = &sync.WaitGroup{}
	for i, cs := range clientStreams {
		wg.Add(2)

		go func(cs *Stream) {
			defer wg.Done()

			n, err := cs.Write(testMsg)
			assert.NoError(t, err)
			assert.EqualValues(t, len(testMsg), n)
			fmt.Printf("Stream %d has written\n", cs.id)
		}(cs)

		ss := serverStreams[i]

		go func(ss *Stream) {
			defer wg.Done()
			recvBuf := make([]byte, 1024)
			n, err := ss.Read(recvBuf)
			assert.NoError(t, err)
			assert.EqualValues(t, len(testMsg), n)
			assert.EqualValues(t, testMsg, recvBuf[:n])
		}(ss)
	}

	wg.Wait()
}
