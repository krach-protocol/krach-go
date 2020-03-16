package krach

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/phayes/freeport"
	"github.com/smolcert/smolcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	localAddr = "[::1]:58123"

	rootCert *smolcert.Certificate
	rootKey  ed25519.PrivateKey
)

func TestMain(m *testing.M) {
	localPort, err := freeport.GetFreePort()
	if err != nil {
		log.Fatal(err)
	}
	localAddr = fmt.Sprintf("127.0.0.1:%d", localPort)

	rootCert, rootKey, err = smolcert.SelfSignedCertificate("testRoot", time.Time{}, time.Time{}, nil)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(m.Run())
}

func TestOverallLocalConnection(t *testing.T) {
	testMsg := []byte("Case schloss die Augen. Fand den geriffelten EIN-Schalter.")
	randData := make([]byte, 2000)
	rand.Read(randData)
	testMsg = append(testMsg, randData...)
	serverCert, serverKey, err := smolcert.SignedCertificate(
		"krachTestServer", 2, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, rootKey, rootCert.Subject,
	)
	require.NoError(t, err)

	l, err := Listen(localAddr, &ConnectionConfig{
		LocalIdentity:    NewPrivateIdentity(serverCert, serverKey),
		HandshakeTimeout: time.Second * 2,
	}, smolcert.NewCertPool(rootCert))
	require.NoError(t, err)
	require.NotEmpty(t, l)
	defer l.Close()

	var serverConn net.Conn

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn, err = l.Accept()
		require.NoError(t, err)
		assert.NotEmpty(t, serverConn)
		defer serverConn.Close()
		if krachConn, ok := serverConn.(*Conn); !ok {
			panic("We somehow got a wrong net.Conn implementation. Should never be possible")
			return
		} else {
			require.NoError(t, krachConn.Handshake())
		}

		recvBuf := make([]byte, len(testMsg))
		n, err := io.ReadFull(serverConn, recvBuf)
		require.NoError(t, err)
		assert.Equal(t, len(testMsg), n)
		assert.Equal(t, testMsg, recvBuf[:n])
	}()

	clientCert, clientKey, err := smolcert.SignedCertificate("krachTestClient",
		2, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, rootKey, rootCert.Subject)
	require.NoError(t, err)

	clientConn, err := Dial(localAddr, &ConnectionConfig{
		LocalIdentity: NewPrivateIdentity(clientCert, clientKey),
	}, smolcert.NewCertPool(rootCert))
	require.NoError(t, err)
	assert.NotEmpty(t, clientConn)
	err = clientConn.Handshake()
	require.NoError(t, err)
	defer clientConn.Close()

	n, err := clientConn.Write(testMsg)
	require.NoError(t, err)
	assert.Equal(t, len(testMsg), n)

	wg.Wait()
}

func runHandshake(b *testing.B, serverCert, clientCert *smolcert.Certificate, serverKey, clientKey ed25519.PrivateKey) {
	l, err := Listen(localAddr, &ConnectionConfig{
		LocalIdentity:    NewPrivateIdentity(serverCert, serverKey),
		ReadTimeout:      time.Second * 1,
		WriteTimeout:     time.Second * 1,
		HandshakeTimeout: time.Second * 2,
	}, smolcert.NewCertPool(rootCert))
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()

	var serverConn net.Conn
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn, err = l.Accept()
		if err != nil {
			b.Log(err)
			return
		}
		defer serverConn.Close()

		if krachConn, ok := serverConn.(*Conn); !ok {
			panic("We somehow got a wrong net.Conn implementation. Should never be possible")
		} else {
			if err := krachConn.Handshake(); err != nil {
				b.Log(err)
			}
		}
	}()

	clientConn, err := Dial(localAddr, &ConnectionConfig{
		LocalIdentity:    NewPrivateIdentity(clientCert, clientKey),
		ReadTimeout:      time.Second * 1,
		WriteTimeout:     time.Second * 1,
		HandshakeTimeout: time.Second * 2,
	}, smolcert.NewCertPool(rootCert))
	err = clientConn.Handshake()
	if err != nil {
		b.Fatal(err)
	}
	clientConn.Close()
	wg.Wait()
}

func BenchmarkKrachHandshake(b *testing.B) {
	serverCert, serverKey, err := smolcert.SignedCertificate(
		"krachTestServer", 3, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, rootKey, rootCert.Subject,
	)
	if err != nil {
		b.Fatal(err)
	}

	clientCert, clientKey, err := smolcert.SignedCertificate("krachTestClient",
		4, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, rootKey, rootCert.Subject)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		runHandshake(b, serverCert, clientCert, serverKey, clientKey)
	}
}

func runThroughput(b *testing.B, serverConn net.Conn, clientConn *Conn, msg []byte, msgCount int) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	totalExpectedBytes := len(msg) * msgCount
	go func() {
		defer wg.Done()
		receivedBytes := 0
		recvBuf := make([]byte, 1500)
		i := 0
		for n, err := serverConn.Read(recvBuf); ; n, err = serverConn.Read(recvBuf) {
			receivedBytes += n
			i++
			if receivedBytes >= totalExpectedBytes {
				break
			}
			if err == io.EOF {
				// Connection has been closed
				break
			}
			require.NoError(b, err, "Failed to read message %d", i+1)
		}
		assert.EqualValues(b, totalExpectedBytes, receivedBytes)
	}()

	var totalBytes int64
	var i int
	for i = 0; i < msgCount; i++ {
		n, err := clientConn.Write(msg)
		require.NoError(b, err, "After %d messages in iteration %d", i, b.N)
		// Assert that we have written all bytes successfully, no matter the actual frame size
		assert.Equal(b, len(msg), n)
		totalBytes += int64(n)
	}
	assert.EqualValues(b, msgCount, i)
	assert.EqualValues(b, totalExpectedBytes, totalBytes)
	wg.Wait()
	b.SetBytes(totalBytes)
}

func BenchmarkThroughput(b *testing.B) {

	testMsg := make([]byte, 1450)
	rand.Reader.Read(testMsg)
	msgCount := 1024

	serverCert, serverKey, err := smolcert.SignedCertificate(
		"krachTestServer", 5, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, rootKey, rootCert.Subject,
	)
	require.NoError(b, err)

	l, err := Listen(localAddr, &ConnectionConfig{
		LocalIdentity:    NewPrivateIdentity(serverCert, serverKey),
		ReadTimeout:      time.Second * 1,
		WriteTimeout:     time.Second * 1,
		HandshakeTimeout: time.Second * 2,
	}, smolcert.NewCertPool(rootCert))
	require.NoError(b, err)
	require.NotEmpty(b, l)
	defer l.Close()

	var serverConn net.Conn

	// Run the handshake manually here, to avoid having the first handshake to have an impact
	// on the throughpout
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn, err = l.Accept()
		if err != nil {
			b.Log(err)
			return
		}
		assert.NotEmpty(b, serverConn)
		if krachConn, ok := serverConn.(*Conn); ok {
			if err := krachConn.Handshake(); err != nil {
				b.Logf("Server side handshake failed: %s", err)
			}
		} else {
			b.Logf("We somehow got a wrong net.Conn implementation. Should never be possible")
		}
	}()

	clientCert, clientKey, err := smolcert.SignedCertificate("krachTestClient",
		2, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, rootKey, rootCert.Subject)
	require.NoError(b, err)

	clientConn, err := Dial(localAddr, &ConnectionConfig{
		LocalIdentity:    NewPrivateIdentity(clientCert, clientKey),
		ReadTimeout:      time.Second * 1,
		WriteTimeout:     time.Second * 1,
		HandshakeTimeout: time.Second * 2,
	}, smolcert.NewCertPool(rootCert))
	err = clientConn.Handshake()
	require.NoError(b, err)
	defer clientConn.Close()
	defer serverConn.Close()
	wg.Wait()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {

		runThroughput(b, serverConn, clientConn, testMsg, msgCount)
	}
}
