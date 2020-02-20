package krach

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/connctd/noise"
	"github.com/smolcert/smolcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	localAddr = "[::1]:58123"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestOverallLocalConnection(t *testing.T) {
	testMsg := []byte("Case schloss die Augen. Fand den geriffelten EIN-Schalter.")
	serverCert, serverKey, err := smolcert.SelfSignedCertificate(
		"krachTestServer", time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil,
	)
	require.NoError(t, err)

	l, err := Listen(localAddr, &ConnectionConfig{
		StaticKey: noise.NewPrivateSmolIdentity(serverCert, serverKey),
	})
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
			t.Fatalf("We somehow got a wrong net.Conn implementation. Should never be possible")
			return
		} else {
			require.NoError(t, krachConn.Handshake())
		}

		recvBuf := make([]byte, 1024)
		n, err := serverConn.Read(recvBuf)
		require.NoError(t, err)
		assert.Equal(t, len(testMsg), n)
		assert.Equal(t, testMsg, recvBuf[:n])
	}()

	clientCert, clientKey, err := smolcert.SignedCertificate("krachTestClient",
		2, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, serverKey, serverCert.Subject)
	require.NoError(t, err)

	clientConn, err := Dial(localAddr, &ConnectionConfig{
		StaticKey: noise.NewPrivateSmolIdentity(clientCert, clientKey),
	})
	err = clientConn.Handshake()
	require.NoError(t, err)
	defer clientConn.Close()

	require.NoError(t, err)
	assert.NotEmpty(t, clientConn)

	n, err := clientConn.Write(testMsg)
	require.NoError(t, err)
	assert.Equal(t, len(testMsg), n)

	wg.Wait()
}

func runHandshake(b *testing.B, serverCert, clientCert *smolcert.Certificate, serverKey, clientKey ed25519.PrivateKey) {
	l, err := Listen(localAddr, &ConnectionConfig{
		StaticKey: noise.NewPrivateSmolIdentity(serverCert, serverKey),
	})
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
			b.Fatal(err)
		}
		defer serverConn.Close()
		if err != nil {
			b.Fatal(err)
		}
		if krachConn, ok := serverConn.(*Conn); !ok {
			panic("We somehow got a wrong net.Conn implementation. Should never be possible")
		} else {
			if err := krachConn.Handshake(); err != nil {
				b.Fatal(err)
			}
		}
	}()

	clientConn, err := Dial(localAddr, &ConnectionConfig{
		StaticKey: noise.NewPrivateSmolIdentity(clientCert, clientKey),
	})
	err = clientConn.Handshake()
	if err != nil {
		b.Fatal(err)
	}
	clientConn.Close()
	wg.Wait()
}

func BenchmarkKrachHandshake(b *testing.B) {
	serverCert, serverKey, err := smolcert.SelfSignedCertificate(
		"krachTestServer", time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil,
	)
	if err != nil {
		b.Fatal(err)
	}

	clientCert, clientKey, err := smolcert.SignedCertificate("krachTestClient",
		2, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, serverKey, serverCert.Subject)
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
	go func() {
		defer wg.Done()
		recvBuf := make([]byte, 1500)
		i := 0
		for n, err := serverConn.Read(recvBuf); i < msgCount; n, err = serverConn.Read(recvBuf) {
			require.NoError(b, err, "Failed to read message %d", i+1)
			assert.Equal(b, len(msg), n, "At message %d", i+1)
			i++
		}
		require.Equal(b, msgCount, i)
	}()

	var totalBytes int64
	for i := 0; i <= msgCount; i++ {
		n, err := clientConn.Write(msg)
		require.NoError(b, err, "After %d messages", i)
		assert.Equal(b, len(msg), n)
		totalBytes = totalBytes + int64(n)
	}
	wg.Wait()
	b.SetBytes(totalBytes)
}

func BenchmarkThroughput(b *testing.B) {

	testMsg := make([]byte, 1450)
	rand.Reader.Read(testMsg)
	msgCount := 1024

	serverCert, serverKey, err := smolcert.SelfSignedCertificate(
		"krachTestServer", time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil,
	)
	require.NoError(b, err)

	l, err := Listen(localAddr, &ConnectionConfig{
		StaticKey: noise.NewPrivateSmolIdentity(serverCert, serverKey),
	})
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
		require.NoError(b, err)
		assert.NotEmpty(b, serverConn)
		if krachConn, ok := serverConn.(*Conn); !ok {
			b.Fatalf("We somehow got a wrong net.Conn implementation. Should never be possible")
			return
		} else {
			require.NoError(b, krachConn.Handshake())
		}
	}()

	clientCert, clientKey, err := smolcert.SignedCertificate("krachTestClient",
		2, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, serverKey, serverCert.Subject)
	require.NoError(b, err)

	clientConn, err := Dial(localAddr, &ConnectionConfig{
		StaticKey: noise.NewPrivateSmolIdentity(clientCert, clientKey),
	})
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
