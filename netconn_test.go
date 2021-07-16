// +build !multiplexing

package krach

import (
	"bytes"
	"crypto/ed25519"
	cryptrand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/smolcert/smolcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalhostConnection(t *testing.T) {
	rootCert, rootKey, err := smolcert.SelfSignedCertificate("root", time.Now(), time.Now().Add(time.Minute*5), nil)
	require.NoError(t, err)
	clientCert, clientKey, err := smolcert.ClientCertificate("client", 1, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(t, err)
	serverCert, serverKey, err := smolcert.ClientCertificate("server", 2, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(t, err)

	clientConf := DefaultConnectionConfig()
	clientConf.IsClient = true
	clientConf.LocalIdentity = NewPrivateIdentity(clientCert, clientKey)

	serverConf := DefaultConnectionConfig()
	serverConf.IsClient = false
	serverConf.LocalIdentity = NewPrivateIdentity(serverCert, serverKey)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	serverPort := 34672
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)

	doneChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	var server *Conn
	var client *Conn
	go func() {
		defer wg.Done()
		l, err := net.Listen("tcp", serverAddr)
		if err != nil {
			errChan <- err
		}
		require.NoError(t, err, "Failed to listen on %s", serverAddr)
		doneChan <- true
		tcpConn, err := l.Accept()
		if err != nil {
			errChan <- err
		}
		require.NoError(t, err, "Failed to accept connection")
		server, err = Server(tcpConn, serverConf)
		if err != nil {
			errChan <- err
		}
		require.NoError(t, err, "Failed to establish encrypted connection")
	}()

	select {
	case <-doneChan:
	case err := <-errChan:
		t.Fatalf("Received error from server side setup: %s", err)
	}

	go func() {
		defer wg.Done()
		client, err = Dial(serverAddr, clientConf)
		require.NoError(t, err, "Failed to dial encrypted connection")
	}()

	wg.Wait()
	defer server.Close()
	defer client.Close()

	payload := []byte("ping")

	wg = &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := client.Write(payload)
		if err != nil {
			errChan <- err
		}
	}()

	buf := make([]byte, 128)
	n, err := server.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, len(payload), n)
	assert.EqualValues(t, payload, buf[:n])
	wg.Wait()
}

func BenchmarkHandshake(b *testing.B) {
	rootCert, rootKey, err := smolcert.SelfSignedCertificate("root", time.Now(), time.Now().Add(time.Minute*5), nil)
	require.NoError(b, err)
	clientCert, clientKey, err := smolcert.ClientCertificate("client", 1, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(b, err)
	serverCert, serverKey, err := smolcert.ClientCertificate("server", 2, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(b, err)

	clientConf := DefaultConnectionConfig()
	clientConf.IsClient = true
	clientConf.LocalIdentity = NewPrivateIdentity(clientCert, clientKey)

	serverConf := DefaultConnectionConfig()
	serverConf.IsClient = false
	serverConf.LocalIdentity = NewPrivateIdentity(serverCert, serverKey)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	serverPort := 34672
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)

	doneChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	var server *Conn
	var client *Conn
	b.ResetTimer()
	go func() {
		defer wg.Done()
		l, err := net.Listen("tcp", serverAddr)
		if err != nil {
			errChan <- err
		}
		require.NoError(b, err, "Failed to listen on %s", serverAddr)
		doneChan <- true
		tcpConn, err := l.Accept()
		if err != nil {
			errChan <- err
		}
		require.NoError(b, err, "Failed to accept connection")
		server, err = Server(tcpConn, serverConf)
		if err != nil {
			errChan <- err
		}
		require.NoError(b, err, "Failed to establish encrypted connection")
	}()

	select {
	case <-doneChan:
	case err := <-errChan:
		b.Fatalf("Received error from server side setup: %s", err)
	}

	go func() {
		defer wg.Done()
		client, err = Dial(serverAddr, clientConf)
		require.NoError(b, err, "Failed to dial encrypted connection")
	}()
	wg.Wait()
	defer server.Close()
	defer client.Close()
}

func BenchmarkNonMultiplexedConnectionLocalhost(b *testing.B) {
	rootCert, rootKey, err := smolcert.SelfSignedCertificate("root", time.Now(), time.Now().Add(time.Minute*5), nil)
	require.NoError(b, err)
	clientCert, clientKey, err := smolcert.ClientCertificate("client", 1, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(b, err)
	serverCert, serverKey, err := smolcert.ClientCertificate("server", 2, time.Now(), time.Now().Add(time.Minute*5), nil, rootKey, rootCert.Subject)
	require.NoError(b, err)

	clientConf := DefaultConnectionConfig()
	clientConf.IsClient = true
	clientConf.LocalIdentity = NewPrivateIdentity(clientCert, clientKey)

	serverConf := DefaultConnectionConfig()
	serverConf.IsClient = false
	serverConf.LocalIdentity = NewPrivateIdentity(serverCert, serverKey)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	serverPort := 34672
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)

	doneChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	var server *Conn
	var client *Conn
	go func() {
		defer wg.Done()
		l, err := net.Listen("tcp", serverAddr)
		if err != nil {
			errChan <- err
		}
		require.NoError(b, err, "Failed to listen on %s", serverAddr)
		doneChan <- true
		tcpConn, err := l.Accept()
		if err != nil {
			errChan <- err
		}
		require.NoError(b, err, "Failed to accept connection")
		server, err = Server(tcpConn, serverConf)
		if err != nil {
			errChan <- err
		}
		require.NoError(b, err, "Failed to establish encrypted connection")
	}()

	select {
	case <-doneChan:
	case err := <-errChan:
		b.Fatalf("Received error from server side setup: %s", err)
	}

	go func() {
		defer wg.Done()
		client, err = Dial(serverAddr, clientConf)
		require.NoError(b, err, "Failed to dial encrypted connection")
	}()

	wg.Wait()
	runConnBench(server, client, b)
}

func runConnBench(server, client net.Conn, b *testing.B) {
	payloadLen := 8192
	randPayload := make([]byte, payloadLen)
	n := 0
	for n < payloadLen {
		n1, err := rand.Read(randPayload)
		require.NoError(b, err)
		n = n + n1
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)
	b.ResetTimer()
	go func() {
		var totalBytes int64
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			client.SetDeadline(time.Now().Add(time.Second * 10))
			n, err := client.Write(randPayload)
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
			server.SetDeadline(time.Now().Add(time.Second * 10))
			n, err := server.Read(buf)
			assert.NoError(b, err)
			assert.EqualValues(b, payloadLen, n)
			assert.EqualValues(b, randPayload, buf[:n])
		}
	}()
	wg.Wait()
	defer server.Close()
	defer client.Close()
}

func generateTlsCerts(b *testing.B) (certBytes []byte, keyBytes []byte) {
	pub, priv, err := ed25519.GenerateKey(cryptrand.Reader)
	//priv, err := ecdsa.GenerateKey(elliptic.P521(), cryptrand.Reader)
	require.NoError(b, err)

	keyUsage := x509.KeyUsageDigitalSignature

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Local test CA"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 1),

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(cryptrand.Reader, &template, &template, pub, priv)
	require.NoError(b, err)
	certBuf := &bytes.Buffer{}
	err = pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	require.NoError(b, err)

	keyBuf := &bytes.Buffer{}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(b, err)
	err = pem.Encode(keyBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	require.NoError(b, err)
	return certBuf.Bytes(), keyBuf.Bytes()
}

func BenchmarkTLSHandshake(b *testing.B) {
	b.Skip()
	certPem, keyPem := generateTlsCerts(b)
	cert, err := tls.X509KeyPair(certPem, keyPem)
	require.NoError(b, err)

	serverPort := 34672
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)

	doneChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	var server net.Listener
	var serverConn net.Conn
	fmt.Println("Starting server")
	b.ResetTimer()
	go func() {
		defer wg.Done()
		server, err = tls.Listen("tcp", serverAddr, &tls.Config{
			Certificates: []tls.Certificate{cert},
			Rand:         cryptrand.Reader,
		})
		assert.NoError(b, err)
		if err != nil {
			errChan <- err
			return
		}
		doneChan <- true
		serverConn, err = server.Accept()
		assert.NoError(b, err)
		if err != nil {
			return
		}
		fmt.Println("Server accepted connection")
	}()

	select {
	case <-doneChan:
		fmt.Println("Server is listeing")
	case err := <-errChan:
		require.NoError(b, err)
	}

	var clientConn net.Conn
	fmt.Println("Starting client")
	go func() {
		defer wg.Done()
		clientConn, err = tls.Dial("tcp", serverAddr, &tls.Config{
			InsecureSkipVerify: true,
		})
		// assert.NoError(b, err)
		if err != nil {
			fmt.Println("Client created connection")
		}
	}()
	fmt.Println("Waiting for connections")
	wg.Wait()
	defer clientConn.Close()
	defer serverConn.Close()
}

func BenchmarkTLS(b *testing.B) {
	b.Skip()
	certPem, keyPem := generateTlsCerts(b)
	cert, err := tls.X509KeyPair(certPem, keyPem)
	require.NoError(b, err)

	doneChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	serverPort := 34672
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)

	wg := &sync.WaitGroup{}
	wg.Add(1)

	var server net.Listener
	var serverConn net.Conn
	fmt.Println("Starting server")
	go func() {
		server, err = tls.Listen("tcp", serverAddr, &tls.Config{
			Certificates: []tls.Certificate{cert},
			Rand:         cryptrand.Reader,
		})
		assert.NoError(b, err)
		if err != nil {
			errChan <- err
			return
		}
		doneChan <- true
		serverConn, err = server.Accept()
		assert.NoError(b, err)
		if err != nil {
			return
		}
		fmt.Println("Server accepted connection")
	}()

	// Wait until server accepts connections
	select {
	case <-doneChan:
		fmt.Println("Server is listeing")
	case err := <-errChan:
		require.NoError(b, err)
	}

	var clientConn net.Conn
	fmt.Println("Starting client")
	go func() {
		defer wg.Done()
		clientConn, err = tls.Dial("tcp", serverAddr, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err == nil {
			fmt.Println("Client created connection")
		}
		assert.NoError(b, err)
	}()
	fmt.Println("Waiting for connections")
	wg.Wait()
	fmt.Println("Benchmarking connections")
	runConnBench(serverConn, clientConn, b)
}
