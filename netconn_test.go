// +build !multiplexing

package krach

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/smolcert/smolcert"
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
}
