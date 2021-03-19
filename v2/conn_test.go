package krach

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/smolcert/smolcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	encMsg := clientConn.hcOut.cs.Encrypt([]byte{}, nil, testMsg)
	assert.EqualValues(t, len(testMsg)+16, len(encMsg)) // Ensure that the message has a correct mac
	decrMsg, err := serverConn.hcIn.cs.Decrypt([]byte{}, nil, encMsg)
	require.NoError(t, err)

	assert.EqualValues(t, testMsg, decrMsg)
}
