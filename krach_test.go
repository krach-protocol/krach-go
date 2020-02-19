package krach

import (
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

	var serverConn net.Conn

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn, err = l.Accept()
		require.NoError(t, err)
		assert.NotEmpty(t, serverConn)
		if krachConn, ok := serverConn.(*Conn); !ok {
			t.Fatalf("We somehow got a wrong net.Conn implementation. Should never be possible")
			return
		} else {
			require.NoError(t, krachConn.Handshake())
		}
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

	require.NoError(t, err)
	assert.NotEmpty(t, clientConn)

	wg.Wait()

}
