package krach

import (
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/smolcert/smolcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamsBasic(t *testing.T) {
	streamID := uint8(42)
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

	go func() {
		serverConn, err := l.Accept()
		require.NoError(t, err)
		assert.NotEmpty(t, serverConn)
		defer serverConn.Close()
		if krachConn, ok := serverConn.(*Conn); !ok {
			panic("We somehow got a wrong net.Conn implementation. Should never be possible")
		} else {
			require.NoError(t, krachConn.Handshake())

			recvBuf := make([]byte, len(testMsg))
			s := newStream(streamID, krachConn)
			krachConn.streams[streamID] = s

			n, err := io.ReadFull(s, recvBuf)
			require.NoError(t, err)
			assert.EqualValues(t, len(testMsg), n)
		}
	}()

	clientCert, clientKey, err := smolcert.SignedCertificate("krachTestClient",
		2, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, rootKey, rootCert.Subject)
	require.NoError(t, err)

	clientConn, err := Dial(localAddr, &ConnectionConfig{
		LocalIdentity: NewPrivateIdentity(clientCert, clientKey),
	}, smolcert.NewCertPool(rootCert))
	err = clientConn.Handshake()
	require.NoError(t, err)
	defer clientConn.Close()

	s := newStream(streamID, clientConn)
	clientConn.streams[streamID] = s
	n, err := s.Write(testMsg)
	require.NoError(t, err)
	assert.EqualValues(t, len(testMsg), n)
}
