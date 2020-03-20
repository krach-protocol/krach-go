package krach

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/smolcert/smolcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamsBasic(t *testing.T) {
	baseStreamID := uint8(42)
	testMsg := []byte("Case schloss die Augen. Fand den geriffelten EIN-Schalter.")

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

	hsWg := &sync.WaitGroup{}
	hsWg.Add(1)
	var serverConn *Conn
	go func() {
		defer hsWg.Done()
		sc, err := l.Accept()
		require.NoError(t, err)
		assert.NotEmpty(t, sc)
		if krachConn, ok := sc.(*Conn); !ok {
			panic("We somehow got a wrong net.Conn implementation. Should never be possible")
		} else {
			serverConn = krachConn
			require.NoError(t, serverConn.Handshake())
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

	hsWg.Wait()
	defer serverConn.Close()

	wg := &sync.WaitGroup{}

	for sID := baseStreamID; sID < baseStreamID+2; sID++ {
		wg.Add(2)
		randData := make([]byte, 2000)
		rand.Read(randData)
		msg := append(testMsg, randData...)
		streamServer := serverConn.newStream(sID)
		streamClient := clientConn.newStream(sID)
		go func(s *Stream, msg []byte) {
			defer wg.Done()
			recvBuf := make([]byte, len(msg))
			n, err := io.ReadFull(s, recvBuf)
			require.NoError(t, err, "Failed to read message on stream %d", s.id)
			assert.EqualValues(t, len(msg), n, "Read not enough bytes on stream %d", s.id)
			assert.EqualValues(t, recvBuf[:n], msg, "Read unexpected data on stream %d", s.id)
			fmt.Printf("Done on server stream %d\n", s.id)
		}(streamServer, msg)

		go func(s *Stream, msg []byte) {
			defer wg.Done()
			n, err := s.Write(msg)
			require.NoError(t, err, "Failed to write data to stream %d", s.id)
			assert.EqualValues(t, len(msg), n, "Did not write enough data on stream %d", s.id)
			fmt.Printf("Done on client stream %d\n", s.id)
		}(streamClient, msg)
	}
	wg.Wait()
}
