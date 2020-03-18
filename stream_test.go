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
		defer sc.Close()
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

	wg := &sync.WaitGroup{}

	for sID := baseStreamID; sID < baseStreamID+10; sID++ {
		wg.Add(2)
		randData := make([]byte, 2000)
		rand.Read(randData)
		testMsg = append(testMsg, randData...)

		go func(streamID uint8, msg []byte) {
			defer wg.Done()
			fmt.Printf("Starting server stream %d\n", streamID)
			s := serverConn.newStream(streamID)
			recvBuf := make([]byte, len(testMsg))
			fmt.Printf("Reading on server stream %d\n", streamID)
			n, err := io.ReadFull(s, recvBuf)
			require.NoError(t, err, "Failed to read message on stream %d", streamID)
			assert.EqualValues(t, len(msg), n, "Read not enough bytes on stream %d", streamID)
			assert.EqualValues(t, recvBuf[:n], msg, "Read unexpected data on stream %d", streamID)
			fmt.Printf("Done on server stream %d", streamID)
		}(sID, testMsg)

		go func(streamID uint8, msg []byte) {
			defer wg.Done()
			fmt.Printf("Starting client stream %d\n", streamID)
			s := clientConn.newStream(streamID)
			fmt.Printf("Writing to client so stream %d\n", streamID)
			n, err := s.Write(testMsg)
			require.NoError(t, err, "Failed to write data to stream %d", streamID)
			assert.EqualValues(t, len(msg), n, "Did not write enough data on stream %d", streamID)
			fmt.Printf("Done on client stream %d\n", streamID)
		}(sID, testMsg)
	}
	wg.Wait()
}
