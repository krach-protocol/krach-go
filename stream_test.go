package krach

import (
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

	parallelStreams := 2

	for sID := baseStreamID; sID < baseStreamID+uint8(parallelStreams); sID++ {
		wg.Add(2)
		randData := make([]byte, 2000, 2000)
		for i := 0; i < 2000; i++ {
			randData[i] = sID
		}
		//rand.Read(randData)
		streamMsg := append(testMsg, randData...)

		go func(streamID uint8, msg []byte) {
			defer wg.Done()
			fmt.Printf("Starting server go routine for stream %d\n", streamID)
			recvBuf := make([]byte, len(msg))
			s, err := serverConn.ListenStream()
			require.NoError(t, err, "Failed to listen for stream %d", streamID)

			fmt.Printf("Waiting for read in stream %d\n", s.id)
			n, err := io.ReadFull(s, recvBuf)
			fmt.Printf("Successfully read data in stream %d\n", s.id)
			require.NoError(t, err, "Failed to read message on stream %d", streamID)
			assert.EqualValues(t, len(msg), n, "Read not enough bytes on stream %d", streamID)
			assert.EqualValues(t, msg, recvBuf[:n], "Read unexpected data on stream %x", streamID)
		}(sID, streamMsg)

		go func(streamID uint8, msg []byte) {
			defer wg.Done()
			fmt.Printf("Starting client go routine for stream %d\n", streamID)
			s, err := clientConn.OpenStream(streamID)
			require.NoError(t, err, "Failed to open stream %s", streamID)
			require.EqualValues(t, streamID, msg[1000])
			fmt.Printf("Blocking write in stream %d\n", s.id)
			n, err := s.Write(msg)
			fmt.Printf("Successfully written data in stream %d\n", s.id)
			require.NoError(t, err, "Failed to write data to stream %d", streamID)

			assert.EqualValues(t, len(msg), n, "Did not write enough data on stream %d", streamID)
		}(sID, streamMsg)
	}
	wg.Wait()
}
