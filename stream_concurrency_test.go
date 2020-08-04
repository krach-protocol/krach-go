package krach

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/smolcert/smolcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func BenchmarkStream(b *testing.B) {
	serverCert, serverKey, err := smolcert.SignedCertificate(
		"krachTestServer", 2, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, rootKey, rootCert.Subject,
	)
	require.NoError(b, err)

	l, err := Listen(localAddr, &ConnectionConfig{
		LocalIdentity:    NewPrivateIdentity(serverCert, serverKey),
		HandshakeTimeout: time.Second * 2,
	}, smolcert.NewCertPool(rootCert))
	require.NoError(b, err)
	require.NotEmpty(b, l)
	defer l.Close()

	hsWg := &sync.WaitGroup{}
	hsWg.Add(1)
	var serverConn *Conn
	go func() {
		defer hsWg.Done()
		sc, err := l.Accept()
		require.NoError(b, err)
		assert.NotEmpty(b, sc)
		if krachConn, ok := sc.(*Conn); !ok {
			panic("We somehow got a wrong net.Conn implementation. Should never be possible")
		} else {
			serverConn = krachConn
			require.NoError(b, serverConn.Handshake())
		}
	}()

	clientCert, clientKey, err := smolcert.SignedCertificate("krachTestClient",
		2, time.Now().Add(time.Minute*-1),
		time.Now().Add(time.Hour), nil, rootKey, rootCert.Subject)
	require.NoError(b, err)

	clientConn, err := Dial(localAddr, &ConnectionConfig{
		LocalIdentity: NewPrivateIdentity(clientCert, clientKey),
	}, smolcert.NewCertPool(rootCert))
	err = clientConn.Handshake()
	require.NoError(b, err)
	defer clientConn.Close()

	loadCtx, loadCancel := context.WithCancel(context.Background())
	defer loadCancel()

	go func() {
		loadStream, err := clientConn.OpenStream(1)
		require.NoError(b, err)
		payloadLen := 1024 * 1024 * 10
		payload := make([]byte, payloadLen) // 10 MBi of payload for load
		len := 0
		for len < payloadLen {
			n, err := rand.Read(payload)
			require.NoError(b, err)
			len += n
		}
		for {
			select {
			case <-loadCtx.Done():
				loadStream.Close()
			default:
				n, err := loadStream.Write(payload)
				require.NoError(b, err)
				require.EqualValues(b, payloadLen, n)
			}
		}
	}()
	totalReceivedBytes := 0

	go func() {
		payloadLen := 1024 * 1024 * 10
		loadStream, err := clientConn.ListenStream()
		require.NoError(b, err)
		buf := make([]byte, payloadLen)
		for {
			// Pull data from the stream
			n, err := loadStream.Read(buf)
			require.NoError(b, err)
			totalReceivedBytes += n
		}
	}()

	var clientTimingStream *Stream
	var serverTimingStream *Stream
	wg := &sync.WaitGroup{}
	fmt.Println("Opening timing streams")
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientTimingStream, err = clientConn.OpenStream(2)
		require.NoError(b, err)
	}()
	go func() {
		defer wg.Done()
		serverTimingStream, err = serverConn.ListenStream()
		require.NoError(b, err)
	}()
	wg.Wait()

	b.ResetTimer()
	fmt.Println("Starting actual iterations")
	for n := 0; n < b.N; n++ {
		wg := &sync.WaitGroup{}
		wg.Add(2)

		go func() {
			defer wg.Done()
			buf := make([]byte, 512)
			nowNano := time.Now().UnixNano()
			n, err := serverTimingStream.Read(buf)
			require.NoError(b, err)
			sendNano, err := binary.ReadVarint(bytes.NewBuffer(buf[:n]))
			require.NoError(b, err)
			b.ReportMetric(float64(nowNano-sendNano), "latencyNanoSec/op")
		}()

		go func() {
			defer wg.Done()
			buf := make([]byte, 512)
			nowNano := time.Now().UnixNano()
			n := binary.PutVarint(buf, nowNano)
			_, err := clientTimingStream.Write(buf[:n])
			require.NoError(b, err)
		}()
		fmt.Printf("Waiting to finish iteration: %d\n", b.N)
		wg.Wait()
	}
	b.SetBytes(int64(totalReceivedBytes))
}
