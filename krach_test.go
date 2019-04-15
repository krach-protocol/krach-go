package krach

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/smux"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)

func TestMultiChannelLatency(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientPub, _ := base64.StdEncoding.DecodeString("L9Xm5qy17ZZ6rBMd1Dsn5iZOyS7vUVhYK+zby1nJPEE=")
	clientPriv, _ := base64.StdEncoding.DecodeString("TPmwb3vTEgrA3oq6PoGEzH5hT91IDXGC9qEMc8ksRiw=")

	serverPub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	serverPriv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverKeys := noise.DHKey{
		Public:  serverPub,
		Private: serverPriv,
	}

	serverConfig := &Config{&noisesocket.ConnectionConfig{
		StaticKey: serverKeys,
	}, smux.DefaultConfig()}

	clientKeys := noise.DHKey{
		Public:  clientPub,
		Private: clientPriv,
	}

	clientConfig := &Config{&noisesocket.ConnectionConfig{
		StaticKey: clientKeys,
	}, smux.DefaultConfig()}

	latencyChan := make(chan time.Duration, 5000)

	serverAddr := "127.0.0.1:9001"
	dataAmount := 1024 * 1024 * 1024
	packetSize := 1500
	packetCount := dataAmount / packetSize
	wg := &sync.WaitGroup{}

	l, err := Listen(serverAddr, serverConfig)
	require.NoError(t, err)
	defer l.Close()
	wg.Add(1)
	go func() {

		for {
			select {
			case <-ctx.Done():
				return
			default:
				sess, err := l.Accept()
				require.NoError(t, err)
				go func(sess *Session) {
					conn, err := sess.Accept()
					require.NoError(t, err)
					go func(conn *Conn) {
						start := time.Now()
						sendBytes := 0
						data := make([]byte, packetSize)
						rand.Read(data)
						for i := 0; i < packetCount; i = i + 1 {
							n, err := conn.Write([]byte(data))
							require.NoError(t, err)
							assert.Equal(t, packetSize, n)
							sendBytes = sendBytes + n
						}
						end := time.Now()
						diff := end.Sub(start)
						throughput := (float64(sendBytes) / float64(1024*1024)) / diff.Seconds()
						fmt.Printf("Throughput sending %d bytes: %f MB/s\n", sendBytes, throughput)
						conn.Close()
						wg.Done()
					}(conn)
				}(sess)

				time.Sleep(time.Millisecond * 50)
				conn, err := sess.Open()
				require.NoError(t, err)
				buf := make([]byte, 1500)
				for {
					select {
					case <-ctx.Done():
						return
					default:
						n, err := conn.Read(buf)
						now := time.Now()
						require.NoError(t, err)
						sent, err := time.Parse(time.RFC3339Nano, string(buf[:n]))
						require.NoError(t, err)
						latency := now.Sub(sent)
						latencyChan <- latency
					}
				}
			}
		}
	}()
	// Wait a bit so the massive data transfer is already running
	time.Sleep(time.Millisecond * 50)
	sess, err := Dial(serverAddr, clientConfig)
	require.NoError(t, err)
	conn1, err := sess.Open()
	require.NoError(t, err)
	wg.Add(1)
	go func(conn *Conn) {
		buf := make([]byte, packetSize)
		receivedBytes := 0
		start := time.Now()
		n := 0
		var err error
		for err == nil {
			n, err = conn.Read(buf)
			receivedBytes = receivedBytes + n
		}
		end := time.Now()
		require.Error(t, err, "EOF")
		fmt.Printf("Received %d bytes in %f Seconds\n", receivedBytes, end.Sub(start).Seconds())
		wg.Done()
	}(conn1)

	wg.Add(1)
	go func(sess *Session) {

		conn, err := sess.Accept()
		require.NoError(t, err)
		go func(conn *Conn) {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					time.Sleep(time.Millisecond * 100)
					n, err := conn.Write([]byte(time.Now().Format(time.RFC3339Nano)))
					require.NoError(t, err)
					assert.True(t, n > 0)
				}
			}
		}(conn)

		wg.Done()
	}(sess)

	fmt.Println("Waiting for waitgroup")
	wg.Wait()
	cancel()
	// Ugly hack for concurrency issues
	time.Sleep(time.Millisecond * 200)
	close(latencyChan)

	var averageLatency float64
	for latency := range latencyChan {
		if averageLatency == 0.0 {
			averageLatency = float64(latency.Nanoseconds())
			continue
		}
		averageLatency = (averageLatency + float64(latency.Nanoseconds())) / 2
	}
	fmt.Printf("Average latency during data transfer is %f milliseconds\n", averageLatency/float64(1000000))
	assert.True(t, averageLatency < 1000000.0)
}

func TestBasicConnection(t *testing.T) {
	t.SkipNow()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testPayload := []byte("something interesting")

	clientPub, _ := base64.StdEncoding.DecodeString("L9Xm5qy17ZZ6rBMd1Dsn5iZOyS7vUVhYK+zby1nJPEE=")
	clientPriv, _ := base64.StdEncoding.DecodeString("TPmwb3vTEgrA3oq6PoGEzH5hT91IDXGC9qEMc8ksRiw=")

	serverPub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	serverPriv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverKeys := noise.DHKey{
		Public:  serverPub,
		Private: serverPriv,
	}

	serverConfig := &Config{&noisesocket.ConnectionConfig{
		StaticKey: serverKeys,
	}, smux.DefaultConfig()}

	clientKeys := noise.DHKey{
		Public:  clientPub,
		Private: clientPriv,
	}

	clientConfig := &Config{&noisesocket.ConnectionConfig{
		StaticKey: clientKeys,
	}, smux.DefaultConfig()}

	serverAddr := "127.0.0.1:9002"

	l, err := Listen(serverAddr, serverConfig)
	log.Println("Listener created")
	require.NoError(t, err)

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer func() {
			log.Println("Server work done")
			time.Sleep(time.Millisecond * 50)
			wg.Done()
		}()
		sess, err := l.Accept()
		require.NoError(t, err)
		log.Println("Session accepted")

		conn, err := sess.Accept()
		require.NoError(t, err)
		log.Println("Connection accepted")

		payload := make([]byte, 1500)
		log.Println("Reading from client")
		n := 0

		n, err = conn.Read(payload)

		log.Println("Read payload on server")
		//require.NoError(t, err)
		assert.Equal(t, len(testPayload), n)
		assert.Equal(t, testPayload, payload[:n])
		<-ctx.Done()

	}()

	sess, err := Dial(serverAddr, clientConfig)
	require.NoError(t, err)
	log.Println("Called server")

	conn, err := sess.Open()
	require.NoError(t, err)
	log.Println("Openend connection with server")

	log.Println("Writing to server")
	n, err := conn.Write(testPayload)
	log.Println("Written to connection")
	require.NoError(t, err)
	assert.Equal(t, len(testPayload), n)

	require.NoError(t, sess.Close())
	cancel()
	log.Println("Waiting for waitgroup")
	wg.Wait()
	log.Println("Closing client session")
	sess.Close()
	l.Close()
}
