package krach

import (
	"context"
	"encoding/base64"
	"fmt"
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

	serverAddr := "127.0.0.1:9002"
	dataAmount := 128 * 1024 * 1024
	packetSize := 1500
	packetCount := dataAmount / packetSize
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		l, err := Listen(serverAddr, serverConfig)
		require.NoError(t, err)
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
						for i := 0; i < packetCount; i = i + 1 {
							data := RandString(packetSize)
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
			//require.NoError(t, err)
			//assert.Equal(t, packetSize, n)
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
	assert.True(t, averageLatency < 100000.0)
}

func TestBasicConnection(t *testing.T) {
	t.Parallel()
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

	serverAddr := "127.0.0.1:9001"

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		l, err := Listen(serverAddr, serverConfig)
		require.NoError(t, err)
		for {
			select {
			case <-ctx.Done():
			default:
				sess, err := l.Accept()
				require.NoError(t, err)
				conn, err := sess.Accept()
				require.NoError(t, err)
				payload := make([]byte, 1500)
				n, err := conn.Read(payload)
				require.NoError(t, err)
				assert.Equal(t, len(testPayload), n)
				assert.Equal(t, testPayload, payload[:n])
				wg.Done()
			}
		}
	}()

	clientKeys := noise.DHKey{
		Public:  clientPub,
		Private: clientPriv,
	}

	clientConfig := &Config{&noisesocket.ConnectionConfig{
		StaticKey: clientKeys,
	}, smux.DefaultConfig()}

	sess, err := Dial(serverAddr, clientConfig)
	require.NoError(t, err)
	conn, err := sess.Open()
	require.NoError(t, err)
	n, err := conn.Write(testPayload)
	require.NoError(t, err)
	assert.Equal(t, len(testPayload), n)
	require.NoError(t, sess.Close())

	wg.Wait()
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func RandString(n int) string {
	src := rand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
