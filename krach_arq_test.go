package krach

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cevatbarisyilmaz/lossy"
	"github.com/connctd/krach/certificates"
	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createLossyConn(t *testing.T, conn *udpNetConn) packetNet {
	t.Helper()
	// Create a lossy packet connection
	bandwidth := 1048 * 1024 // 8 Mbit/s ?
	minLatency := 100 * time.Millisecond
	maxLatency := time.Second
	packetLossRate := 0.0
	headerOverhead := lossy.UDPv4MinHeaderOverhead
	lossyPacketConn := lossy.NewPacketConn(conn.PacketConn, bandwidth, minLatency, maxLatency, packetLossRate, headerOverhead)
	return &udpNetConn{lossyPacketConn}
}

func setupLocalUDPConnections(t *testing.T) (clientSess *Session, serverSess *Session) {
	t.Helper()
	logrus.SetLevel(logrus.DebugLevel)
	logg := LogrusLogger(logrus.WithField("test", true))

	serverKeyPair, err := noise.DH25519.GenerateKeypair(rand.Reader)
	require.NoError(t, err)
	clientKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	clientCert := &certificates.Certificate{
		SerialNumber: 1,
		Issuer:       rootCert.Subject,
		Validity:     &certificates.Validity{},
		Subject:      "testclient",
		PublicKey:    clientKey.Public,
		Extensions:   []certificates.Extension{},
	}
	clientCert, err = certificates.SignCertificate(clientCert, rootKey)
	require.NoError(t, err)

	serverAddr := "127.0.0.1:9901"

	l, err := Listen(serverAddr,
		WithResponderLogger(logg),
		WithKeyPair(serverKeyPair),
		WithCertPool(certificates.NewCertPool(rootCert)),
	)
	require.NoError(t, err)
	require.NotEmpty(t, l)

	remoteAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to resolve local udp server addr: %s", err.Error())
	}

	clientConn, err := newUDPNetConn(remoteAddr)
	if err != nil {
		t.Fatalf("Failed to create local UDP based packetNet: %s", err.Error())
	}
	lossyClientConn := createLossyConn(t, clientConn)

	clientSess, err = Dial(serverAddr, serverKeyPair.Public,
		withInitiatorConn(lossyClientConn),
		WithLogger(logg),
		ClientCert(clientKey.Private, clientCert, nil),
	)
	require.NoError(t, err)
	require.NotEmpty(t, clientSess)

	serverSess, err = l.Accept()
	require.NoError(t, err)
	require.NotEmpty(t, serverSess)
	return
}

func TestLossyKrachConnection(t *testing.T) {
	clientSess, serverSess := setupLocalUDPConnections(t)

	testMessage := []byte(`Der Hegemoniekonsul saß auf dem Balkon seines Ebenholzraumschiffs 
		und spielte Rachmaninoffs Prelude in cis-Moll auf einem uralten, 
		aber gut erhaltenen Steinway, während sich große grüne Saurierwesen unten 
		in den Sümpfen drängten und heulten`)

	n1, err := clientSess.Write(testMessage)
	require.NoError(t, err)
	buf := make([]byte, 4096)

	n2, err := serverSess.Read(buf)
	require.NoError(t, err)
	assert.EqualValues(t, n1, n2)

	assert.EqualValues(t, testMessage, buf[:n2])
}

func TestSpeedTest(t *testing.T) {
	clientSess, serverSess := setupLocalUDPConnections(t)
	speedy := &speedTest{clientSess, serverSess}
	speedy.runTest(t, 1400, 100, false)
}

type speedTest struct {
	clientSess *Session
	serverSess *Session
}

func (s *speedTest) generateBlock(t *testing.T, len int) []byte {
	t.Helper()
	payload := make([]byte, len)
	n, err := mrand.Read(payload[:(len - sha256.Size)])
	if err != nil {
		t.Fatalf("Failed to generate random payload: %s", err)
	}
	if n != (len - sha256.Size) {
		t.Fatalf("Didn't read enough random data")
	}
	checksum := sha256.Sum256(payload[:len-sha256.Size])
	copy(payload[(len-sha256.Size):], checksum[:])
	return payload
}

func (s *speedTest) verifyBlock(t *testing.T, block []byte) error {
	t.Helper()

	receivedChecksumSlice := block[(len(block) - sha256.Size):]
	var receivedChecksum [32]byte
	copy(receivedChecksum[:], receivedChecksumSlice)
	calcedChecksum := sha256.Sum256(block[:(len(block) - sha256.Size)])
	if receivedChecksum != calcedChecksum {
		return errors.New("Received block is corrupt")
	}
	return nil
}

func (s *speedTest) runTest(t *testing.T, blockSize, blockAmount int, reversed bool) {
	wg := &sync.WaitGroup{}
	wg.Add(2)
	var senderSession *Session
	var receiverSession *Session
	if reversed {
		senderSession = s.serverSess
		receiverSession = s.clientSess
	} else {
		senderSession = s.clientSess
		receiverSession = s.serverSess
	}
	go func() {
		startTime := time.Now()
		sendAmount := 0
		for i := 0; i < blockAmount; i++ {
			block := s.generateBlock(t, blockSize)
			n, err := senderSession.Write(block)
			if err != nil {
				t.Fatalf("Failed to send block %d to receiver: %s", i, err.Error())
			}
			if n != len(block) {
				t.Errorf("Unable to write full block %d to client (%d written, %d expected)", i, n, len(block))
			}
			sendAmount = sendAmount + n
		}
		elapsedTime := time.Now().Sub(startTime)
		bandwidth := float64(sendAmount) / elapsedTime.Seconds()
		fmt.Printf("Send %d blocks with %f bytes/second", blockAmount, bandwidth)

		defer wg.Done()
	}()

	go func() {
		startTime := time.Now()
		receivedAmount := 0
		buf := make([]byte, blockSize)
		for i := 0; i < blockAmount; i++ {
			n, err := receiverSession.Read(buf)
			if err != nil {
				t.Fatalf("Failed to read block %d from session: %s", i, err.Error())
			}
			if n != blockSize {
				t.Errorf("Block %d has not the expected size (%d expected, actual %d)", i, blockSize, n)
			}
			if err := s.verifyBlock(t, buf[:n]); err != nil {
				t.Errorf("Block %d was invalid", i)
			}
			receivedAmount = receivedAmount + n
		}
		elapsedTime := time.Now().Sub(startTime)
		bandwidth := float64(receivedAmount) / elapsedTime.Seconds()
		fmt.Printf("Received %d blocks with %f bytes/second", blockAmount, bandwidth)
		defer wg.Done()
	}()
	wg.Wait()
}
