package krach

import (
	"crypto/rand"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/connctd/krach/certificates"
	"github.com/flynn/noise"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

var (
	rootCert *certificates.Certificate
	rootKey  ed25519.PrivateKey
)

func TestMain(m *testing.M) {
	var err error
	rootCert, rootKey, err = certificates.SelfSignedCertificate("testroot", time.Now(), time.Now().Add(time.Minute*10), nil)
	if err != nil {
		log.Fatalf("failed to generate test root certificate: %s", err)
	}
	os.Exit(m.Run())
}

func TestHandshakeAndCipherstate(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	logg := logrus.WithField("test", true)
	logg.Level = logrus.DebugLevel
	logger := LogrusLogger(logg)
	serverIndex := newInMemoryIndex()

	serverKeyPair, err := noise.DH25519.GenerateKeypair(rand.Reader)
	require.NoError(t, err)
	clientKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	serverAddr := &net.UDPAddr{
		IP:   net.ParseIP("fe80::1"),
		Port: 5000,
	}
	clientAddr := &net.UDPAddr{
		IP:   net.ParseIP("fe80::2"),
		Port: 5001,
	}
	conn := newMockConnection()
	serverSock, err := conn.Listen(serverAddr)
	require.NoError(t, err)
	clientSock, err := conn.Listen(clientAddr)
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

	server := newResponder(serverSock, &ResponderConfig{
		StaticKeyPair: serverKeyPair,
		Table:         serverIndex,
		Logger:        logger,
		CertPool:      certificates.NewCertPool(rootCert),
	})

	client := newInitiator(logger, clientSock, clientKey, PeerIndex(32), []*certificates.Certificate{clientCert})

	clientSess, err := client.openSession(serverAddr, serverKeyPair.Public)
	defer clientSess.Close()
	require.NoError(t, err)

	time.Sleep(time.Millisecond * 50)
	serverSess, err := server.Accept()
	defer serverSess.Close()
	require.NoError(t, err)

	require.NotNil(t, clientSess)
	require.NotNil(t, serverSess)

	testMessage := []byte(`Der Hegemoniekonsul saß auf dem Balkon seines Ebenholzraumschiffs 
		und spielte Rachmaninoffs Prelude in cis-Moll auf einem uralten, 
		aber gut erhaltenen Steinway, während sich große grüne Saurierwesen unten 
		in den Sümpfen drängten und heulten`)
	n1, err := clientSess.Write(testMessage)
	require.NoError(t, err)
	assert.EqualValues(t, len(testMessage), n1)

	readBuf := make([]byte, 4096)
	n2, err := serverSess.Read(readBuf)
	require.NoError(t, err)
	assert.Equal(t, n1, n2)
	assert.EqualValues(t, testMessage, readBuf[:n2])

	n1, err = serverSess.Write(testMessage)
	require.NoError(t, err)
	assert.EqualValues(t, n1, len(testMessage))

	n2, err = clientSess.Read(readBuf)
	require.NoError(t, err)
	assert.EqualValues(t, n2, n1)
	assert.EqualValues(t, testMessage, readBuf[:n2])

}

func TestLocalNetworkConnection(t *testing.T) {
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

	serverAddr := "127.0.0.1:8901"

	l, err := Listen(serverAddr,
		WithResponderLogger(logg),
		WithKeyPair(serverKeyPair),
		WithCertPool(certificates.NewCertPool(rootCert)),
	)
	require.NoError(t, err)
	require.NotEmpty(t, l)

	clientSess, err := Dial(serverAddr, serverKeyPair.Public, WithLogger(logg), ClientCert(clientKey.Private, clientCert, nil))
	require.NoError(t, err)
	require.NotEmpty(t, clientSess)
	defer clientSess.Close()

	serverSess, err := l.Accept()
	require.NoError(t, err)
	require.NotEmpty(t, serverSess)
	defer serverSess.Close()

	testMessage := []byte(`Der Hegemoniekonsul saß auf dem Balkon seines Ebenholzraumschiffs 
		und spielte Rachmaninoffs Prelude in cis-Moll auf einem uralten, 
		aber gut erhaltenen Steinway, während sich große grüne Saurierwesen unten 
		in den Sümpfen drängten und heulten`)
	n1, err := clientSess.Write(testMessage)
	require.NoError(t, err)
	assert.EqualValues(t, len(testMessage), n1)

	readBuf := make([]byte, 4096)
	n2, err := serverSess.Read(readBuf)
	require.NoError(t, err)
	assert.Equal(t, n1, n2)
	assert.EqualValues(t, testMessage, readBuf[:n2])
}

func TestUDPReadDeadline(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 9002,
	})
	require.NoError(t, err)
	udpConn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))

	n, _, err := udpConn.ReadFrom(make([]byte, 1500))
	require.EqualValues(t, 0, n)
	require.True(t, isPollTimeout(err))

}
