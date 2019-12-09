package krach

import (
	"fmt"
	mathrand "math/rand"
	"net"
	"time"

	"github.com/connctd/krach/certificates"
	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

var (
	// DefaultHandshakeTimeout is the default time we wait between handshake packets before we declare
	// the handshake failed
	DefaultHandshakeTimeout = time.Second * 10
)

type InitiatiorConfigFunc func(*initiatorConfig) error

func ClientCert(privateKey ed25519.PrivateKey, clientCert *certificates.Certificate, intermediates []*certificates.Certificate) InitiatiorConfigFunc {
	return func(i *initiatorConfig) error {
		keyPair := noise.DHKey{
			Private: []byte(privateKey),
			Public:  []byte(clientCert.PublicKey),
		}

		i.staticKeyPair = keyPair
		// Make sure that the actual client cert is first in the slice. Just for a nice form
		i.certs = append([]*certificates.Certificate{clientCert}, intermediates...)
		return nil
	}
}

func WithLogger(logger Logger) InitiatiorConfigFunc {
	return func(i *initiatorConfig) error {
		i.logger = logger
		return nil
	}
}

func withInitiatorConn(conn packetNet) InitiatiorConfigFunc {
	return func(i *initiatorConfig) error {
		i.netConn = conn
		return nil
	}
}

type initiatorConfig struct {
	logger        Logger
	certs         []*certificates.Certificate
	netConn       packetNet
	staticKeyPair noise.DHKey
}

func Dial(addr string, configFuncs ...InitiatiorConfigFunc) (*Session, error) {
	i := &initiatorConfig{
		logger: dummyLogger{},
	}
	noiseConfig := DefaultNoiseConfig()
	noiseConfig.Initiator = true

	for _, cf := range configFuncs {
		if err := cf(i); err != nil {
			return nil, err
		}
	}

	// Verify that the initiator is in a usable state

	if len(i.certs) == 0 {
		return nil, errors.New("No client certificate specified")
	}
	noiseConfig.StaticKeypair = i.staticKeyPair

	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	if i.netConn == nil {
		conn, err := newUDPNetConn(remoteAddr)
		if err != nil {
			return nil, err
		}
		i.netConn = conn
	}
	//go readLoop(i.logger, i.readLoopCloseChan, i.netConn, nil, i.handleHandshakeResponse, i.handleTransportPacket)
	sess := newSession(i.logger, i.netConn)
	sess.RemoteAddr = remoteAddr
	sess.handshakeState, err = noise.NewHandshakeState(*sess.noiseConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to create handshake state: %w", err)
	}
	sess.SenderIndex = generatePeerIndex()
	if err := handshake_xx_phase0(sess); err != nil {
		return nil, fmt.Errorf("Handshake phase 0 failed: %w", err)
	}

	if err := handshake_xx_phase2(sess); err != nil {
		return nil, fmt.Errorf("Handshake phase 2 failed: %w", err)
	}
	return sess, nil
}

// Initiator represents the initiating (client side) of a Session
type Initiator struct {
	netConn           packetNet
	logger            Logger
	certBundle        []*certificates.Certificate
	noiseConfig       *noise.Config
	readLoopCloseChan chan bool
	errorChan         chan error

	peer *Session
}

func (i *Initiator) handleTransportPacket(pktBuf []byte, remoteAddr *net.UDPAddr) {
	senderIndex := extractSenderIndex(pktBuf)
	receiverIndex := extractReceiverIndex(pktBuf)
	logger := i.logger.WithFields(map[string]interface{}{
		"remoteAddr":    remoteAddr,
		"senderIndex":   senderIndex,
		"receiverIndex": receiverIndex,
	})

	if i.peer == nil {
		logger.Error("We have no valid peer session")
		return
	}
	if i.peer.SenderIndex != senderIndex || i.peer.ReceiverIndex != receiverIndex {
		logger.WithFields(map[string]interface{}{
			"expectedReceiverIndex": i.peer.ReceiverIndex,
			"expectedSenderIndex":   i.peer.SenderIndex,
		}).Error("Received packet with unexpected receiver or sender index")
		return
	}
	// TODO receiver and sender index need to be part of additional authenticated data

	i.peer.receivePacket(pktBuf, remoteAddr)
}

func (i *Initiator) openSession(remoteAddr *net.UDPAddr) (*Session, error) {
	logger := i.logger.WithField("remoteAddr", remoteAddr)
	var err error

	peer := newSession(i.logger, i.netConn)
	peer.RemoteAddr = remoteAddr
	peer.isInitiator = true

	peer.handshakeState, err = noise.NewHandshakeState(*i.noiseConfig)
	if err != nil {
		logger.WithError(err).Error("Failed to create initiator handshake state")
		return nil, err
	}

	peer.SenderIndex = i.generatePeerIndex()
	logger = logger.WithField("senderIndex", peer.SenderIndex)
	logger.Debug("Initiating session")

	initPacket := NewHandshakeInitPacket()

	_, _, err = peer.handshakeState.WriteMessage(initPacket, nil)
	if err != nil {
		return nil, err
	}

	_, err = i.netConn.WriteTo(initPacket.Serialize(), peer.RemoteAddr)
	if err != nil {
		logger.WithError(err).Error("Failed sending the handshake init message")
		return nil, err
	}
	peer.lastPktReceived = time.Now()
	i.peer = peer

	timeoutTicker := time.NewTicker(DefaultHandshakeTimeout)
	defer timeoutTicker.Stop()
	select {
	case <-peer.handshakeFinished():
		//case <-timeoutTicker.C:
		//	return nil, errors.New("Timeout during handshake")
	}
	return peer, nil
}

func (i *Initiator) handleHandshakeResponse(pktBuf []byte, remoteAddr *net.UDPAddr) {
	senderIndex := extractSenderIndex(pktBuf)
	receiverIndex := extractReceiverIndex(pktBuf)
	logger := i.logger.WithFields(map[string]interface{}{
		"senderIndex":   senderIndex,
		"receiverIndex": receiverIndex,
		"remoteAddr":    remoteAddr.String(),
		"isInitiator":   true,
	})
	if !i.noiseConfig.Initiator {
		logger.Error("Receivers should never receive handshake responses")
		return
	}
	if i.peer == nil || i.peer.SenderIndex != senderIndex {
		logger.Error("Received packet with unknown sender index")
		return
	}
	logger.Debug("Received handshake response")
	pktMsg := pktBuf[PayloadHandshakeResponseOffset:]
	var payload []byte
	payload, cs1, cs2, err := i.peer.handshakeState.ReadMessage(payload, pktMsg)
	if err != nil {
		logger.WithError(err).Error("Failed to read noise message and complete handshake")
		return
	}
	i.peer.transportCipher = newNoiseCipher(cs2, cs1)
	i.peer.lastPktReceived = time.Now()
	// Handshake should be finished on client side
	response := &handshakeResponsePayload{}
	if err = unmarshalCBOR(response, payload); err != nil {
		logger.WithError(err).Error("Failed to unmarshal handshake payload")
		return
	}
	if senderIndex != response.SenderIndex {
		logger.Error("Failed to verify sender index")
		return
	}
	if receiverIndex != response.ReceiverIndex {
		logger.Error("Failed to verify receiver index")
		return
	}
	i.peer.ReceiverIndex = receiverIndex
	i.peer.handshakeFinishedChan <- true
}

func generatePeerIndex() PeerIndex {
	// FIXME we probably want a "cryptographical" random value here.
	// FIXME this value must be unique
	return PeerIndex(mathrand.Uint32())
}
