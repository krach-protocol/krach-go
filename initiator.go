package krach

import (
	mathrand "math/rand"
	"net"
	"time"

	"github.com/connctd/krach/certificates"
	"github.com/flynn/noise"
)

var (
	// DefaultHandshakeTimeout is the default time we wait between handshake packets before we declare
	// the handshake failed
	DefaultHandshakeTimeout = time.Second * 10
)

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

func newInitiator(
	logger Logger,
	netConn packetNet, staticKeyPair noise.DHKey,
	senderIndex PeerIndex, certBundle []*certificates.Certificate) *Initiator {
	i := &Initiator{
		netConn:           netConn,
		logger:            logger,
		noiseConfig:       DefaultNoiseConfig(staticKeyPair),
		readLoopCloseChan: make(chan bool, 1),
		errorChan:         make(chan error, 10),
		certBundle:        certBundle,
	}
	i.noiseConfig.Initiator = true
	go readLoop(i.logger, i.readLoopCloseChan, i.netConn, nil, i.handleHandshakeResponse, i.handleTransportPacket)
	return i
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

func (i *Initiator) openSession(remoteAddr *net.UDPAddr, remoteStaticKey []byte) (*Session, error) {
	logger := i.logger.WithField("remoteAddr", remoteAddr)
	var err error
	i.noiseConfig.PeerStatic = remoteStaticKey

	peer := newSession(i.logger, i.netConn.WriteTo)
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

	handshakePayload, err := marshalCBOR(&handshakeInitPayload{
		SenderIndex:      peer.SenderIndex,
		CertificateChain: i.certBundle,
		Config:           &PeerConnectionConfig{},
	})

	var out []byte
	out, _, _, err = peer.handshakeState.WriteMessage(out, handshakePayload)
	if err != nil {
		return nil, err
	}

	handshakePkt := createHandshakeInit(peer.SenderIndex, out)
	_, err = i.netConn.WriteTo(handshakePkt, peer.RemoteAddr)
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
	i.peer.encryptionCipherstate = cs2
	i.peer.decryptionCipherState = cs1
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

func (i *Initiator) generatePeerIndex() PeerIndex {
	// FIXME we probably want a "cryptographical" random value here.
	// FIXME this value must be unique
	return PeerIndex(mathrand.Uint32())
}
