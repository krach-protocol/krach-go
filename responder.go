package krach

import (
	"net"
	"time"

	"github.com/connctd/krach/certificates"
	"github.com/flynn/noise"
)

type ResponderConfig struct {
	StaticKeyPair noise.DHKey
	Logger        Logger
	Table         indextable
	CertPool      *certificates.CertPool
}

type Responder struct {
	netConn             packetNet
	table               indextable
	logger              Logger
	acceptedSessionChan chan *Session
	noiseConfig         *noise.Config
	readLoopCloseChan   chan bool
	errorChan           chan error

	certPool *certificates.CertPool
}

func newResponder(netConn packetNet, c *ResponderConfig) *Responder {
	if c.CertPool == nil {
		c.CertPool = certificates.NewCertPool()
	}
	r := &Responder{
		netConn:             netConn,
		logger:              c.Logger,
		table:               c.Table,
		readLoopCloseChan:   make(chan bool, 1),
		acceptedSessionChan: make(chan *Session, 100),
		noiseConfig:         DefaultNoiseConfig(c.StaticKeyPair),
		errorChan:           make(chan error, 10),
		certPool:            c.CertPool,
	}
	go readLoop(r.logger, r.readLoopCloseChan, r.netConn, r.handleHandshakeInit, nil)
	return r
}

func (r *Responder) handleHandshakeInit(pktBuf []byte, remoteAddr *net.UDPAddr) {
	logger := r.logger.WithField("remoteAddr", remoteAddr)
	pktMsg := pktBuf[PayloadHandshakeInitOffset:]
	hsState, err := noise.NewHandshakeState(*r.noiseConfig)
	if err != nil {
		logger.WithError(err).Error("Failed to create handshake state for peer")
		return
	}
	peer := newSession(r.netConn.WriteTo)
	peer.RemoteAddr = remoteAddr
	peer.handshakeState = hsState

	var payload []byte
	payload, _, _, err = peer.handshakeState.ReadMessage(payload, pktMsg)
	if err != nil {
		logger.WithError(err).Error("Failed to read initial handshake message")
		return
	}
	unauthedSenderIndex := extractSenderIndex(pktBuf)
	certBundle, senderIndex, config, err := decodeHandshakeData(payload)
	if err != nil {
		logger.WithError(err).Error("Failed to decode handshake init payload")
		return
	}
	_, err = r.verifyClientCertificates(certBundle)
	if err != nil {
		logger.WithError(err).Error("Failed to validate client certificate bundle")
		return
	}
	if unauthedSenderIndex != senderIndex {
		logger.WithFields(map[string]interface{}{
			"authenticatedSenderIndex":   senderIndex,
			"unauthenticatedSenderIndex": unauthedSenderIndex,
		}).Error("Sender index couldn't be authenticated")
	}

	peer.connectionConfig = config
	peer.SenderIndex = senderIndex

	peer.ReceiverIndex = r.generatePeerIndex()
	responsePayload, err := createHandshakeResponsePayload(senderIndex, peer.ReceiverIndex)
	if err != nil {
		logger.WithError(err).Error("Failed to create handshake response payload")
	}
	var rspMsg []byte
	rspMsg, enc, dec, err := peer.handshakeState.WriteMessage(rspMsg, responsePayload)
	if err != nil {
		logger.WithError(err).Error("Failed to create response to handshake")
		return
	}
	responsePkt := createHandshakeResponse(senderIndex, peer.ReceiverIndex, rspMsg)
	_, err = r.netConn.WriteTo(responsePkt, peer.RemoteAddr)
	if err != nil {
		logger.WithError(err).Error("Failed to send handshake response to peer")
		return
	}

	peer.encryptionCipherstate = enc
	peer.decryptionCipheState = dec

	peer.lastPktReceived = time.Now()
	r.table.AddPeer(peer.ReceiverIndex, peer)
	// Handshake should be finished on server side
	r.acceptedSessionChan <- peer
}

func (r *Responder) Accept() (*Session, error) {
	// When closed we should return  an error
	select {
	case sess := <-r.acceptedSessionChan:
		return sess, nil
	case err := <-r.errorChan:
		return nil, err
	}
}

func (r *Responder) verifyClientCertificates(certBundle []*certificates.Certificate) (*certificates.Certificate, error) {
	// TODO add root certs
	return r.certPool.ValidateBundle(certBundle)
}
