package krach

import (
	"net"
	"time"

	"github.com/connctd/krach/certificates"
	"github.com/flynn/noise"
	"github.com/pkg/errors"
)

type ResponderConfigFunc func(r *Responder) error

func WithKeyPair(dhKey noise.DHKey) ResponderConfigFunc {
	return func(r *Responder) error {
		r.noiseConfig = DefaultNoiseConfig(dhKey)
		return nil
	}
}

func WithCertPool(certPool *certificates.CertPool) ResponderConfigFunc {
	return func(r *Responder) error {
		r.certPool = certPool
		return nil
	}
}

func WithResponderLogger(logg Logger) ResponderConfigFunc {
	return func(r *Responder) error {
		r.logger = logg
		return nil
	}
}

func withResponderNetConn(conn packetNet) ResponderConfigFunc {
	return func(r *Responder) error {
		r.netConn = conn
		return nil
	}
}

func Listen(listenAddr string, configFuncs ...ResponderConfigFunc) (*Responder, error) {
	r := &Responder{
		logger:              dummyLogger{},
		readLoopCloseChan:   make(chan bool, 1),
		acceptedSessionChan: make(chan *Session, 100),
		errorChan:           make(chan error, 10),
	}

	for _, cf := range configFuncs {
		if err := cf(r); err != nil {
			return nil, err
		}
	}

	lAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}

	if r.netConn == nil {
		r.netConn, err = listenUDPNetConn(lAddr)
		if err != nil {
			return nil, err
		}
	}

	if r.table == nil {
		r.table = newInMemoryIndex()
	}

	if r.noiseConfig == nil {
		return nil, errors.New("No DH key pair specified")
	}
	if r.certPool == nil {
		return nil, errors.New("No certificate to validate client certificates specified")
	}
	go readLoop(r.logger, r.readLoopCloseChan, r.netConn, r.handleHandshakeInit, nil, r.handleTransportPacket)
	return r, nil
}

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
	go readLoop(r.logger, r.readLoopCloseChan, r.netConn, r.handleHandshakeInit, nil, r.handleTransportPacket)
	return r
}

func (r *Responder) handleTransportPacket(pktBuf []byte, remoteAddr *net.UDPAddr) {
	senderIndex := extractSenderIndex(pktBuf)
	receiverIndex := extractReceiverIndex(pktBuf)
	logger := r.logger.WithFields(map[string]interface{}{
		"remoteAddr":    remoteAddr,
		"senderIndex":   senderIndex,
		"receiverIndex": receiverIndex,
	})

	session := r.table.LookupPeer(receiverIndex)
	if session == nil {
		logger.Error("Can't find session with this receiverIndex")
		return
	}
	session.receivePacket(pktBuf, remoteAddr)
}

func (r *Responder) handleHandshakeInit(pktBuf []byte, remoteAddr *net.UDPAddr) {
	logger := r.logger.WithField("remoteAddr", remoteAddr.String())
	pktMsg := pktBuf[PayloadHandshakeInitOffset:]
	hsState, err := noise.NewHandshakeState(*r.noiseConfig)
	if err != nil {
		logger.WithError(err).Error("Failed to create handshake state for peer")
		return
	}
	peer := newSession(r.logger, r.netConn.WriteTo)
	peer.isInitiator = false
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
		return
	}
	logger.WithField("senderIndex", senderIndex)

	peer.connectionConfig = config
	peer.SenderIndex = senderIndex

	peer.ReceiverIndex = r.generatePeerIndex()
	logger.WithField("receiverIndex", peer.ReceiverIndex)
	responsePayload, err := createHandshakeResponsePayload(senderIndex, peer.ReceiverIndex)
	if err != nil {
		logger.WithError(err).Error("Failed to create handshake response payload")
	}
	var rspMsg []byte
	rspMsg, cs1, cs2, err := peer.handshakeState.WriteMessage(rspMsg, responsePayload)
	if err != nil {
		logger.WithError(err).Error("Failed to create response to handshake")
		return
	}
	logger.Debug("Received handshake init")
	responsePkt := createHandshakeResponse(peer.SenderIndex, peer.ReceiverIndex, rspMsg)
	_, err = r.netConn.WriteTo(responsePkt, peer.RemoteAddr)
	if err != nil {
		logger.WithError(err).Error("Failed to send handshake response to peer")
		return
	}

	peer.encryptionCipherstate = cs1
	peer.decryptionCipherState = cs2

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
