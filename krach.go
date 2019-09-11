package krach

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
	"net"
	"time"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"
	"github.com/xtaci/smux"

	"github.com/connctd/krach/certificates"
)

var (
	ch = &codec.CborHandle{
		TimeRFC3339: false,
	}
)

const (
	KrachVersion byte = 0x00
)

func init() {
	ch.EncodeOptions.Canonical = true
	ch.TimeNotBuiltin = false
}

const errPrefix = "krach: "

//const MaxPayloadSize = math.MaxUint16 - 16 /*mac size*/ - uint16Size /*data len*/

const MaxPacketLength = 508    // 576 bytes minimum IPv4 reassembly buffer - 60 bytes max IP header - 8 bytes UDP header
const MinPacketLength = 1      // Every packet smaller than this can only be invalid
const MaxV6PacketLength = 1212 // 1280 bytes - 60 bytes IPv6 header - 8 bytes UDP header
const HeaderLen = 10           // Header length in bytes
const AuthTagLen = 16          // Length of the AuthenticationTag in bytes

var DefaultReadBufferSize = 2048

type PacketType uint8

func (p PacketType) Byte() byte {
	return byte(p)
}

const (
	PacketTypeHandshakeInit     PacketType = 1
	PacketTypeHandshakeResponse PacketType = 2
	PacketTypeTransport         PacketType = 0x10
)

type PeerIndex uint32

func (p PeerIndex) Uint32() uint32 {
	return uint32(p)
}

var (
	PacketTypeOffset = 1

	ReceiverIndexStartOffset = 6
	ReceiverIndexEndOffset   = ReceiverIndexStartOffset + 4

	SenderIndexStartOffset = 2
	SenderIndexEndOffset   = SenderIndexStartOffset + 4

	PayloadHandshakeInitOffset     = 6
	PayloadHandshakeResponseOffset = 10

	PayloadTransportOffset = 10
)

var (
	DefaultReadDeadline = time.Second * 5
)

var (
	// A timeout error which should be similar enough to the timeout error used in the net package.
	timeoutError = &net.OpError{Err: errors.New("i/o timeout")}
)

type packetNet interface {
	ReadFrom(b []byte) (int, *net.UDPAddr, error)
	WriteTo(b []byte, addr *net.UDPAddr) (int, error)
}

type indextable interface {
	// LookupPeer looks up the Peer by its ID. Returns nil, if the peer can't be found
	LookupPeer(index PeerIndex) *Session
	RemovePeer(index PeerIndex)
	AddPeer(index PeerIndex, peer *Session)
}

type Config struct {
	*smux.Config
}

type unencryptedPacket struct {
	payload    []byte
	remoteAddr *net.UDPAddr
}

type encryptedPacket struct {
	payload  []byte
	destAddr *net.UDPAddr
}

type Session struct {
	SenderIndex   PeerIndex
	ReceiverIndex PeerIndex
	RemoteAddr    *net.UDPAddr
	logger        Logger
	isInitiator   bool

	connectionConfig      *PeerConnectionConfig
	encryptionCipherstate *noise.CipherState
	decryptionCipheState  *noise.CipherState
	handshakeState        *noise.HandshakeState

	send func([]byte, *net.UDPAddr) (int, error)

	lastPktReceived time.Time
	readDeadline    time.Duration

	handshakeFinishedChan chan bool
	receivePacketChan     chan *unencryptedPacket
	sendPacketChan        chan *encryptedPacket
	errorChan             chan error
}

func newSession(logger Logger, sendFunc func([]byte, *net.UDPAddr) (int, error)) *Session {
	return &Session{
		send:                  sendFunc,
		handshakeFinishedChan: make(chan bool, 1),
		receivePacketChan:     make(chan *unencryptedPacket, 100),
		errorChan:             make(chan error, 100),
		logger:                logger,
		isInitiator:           false,
	}
}

func (s *Session) handshakeFinished() chan bool {
	return s.handshakeFinishedChan
}

func (s *Session) receivePacket(pktBuf []byte, remoteAddr *net.UDPAddr) {
	logger := s.logger.WithFields(map[string]interface{}{
		"remoteAddr":    remoteAddr.String(),
		"senderIndex":   s.SenderIndex,
		"receiverIndex": s.ReceiverIndex,
		"isInitiator":   s.isInitiator,
	})
	logger.Debug("Received packet in session")
	var err error
	pktPayload := pktBuf[PayloadTransportOffset:]
	var decryptedPayload []byte
	decryptedPayload, err = s.decryptionCipheState.Decrypt(
		decryptedPayload,
		pktBuf[:PayloadTransportOffset], // Use the whole header as additional authenticated data
		pktPayload)
	if err != nil {
		logger.WithError(err).Info("Received invalid packet from known peer")
		return
	}
	// We have received a valid packet, the remote address might have changed though so we update it here
	s.RemoteAddr = remoteAddr
	select {
	case s.receivePacketChan <- &unencryptedPacket{payload: decryptedPayload, remoteAddr: remoteAddr}:
		return
	default:
		s.errorChan <- errors.New("Dropping packet, because packets aren't read fast enough")
	}
}

//Start to implement net.Conn interface, although later this will be done by multiplexed sessions

func (s *Session) Write(b []byte) (n int, err error) {
	logger := s.logger.WithFields(map[string]interface{}{
		"remoteAddr":    s.RemoteAddr.String(),
		"senderIndex":   s.SenderIndex,
		"receiverIndex": s.ReceiverIndex,
		"isInitiator":   s.isInitiator,
	})

	// Check if we have any errors in this session. If so, this is an indication that this session
	// is now invalid
	logger.Debug("Writing message into session")
	select {
	case err = <-s.errorChan:
		if err != nil {
			logger.WithError(err).Debug("Received an error in Write method, return error instead of attempting to write data")
			return 0, err
		}
	default:
	}
	header := createTransportHeader(s.SenderIndex, s.ReceiverIndex)
	var encryptedPayload []byte
	encryptedPayload = s.encryptionCipherstate.Encrypt(encryptedPayload, header, b)
	packet := append(header, encryptedPayload...)
	return s.send(packet, s.RemoteAddr)
}

func (s *Session) Read(b []byte) (n int, err error) {
	deadlineTicker := time.NewTicker(DefaultReadDeadline)
	defer deadlineTicker.Stop()
	select {
	case pkt := <-s.receivePacketChan:
		n := copy(b, pkt.payload)
		return n, nil
	case <-deadlineTicker.C:
		return 0, timeoutError
	case err := <-s.errorChan:
		return 0, err
	}
}

type PeerConnectionConfig struct {
}

func DefaultNoiseConfig(staticKeyPair noise.DHKey) *noise.Config {
	return &noise.Config{
		Pattern:       noise.HandshakeIK,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Random:        rand.Reader,
		Initiator:     false,
		StaticKeypair: staticKeyPair,
	}
}

func readLoop(logger Logger,
	closeChan chan bool, netConn packetNet,
	handleHandshakeInit func(packetBuf []byte, addr *net.UDPAddr),
	handleHandshakeResponse func(packetBuf []byte, addr *net.UDPAddr),
	handleTransportPacket func(packetBuf []byte, addr *net.UDPAddr)) {
	buf := make([]byte, DefaultReadBufferSize)
	for {
		select {
		case <-closeChan:
			// TODO probably send close messages to clients
			return
		default:
			n, addr, err := netConn.ReadFrom(buf)
			// TODO, we need to verify, that the UDPConn is still alive and kicking after an I/O Timeout. That
			// is the current expectation.
			if err != nil {
				if isPollTimeout(err) {
					continue
				} else {
					logger.WithError(err).Error("Failed to poll connection, closing session")
					return
				}
			}

			if n < MinPacketLength {
				continue
			}
			logger.WithFields(map[string]interface{}{
				"byteCount":  n,
				"remoteAddr": addr,
			}).Debug("Received raw packet")

			packetBuf := buf[:n]
			version := packetBuf[0]
			if !isVersionSupported(version) {
				continue
			}
			pktType := PacketType(packetBuf[PacketTypeOffset : PacketTypeOffset+1][0])
			switch pktType {
			case PacketTypeHandshakeInit:
				if handleHandshakeInit != nil {
					handleHandshakeInit(packetBuf, addr)
				}
			case PacketTypeHandshakeResponse:
				if handleHandshakeResponse != nil {
					handleHandshakeResponse(packetBuf, addr)
				}
			case PacketTypeTransport:
				if handleTransportPacket != nil {
					handleTransportPacket(packetBuf, addr)
				}
			default:
				logger.WithField("packetType", pktType.Byte()).Debug("Received packet with unknown packet type")
			}
		}
	}
}

func extractReceiverIndex(pktBuf []byte) PeerIndex {
	return PeerIndex(binary.LittleEndian.Uint32(pktBuf[ReceiverIndexStartOffset:ReceiverIndexEndOffset]))
}

func extractSenderIndex(pktBuf []byte) PeerIndex {
	return PeerIndex(binary.LittleEndian.Uint32(pktBuf[SenderIndexStartOffset:SenderIndexEndOffset]))
}

type handshakeInitPayload struct {
	SenderIndex      PeerIndex
	CertificateChain []*certificates.Certificate
	Config           *PeerConnectionConfig
}

func decodeHandshakeData(payload []byte) ([]*certificates.Certificate, PeerIndex, *PeerConnectionConfig, error) {
	hsPayload := &handshakeInitPayload{}
	err := unmarshalCBOR(hsPayload, payload)
	return hsPayload.CertificateChain, hsPayload.SenderIndex, hsPayload.Config, err
}

func marshalCBOR(v interface{}) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := codec.NewEncoder(buf, ch)

	err := enc.Encode(v)
	enc.Release()
	return buf.Bytes(), err
}

func unmarshalCBOR(target interface{}, in []byte) (err error) {
	dec := codec.NewDecoderBytes(in, ch)
	err = dec.Decode(target)
	dec.Release()
	return
}

// Check if we support the given protocol version. This might get more complex in the future
func isVersionSupported(version byte) bool {
	if version == KrachVersion {
		return true
	}
	return false
}

// isPollTimeout simply tells you that this error is an I/O timeout.
func isPollTimeout(err error) bool {
	if netErr, ok := err.(*net.OpError); ok {
		// This is very ugly, but internal/poll is internal and can't be used by us to get access tio the TimeoutError :(
		if netErr.Err.Error() == "i/o timeout" {
			return true
		}
	}
	return false
}

func (r *Responder) generatePeerIndex() PeerIndex {
	// FIXME we probably want a "cryptographical" random value here.
	// FIXME this value must be unique
	return PeerIndex(mathrand.Uint32())
}

type handshakeResponsePayload struct {
	SenderIndex   PeerIndex
	ReceiverIndex PeerIndex
}

func createHandshakeResponse(senderIndex, receiverIndex PeerIndex, noisePayload []byte) []byte {
	packetBuf := make([]byte, 10)
	packetBuf[0] = KrachVersion
	packetBuf[1] = PacketTypeHandshakeResponse.Byte()
	binary.LittleEndian.PutUint32(packetBuf[SenderIndexStartOffset:SenderIndexEndOffset], senderIndex.Uint32())
	binary.LittleEndian.PutUint32(packetBuf[ReceiverIndexStartOffset:ReceiverIndexEndOffset], receiverIndex.Uint32())
	packetBuf = append(packetBuf, noisePayload...)
	return packetBuf
}

func createTransportHeader(senderIndex, receiverIndex PeerIndex) []byte {
	b := make([]byte, 10)
	b[0] = KrachVersion
	b[1] = PacketTypeTransport.Byte()
	binary.LittleEndian.PutUint32(b[SenderIndexStartOffset:SenderIndexEndOffset], senderIndex.Uint32())
	binary.LittleEndian.PutUint32(b[ReceiverIndexStartOffset:ReceiverIndexEndOffset], receiverIndex.Uint32())
	return b
}

func createHandshakeInit(senderIndex PeerIndex, noisePayload []byte) []byte {
	packetBuf := make([]byte, 6)
	packetBuf[0] = KrachVersion
	packetBuf[1] = PacketTypeHandshakeInit.Byte()
	binary.LittleEndian.PutUint32(packetBuf[2:], senderIndex.Uint32())
	packetBuf = append(packetBuf, noisePayload...)
	return packetBuf
}

func createHandshakeResponsePayload(senderIndex, receiverIndex PeerIndex) ([]byte, error) {
	payload := &handshakeResponsePayload{
		SenderIndex:   senderIndex,
		ReceiverIndex: receiverIndex,
	}
	return marshalCBOR(payload)
}
