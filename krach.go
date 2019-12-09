package krach

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
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
	// KrachVersion is the byte representation of the currently supported wire protocol format for Krach
	KrachVersion byte = 0x00
)

// configure the CBOR codec, so we serialize structs as arrays and have always the same byte representation of data
func init() {
	ch.EncodeOptions.Canonical = true
	ch.TimeNotBuiltin = false
}

const errPrefix = "krach: "

// Some constants for packet sizing
const (
	// MaxPayloadSize = math.MaxUint16 - 16 /*mac size*/ - uint16Size /*data len*/
	MaxPacketLength   = 508  // 576 bytes minimum IPv4 reassembly buffer - 60 bytes max IP header - 8 bytes UDP header
	MinPacketLength   = 1    // Every packet smaller than this can only be invalid
	MaxV6PacketLength = 1212 // 1280 bytes - 60 bytes IPv6 header - 8 bytes UDP header
	HeaderLen         = 10   // Header length in bytes
	AuthTagLen        = 16   // Length of the AuthenticationTag in bytes
)

// DefaultReadBufferSize is the default size for the read buffer in the readLoop. At least one full packet
// should fit in the read buffer
var DefaultReadBufferSize = 2048

// PeerIndex represents the 32 bit index each peer assigns to a session for identification independent
// from IP address and port
type PeerIndex uint32

// Uint32 returns the PeerIndex as an unsigned 32 bit integer to be used when serializing a packet
func (p PeerIndex) Uint32() uint32 {
	return uint32(p)
}

// Several offsets used during serilization and deserilization
var (
	ProtocolVersionOffset = 0
	PacketTypeOffset      = 1

	ReceiverIndexStartOffset = 6
	ReceiverIndexEndOffset   = ReceiverIndexStartOffset + 4

	SenderIndexStartOffset = 2
	SenderIndexEndOffset   = SenderIndexStartOffset + 4

	PayloadHandshakeInitOffset     = 6
	PayloadHandshakeResponseOffset = 10

	PayloadTransportOffset = 10

	// Investigate if we can get away with 32 bit nonces...
	NonceStartOffset = 10
	NonceEndOffset   = 18
)

var (
	// DefaultReadDeadline how long we wait when polling the UDP socket. Essentially this controls
	// how quick we can react to state changes like closing a connection
	DefaultReadDeadline = time.Second * 5
)

var (
	// A timeout error which should be similar enough to the timeout error used in the net package.
	timeoutError = &net.OpError{Err: errors.New("i/o timeout")}
)

// packetNet is a simple interface to abstract away different ways to efficiently poll from or write to
// a UDP socket.
type packetNet interface {
	// ReadFrom takes a buffer in which data from this connection is read. It returns the amount of data
	// read into the buffer, the remote address the data was received from and an error if something went
	// wrong. If error is not nil, the other return values are not expected to be valid.
	ReadFrom(b []byte) (int, *net.UDPAddr, error)
	// Write To takes a buffer and a target UDP address and writes the data of the buffer to this target
	// address. It return the amount of data which was written to the target and an error if anything went wrong
	WriteTo(b []byte, addr *net.UDPAddr) (int, error)

	Close() error
}

type cipher interface {
	EncryptToRemote(out, payload, ad []byte, nonce uint64)
	DecryptFromRemote(out, payload, ad []byte, nonce uint64) error
}

type indextable interface {
	// LookupPeer looks up the Peer by its ID. Returns nil, if the peer can't be found
	LookupPeer(index PeerIndex) *Session
	// RemovePeer removes the peer with the given PeerIndex if it exists
	RemovePeer(index PeerIndex)
	// AddPeer adds the given session with the given PeerIndex
	AddPeer(index PeerIndex, peer *Session)
}

type Config struct {
	*smux.Config
}

// unencryptedPacket is a simple wraper struct around a byte slice and the address it was received from
type unencryptedPacket struct {
	payload    []byte
	remoteAddr *net.UDPAddr
}

// encryptedPacket is similar to unencryptedPacket. Might use type aliasing here rather than redefining this struct
type encryptedPacket struct {
	payload  []byte
	destAddr *net.UDPAddr
}

type packetSender interface {
	Close() error
	WriteTo([]byte, *net.UDPAddr) (int, error)
}

// Session represents some form of connection between two peers. A session does not depend upon IP address and port,
// but on identifiers called PeerIndex. Each side chooses its own PeerIndex during handshake to identify this Session.
type Session struct {
	// SenderIndex is the PeerIndex chosen by the initiating (client) side
	SenderIndex PeerIndex
	//ReceiverIndex is the PeerIndex chosen by the receiving (server) side
	ReceiverIndex PeerIndex
	// RemoteAddr is the last known address of the remote side. This should be updated every time we receive a
	// valid packet from a new address
	RemoteAddr *net.UDPAddr
	logger     Logger

	noiseConfig      *noise.Config
	connectionConfig *PeerConnectionConfig
	transportCipher  cipher
	handshakeState   *noise.HandshakeState
	receivingNonce   uint64
	sendingNonce     uint64

	sender  packetSender
	netConn packetNet

	lastPktReceived time.Time
	readDeadline    time.Duration

	handshakeFinishedChan chan bool
	receivePacketChan     chan *unencryptedPacket
	sendPacketChan        chan *encryptedPacket
	errorChan             chan error
	readLoopCloseChan     chan bool
}

func newSession(logger Logger, sender packetSender) *Session {
	return &Session{
		sender:                sender,
		handshakeFinishedChan: make(chan bool, 1),
		receivePacketChan:     make(chan *unencryptedPacket, 100),
		errorChan:             make(chan error, 100),
		logger:                logger,
		isInitiator:           false,
		receivingNonce:        0,
	}
}

// handshakeFinished returns a channel which indicates if a handshake was finished for this session
func (s *Session) handshakeFinished() chan bool {
	return s.handshakeFinishedChan
}

// receivePacket feeds a received, encrypted and unverified packet into this session
func (s *Session) receivePacket(pktBuf []byte, remoteAddr *net.UDPAddr) {
	logger := s.logger.WithFields(map[string]interface{}{
		"remoteAddr":    remoteAddr.String(),
		"senderIndex":   s.SenderIndex,
		"receiverIndex": s.ReceiverIndex,
		"isInitiator":   s.isInitiator,
	})
	logger.Debug("Received packet in session")
	var err error

	decryptedPayload, err := s.decryptPacket(pktBuf)
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

func (s *Session) decryptPacket(pktBuf []byte) ([]byte, error) {
	pktPayload := pktBuf[PayloadTransportOffset:]
	header := pktBuf[:PayloadTransportOffset]
	nonce := extractNonce(pktBuf)
	// This looks like a reused nonce, so we reject it
	if nonce <= s.receivingNonce {
		return nil, errors.New("Invalid nonce")
	}
	var decryptedPayload []byte
	err := s.transportCipher.DecryptFromRemote(decryptedPayload, pktPayload, header, nonce)
	if err == nil {
		// FIXME we want to detect already used nonces here, this might not be the smartest way, especially
		// if we expect packets out of order...
		s.receivingNonce = nonce
	}
	return decryptedPayload, err
}

func (s *Session) encryptPacket(header, payload []byte) []byte {
	s.sendingNonce = s.sendingNonce + 1
	binary.LittleEndian.PutUint64(header[NonceStartOffset:NonceEndOffset], s.sendingNonce)
	var encryptedPayload []byte
	s.transportCipher.EncryptToRemote(encryptedPayload, payload, header, s.sendingNonce)
	return encryptedPayload
}

func (s *Session) Close() error {
	return s.sender.Close()
}

//Start to implement net.Conn interface, although later this will be done by multiplexed sessions

// Write takes a byte slice. The slice then packetized, encrypted and send to the last known remote address.
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
		// Do nothing, just check if we are having an error
	}
	header := createTransportHeader(s.SenderIndex, s.ReceiverIndex)
	encryptedPayload := s.encryptPacket(header, b)
	packet := append(header, encryptedPayload...)
	n, err = s.sender.WriteTo(packet, s.RemoteAddr)
	n = n - (AuthTagLen + len(header))
	return
}

// Read takes a byte slice into which data received within this session is read.
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

// PeerConnectionConfig contains the config of the initiating party. This is for future use
// only. It is intended to let the initiator (client) define things like sleep intervals,
// support for forward error correction etc. here.
type PeerConnectionConfig struct {
}

// DefaultNoiseConfig returns our default noise configuration. Will be obsolete soon, as we have to have
// a custom noise handshake implementation.
func DefaultNoiseConfig() *noise.Config {
	return &noise.Config{
		Pattern:     noise.HandshakeIK,
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Random:      rand.Reader,
		Initiator:   false,
	}
}

func extractReceiverIndex(pktBuf []byte) PeerIndex {
	return PeerIndex(binary.LittleEndian.Uint32(pktBuf[ReceiverIndexStartOffset:ReceiverIndexEndOffset]))
}

func extractSenderIndex(pktBuf []byte) (PeerIndex, error) {
	if len(pktBuf) < SenderIndexEndOffset+1 {
		return PeerIndex(0), fmt.Errorf("Packet is too short to contain a sender index")
	}
	return PeerIndex(binary.LittleEndian.Uint32(pktBuf[SenderIndexStartOffset:SenderIndexEndOffset])), nil
}

func extractNonce(pktBuf []byte) uint64 {
	return binary.LittleEndian.Uint64(pktBuf[NonceStartOffset:NonceEndOffset])
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
	packetBuf[1] = PacketTypeHandshakeInitResponse.Byte()
	binary.LittleEndian.PutUint32(packetBuf[SenderIndexStartOffset:SenderIndexEndOffset], senderIndex.Uint32())
	binary.LittleEndian.PutUint32(packetBuf[ReceiverIndexStartOffset:ReceiverIndexEndOffset], receiverIndex.Uint32())
	packetBuf = append(packetBuf, noisePayload...)
	return packetBuf
}

func createTransportHeader(senderIndex, receiverIndex PeerIndex) []byte {
	b := make([]byte, 18)
	b[0] = KrachVersion
	b[1] = PacketTypeTransport.Byte()
	binary.LittleEndian.PutUint32(b[SenderIndexStartOffset:SenderIndexEndOffset], senderIndex.Uint32())
	binary.LittleEndian.PutUint32(b[ReceiverIndexStartOffset:ReceiverIndexEndOffset], receiverIndex.Uint32())
	return b
}

func createHandshakeResponsePayload(senderIndex, receiverIndex PeerIndex) ([]byte, error) {
	payload := &handshakeResponsePayload{
		SenderIndex:   senderIndex,
		ReceiverIndex: receiverIndex,
	}
	return marshalCBOR(payload)
}
