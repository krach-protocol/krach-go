package krach

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
	"net"
	"time"

	"github.com/flynn/noise"
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

type Session struct {
	SenderIndex   PeerIndex
	ReceiverIndex PeerIndex
	RemoteAddr    *net.UDPAddr

	connectionConfig      *PeerConnectionConfig
	encryptionCipherstate *noise.CipherState
	decryptionCipheState  *noise.CipherState
	handshakeState        *noise.HandshakeState

	send func([]byte, *net.UDPAddr) (int, error)

	lastPktReceived time.Time

	handshakeFinishedChan chan bool
}

func newSession(sendFunc func([]byte, *net.UDPAddr) (int, error)) *Session {
	return &Session{
		send:                  sendFunc,
		handshakeFinishedChan: make(chan bool, 1),
	}
}

func (s *Session) handshakeFinished() chan bool {
	return s.handshakeFinishedChan
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
	handleHandshakeResponse func(packetBuf []byte, addr *net.UDPAddr)) {
	buf := make([]byte, DefaultReadBufferSize)
	for {
		select {
		case <-closeChan:
			// TODO probably send close messages to clients
			return
		default:
			n, addr, err := netConn.ReadFrom(buf)
			logger.WithFields(map[string]interface{}{
				"byteCount":  n,
				"remoteAddr": addr,
			}).Debug("Received packet")
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
			default:
				// TODO log error about invalid packet type
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
