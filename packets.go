package krach

import (
	"fmt"
	"github.com/connctd/krach/certificates"
)

// PacketType represents the type of a packet as unsigned 8 bit integer
type PacketType uint8

// Byte returns the representation of the packet type as a single byte
func (p PacketType) Byte() byte {
	return byte(p)
}

// Known packet types are defined here
const (
	PacketTypeInvalid               PacketType = 0x00
	PacketTypeHandshakeInit         PacketType = 0x01
	PacketTypeHandshakeInitResponse PacketType = 0x02
	PacketTypeHandshakeFin          PacketType = 0x03
	PacketTypeTransport             PacketType = 0x10
)

type Packet struct {
	// Can we use this as AD?
	Version uint8
	Type    PacketType

	EncryptedPayload []byte
}

type HandshakeInitPacket struct {
	Packet
	EphemeralPublicKey [32]byte
}

func (h *HandshakeInitPacket) WriteEPublic(e []byte) {
	copy(h.EphemeralPublicKey[:], e)
}
func (h *HandshakeInitPacket) WriteEncryptedSPublic(s []byte) {
	// Not supported here, probably a design problem
}
func (h *HandshakeInitPacket) WriteEncryptedPayload(p []byte) {
	h.EncryptedPayload = make([]byte, len(p))
	copy(h.EncryptedPayload, p)
}

func (h *HandshakeInitPacket) Serialize() []byte {
	buf := make([]byte, 2+len(h.EphemeralPublicKey)+len(h.EncryptedPayload))
	buf[0] = h.Version
	buf[1] = h.Type.Byte()
	copy(buf[2:], h.EphemeralPublicKey[:])
	copy(buf[2+len(h.EphemeralPublicKey):], h.EncryptedPayload)
	return buf
}

func NewHandshakeInitPacket() *HandshakeInitPacket {
	p := &HandshakeInitPacket{}
	p.Version = KrachVersion
	p.Type = PacketTypeHandshakeInit
	return p
}

type HandshakeInitResponsePacket struct {
	Packet
	// Should be AD
	SenderIndex        PeerIndex
	EphemeralPublicKey [32]byte
	// Should be encrypted
	Identity *certificates.Certificate
}

func (h *HandshakeInitResponsePacket) WriteEPublic(e []byte) {
	copy(h.EphemeralPublicKey[:], e)
}
func (h *HandshakeInitResponsePacket) WriteEncryptedSPublic(s []byte) {
	// Skip. The public key should be contained in the Identity
}
func (h *HandshakeInitResponsePacket) WriteEncryptedPayload(p []byte) {
	h.EncryptedPayload = make([]byte, len(p))
	copy(h.EncryptedPayload, p)
}

func ParseHandshakeInitResponsePacket(pktBuf []byte) (*HandshakeInitResponsePacket, error) {
	version, err := extractVersion(pktBuf)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse Handshake Init Response: %w", err)
	}
	if !isVersionSupported(version) {
		return nil, fmt.Errorf("Unsupported krach version. Supported version is %d, but we got %d", KrachVersion, version)
	}
	pktType, err := extractPacketType(pktBuf)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse Handshake Init Response: %w", err)
	}
	if pktType != PacketTypeHandshakeInitResponse {
		return nil, fmt.Errorf("Invalid packet type. Expected HandshakeInitResponse (%X), got %X", PacketTypeHandshakeInitResponse.Byte(), pktType.Byte())
	}

	senderIndex, err := extractSenderIndex(pktBuf)
	if err != nil {
		return nil, fmt.Errorf("Unable to extract sender index from HandshakeInitResponse: %w")
	}

	// We expect at least 32 more bytes after the SenderIndex to have a valid ephemeral public key
	if len(pktBuf) < SenderIndexEndOffset+1+32 {
		return nil, fmt.Errorf("HandshakeInitResponse packet too short to contain ephemeral public key")
	}
	ephPubBytes := pktBuf[SenderIndexEndOffset+1 : SenderIndexEndOffset+1+32]
	var ephPubKey [32]byte
	copy(ephPubKey[:], ephPubBytes)
	var payload []byte
	if len(pktBuf) > SenderIndexEndOffset+1+32 {
		payloadLength := len(pktBuf) - SenderIndexEndOffset + 1 + 32
		payload = make([]byte, payloadLength)
		copy(payload, pktBuf[SenderIndexEndOffset+1+32:])
	}

	pkt := &HandshakeInitResponsePacket{
		Packet{
			Version:          version,
			Type:             pktType,
			EncryptedPayload: payload,
		},
		senderIndex,
		ephPubKey,
		// Payload is not encrypted here, therefore we can't extract identities
		nil,
	}
	return pkt, nil
}

type HandshakeInitiatorPayload struct {
	CertificateChain []*certificates.Certificate
	Config           *PeerConnectionConfig
}

type HandshakeFinPacket struct {
	Packet
	// Needs to be AD
	SenderIndex   PeerIndex
	ReceiverIndex PeerIndex
	// Encrypted parts
	Payload *HandshakeInitiatorPayload
}

func extractVersion(pktBuf []byte) (uint8, error) {
	if len(pktBuf) < ProtocolVersionOffset+1 {
		return 0, fmt.Errorf("Packet too short to contain protocol version")
	}
	return uint8(pktBuf[ProtocolVersionOffset]), nil
}

func extractPacketType(pktBuf []byte) (PacketType, error) {
	if len(pktBuf) < PacketTypeOffset+1 {
		return PacketTypeInvalid, fmt.Errorf("Packet too short to contain packet type")
	}
	return PacketType(pktBuf[PacketTypeOffset]), nil
}
