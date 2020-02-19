package krach

import (
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
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
	Buf []byte
}

func PacketFromBuf(buf []byte) *Packet {
	return &Packet{
		Buf: buf,
	}
}

func (p *Packet) Length() int {
	return len(p.Buf)
}

func (p *Packet) Version() byte {
	return p.Buf[0]
}

func (p *Packet) Type() PacketType {
	return PacketType(p.Buf[1])
}

// ReceiverIndex extracts the receiver index. Might panic during handshake if called on HandshakeInit
func (p *Packet) ReceiverIndex() PeerIndex {
	return PeerIndex(binary.LittleEndian.Uint32(p.Buf[2:6]))
}

// SenderIndex extracts the sender index from a packet. Might panic if called before HandshakeResponseFin
func (p *Packet) SenderIndex() PeerIndex {
	return PeerIndex(binary.LittleEndian.Uint32(p.Buf[6:]))
}

type HandshakeInitPacket struct {
	Packet
}

func HandshakeInitFromBuf(b []byte) *HandshakeInitPacket {
	return &HandshakeInitPacket{
		Packet: Packet{
			Buf: b,
		},
	}
}

func (h *HandshakeInitPacket) ReadEPublic() ([]byte, error) {
	return h.Buf[2:34], nil
}

func (h *HandshakeInitPacket) ReadEncryptedIdentity() ([]byte, error) {
	panic("HandshakeInit should not contain a static identity")
}

func (h *HandshakeInitPacket) ReadPayload() ([]byte, error) {
	// The initial handshale should never contain sensitive information
	return []byte{}, nil
}
func (h *HandshakeInitPacket) EphemeralPublicKey() [32]byte {
	var key [32]byte
	// TODO, see if this is necessary or if we can cast the subslice to [32]byte
	copy(key[:], h.Buf[2:(2+32)])
	return key
}

func (h *HandshakeInitPacket) WriteEPublic(e []byte) {
	copy(h.Buf[2:], e)
}

func (h *HandshakeInitPacket) WriteEncryptedIdentity(s []byte) {
	panic(errors.New("HandshakeInitPacket should not contain the encrypted identity"))
}

func (h *HandshakeInitPacket) WriteEncryptedPayload(p []byte) {
	h.Buf = append(h.Buf, p...)
}

func ComposeHandshakeInitPacket() *HandshakeInitPacket {
	// 1 byte for the version, 1 for the packet type, 32 for the ephemeral public key
	buf := make([]byte, 34, 34)
	buf[0] = KrachVersion
	buf[1] = PacketTypeHandshakeInit.Byte()
	return &HandshakeInitPacket{
		Packet: Packet{
			Buf: buf,
		},
	}
}

type HandshakeResponsePacket struct {
	Packet
}

func HandshakeResponseFromBuf(buf []byte) *HandshakeResponsePacket {
	return &HandshakeResponsePacket{
		Packet: Packet{
			Buf: buf,
		},
	}
}

func ComposeHandshakeResponse(receiverIndex PeerIndex) *HandshakeResponsePacket {
	buf := make([]byte, 40)
	buf[0] = KrachVersion
	buf[1] = PacketTypeHandshakeInitResponse.Byte()
	binary.LittleEndian.PutUint32(buf[2:6], receiverIndex.Uint32())
	return &HandshakeResponsePacket{
		Packet: Packet{
			Buf: buf,
		},
	}
}

func (h *HandshakeResponsePacket) WriteEPublic(e []byte) {
	if len(h.Buf) < 38 {
		buf := make([]byte, 38)
		copy(buf, h.Buf)
		h.Buf = buf
	}
	copy(h.Buf[6:], e)
}

func (h *HandshakeResponsePacket) WriteEncryptedIdentity(s []byte) {
	expectedPacketLen := 38 + 2 + len(s)
	if len(h.Buf) < expectedPacketLen {
		buf := make([]byte, expectedPacketLen)
		copy(buf, h.Buf)
		h.Buf = buf
	}
	binary.LittleEndian.PutUint16(h.Buf[38:], uint16(len(s)))
	copy(h.Buf[40:], s)
}

func (h *HandshakeResponsePacket) WriteEncryptedPayload(p []byte) {
	idLen := binary.LittleEndian.Uint16(h.Buf[38:])
	expectedPacketLen := 38 + 2 + int(idLen) + 2 + len(p)
	if len(h.Buf) < expectedPacketLen {
		buf := make([]byte, expectedPacketLen)
		copy(buf, h.Buf)
		h.Buf = buf
	}
	binary.LittleEndian.PutUint16(h.Buf[40+idLen:], uint16(len(p)))
	copy(h.Buf[42+idLen:], p)
}

func (h *HandshakeResponsePacket) ReadEPublic() ([]byte, error) {
	if len(h.Buf) < 38 {
		return nil, fmt.Errorf("HandshakeResponse packet is too small. Expected at least 38 bytes, got %d", len(h.Buf))
	}
	return h.Buf[6:38], nil
}

func (h *HandshakeResponsePacket) ReadEncryptedIdentity() ([]byte, error) {
	certLen := binary.LittleEndian.Uint16(h.Buf[38:])
	if len(h.Buf) < int(40+certLen) {
		return nil, fmt.Errorf("Invalid certificate length specifier. Bytes in packet are shorter than expected Packet length")
	}
	return h.Buf[40 : 40+certLen], nil
}

func (h *HandshakeResponsePacket) ReadPayload() ([]byte, error) {
	certLen := binary.LittleEndian.Uint16(h.Buf[38:])
	payloadLenOffset := 40 + certLen
	// Check if we have a payload at all
	if len(h.Buf) <= int(payloadLenOffset) {
		// Seems not payload is specified
		return []byte{}, nil
	}

	if len(h.Buf) < int(payloadLenOffset+2) {
		return nil, fmt.Errorf("Payload size is set, but no payload available")
	}

	payloadLen := binary.LittleEndian.Uint16(h.Buf[payloadLenOffset:])
	if len(h.Buf) != int(payloadLenOffset+payloadLen+2) {
		return nil, fmt.Errorf("Handshake packet has invalid payload length field")
	}
	return h.Buf[payloadLenOffset+2:], nil
}

type HandshakeFinPacket struct {
	Packet
}

func ComposeHandshakeFinPacket(senderIndex, receiverIndex PeerIndex) *HandshakeFinPacket {
	buf := make([]byte, 14)
	buf[0] = KrachVersion
	buf[1] = PacketTypeHandshakeFin.Byte()
	binary.LittleEndian.PutUint32(buf[2:], receiverIndex.Uint32())
	binary.LittleEndian.PutUint32(buf[6:], senderIndex.Uint32())

	return &HandshakeFinPacket{
		Packet: Packet{
			Buf: buf,
		},
	}
}

func HandshakeFinFromBuf(b []byte) *HandshakeFinPacket {
	return &HandshakeFinPacket{
		Packet: Packet{
			Buf: b,
		},
	}
}

func (h *HandshakeFinPacket) ReadEPublic() ([]byte, error) {
	panic("Handshake Fin should not contain an ephemeral public key")
}

func (h *HandshakeFinPacket) ReadEncryptedIdentity() ([]byte, error) {
	if len(h.Buf) < 15 {
		return nil, fmt.Errorf("HandshakeFinPacket is too short")
	}
	idLen := binary.LittleEndian.Uint16(h.Buf[12:])
	if len(h.Buf) < int(15+idLen) {
		return nil, fmt.Errorf("HandshakeInit has invalid ID length field")
	}
	return h.Buf[14 : idLen+14], nil
}

func (h *HandshakeFinPacket) ReadPayload() ([]byte, error) {
	if len(h.Buf) < 15 {
		return nil, fmt.Errorf("HandshakeFinPacket is too short")
	}
	idLen := binary.LittleEndian.Uint16(h.Buf[12:])
	if len(h.Buf) == int(15+idLen) {
		return []byte{}, nil
	}

	payloadLen := binary.LittleEndian.Uint16(h.Buf[15+idLen:])
	if len(h.Buf) != int(15+idLen+2+payloadLen) {
		return nil, fmt.Errorf("HandshakeFinPacket specified invalid payload length")
	}
	return h.Buf[(15 + idLen + 2):], nil
}

func (h *HandshakeFinPacket) WriteEPublic(e []byte) {
	panic("The handshake fin packet should not contain an ephemeral public key")
}

func (h *HandshakeFinPacket) WriteEncryptedIdentity(s []byte) {
	idLen := len(s)
	if len(h.Buf) < 14+idLen {
		// Resize packet buf if necessary
		buf := make([]byte, 14+idLen)
		copy(buf, h.Buf)
		h.Buf = buf
	}
	binary.LittleEndian.PutUint16(h.Buf[12:], uint16(idLen))
	copy(h.Buf[14:], s)
}

func (h *HandshakeFinPacket) WriteEncryptedPayload(p []byte) {
	// TODO implement this, currently not needed
	panic("Write payload is not implemented")
}

/*type HandshakeInitPacket struct {
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
}*/

/*type HandshakeInitResponsePacket struct {
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
}*/
