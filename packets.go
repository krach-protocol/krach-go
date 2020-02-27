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

func (h *HandshakeInitPacket) ReadEPublic() (pubKey [32]byte, err error) {
	copy(pubKey[:], h.Buf[2:34])
	return
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

func (h *HandshakeInitPacket) WriteEPublic(e [32]byte) {
	copy(h.Buf[2:], e[:])
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

func ComposeHandshakeResponse() *HandshakeResponsePacket {
	buf := make([]byte, 34)
	buf[0] = KrachVersion
	buf[1] = PacketTypeHandshakeInitResponse.Byte()
	return &HandshakeResponsePacket{
		Packet: Packet{
			Buf: buf,
		},
	}
}

func (h *HandshakeResponsePacket) WriteEPublic(e [32]byte) {
	if len(h.Buf) < 34 {
		buf := make([]byte, 34)
		copy(buf, h.Buf)
		h.Buf = buf
	}
	copy(h.Buf[2:], e[:])
}

func (h *HandshakeResponsePacket) WriteEncryptedIdentity(s []byte) {
	expectedPacketLen := 34 + 2 + len(s)
	if len(h.Buf) < expectedPacketLen {
		buf := make([]byte, expectedPacketLen)
		copy(buf, h.Buf)
		h.Buf = buf
	}
	binary.LittleEndian.PutUint16(h.Buf[34:], uint16(len(s)))
	copy(h.Buf[36:], s)
}

func (h *HandshakeResponsePacket) WriteEncryptedPayload(p []byte) {
	idLen := binary.LittleEndian.Uint16(h.Buf[34:])
	expectedPacketLen := 34 + 2 + int(idLen) + 2 + len(p)
	if len(h.Buf) < expectedPacketLen {
		buf := make([]byte, expectedPacketLen)
		copy(buf, h.Buf)
		h.Buf = buf
	}
	binary.LittleEndian.PutUint16(h.Buf[36+idLen:], uint16(len(p)))
	copy(h.Buf[38+idLen:], p)
}

func (h *HandshakeResponsePacket) ReadEPublic() (pubKey [32]byte, err error) {
	if len(h.Buf) < 34 {
		return pubKey, fmt.Errorf("HandshakeResponse packet is too small. Expected at least 38 bytes, got %d", len(h.Buf))
	}
	copy(pubKey[:], h.Buf[2:34])
	return pubKey, nil
}

func (h *HandshakeResponsePacket) ReadEncryptedIdentity() ([]byte, error) {
	certLen := binary.LittleEndian.Uint16(h.Buf[34:])
	if len(h.Buf) < int(34+2+certLen) {
		return nil, fmt.Errorf("Invalid certificate length specifier. Bytes in packet are shorter than expected Packet length")
	}
	return h.Buf[36 : 36+certLen], nil
}

func (h *HandshakeResponsePacket) ReadPayload() ([]byte, error) {
	certLen := binary.LittleEndian.Uint16(h.Buf[34:])
	payloadLenOffset := 34 + 2 + certLen
	// Check if we have a payload at all
	if len(h.Buf) < int(payloadLenOffset) {
		// Seems not payload is specified

		return []byte{}, nil
	}

	if len(h.Buf) < int(payloadLenOffset+2) {
		return nil, fmt.Errorf("Payload size is set, but no payload available")
	}

	payloadLen := binary.LittleEndian.Uint16(h.Buf[payloadLenOffset:])
	if len(h.Buf) != int(payloadLenOffset+payloadLen+2) {
		return nil, fmt.Errorf("Handshake response packet has invalid payload length field")
	}
	return h.Buf[payloadLenOffset+2:], nil
}

type HandshakeFinPacket struct {
	Packet
}

func ComposeHandshakeFinPacket() *HandshakeFinPacket {
	buf := make([]byte, 6)
	buf[0] = KrachVersion
	buf[1] = PacketTypeHandshakeFin.Byte()

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

func (h *HandshakeFinPacket) ReadEPublic() ([32]byte, error) {
	panic("Handshake Fin should not contain an ephemeral public key")
}

func (h *HandshakeFinPacket) ReadEncryptedIdentity() ([]byte, error) {
	if len(h.Buf) < 15 {
		return nil, fmt.Errorf("HandshakeFinPacket is too short")
	}
	idLen := binary.LittleEndian.Uint16(h.Buf[2:])
	if len(h.Buf) < int(4+idLen) {
		return nil, fmt.Errorf("HandshakeInit has invalid ID length field")
	}
	return h.Buf[4 : idLen+4], nil
}

func (h *HandshakeFinPacket) ReadPayload() ([]byte, error) {
	if len(h.Buf) < 15 {
		// Fifteen is an arbitrary number, which is simply larger than 12, because the packet including the
		// the identity length field is 12 bytes. The identity can't be zero bytes
		return nil, fmt.Errorf("HandshakeFinPacket is too short")
	}
	idLen := binary.LittleEndian.Uint16(h.Buf[2:4])
	if len(h.Buf) == int(4+idLen) {
		// We do not have any payload
		return []byte{}, nil
	}

	payloadLen := binary.LittleEndian.Uint16(h.Buf[4+idLen:])
	if len(h.Buf) != int(4+idLen+2+payloadLen) {
		return nil, fmt.Errorf("HandshakeFinPacket specified invalid payload length")
	}
	return h.Buf[(4 + idLen + 2):], nil
}

func (h *HandshakeFinPacket) WriteEncryptedPayload(p []byte) {
	idLen := int(binary.LittleEndian.Uint16(h.Buf[2:]))
	expectedLen := idLen + 4 + 2 + len(p)
	if len(h.Buf) < expectedLen {
		buf := make([]byte, expectedLen)
		copy(buf, h.Buf)
		h.Buf = buf
	}

	binary.LittleEndian.PutUint16(h.Buf[4+idLen:], uint16(len(p)))
	copy(h.Buf[4+idLen+2:], p)
}

func (h *HandshakeFinPacket) WriteEPublic(e [32]byte) {
	panic("The handshake fin packet should not contain an ephemeral public key")
}

func (h *HandshakeFinPacket) WriteEncryptedIdentity(s []byte) {
	idLen := len(s)
	if len(h.Buf) < 4+idLen {
		// Resize packet buf if necessary
		buf := make([]byte, 4+idLen)
		copy(buf, h.Buf)
		h.Buf = buf
	}
	binary.LittleEndian.PutUint16(h.Buf[2:], uint16(idLen))
	copy(h.Buf[4:], s)
}
