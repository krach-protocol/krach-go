package krach

import (
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
)

// packetType represents the type of a packet as unsigned 8 bit integer
type packetType uint8

// Byte returns the representation of the packet type as a single byte
func (p packetType) Byte() byte {
	return byte(p)
}

// Known packet types are defined here
const (
	packetTypeInvalid               packetType = 0x00
	packetTypeHandshakeInit         packetType = 0x01
	packetTypeHandshakeInitResponse packetType = 0x02
	packetTypeHandshakeFin          packetType = 0x03
	packetTypeTransport             packetType = 0x10
)

type frameCommand uint8

const (
	frameCmdSYN    frameCommand = 0x01
	frameCmdSYNACK frameCommand = 0x02
	frameCmdPSH    frameCommand = 0x03
	frameCmdFIN    frameCommand = 0x04
)

func (f frameCommand) Byte() byte {
	return byte(f)
}

type packet struct {
	Buf []byte
}

func packetFromBuf(buf []byte) *packet {
	return &packet{
		Buf: buf,
	}
}

func (p *packet) Length() int {
	return len(p.Buf)
}

func (p *packet) Version() byte {
	return p.Buf[0]
}

func (p *packet) Type() packetType {
	return packetType(p.Buf[1])
}

type handshakeInitPacket struct {
	packet
}

func handshakeInitFromBuf(b []byte) *handshakeInitPacket {
	return &handshakeInitPacket{
		packet: packet{
			Buf: b,
		},
	}
}

func (h *handshakeInitPacket) ReadEPublic() (pubKey [32]byte, err error) {
	copy(pubKey[:], h.Buf[2:34])
	return
}

func (h *handshakeInitPacket) ReadEncryptedIdentity() ([]byte, error) {
	panic("HandshakeInit should not contain a static identity")
}

func (h *handshakeInitPacket) ReadPayload() ([]byte, error) {
	// The initial handshale should never contain sensitive information
	return []byte{}, nil
}
func (h *handshakeInitPacket) EphemeralPublicKey() [32]byte {
	var key [32]byte
	// TODO, see if this is necessary or if we can cast the subslice to [32]byte
	copy(key[:], h.Buf[2:(2+32)])
	return key
}

func (h *handshakeInitPacket) WriteEPublic(e [32]byte) {
	copy(h.Buf[2:], e[:])
}

func (h *handshakeInitPacket) WriteEncryptedIdentity(s []byte) {
	panic(errors.New("HandshakeInitPacket should not contain the encrypted identity"))
}

func (h *handshakeInitPacket) WriteEncryptedPayload(p []byte) {
	h.Buf = append(h.Buf, p...)
}

func composeHandshakeInitPacket() *handshakeInitPacket {
	// 1 byte for the version, 1 for the packet type, 32 for the ephemeral public key
	buf := make([]byte, 34, 34)
	buf[0] = KrachVersion
	buf[1] = packetTypeHandshakeInit.Byte()
	return &handshakeInitPacket{
		packet: packet{
			Buf: buf,
		},
	}
}

type handshakeResponsePacket struct {
	packet
}

func handshakeResponseFromBuf(buf []byte) *handshakeResponsePacket {
	return &handshakeResponsePacket{
		packet: packet{
			Buf: buf,
		},
	}
}

func composeHandshakeResponse() *handshakeResponsePacket {
	buf := make([]byte, 34)
	buf[0] = KrachVersion
	buf[1] = packetTypeHandshakeInitResponse.Byte()
	return &handshakeResponsePacket{
		packet: packet{
			Buf: buf,
		},
	}
}

func (h *handshakeResponsePacket) WriteEPublic(e [32]byte) {
	if len(h.Buf) < 34 {
		buf := make([]byte, 34)
		copy(buf, h.Buf)
		h.Buf = buf
	}
	copy(h.Buf[2:], e[:])
}

func (h *handshakeResponsePacket) WriteEncryptedIdentity(s []byte) {
	expectedPacketLen := 34 + 2 + len(s)
	if len(h.Buf) < expectedPacketLen {
		buf := make([]byte, expectedPacketLen)
		copy(buf, h.Buf)
		h.Buf = buf
	}
	binary.LittleEndian.PutUint16(h.Buf[34:], uint16(len(s)))
	copy(h.Buf[36:], s)
}

func (h *handshakeResponsePacket) WriteEncryptedPayload(p []byte) {
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

func (h *handshakeResponsePacket) ReadEPublic() (pubKey [32]byte, err error) {
	if len(h.Buf) < 34 {
		return pubKey, fmt.Errorf("HandshakeResponse packet is too small. Expected at least 38 bytes, got %d", len(h.Buf))
	}
	copy(pubKey[:], h.Buf[2:34])
	return pubKey, nil
}

func (h *handshakeResponsePacket) ReadEncryptedIdentity() ([]byte, error) {
	certLen := binary.LittleEndian.Uint16(h.Buf[34:])
	if len(h.Buf) < int(34+2+certLen) {
		return nil, fmt.Errorf("Invalid certificate length specifier. Bytes in packet are shorter than expected Packet length")
	}
	return h.Buf[36 : 36+certLen], nil
}

func (h *handshakeResponsePacket) ReadPayload() ([]byte, error) {
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

type handshakeFinPacket struct {
	packet
}

func composeHandshakeFinPacket() *handshakeFinPacket {
	buf := make([]byte, 6)
	buf[0] = KrachVersion
	buf[1] = packetTypeHandshakeFin.Byte()

	return &handshakeFinPacket{
		packet: packet{
			Buf: buf,
		},
	}
}

func handshakeFinFromBuf(b []byte) *handshakeFinPacket {
	return &handshakeFinPacket{
		packet: packet{
			Buf: b,
		},
	}
}

func (h *handshakeFinPacket) ReadEPublic() ([32]byte, error) {
	panic("Handshake Fin should not contain an ephemeral public key")
}

func (h *handshakeFinPacket) ReadEncryptedIdentity() ([]byte, error) {
	if len(h.Buf) < 15 {
		return nil, fmt.Errorf("HandshakeFinPacket is too short")
	}
	idLen := binary.LittleEndian.Uint16(h.Buf[2:])
	if len(h.Buf) < int(4+idLen) {
		return nil, fmt.Errorf("HandshakeInit has invalid ID length field")
	}
	return h.Buf[4 : idLen+4], nil
}

func (h *handshakeFinPacket) ReadPayload() ([]byte, error) {
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

func (h *handshakeFinPacket) WriteEncryptedPayload(p []byte) {
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

func (h *handshakeFinPacket) WriteEPublic(e [32]byte) {
	panic("The handshake fin packet should not contain an ephemeral public key")
}

func (h *handshakeFinPacket) WriteEncryptedIdentity(s []byte) {
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
