package krach

import (
	_ "encoding/binary"
	"errors"
	"fmt"
	_ "fmt"
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

type handshakeInitPacket struct {
	ephemeralKey [32]byte
}

func (h *handshakeInitPacket) PacketType() packetType {
	return packetTypeHandshakeInit
}

func (h *handshakeInitPacket) Length() int {
	return 32
}

func (h *handshakeInitPacket) Type() packetType {
	return packetTypeHandshakeInit
}

func (h *handshakeInitPacket) ReadEPublic() ([32]byte, error) {
	return h.ephemeralKey, nil
}

func (h *handshakeInitPacket) ReadEncryptedIdentity() ([]byte, error) {
	panic("Handshake Init must not contain an encrypted identitiy")
}

func (h *handshakeInitPacket) ReadPayload() ([]byte, error) {
	// panic("Handshake init must not have a generic payload")
	return nil, nil
}

func (h *handshakeInitPacket) WriteEPublic(e [32]byte) {
	h.ephemeralKey = e
}

func (h *handshakeInitPacket) WriteEncryptedIdentity(s []byte) {
	panic("Handshake Init packets can't contain an encrypted identity")
}

func (h *handshakeInitPacket) WriteEncryptedPayload(p []byte) {
	// panic("Handshake Init packets can't contain a payload")
	// Ignore, we don't want to add payloads to init packets
}

func (h *handshakeInitPacket) Serialize() []byte {
	len := 1 /*Version*/ + 1 /*Handshake Type*/ + 2 /*Packet length*/ + 32 /*key length*/
	buf := make([]byte, len)
	buf[0] = KrachVersion
	buf[1] = packetTypeHandshakeInit.Byte()
	endianess.PutUint16(buf[2:4], 32 /*key length*/) // Packet length only counts bytes following the packet length
	copy(buf[4:], h.ephemeralKey[:])
	return buf
}

func (h *handshakeInitPacket) Deserialize(buf []byte) error {
	if len(buf) != 32 {
		return errors.New("Invalid length of handshake init packet. Expected 32 bytes")
	}
	var ek [32]byte
	copy(ek[:], buf)
	h.ephemeralKey = ek
	return nil
}

type handshakeResponsePacket struct {
	ephemeralKey      [32]byte
	smolCertEncrypted []byte
	payloadEncrypted  []byte

	receivedLength int
}

func (h *handshakeResponsePacket) PacketType() packetType {
	return packetTypeHandshakeInitResponse
}

func (h *handshakeResponsePacket) Length() int {
	return h.receivedLength
}

func (h *handshakeResponsePacket) ReadEPublic() ([32]byte, error) {
	return h.ephemeralKey, nil
}

func (h *handshakeResponsePacket) ReadEncryptedIdentity() ([]byte, error) {
	return h.smolCertEncrypted, nil
}

func (h *handshakeResponsePacket) ReadPayload() ([]byte, error) {
	return h.payloadEncrypted, nil
}

func (h *handshakeResponsePacket) WriteEPublic(e [32]byte) {
	h.ephemeralKey = e
}

func (h *handshakeResponsePacket) WriteEncryptedIdentity(s []byte) {
	h.smolCertEncrypted = s
}

func (h *handshakeResponsePacket) WriteEncryptedPayload(p []byte) {
	h.payloadEncrypted = p
}

func (h *handshakeResponsePacket) Serialize() []byte {
	length := 1 /*Packet type*/ + 2 /*Packet length*/ + 32 /*ephemeral key length*/ +
		2 /*id length*/ + len(h.smolCertEncrypted) + 2 /*payload length*/ + len(h.payloadEncrypted)

	buf := make([]byte, length)
	buf[0] = packetTypeHandshakeInitResponse.Byte()
	endianess.PutUint16(buf[1:3], uint16(length-3))
	copy(buf[3:35], h.ephemeralKey[:])
	offset := writeLengthPrefixed(buf[35:], h.smolCertEncrypted) + 35 /* manual offset from ephemeral key */
	writeLengthPrefixed(buf[offset:], h.payloadEncrypted)
	return buf
}

func (h *handshakeResponsePacket) Deserialize(buf []byte) (err error) {
	if len(buf) < 84 /*Minimal possible length*/ {
		return fmt.Errorf("Invalid packet length for HandshakeResponse packet. Got only %d bytes", len(buf))
	}
	h.receivedLength = len(buf)
	copy(h.ephemeralKey[:], buf[:32])
	offset := 32
	var nextOffset int
	h.smolCertEncrypted, nextOffset, err = readLengthPrefixed(buf[offset:])
	if err != nil {
		return err
	}
	offset = offset + nextOffset
	h.payloadEncrypted, nextOffset, err = readLengthPrefixed(buf[offset:])
	return
}

type handshakeFinPacket struct {
	smolCertEncrypted []byte
	payloadEncrypted  []byte
	receivedLength    int
}

func (h *handshakeFinPacket) PacketType() packetType {
	return packetTypeHandshakeFin
}

func (h *handshakeFinPacket) Length() int {
	return h.receivedLength
}

func (h *handshakeFinPacket) ReadEPublic() ([32]byte, error) {
	panic("HandshakeFin packets do not contain ephemeral public keys")
}

func (h *handshakeFinPacket) ReadEncryptedIdentity() ([]byte, error) {
	return h.smolCertEncrypted, nil
}

func (h *handshakeFinPacket) ReadPayload() ([]byte, error) {
	return h.payloadEncrypted, nil
}

func (h *handshakeFinPacket) WriteEPublic(e [32]byte) {
	panic("HandshakeFin packets can't contain ephemeral public keys")
}

func (h *handshakeFinPacket) WriteEncryptedIdentity(s []byte) {
	h.smolCertEncrypted = s
}

func (h *handshakeFinPacket) WriteEncryptedPayload(p []byte) {
	h.payloadEncrypted = p
}

func (h *handshakeFinPacket) Serialize() []byte {
	length := 1 /*Packet type*/ + 2 /*Packet length*/ +
		2 /*id length*/ + len(h.smolCertEncrypted) + 2 /*payload length*/ + len(h.payloadEncrypted)
	buf := make([]byte, length)
	buf[0] = packetTypeHandshakeFin.Byte()
	endianess.PutUint16(buf[1:3], uint16(length-3))
	offset := 3
	nextOffset := writeLengthPrefixed(buf[offset:], h.smolCertEncrypted)
	offset = offset + nextOffset
	writeLengthPrefixed(buf[offset:], h.payloadEncrypted)
	return buf
}

func (h *handshakeFinPacket) Deserialize(buf []byte) (err error) {
	if len(buf) < 52 {
		return fmt.Errorf("Received buffer is too small to contain a Handshake Fin packet. Received only %d bytes", len(buf))
	}
	h.receivedLength = len(buf)
	offset := 0
	h.smolCertEncrypted, offset, err = readLengthPrefixed(buf)
	if err != nil {
		return err
	}
	h.payloadEncrypted, _, err = readLengthPrefixed(buf[offset:])
	return err
}

// readLengthPrefixed reads a length prefixed payload from the given buffer. It return the read payload,
// the offset after the payload, which was just read and if necessary an error
func readLengthPrefixed(buf []byte) ([]byte, int, error) {
	if len(buf) < 2 {
		return nil, 0, errors.New("Buffer too small to decode length prefixed value")
	}
	length := endianess.Uint16(buf[:2])
	if len(buf) < int(length+2) {
		return nil, 0, errors.New("Got invalid length. Prefixed length is smaller than remaining buffer")
	}
	return buf[2 : length+2], int(length + 2), nil
}

// writeLengthPrefixed writes the payload into the given buffer by prefixing the payload with an uint16
// representation of the payloads length. Therefore the given buffer must at least have a size of
// payload length + 2. This method return the offset in the given buffer, after the payload
func writeLengthPrefixed(buf []byte, payload []byte) (offset int) {
	endianess.PutUint16(buf[:2], uint16(len(payload)))
	copy(buf[2:], payload)
	return 2 + len(payload)
}

func padPayload(buf []byte) ([]byte, uint8) {
	origDataLen := len(buf)
	bytesToPad := 16 - (origDataLen % 16) /*always pad to 16 bytes as recommended by the specification of ChaCha2020 */
	if bytesToPad == 16 {
		// We don't need padding if the payload is already divisible by 16
		bytesToPad = 0
	}
	if origDataLen+bytesToPad > cap(buf) {
		newBuf := make([]byte, origDataLen+bytesToPad)
		copy(newBuf, buf)
		buf = newBuf
	}
	return buf[:origDataLen+bytesToPad], uint8(bytesToPad)
}

func padPrefixPayload(buf []byte) []byte {
	// FIXME padding prefix byte is not taken into account here
	if len(buf) == 0 {
		return buf
	}
	prefixedBuf := append([]byte{byte(0x00)}, buf...)
	paddedBuf, padLen := padPayload(prefixedBuf)
	paddedBuf[0] = padLen
	return paddedBuf
}

func unpadPayload(buf []byte) []byte {
	if len(buf) < 2 {
		return buf
	}
	paddedBytes := int(buf[0])
	return buf[1 : len(buf)-(paddedBytes)]
}
