package krach

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketTypes(t *testing.T) {
	pktBuf := make([]byte, 256)
	rand.Read(pktBuf)
	pktBuf[0] = KrachVersion
	pktBuf[1] = PacketTypeHandshakeInit.Byte()

	pkt := PacketFromBuf(pktBuf)
	assert.Equal(t, pkt.Type(), PacketTypeHandshakeInit)

	handshakeInit := HandshakeInitPacket{*pkt}
	handshakeInit.Type()
}

func TestHandshakeResponsePacket(t *testing.T) {
	pktBuf := []byte{KrachVersion, PacketTypeHandshakeInitResponse.Byte()}
	pktBuf = append(pktBuf, 0x00, 0x00, 0x00, 0x01)
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	pktBuf = append(pktBuf, randomBytes...)
	randomCertBytes := make([]byte, 139)
	certLengthBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(certLengthBuf, 139)

	pktBuf = append(pktBuf, certLengthBuf...)
	pktBuf = append(pktBuf, randomCertBytes...)

	randomPayload := make([]byte, 92)
	rand.Read(randomPayload)
	payloadLengthBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(payloadLengthBuf, 92)
	pktBuf = append(pktBuf, payloadLengthBuf...)
	pktBuf = append(pktBuf, randomPayload...)

	handshakeResponse := HandshakeResponseFromBuf(pktBuf)

	assert.Equal(t, KrachVersion, handshakeResponse.Version())
	assert.Equal(t, PacketTypeHandshakeInitResponse, handshakeResponse.Type())

	pubKeyBytes, err := handshakeResponse.ReadEPublic()
	require.NoError(t, err)
	assert.EqualValues(t, randomBytes, pubKeyBytes)

	certBytes, err := handshakeResponse.ReadEncryptedIdentity()
	require.NoError(t, err)
	assert.EqualValues(t, randomCertBytes, certBytes)

	payload, err := handshakeResponse.ReadPayload()
	require.NoError(t, err)
	assert.EqualValues(t, randomPayload, payload)
}
