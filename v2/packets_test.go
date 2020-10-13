package krach

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketTypes(t *testing.T) {
	pktBuf := make([]byte, 256)
	rand.Read(pktBuf)
	pktBuf[0] = KrachVersion
	pktBuf[1] = packetTypeHandshakeInit.Byte()

	pkt := packetFromBuf(pktBuf)
	assert.Equal(t, pkt.Type(), packetTypeHandshakeInit)

	handshakeInit := handshakeInitPacket{*pkt}
	handshakeInit.Type()
}

func TestHandshakeResponsePacket(t *testing.T) {
	handshakeResponse := composeHandshakeResponse()

	var randomBytes [32]byte
	rand.Read(randomBytes[:])
	handshakeResponse.WriteEPublic(randomBytes)
	randomCertBytes := make([]byte, 139)
	rand.Read(randomCertBytes)
	handshakeResponse.WriteEncryptedIdentity(randomCertBytes)

	randomPayload := make([]byte, 92)
	rand.Read(randomPayload)
	handshakeResponse.WriteEncryptedPayload(randomPayload)

	assert.Equal(t, KrachVersion, handshakeResponse.Version())
	assert.Equal(t, packetTypeHandshakeInitResponse, handshakeResponse.Type())

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

func TestHandshakeFinPacket(t *testing.T) {
	handshakeFin := composeHandshakeFinPacket()
	randomCertBytes := make([]byte, 127)
	rand.Read(randomCertBytes)
	randomPayloadBytes := make([]byte, 95)
	rand.Read(randomPayloadBytes)

	handshakeFin.WriteEncryptedIdentity(randomCertBytes)
	handshakeFin.WriteEncryptedPayload(randomPayloadBytes)

	certBytes, err := handshakeFin.ReadEncryptedIdentity()
	require.NoError(t, err)
	assert.EqualValues(t, randomCertBytes, certBytes)

	payloadBytes, err := handshakeFin.ReadPayload()
	require.NoError(t, err)
	assert.EqualValues(t, randomPayloadBytes, payloadBytes)
}

func TestPadding(t *testing.T) {
	cases := []struct {
		payload             []byte
		expectedPaddedBytes int
	}{
		{[]byte{0x00}, 15},
		{[]byte{0x00, 0x01}, 14},
		{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, 0},
		{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}, 15},
		{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E}, 1},
	}

	for i, c := range cases {
		paddedPayload, paddedBytes := padPayload(c.payload)
		assert.EqualValues(t, c.expectedPaddedBytes, paddedBytes, "[case %d] Padded bytes do not match", i)
		assert.EqualValues(t, 0, len(paddedPayload)%16, "[case %d] Padded payload is not divisible by 16", i)
	}
}
