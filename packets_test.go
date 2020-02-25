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
	pktBuf[1] = PacketTypeHandshakeInit.Byte()

	pkt := PacketFromBuf(pktBuf)
	assert.Equal(t, pkt.Type(), PacketTypeHandshakeInit)

	handshakeInit := HandshakeInitPacket{*pkt}
	handshakeInit.Type()
}

func TestHandshakeResponsePacket(t *testing.T) {
	handshakeResponse := ComposeHandshakeResponse()

	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	handshakeResponse.WriteEPublic(randomBytes)
	randomCertBytes := make([]byte, 139)
	rand.Read(randomCertBytes)
	handshakeResponse.WriteEncryptedIdentity(randomCertBytes)

	randomPayload := make([]byte, 92)
	rand.Read(randomPayload)
	handshakeResponse.WriteEncryptedPayload(randomPayload)

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

func TestHandshakeFinPacket(t *testing.T) {
	handshakeFin := ComposeHandshakeFinPacket()
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
