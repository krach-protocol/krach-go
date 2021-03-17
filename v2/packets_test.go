package krach

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteLengthPrefixed(t *testing.T) {
	payload1 := []byte{0x01, 0x01, 0x01, 0x01}
	payload2 := []byte{0x02, 0x02, 0x02, 0x02, 0x02}

	buf := make([]byte, len(payload1)+len(payload2)+4)
	offset := writeLengthPrefixed(buf, payload1)
	writeLengthPrefixed(buf[offset:], payload2)
	assert.EqualValues(t, len(payload1), endianess.Uint16(buf[:2]))
	assert.EqualValues(t, 0x01, buf[3])
	assert.EqualValues(t, len(payload2), endianess.Uint16(buf[6:8]))
	assert.EqualValues(t, 0x02, buf[8])
	assert.EqualValues(t, 0x02, buf[len(buf)-1])
}

func TestReadLengthPrefixed(t *testing.T) {
	payload1 := []byte{0x01, 0x01, 0x01, 0x01}
	buf := make([]byte, len(payload1)+2)
	writeLengthPrefixed(buf, payload1)

	payload, _, err := readLengthPrefixed(buf)
	require.NoError(t, err)
	assert.EqualValues(t, payload1, payload)
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

		buf := padPrefixPayload(c.payload)
		assert.Len(t, buf, len(c.payload)+1+int(paddedBytes))

		unpaddedBuf := unpadPayload(buf)
		assert.Len(t, unpaddedBuf, len(c.payload))
		assert.EqualValues(t, c.payload, unpaddedBuf)
	}
}

func TestHandshakeInitFormat(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var ek [32]byte
	copy(ek[:], pub)
	hndInit := &handshakeInitPacket{
		ephemeralKey: ek,
	}

	buf := hndInit.Serialize()

	hndInit2 := &handshakeInitPacket{}
	err = hndInit2.Deserialize(buf[4:])
	require.NoError(t, err)
	assert.EqualValues(t, hndInit.ephemeralKey, hndInit2.ephemeralKey)
}

func TestHandshakeResponseFormat(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var ek [32]byte
	copy(ek[:], pub)

	hndResponse := &handshakeResponsePacket{}
	hndResponse.WriteEPublic(ek)

	fakeSmolCert := []byte("Fake smolcert with enough length, so lentgh checks don't fail despite this bein not valid data")
	fakePayload := []byte("Fake payload")
	hndResponse.WriteEncryptedIdentity(fakeSmolCert)
	hndResponse.WriteEncryptedPayload(fakePayload)
	buf := hndResponse.Serialize()

	hndRsp := &handshakeResponsePacket{}
	err = hndRsp.Deserialize(buf[3:])
	require.NoError(t, err)

	assert.EqualValues(t, ek, hndRsp.ephemeralKey)
	assert.Len(t, hndRsp.smolCertEncrypted, len(fakeSmolCert))
	assert.EqualValues(t, fakeSmolCert, hndRsp.smolCertEncrypted)
	assert.EqualValues(t, fakePayload, hndRsp.payloadEncrypted)
}
