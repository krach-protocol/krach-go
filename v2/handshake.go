package krach

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math"

	"github.com/pkg/errors"
	"github.com/smolcert/smolcert"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// maxMsgLen is the maximum number of bytes transmittable in one message
	maxMsgLen = 65535

	dhLen = 32
)

// readableHandshakeMessage provides the HandshakeState the possibility to digest handshake messages in other
// formats than simple concatenated byte slices
type readableHandshakeMessage interface {
	ReadEPublic() ([32]byte, error)
	ReadEncryptedIdentity() ([]byte, error)
	ReadPayload() ([]byte, error)
	Length() int
	Deserialize([]byte) error
	PacketType() packetType
}

// writeableHandshakeMessage takes data from the HandshakeState to marshal it to a custom format.
type writeableHandshakeMessage interface {
	WriteEPublic(e [32]byte)
	WriteEncryptedIdentity(s []byte)
	WriteEncryptedPayload(p []byte)
	Serialize() []byte
}

type cipherState struct {
	c cipher.AEAD
	k [32]byte
	n uint64
}

func (s *cipherState) Cipher(k [32]byte) cipher.AEAD {
	c, err := chacha20poly1305.New(k[:])
	if err != nil {
		panic(fmt.Errorf("Failed to create ChaChaPoly1305 cipher: %w", err))
	}
	return c
}

func (s *cipherState) nonce(in uint64) []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], in)
	return nonce[:]
}

func (s *cipherState) Encrypt(out, ad, plaintext []byte) []byte {
	out = s.c.Seal(out, s.nonce(s.n), plaintext, ad)
	s.n++
	return out
}

func (s *cipherState) Decrypt(out, ad, ciphertext []byte) ([]byte, error) {
	out, err := s.c.Open(out, s.nonce(s.n), ciphertext, ad)
	s.n++
	return out, err
}

func (s *cipherState) GenerateKeypair(random io.Reader) (dhKey, error) {
	var pubkey, privkey [32]byte
	if random == nil {
		random = rand.Reader
	}
	if _, err := io.ReadFull(random, privkey[:]); err != nil {
		return dhKey{}, fmt.Errorf("Failed too generate enough random bytes for private key: %w", err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return dhKey{Private: privkey, Public: pubkey}, nil
}

func (s *cipherState) DH(privkey, pubkey [32]byte) []byte {
	var dst, in, base [32]byte
	copy(in[:], privkey[:])
	copy(base[:], pubkey[:])
	curve25519.ScalarMult(&dst, &in, &base)
	return dst[:]
}

func (s *cipherState) Rekey() {
	var zeros [32]byte
	var out []byte
	out = s.c.Seal(out, s.nonce(math.MaxUint64), []byte{}, zeros[:])
	copy(s.k[:], out[:32])

	s.c = s.Cipher(s.k)
}

func (s *cipherState) Hash() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(fmt.Errorf("Failed too create Blake2S hash: %w", err))
	}
	return h
}

func (s *cipherState) Name() []byte {
	return []byte("ed25519" + "_" + "ChaCha20Poly1305" + "_" + "Blake2S")
}

type symmetricState struct {
	cipherState
	hasK bool
	ck   []byte
	h    []byte

	prevCK []byte
	prevH  []byte
}

func (s *symmetricState) InitializeSymmetric(handshakeName []byte) {
	h := s.Hash()
	if len(handshakeName) <= h.Size() {
		s.h = make([]byte, h.Size())
		copy(s.h, handshakeName)
	} else {
		h.Write(handshakeName)
		s.h = h.Sum(nil)
	}
	s.ck = make([]byte, len(s.h))
	copy(s.ck, s.h)
}

func (s *symmetricState) MixKey(dhOutput []byte) {
	s.n = 0
	s.hasK = true
	var hk []byte
	s.ck, hk, _ = hkdf(s.Hash, 2, s.ck[:0], s.k[:0], nil, s.ck, dhOutput)
	copy(s.k[:], hk)
	s.c = s.Cipher(s.k)
}

func (s *symmetricState) MixHash(data []byte) {
	h := s.Hash()
	h.Write(s.h)
	h.Write(data)
	s.h = h.Sum(s.h[:0])
}

func (s *symmetricState) MixKeyAndHash(data []byte) {
	var hk []byte
	var temp []byte
	s.ck, temp, hk = hkdf(s.Hash, 3, s.ck[:0], temp, s.k[:0], s.ck, data)
	s.MixHash(temp)
	copy(s.k[:], hk)
	s.c = s.Cipher(s.k)
	s.n = 0
	s.hasK = true
}

func (s *symmetricState) EncryptAndHash(out, plaintext []byte) []byte {
	if !s.hasK {
		s.MixHash(plaintext)
		return append(out, plaintext...)
	}
	ciphertext := s.Encrypt(out, s.h, plaintext)
	s.MixHash(ciphertext[len(out):])
	return ciphertext
}

func (s *symmetricState) DecryptAndHash(out, data []byte) ([]byte, error) {
	if !s.hasK {
		s.MixHash(data)
		return append(out, data...), nil
	}
	plaintext, err := s.Decrypt(out, s.h, data)
	if err != nil {
		return nil, err
	}
	s.MixHash(data)
	return plaintext, nil
}

func (s *symmetricState) Split() (*cipherState, *cipherState) {
	s1, s2 := &cipherState{}, &cipherState{}
	hk1, hk2, _ := hkdf(s.Hash, 2, s1.k[:0], s2.k[:0], nil, s.ck, nil)
	copy(s1.k[:], hk1)
	copy(s2.k[:], hk2)
	s1.c = s.Cipher(s1.k)
	s2.c = s.Cipher(s2.k)
	return s1, s2
}

func (s *symmetricState) Checkpoint() {
	if len(s.ck) > cap(s.prevCK) {
		s.prevCK = make([]byte, len(s.ck))
	}
	s.prevCK = s.prevCK[:len(s.ck)]
	copy(s.prevCK, s.ck)

	if len(s.h) > cap(s.prevH) {
		s.prevH = make([]byte, len(s.h))
	}
	s.prevH = s.prevH[:len(s.h)]
	copy(s.prevH, s.h)
}

func (s *symmetricState) Rollback() {
	s.ck = s.ck[:len(s.prevCK)]
	copy(s.ck, s.prevCK)
	s.h = s.h[:len(s.prevH)]
	copy(s.h, s.prevH)
}

type dhKey struct {
	Private [32]byte
	Public  [32]byte
}

type handshakeConfig struct {
	Random        io.Reader
	Initiator     bool
	LocalIdentity *PrivateIdentity
}

type writeOperation func(s *handshakeState, msg writeableHandshakeMessage) error
type readOperation func(s *handshakeState, msg readableHandshakeMessage) error

func writeMessageE(s *handshakeState, msg writeableHandshakeMessage) error {
	e, err := s.symmState.GenerateKeypair(s.rng)
	if err != nil {
		return fmt.Errorf("Failed to generate ephemeral key pair: %w", err)
	}
	s.ephemeralDHKey = e
	msg.WriteEPublic(s.ephemeralDHKey.Public)
	s.symmState.MixHash(s.ephemeralDHKey.Public[:])
	// Ignore PSK for now
	/* if len(s.psk) > 0 {
		s.symmState.MixKey(s.ephemeralDHKey.Public)
	} */
	return nil
}

func writeMessageS(s *handshakeState, msg writeableHandshakeMessage) error {
	if len(s.localIdentity.PublicKey()) == 0 {
		return errors.New("Invalid state, Public Key of local identity is nil")
	}
	idBytes, err := s.localIdentity.Bytes()
	if err != nil {
		return fmt.Errorf("Unable to marshal local identity: %w", err)
	}
	var encryptedSPublic []byte
	encryptedSPublic = s.symmState.EncryptAndHash(encryptedSPublic, padPrefixPayload(idBytes))
	msg.WriteEncryptedIdentity(encryptedSPublic)

	return nil
}

func writeMessageDHEE(s *handshakeState, msg writeableHandshakeMessage) error {
	s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteEphemeralPubKey))
	return nil
}

func writeMessageDHES(s *handshakeState, msg writeableHandshakeMessage) error {
	if s.initiator {
		s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteIdentity.PublicKey()))
	} else {
		s.symmState.MixKey(s.symmState.DH(s.localIdentity.PrivateKey(), s.remoteEphemeralPubKey))
	}
	return nil
}

func writeMessageDHSE(s *handshakeState, msg writeableHandshakeMessage) error {
	if s.initiator {
		s.symmState.MixKey(s.symmState.DH(s.localIdentity.PrivateKey(), s.remoteEphemeralPubKey))
	} else {
		s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteIdentity.PublicKey()))
	}
	return nil
}

func writeMessageE_DHEE_S_DHES(s *handshakeState, msg writeableHandshakeMessage) error {
	for _, f := range []writeOperation{writeMessageE, writeMessageDHEE, writeMessageS, writeMessageDHES} {
		if err := f(s, msg); err != nil {
			return err
		}
	}
	return nil
}

func writeMessageS_DHSE(s *handshakeState, msg writeableHandshakeMessage) error {
	for _, f := range []writeOperation{writeMessageS, writeMessageDHSE} {
		if err := f(s, msg); err != nil {
			return err
		}
	}
	return nil
}

func readMessageE(s *handshakeState, msg readableHandshakeMessage) (err error) {
	if msg.Length() < dhLen {
		return errors.New("Message is too short")
	}

	s.remoteEphemeralPubKey, err = msg.ReadEPublic()
	if err != nil {
		return fmt.Errorf("Failed to read remote ephemeral public key from packet: %w", err)
	}
	s.symmState.MixHash(s.remoteEphemeralPubKey[:])
	// Ignore PSK for now
	/* if len(s.psk) > 0 {
		s.symmState.MixKey(s.remoteEphemeralPubKey[:])
	} */
	return nil
}

func readMessageS(s *handshakeState, msg readableHandshakeMessage) error {
	expected := dhLen
	if s.symmState.hasK {
		expected += 16
	}

	if msg.Length() < expected {
		return errors.New("Message is too short")
	}

	if s.remoteIdentity != nil {
		return errors.New("Invalid state, we already received the remote identity")
	}

	idBytes, err := msg.ReadEncryptedIdentity()
	if err != nil {
		return fmt.Errorf("Failed to read encrypted identity bytes from message: %w", err)
	}
	var decryptedRawIdentity []byte
	decryptedRawIdentity, err = s.symmState.DecryptAndHash(decryptedRawIdentity, idBytes)
	if err != nil {
		return fmt.Errorf("Failed to decrypt remote identity: %w", err)
	}
	smCrt, err := smolcert.ParseBuf(unpadPayload(decryptedRawIdentity))
	if err != nil {
		return fmt.Errorf("Failed to parse remote identity: %w", err)
	}
	identity := &Identity{*smCrt}

	if err := s.eventuallyVerifyIdentity(identity); err != nil {
		return fmt.Errorf("Failed to verify remote identity: %w", err)
	}
	s.remoteIdentity = identity

	return nil
}

func readMessageDHEE(s *handshakeState, msg readableHandshakeMessage) error {
	s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteEphemeralPubKey))
	return nil
}

func readMessageDHES(s *handshakeState, msg readableHandshakeMessage) error {
	if s.remoteIdentity == nil {
		return errors.New("Invalid state! We haven't received a remote identity yet")
	}
	if s.initiator {
		s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteIdentity.PublicKey()))
	} else {
		s.symmState.MixKey(s.symmState.DH(s.localIdentity.PrivateKey(), s.remoteEphemeralPubKey))
	}
	return nil
}

func readMessageDHSE(s *handshakeState, msg readableHandshakeMessage) error {
	if s.remoteIdentity == nil {
		return errors.New("Invalid state! We haven't received a remote identity yet")
	}
	if s.initiator {
		s.symmState.MixKey(s.symmState.DH(s.localIdentity.PrivateKey(), s.remoteEphemeralPubKey))
	} else {
		s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteIdentity.PublicKey()))
	}
	return nil
}

func readMessageE_DHEE_S_DHES(s *handshakeState, msg readableHandshakeMessage) error {
	for _, f := range []readOperation{readMessageE, readMessageDHEE, readMessageS, readMessageDHES} {
		if err := f(s, msg); err != nil {
			return err
		}
	}
	return nil
}

func readMessageS_DHSE(s *handshakeState, msg readableHandshakeMessage) error {
	for _, f := range []readOperation{readMessageS, readMessageDHSE} {
		if err := f(s, msg); err != nil {
			return err
		}
	}
	return nil
}

type handshakeState struct {
	rng         io.Reader
	readMsgIdx  int
	writeMsgIdx int

	writeOperations []writeOperation
	readOperations  []readOperation

	ephemeralDHKey        dhKey
	symmState             *symmetricState
	localIdentity         *PrivateIdentity
	remoteIdentity        *Identity
	remoteEphemeralPubKey [32]byte
	initiator             bool
	shouldWrite           bool
	cs1                   *cipherState
	cs2                   *cipherState
}

func newState(conf *handshakeConfig) *handshakeState {
	s := &handshakeState{
		rng:           conf.Random,
		localIdentity: conf.LocalIdentity,
		initiator:     conf.Initiator,
		shouldWrite:   conf.Initiator,
		readMsgIdx:    0,
		writeMsgIdx:   0,
	}

	if s.rng == nil {
		s.rng = rand.Reader
	}
	s.symmState = &symmetricState{}
	s.symmState.InitializeSymmetric([]byte("Krach_" + "XX" + "_" + string(s.symmState.Name())))
	// TODO investigate if we need to call MixHash for prologue, and if we need a prologue
	s.symmState.MixHash([]byte{})

	if s.initiator {
		s.writeOperations = []writeOperation{writeMessageE, writeMessageS_DHSE}
		s.readOperations = []readOperation{readMessageE_DHEE_S_DHES}
	} else {
		s.writeOperations = []writeOperation{writeMessageE_DHEE_S_DHES}
		s.readOperations = []readOperation{readMessageE, readMessageS_DHSE}
	}
	return s
}

func (s *handshakeState) eventuallyVerifyIdentity(id *Identity) error {
	return nil
}

func (s *handshakeState) WriteMessage(out writeableHandshakeMessage, payload []byte) (err error) {
	if !s.shouldWrite {
		return errors.New("Unexpected call to WriteMessage should be ReadMessage")
	}
	if s.writeMsgIdx >= len(s.writeOperations) {
		return errors.New("Invalid state, no more write operations")
	}
	op := s.writeOperations[s.writeMsgIdx]
	s.writeMsgIdx++
	if err := op(s, out); err != nil {
		return err
	}
	s.shouldWrite = false
	paddedPayload := padPrefixPayload(payload)
	var encryptedPayload []byte
	encryptedPayload = s.symmState.EncryptAndHash(encryptedPayload, paddedPayload)
	out.WriteEncryptedPayload(encryptedPayload)

	if s.writeMsgIdx == len(s.writeOperations) {
		s.cs1, s.cs2 = s.symmState.Split()
	}
	return nil
}

func (s *handshakeState) ReadMessage(out []byte, message readableHandshakeMessage) (payload []byte, err error) {
	if s.shouldWrite {
		return nil, errors.New("Unexpected call to ReadMessage should be WriteMessage")
	}
	if s.readMsgIdx >= len(s.readOperations) {
		return nil, errors.New("Invalid state, no more read operations")
	}
	s.symmState.Checkpoint()

	op := s.readOperations[s.readMsgIdx]
	s.readMsgIdx++
	if err := op(s, message); err != nil {
		return nil, err
	}

	msgBytes, err := message.ReadPayload()
	if err != nil {
		return nil, fmt.Errorf("Failed to read payload from received handshake packet: %w", err)
	}

	out, err = s.symmState.DecryptAndHash(out, msgBytes)
	out = unpadPayload(out)
	if err != nil {
		s.symmState.Rollback()
		return nil, fmt.Errorf("Failed to decrypt payload: %w", err)
	}

	s.shouldWrite = true

	if s.readMsgIdx == len(s.readOperations) {
		s.cs1, s.cs2 = s.symmState.Split()
	}
	return out, nil
}

func (s *handshakeState) CipherStates() (*cipherState, *cipherState, error) {
	if s.cs1 != nil && s.cs2 != nil {
		return s.cs1, s.cs2, nil
	}
	return nil, nil, errors.New("Invalid state! No CipherStates derived yet")
}

func (s *handshakeState) ChannelBinding() []byte {
	return s.symmState.h
}

func (s *handshakeState) PeerIdentity() *Identity {
	return s.remoteIdentity
}
