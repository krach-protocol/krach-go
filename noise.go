package krach

import (
	"github.com/flynn/noise"
)

type noiseCipher struct {
	encryptionCipher noise.Cipher
	decryptionCipher noise.Cipher
}

func newNoiseCipher(c1 *noise.CipherState, c2 *noise.CipherState) *noiseCipher {
	n := &noiseCipher{
		encryptionCipher: c1.Cipher(),
		decryptionCipher: c2.Cipher(),
	}
	return n
}

func (n *noiseCipher) EncryptToRemote(out, payload, ad []byte, nonce uint64) {
	n.encryptionCipher.Encrypt(out, nonce, ad, payload)
}

func (n *noiseCipher) DecryptFromRemote(out, payload, ad []byte, nonce uint64) error {
	_, err := n.decryptionCipher.Decrypt(out, nonce, ad, payload)
	return err
}
