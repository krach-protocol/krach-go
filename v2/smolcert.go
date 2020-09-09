package krach

import (
	"github.com/iost-official/ed25519/extra25519"
	"github.com/smolcert/smolcert"
	"golang.org/x/crypto/ed25519"
)

// Identity wraps a smolcert based certificate and provides the public
// key as curve25519 representation instead of ed25519
type Identity struct {
	smolcert.Certificate
}

// PublicKey returns the curve25519 representation of the ed25519 public key of this certificate
func (s *Identity) PublicKey() [32]byte {
	// The certificates used by Smolcert use ed25519 keys, but we need curve25519 keys.
	// As they both are based on the same curve, we can convert them.
	var curvePubKey [32]byte
	var edPubKey [32]byte
	copy(edPubKey[:], s.Certificate.PubKey)
	if !extra25519.PublicKeyToCurve25519(&curvePubKey, &edPubKey) {
		// Signal that we couldn't create a valid curve25519 representation
		panic("Failed to convert ed25519 public to curve25519 public key")
	}
	return curvePubKey
}

// Cert returns the plain smolcert certificate
func (s *Identity) Cert() *smolcert.Certificate {
	return &s.Certificate
}

// PrivateIdentity wraps a SmolIdentity and an ed25519 private key
type PrivateIdentity struct {
	Identity
	privKey ed25519.PrivateKey
}

// NewPrivateIdentity creates a new PrivateSmolIdentity which contains the smolcert with the private key.
// This might be needed for cryptographic operations like eDH or eDSA etc.
func NewPrivateIdentity(cert *smolcert.Certificate, privKey ed25519.PrivateKey) *PrivateIdentity {
	return &PrivateIdentity{
		Identity: Identity{
			Certificate: *cert,
		},
		privKey: privKey,
	}
}

// PrivateKey returns a curve25519 representation of the private key
func (p *PrivateIdentity) PrivateKey() [32]byte {
	var edPrivKey [64]byte
	var curvePrivKey [32]byte
	copy(edPrivKey[:], p.privKey)
	extra25519.PrivateKeyToCurve25519(&curvePrivKey, &edPrivKey)
	return curvePrivKey
}
