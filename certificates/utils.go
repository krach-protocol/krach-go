package certificates

import (
	"crypto/rand"
	"time"

	"golang.org/x/crypto/ed25519"
)

// SelfSignedCertificate is a simple function to generate a self signed certificate
func SelfSignedCertificate(subject string,
	notBefore, notAfter time.Time,
	extensions []Extension) (*Certificate, ed25519.PrivateKey, error) {
	validity := &Validity{}
	if notBefore.IsZero() {
		validity.NotBefore = &ZeroTime
	} else {
		validity.NotBefore = NewTime(notBefore)
	}
	if notAfter.IsZero() {
		validity.NotAfter = &ZeroTime
	} else {
		validity.NotAfter = NewTime(notAfter)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ed25519.PrivateKey{}, err
	}
	cert := &Certificate{
		SerialNumber: 1,
		Issuer:       subject,
		Validity:     validity,
		Subject:      subject,
		PublicKey:    pub,
		Extensions:   extensions,
	}
	certBytes, err := cert.Bytes()
	if err != nil {
		return nil, ed25519.PrivateKey{}, err
	}
	cert.Signature = ed25519.Sign(priv, certBytes)
	return cert, priv, nil
}
