package certificates

import (
	"crypto/rand"
	"time"

	"golang.org/x/crypto/ed25519"
)

// SignCertificates takes a certificate, removes the signature and creates a new signature with the given key
func SignCertificate(cert *Certificate, priv ed25519.PrivateKey) (*Certificate, error) {
	cert.Signature = nil
	certBytes, err := cert.Bytes()
	if err != nil {
		return nil, err
	}
	cert.Signature = ed25519.Sign(priv, certBytes)
	return cert, nil
}

// SelfSignedCertificate is a simple function to generate a self signed certificate
func SelfSignedCertificate(subject string,
	notBefore, notAfter time.Time,
	extensions []Extension) (*Certificate, ed25519.PrivateKey, error) {
	validity := &Validity{}
	if extensions == nil {
		extensions = []Extension{}
	}
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
		Signature:    nil,
	}
	cert, err = SignCertificate(cert, priv)
	return cert, priv, err
}
