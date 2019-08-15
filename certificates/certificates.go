/*
This package implements CBOR based certificates loosely based on the CBOR profile for X.509 certificates
(https://tools.ietf.org/id/draft-raza-ace-cbor-certificates-00.html)

Current ToDos:
- Limit key usage, not everyone should be able to sign keys
- probably more
*/
package certificates

import (
	"bytes"
	"errors"
	"io"
	"time"

	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/ed25519"
)

var (
	ch = &codec.CborHandle{
		TimeRFC3339: false,
	}
)

func init() {
	ch.EncodeOptions.Canonical = true
	ch.TimeNotBuiltin = false
}

// CertPool is a pool of root certificates which can be used to validate a certificate
type CertPool map[string]*Certificate

// NewCertPool creates a new CertPool from a group of root certificates
func NewCertPool(rootCerts ...*Certificate) *CertPool {
	p := make(CertPool)
	for _, c := range rootCerts {
		p[c.Subject] = c
	}
	return &p
}

// Validate takes a certificate, checks if the issuer is known to the CertPool, validates
// the issuer certificate and then validates the given certificate against the issuer certificate
func (c *CertPool) Validate(cert *Certificate) error {

	issuerCert, exists := (*c)[cert.Issuer]
	if !exists {
		return errors.New("certificate is not signed by a known issuer")
	}
	// Validate the issuer cert, might be invalid too (expired etc.)
	if err := validateCertificate(issuerCert, issuerCert.PublicKey); err != nil {
		return errors.New("Error validating issuing root certificate: " + err.Error())
	}

	return validateCertificate(cert, issuerCert.PublicKey)
}

func (c *CertPool) ValidateBundle(certBundle []*Certificate) (*Certificate, error) {
	// FIXME when we have defined extensions, validate capabilities of certificates through extensions
	issuerMap := make(map[string]*Certificate)
	subjectMap := make(map[string]*Certificate)
	for _, cert := range certBundle {
		issuerMap[cert.Issuer] = cert
		subjectMap[cert.Subject] = cert
	}

	var clientCert *Certificate
	var intermediateCerts []*Certificate
	for _, cert := range certBundle {
		if _, found := issuerMap[cert.Subject]; found {
			intermediateCerts = append(intermediateCerts, cert)
			continue
		} else {
			clientCert = cert
		}
	}

	if clientCert == nil {
		return nil, errors.New("Can't find non-intermediate certificate in certificate chain")
	}

	if clientIssuer, found := subjectMap[clientCert.Issuer]; found {
		if err := validateCertificate(clientCert, clientIssuer.PublicKey); err != nil {
			return nil, err
		}
	} else {
		// Might be that the certificate is already trusted through the current pool
		if err := c.Validate(clientCert); err == nil {
			return clientCert, nil
		}
		return nil, errors.New("No issuer for the client certificate was found in the intermediate certificates")
	}

	var chainTopCert *Certificate
	// Validate the chain of intermediate certs
	for _, cert := range intermediateCerts {
		if issuerCert, exists := subjectMap[cert.Issuer]; exists {
			if err := validateCertificate(cert, issuerCert.PublicKey); err != nil {
				return nil, errors.New("Validation error in chain of intermediate certificates")
			}
		} else {
			chainTopCert = cert
		}
	}

	if chainTopCert == nil {
		return nil, errors.New("The intermediate chain is self signed and not signed by one of the root certs of this pool")
	}
	if err := c.Validate(chainTopCert); err != nil {
		return nil, err
	}
	return clientCert, nil
}

func validateCertificate(cert *Certificate, pubKey ed25519.PublicKey) error {
	if !cert.Validity.NotBefore.IsZero() {
		notBefore := cert.Validity.NotBefore.StdTime()
		if time.Now().Before(notBefore) {
			return errors.New("certificate can't be valid yet")
		}
	}

	if !cert.Validity.NotAfter.IsZero() {
		notAfter := cert.Validity.NotAfter.StdTime()
		if time.Now().After(notAfter) {
			return errors.New("certificate is not valid anymore")
		}
	}
	sig := cert.Signature

	cert.Signature = nil
	certBytes, err := cert.Bytes()

	if err != nil {
		return errors.New("Failed to serialize certificate for validation")
	}
	if !ed25519.Verify(pubKey, certBytes, sig) {
		return errors.New("Signature validation failed")
	}
	return nil
}

// Certificate represents CBOR based certificates based on the provide spec.cddl
type Certificate struct {
	_struct interface{} `codec:"-,toarray"`

	SerialNumber uint64 `codec:"serial_number"`
	Issuer       string `codec:"issuer"`
	// NotBefore and NotAfter might be 0 to indicate to be ignored during validation
	Validity   *Validity         `codec:"validity,omitempty"`
	Subject    string            `codec:"subject"`
	PublicKey  ed25519.PublicKey `codec:"public_key"`
	Extensions []Extension       `codec:"extensions"`
	Signature  []byte            `codec:"signature"`
}

// Bytes returns the CBOR encoded form of the certificate as byte slice
func (c *Certificate) Bytes() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := Serialize(c, buf)
	return buf.Bytes(), err
}

// Time is a type to represent int encoded time stamps based on the elapsed seconds since epoch
type Time int64

// ZeroTime represent a zero timestamp which might indicate that this timestamp can be ignored
var ZeroTime = Time(0)

// NewTime creates a new Time from a given time.Time with second precision
func NewTime(now time.Time) *Time {
	unix := now.Unix()
	t := Time(unix)
	return &t
}

// StdTime returns a time.Time with second precision
func (t *Time) StdTime() time.Time {
	return time.Unix(int64(*t), 0)
}

// IsZero is true if this is a zero time
func (t *Time) IsZero() bool {
	return int64(*t) == 0
}

// Validity represents the time constrained validity of a Certificate.
// NotBefore might be ZeroTime to ignore this constraint, same goes for NotAfter
type Validity struct {
	_struct interface{} `codec:"-,toarray"`

	NotBefore *Time `codec:"notBefore"`
	NotAfter  *Time `codec:"notAfter"`
}

// Extension represents a Certificate Extension as specified for X.509 certificates
type Extension struct {
	_struct interface{} `codec:"-,toarray"`

	OID      uint64 `codec:"oid"`
	Critical bool   `codec:"critical"`
	Value    []byte `codec:"value"`
}

// Parse parses a Certificate from an io.Reader
func Parse(r io.Reader) (cert *Certificate, err error) {
	dec := codec.NewDecoder(r, ch)

	cert = &Certificate{}
	if err := dec.Decode(cert); err != nil {
		return nil, err
	}

	return cert, err
}

// Serialize serializes a Certificate to an io.Writer
func Serialize(cert *Certificate, w io.Writer) (err error) {
	enc := codec.NewEncoder(w, ch)

	err = enc.Encode(cert)
	enc.Release()
	return
}
