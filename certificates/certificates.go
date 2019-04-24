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

type Issuer interface {
	ID() string
	Sign(cert *Certificate) (*Certificate, error)
}

type CertPool map[string]*Certificate

func NewCertPool(rootCerts ...*Certificate) *CertPool {
	p := make(CertPool)
	for _, c := range rootCerts {
		p[c.Subject] = c
	}
	return &p
}

func (c *CertPool) Validate(cert *Certificate) error {
	if !cert.Validity.NotBefore.IsZero() {
		// Validate notBefore
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

	issuerCert, exists := (*c)[cert.Issuer]
	if !exists {
		return errors.New("certificate is not signed by a known issuer")
	}
	sig := cert.Signature
	cert.Signature = nil
	certBytes, err := cert.Bytes()
	if err != nil {
		return errors.New("Failed to serialize certificate for validation")
	}
	if !ed25519.Verify(issuerCert.PublicKey, certBytes, sig) {
		return errors.New("Signature validation failed")
	}
	return nil
}

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

func (c *Certificate) Bytes() ([]byte, error) {
	buf := &bytes.Buffer{}
	err := Serialize(c, buf)
	return buf.Bytes(), err
}

type Time int64

var ZeroTime = Time(0)

func NewTime(now time.Time) *Time {
	unix := now.Unix()
	t := Time(unix)
	return &t
}

func (t *Time) StdTime() time.Time {
	return time.Unix(int64(*t), 0)
}

func (t *Time) IsZero() bool {
	return int64(*t) == 0
}

type Validity struct {
	_struct interface{} `codec:"-,toarray"`

	NotBefore *Time `codec:"notBefore"`
	NotAfter  *Time `codec:"notAfter"`
}

type Extension struct {
	_struct interface{} `codec:"-,toarray"`

	OID      uint64 `codec:"oid"`
	Critical bool   `codec:"critical"`
	Value    []byte `codec:"value"`
}

func Issue(template *Certificate, issuer Issuer) (*Certificate, error) {

	cert, err := issuer.Sign(template)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func Parse(r io.Reader) (cert *Certificate, err error) {
	dec := codec.NewDecoder(r, ch)

	cert = &Certificate{}
	if err := dec.Decode(cert); err != nil {
		return nil, err
	}

	return cert, err
}

func Serialize(cert *Certificate, w io.Writer) (err error) {
	enc := codec.NewEncoder(w, ch)

	err = enc.Encode(cert)
	enc.Release()
	return
}
