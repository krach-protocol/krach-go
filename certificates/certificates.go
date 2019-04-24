package certificates

import (
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

func (c *CertPool) Validate(cert *Certificate) error {
	if cert.Validity != nil {
		// Certificate has Validity, validate it

	}
	return nil
}

type Certificate struct {
	_struct interface{} `codec:"-,toarray"`

	SerialNumber uint64            `codec:"serial_number"`
	Issuer       string            `codec:"issuer"`
	Validity     *Validity         `codec:"validity,omitempty"`
	Subject      string            `codec:"subject"`
	PublicKey    ed25519.PublicKey `codec:"public_key"`
	Extensions   []Extension       `codec:"extensions"`
	Signature    []byte            `codec:"signature"`
}

type Time int64

func NewTime(now time.Time) *Time {
	unix := now.Unix()
	t := Time(unix)
	return &t
}

/*func (t *Time) MarshalBinary() (data []byte, err error) {

}

func (t *Time) UnmarshalBinary(data []byte) error {

}*/

// TODO serialize this into time.Time
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
