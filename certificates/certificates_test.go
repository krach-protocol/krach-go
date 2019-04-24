package certificates

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

var validateCDDL = true

func TestCertificateSerilization(t *testing.T) {
	notBefore := time.Now().UTC().Add(time.Hour * -12)
	notAfter := time.Now().UTC().Add(time.Hour * 12)

	pubKey := ed25519.PublicKey([]byte{0x00, 0x42, 0x23, 0x05})
	cert := &Certificate{
		Issuer:       "connctd",
		PublicKey:    pubKey,
		SerialNumber: 12,
		Signature:    []byte{0x55, 0x42, 0x07},
		Subject:      "device",
		Extensions:   []Extension{},
		Validity:     &Validity{NotBefore: NewTime(notBefore), NotAfter: NewTime(notAfter)},
	}

	certFile, err := os.Create("./cert.cbor")
	require.NoError(t, err)
	defer certFile.Close()
	defer func() {
		require.NoError(t, os.Remove("cert.cbor"))
	}()
	require.NotZero(t, certFile)
	require.NoError(t, Serialize(cert, certFile))
	if validateCDDL {
		certFile.Close()
		cmd := exec.Command("cddl", "spec.cddl", "validate", "cert.cbor")
		cmdOut, err := cmd.CombinedOutput()
		require.NoError(t, err, "Certificate does not match specification: %s", cmdOut)
	}
}

func TestCertificateParsing(t *testing.T) {
	notBefore := time.Now().UTC().Add(time.Hour * -12)
	notAfter := time.Now().UTC().Add(time.Hour * 12)

	buf := &bytes.Buffer{}
	pubKey := ed25519.PublicKey([]byte{0x00, 0x42, 0x23, 0x05})
	cert := &Certificate{
		Issuer:       "connctd",
		PublicKey:    pubKey,
		SerialNumber: 12,
		Signature:    []byte{0x55, 0x42, 0x07},
		Subject:      "device",
		Extensions:   []Extension{},
		Validity:     &Validity{NotBefore: NewTime(notBefore), NotAfter: NewTime(notAfter)},
	}
	require.NoError(t, Serialize(cert, buf))

	cert2, err := Parse(buf)
	require.NoError(t, err)
	require.NotZero(t, cert2)

	assert.EqualValues(t, cert, cert2)
	assert.EqualValues(t, notAfter.Unix(), int64(*cert2.Validity.NotAfter))
}

func TestCertPool(t *testing.T) {
	// Create a self signed certificate
	rootCert, rootPriv, err := SelfSignedCertificate("root", time.Time{}, time.Time{}, []Extension{})
	rootCertBytes, err := rootCert.Bytes()
	require.NoError(t, err)
	rootCert.Signature = ed25519.Sign(rootPriv, rootCertBytes)

	// Create a new 'normal' certificate

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cert := &Certificate{
		Extensions:   []Extension{},
		Issuer:       "root",
		PublicKey:    pub,
		SerialNumber: 1,
		Subject:      "device",
		Validity:     &Validity{NotBefore: &ZeroTime, NotAfter: &ZeroTime},
	}
	certBytes, err := cert.Bytes()
	cert.Signature = ed25519.Sign(rootPriv, certBytes)

	pool := NewCertPool(rootCert)

	err = pool.Validate(cert)
	assert.NoError(t, err)
}
