package certificates

import (
	"bytes"
	"crypto/rand"
	"fmt"
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

func TestCreateSelfSignedCert(t *testing.T) {
	cert, _, err := SelfSignedCertificate("root", time.Time{}, time.Time{}, []Extension{})
	require.NoError(t, err)
	err = validateCertificate(cert, cert.PublicKey)
	assert.NoError(t, err)
}

func TestCertPool(t *testing.T) {
	// Create a self signed certificate
	rootCert, rootPriv, err := SelfSignedCertificate("root", time.Time{}, time.Time{}, []Extension{})
	require.NoError(t, err)

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
	cert, err = SignCertificate(cert, rootPriv)
	require.NoError(t, err)

	pool := NewCertPool(rootCert)

	err = pool.Validate(cert)
	assert.NoError(t, err)
}

func TestCertPoolValidateSingleCert(t *testing.T) {
	rootCert, rootKey, err := SelfSignedCertificate("testroot", time.Time{}, time.Time{}, []Extension{})
	require.NoError(t, err)

	var certChain []*Certificate
	clientPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientCert := &Certificate{
		Extensions:   []Extension{},
		Issuer:       rootCert.Subject,
		PublicKey:    clientPub,
		SerialNumber: 1,
		Subject:      "client",
		Validity:     &Validity{NotBefore: &ZeroTime, NotAfter: &ZeroTime},
	}
	clientCert, err = SignCertificate(clientCert, rootKey)
	require.NoError(t, err)
	certChain = append(certChain, clientCert)

	certPool := NewCertPool(rootCert)
	c, err := certPool.ValidateBundle(certChain)
	assert.NoError(t, err)
	assert.EqualValues(t, clientCert, c)
}

func TestCertPoolValidateUntrustedBundle(t *testing.T) {
	rootCert, _, err := SelfSignedCertificate("testroot", time.Time{}, time.Time{}, []Extension{})
	require.NoError(t, err)

	var certChain []*Certificate
	var intermediateStartCert *Certificate
	var lastCert *Certificate
	var lastPrivKey ed25519.PrivateKey
	for i := 0; i < 3; i++ {
		if lastCert == nil {
			intermediateStartCert, lastPrivKey, err = SelfSignedCertificate("intermediate 0", time.Time{}, time.Time{}, []Extension{})
			require.NoError(t, err)
			certChain = append(certChain, intermediateStartCert)
			lastCert = intermediateStartCert
		} else {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			cert := &Certificate{
				Extensions:   []Extension{},
				Issuer:       lastCert.Subject,
				PublicKey:    pub,
				SerialNumber: 1,
				Subject:      fmt.Sprintf("intermediate %d", i),
				Validity:     &Validity{NotBefore: &ZeroTime, NotAfter: &ZeroTime},
			}
			cert, err = SignCertificate(cert, lastPrivKey)
			require.NoError(t, err)
			certChain = append(certChain, cert)
			lastCert = cert
			lastPrivKey = priv
		}
	}

	clientPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientCert := &Certificate{
		Extensions:   []Extension{},
		Issuer:       lastCert.Subject,
		PublicKey:    clientPub,
		SerialNumber: 1,
		Subject:      "client",
		Validity:     &Validity{NotBefore: &ZeroTime, NotAfter: &ZeroTime},
	}
	clientCert, err = SignCertificate(clientCert, lastPrivKey)
	require.NoError(t, err)
	certChain = append(certChain, clientCert)

	pool := NewCertPool(rootCert)

	_, err = pool.ValidateBundle(certChain)
	require.Error(t, err)
}

func TestCertPoolValidateTrustedBundle(t *testing.T) {
	rootCert, rootPriv, err := SelfSignedCertificate("testroot", time.Time{}, time.Time{}, []Extension{})
	require.NoError(t, err)

	var certChain []*Certificate
	var intermediateStartCert *Certificate
	var lastCert *Certificate
	var lastPrivKey ed25519.PrivateKey
	for i := 0; i < 3; i++ {
		if lastCert == nil {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			intermediateStartCert = &Certificate{
				Subject:      "intermediate 0",
				Extensions:   []Extension{},
				PublicKey:    pub,
				SerialNumber: 1,
				Issuer:       rootCert.Subject,
				Validity:     &Validity{NotBefore: &ZeroTime, NotAfter: &ZeroTime},
			}
			intermediateStartCert, err = SignCertificate(intermediateStartCert, rootPriv)
			require.NoError(t, err)
			certChain = append(certChain, intermediateStartCert)
			lastCert = intermediateStartCert
			lastPrivKey = priv
		} else {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			cert := &Certificate{
				Extensions:   []Extension{},
				Issuer:       lastCert.Subject,
				PublicKey:    pub,
				SerialNumber: 1,
				Subject:      fmt.Sprintf("intermediate %d", i),
				Validity:     &Validity{NotBefore: &ZeroTime, NotAfter: &ZeroTime},
			}
			cert, err = SignCertificate(cert, lastPrivKey)
			require.NoError(t, err)
			certChain = append(certChain, cert)
			lastCert = cert
			lastPrivKey = priv
		}
	}

	clientPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientCert := &Certificate{
		Extensions:   []Extension{},
		Issuer:       lastCert.Subject,
		PublicKey:    clientPub,
		SerialNumber: 1,
		Subject:      "client",
		Validity:     &Validity{NotBefore: &ZeroTime, NotAfter: &ZeroTime},
	}
	clientCert, err = SignCertificate(clientCert, lastPrivKey)
	require.NoError(t, err)
	certChain = append(certChain, clientCert)

	pool := NewCertPool(rootCert)

	c, err := pool.ValidateBundle(certChain)
	assert.NoError(t, err)
	assert.EqualValues(t, clientCert, c)

}

func TestCopyCertificate(t *testing.T) {
	c1, _, err := SelfSignedCertificate("Ned Flanders", time.Now(), time.Now().Add(time.Minute), nil)
	require.NoError(t, err)

	c2 := c1.Copy()
	assert.EqualValues(t, c1, c2)

	c2.Signature = nil
	c2.Validity.NotAfter = NewTime(time.Now().Add(time.Minute * 5))
	assert.Len(t, c1.Signature, 64)
	assert.Len(t, c2.Signature, 0)
}
