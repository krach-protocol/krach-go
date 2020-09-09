package krach

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smolcert/smolcert"
)

var (
	errGoAway = errors.New("Go away, someone else is writing")
)

// MaxPayloadSize is the maximal size for the payload of transport packets
const MaxPayloadSize = math.MaxUint16 - 16 /*mac size*/ - uint16Size /*data len*/

// VerifyCallbackFunc is used to verify that the identity and transmitted payload are valid for this connection.
// If an  error is returned the handshake is canceled and the connection closed.
type VerifyCallbackFunc func(publicKey *Identity, data []byte) error

// CertPool Is the interface definition for implementors providing the capability to validate certificates
// against a PKI. If more detailed or additional validations are needed VerifyCallbackFunc can be used.
type CertPool interface {
	Validate(cert *smolcert.Certificate) error
}

// ConnectionConfig provides configuration details for the Dial and Listen
type ConnectionConfig struct {
	isClient bool
	Payload  []byte //additional certificates, configuration
	// LocalIdentity is this sides identity including the ed25519.PrivateKey
	LocalIdentity *PrivateIdentity
	// PeerStatic is the remotes static identity (a smolcert), received during the handshake
	PeerStatic *Identity
	// Padding is the amount of bytes to pad messages with
	Padding uint16
	// MaxFrameLength specifies the maximum length a frame can have. This may depend on the MTU etc.
	MaxFrameLength uint16
	// ReadTimeout sets a deadline to every read operation
	ReadTimeout time.Duration
	// WriteTimeout sets a deadline to every write operation
	WriteTimeout time.Duration
	// HandshakeTimeout specifies the maximum duration which a handshake is allowed to take
	HandshakeTimeout time.Duration
	// VerifyCallback can be called to validate the identity and received payload during the handshake
	VerifyCallback VerifyCallbackFunc
}

type Conn struct {
	netConn net.Conn

	streams           [255]*Stream
	currStreamWriteID int32
	nextStreamWriteID int32
	writeMtx          *sync.Mutex

	testBuf []byte
}

func NewConn(conf *ConnectionConfig) (*Conn, error) {
	c := &Conn{
		currStreamWriteID: 0,
		writeMtx:          &sync.Mutex{},
	}

	return c, nil
}

func (c *Conn) acquireConn(streamID uint8) (err error) {
	// If not busy allow one stream to move the round robin forward
	if !atomic.CompareAndSwapInt32(&c.currStreamWriteID, 0, int32(streamID)) {
		return errGoAway
	}
	c.writeMtx.Lock()
	defer c.writeMtx.Unlock()
	// we are not busy, so we select the next stream eligible to write
	var s *Stream
	nextStreamID := atomic.LoadInt32(&c.nextStreamWriteID)
	for {
		if nextStreamID >= 255 {
			nextStreamID = 0
		}
		s = c.streams[nextStreamID]
		if s != nil && s.needsWrite() {
			fmt.Printf("Stream %d needs write\n", nextStreamID)
			break
		}
		nextStreamID++
	}
	atomic.StoreInt32(&c.nextStreamWriteID, nextStreamID)

	atomic.StoreInt32(&s.writeLock, 1)
	return nil
}

func (c *Conn) newStream(id uint8) *Stream {
	s := &Stream{
		writeLock:      0,
		needsWriteFlag: 0,
		conn:           c,
		id:             id,
	}
	c.streams[id] = s
	return s
}

type Stream struct {
	writeLock      int32
	conn           *Conn
	needsWriteFlag int32
	id             uint8
}

func (s *Stream) needsWrite() bool {
	return atomic.LoadInt32(&s.needsWriteFlag) == 1
}

func (s *Stream) Write(buf []byte) (n int, err error) {
	m := len(buf)

	for m > 0 {
		atomic.StoreInt32(&s.needsWriteFlag, 1)
		for !atomic.CompareAndSwapInt32(&s.writeLock, 1, 0) {
			s.conn.acquireConn(s.id)
		}
		fmt.Printf("Stream %d is allowed to write\n", s.id)
		// Simulate a write to a connection for now with this...
		s.conn.testBuf = append(s.conn.testBuf, buf...)
		// TODO write stuff to connection
		m = m - len(buf)

		atomic.StoreInt32(&s.needsWriteFlag, 0)
		atomic.StoreInt32(&s.conn.currStreamWriteID, 0)
	}

	// Wait to be allowed to write
	// Ask if we are allowed
	// Write a frame
	// go back to top
	return
}
