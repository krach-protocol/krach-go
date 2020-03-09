package krach

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/smolcert/smolcert"
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

// locking logic has been copied from the original TLS.conn

// Conn represents a transport encrypted connection between to endpoints
type Conn struct {
	conn net.Conn

	in, out           halfConn
	handshakeMutex    sync.Mutex
	handshakeComplete bool

	handshakeErr error
	input        *buffer
	rawInput     *buffer
	hand         bytes.Buffer // handshake data waiting to be read

	// activeCall is an atomic int32; the low bit is whether Close has
	// been called. the rest of the bits are the number of goroutines
	// in Conn.Write.
	activeCall int32
	// handshakeCond, if not nil, indicates that a goroutine is committed
	// to running the handshake for this Conn. Other goroutines that need
	// to wait for the handshake can wait on this, under handshakeMutex.
	handshakeCond  *sync.Cond
	channelBinding []byte
	config         ConnectionConfig

	certPool     CertPool
	maxFrameSize uint16
}

// Access to net.Conn methods.
// Cannot just embed net.Conn because that would
// export the struct Field too.

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means Read and Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// ConnectionState returns a tls compatible state of this connection
func (c *Conn) ConnectionState() tls.ConnectionState {

	data := &struct {
		PeerPublic    [32]byte
		HandshakeHash []byte
	}{PeerPublic: c.config.PeerStatic.PublicKey(),
		HandshakeHash: c.channelBinding}

	bytes, _ := json.Marshal(data)
	return tls.ConnectionState{
		ServerName:        c.config.PeerStatic.Subject,
		HandshakeComplete: true,
		// Used CipherSuite is not specified in crypto.tls since Blake2S is not supported by TLS
		TLSUnique: bytes,
	}
}

// ChannelBinding returns a unique identifier for this connection. This identifier is derived during the handshake.
func (c *Conn) ChannelBinding() []byte {
	return c.channelBinding
}

var (
	errClosed = errors.New("tls: use of closed connection")
)

// Write writes data to the underlying connnection
func (c *Conn) Write(b []byte) (int, error) {
	// interlock with Close below
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return 0, errClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			defer atomic.AddInt32(&c.activeCall, -2)
			break
		}
	}

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.out.Lock()
	defer c.out.Unlock()
	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.handshakeComplete {
		return 0, errors.New("internal error")
	}

	n, err := c.writePacketLocked(b)
	return n, c.out.setErrorLocked(err)
}

func (c *Conn) writePacket(data []byte) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	return c.writePacketLocked(data)
}

// InitializePacket adds additional sub-messages if needed
func (c *Conn) InitializePacket() *buffer {
	block := c.out.newBlock()
	block.resize(uint16Size)
	return block
}

func (c *Conn) writePacketLocked(data []byte) (int, error) {

	var n int

	if len(data) == 0 { //special case to answer when everything is ok during handshake
		if c.config.WriteTimeout.Nanoseconds() > 0 {
			c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout))
		}
		if _, err := c.conn.Write(make([]byte, 2)); err != nil {
			return 0, err
		}
	}

	for len(data) > 0 {

		m := len(data)

		packet := c.InitializePacket()

		maxPayloadSize := c.maxPayloadSizeForWrite(packet)
		if m > int(maxPayloadSize) {
			m = int(maxPayloadSize)
		}
		if c.out.cs != nil {
			packet.reserve(uint16Size + uint16Size + m + macSize)
			packet.resize(uint16Size + uint16Size + m)
			copy(packet.data[uint16Size+uint16Size:], data[:m])
			binary.BigEndian.PutUint16(packet.data[uint16Size:], uint16(m))
		} else {
			packet.resize(len(packet.data) + len(data))
			copy(packet.data[uint16Size:len(packet.data)], data[:m])
			binary.BigEndian.PutUint16(packet.data, uint16(len(data)))
		}

		b := c.out.encryptIfNeeded(packet)
		c.out.freeBlock(packet)

		if c.config.WriteTimeout.Nanoseconds() > 0 {
			c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout))
		}
		if _, err := c.conn.Write(b); err != nil {
			return n, err
		}

		n += m
		data = data[m:]
	}

	return n, nil
}

func (c *Conn) maxPayloadSizeForWrite(block *buffer) uint16 {

	//return MaxPayloadSize //TODO
	return c.config.MaxFrameLength
}

// Read reads data from the connection.
// Read can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (c *Conn) Read(b []byte) (n int, err error) {

	if err = c.Handshake(); err != nil {
		return
	}
	if len(b) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return
	}

	c.in.Lock()
	defer c.in.Unlock()

	if c.rawInput != nil {
		//fmt.Println("raw 7:", hex.EncodeToString(c.rawInput.data))
	}
	if c.input == nil && c.in.err == nil {
		if err := c.readPacket(); err != nil {
			return 0, err
		}
	}

	if err := c.in.err; err != nil {
		return 0, err
	}

	n, err = c.input.Read(b)
	if c.input.off >= len(c.input.data) {
		c.in.freeBlock(c.input)
		c.input = nil
	}

	if ri := c.rawInput; ri != nil &&
		n != 0 && err == nil &&
		c.input == nil && len(ri.data) > 0 {
		if recErr := c.readPacket(); recErr != nil {
			err = recErr // will be io.EOF on closeNotify
		}
	}

	if n != 0 || err != nil {
		return n, err
	}

	return n, err
}

// readPacket reads the next noise packet from the connection
// and updates the record layer state.
// c.in.Mutex <= L; c.input == nil.
func (c *Conn) readPacket() error {

	if c.rawInput == nil {
		c.rawInput = c.in.newBlock()
		//fmt.Println("new block!")
	}
	b := c.rawInput

	if c.config.ReadTimeout.Nanoseconds() > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout))
	}
	if err := b.readFromUntil(c.conn, uint16Size); err != nil {

		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}

	n := int(binary.BigEndian.Uint16(b.data))

	if c.config.ReadTimeout.Nanoseconds() > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout))
	}
	if err := b.readFromUntil(c.conn, uint16Size+n); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}

	//b is c.rawinput
	b, c.rawInput = c.in.splitBlock(b, uint16Size+n)

	off, length, err := c.in.decryptIfNeeded(b)

	b.off = off

	data := b.data[off : off+length]
	if err != nil {
		c.in.setErrorLocked(err)
		return err
	}

	if c.in.cs != nil {

		c.input = b
		b = nil

	} else {
		c.hand.Write(data)
	}
	if b != nil {
		c.in.freeBlock(b)
	}

	return c.in.err
}

// Close closes the connection.
func (c *Conn) Close() error {
	// Interlock with Conn.Write above.
	var x int32
	for {
		x = atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return errClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x|1) {
			break
		}
	}
	if x != 0 {
		// io.Writer and io.Closer should not be used concurrently.
		// If Close is called while a Write is currently in-flight,
		// interpret that as a sign that this Close is really just
		// being used to break the Write and/or clean up resources and
		// avoid sending the alertCloseNotify, which may block
		// waiting on handshakeMutex or the c.out mutex.
		return c.conn.Close()
	}

	var alertErr error

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if c.handshakeComplete {
		alertErr = errors.New("close error")
	}

	if err := c.conn.Close(); err != nil {
		return err
	}
	return alertErr
}

// Handshake runs the client or server handshake
// protocol if it has not yet been run.
// Most uses of this package need not call Handshake
// explicitly: the first Read or Write will call it automatically.
func (c *Conn) Handshake() error {
	// c.handshakeErr and c.handshakeComplete are protected by
	// c.handshakeMutex. In order to perform a handshake, we need to lock
	// c.in also and c.handshakeMutex must be locked after c.in.
	//
	// However, if a Read() operation is hanging then it'll be holding the
	// lock on c.in and so taking it here would cause all operations that
	// need to check whether a handshake is pending (such as Write) to
	// block.
	//
	// Thus we first take c.handshakeMutex to check whether a handshake is
	// needed.
	//
	// If so then, previously, this code would unlock handshakeMutex and
	// then lock c.in and handshakeMutex in the correct order to run the
	// handshake. The problem was that it was possible for a Read to
	// complete the handshake once handshakeMutex was unlocked and then
	// keep c.in while waiting for network data. Thus a concurrent
	// operation could be blocked on c.in.
	//
	// Thus handshakeCond is used to signal that a goroutine is committed
	// to running the handshake and other goroutines can wait on it if they
	// need. handshakeCond is protected by handshakeMutex.
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	for {
		if err := c.handshakeErr; err != nil {
			return err
		}
		if c.handshakeComplete {
			return nil
		}
		if c.handshakeCond == nil {
			break
		}
		c.handshakeCond.Wait()
	}

	// Set handshakeCond to indicate that this goroutine is committing to
	// running the handshake.
	c.handshakeCond = sync.NewCond(&c.handshakeMutex)
	c.handshakeMutex.Unlock()

	c.in.Lock()
	defer c.in.Unlock()

	c.handshakeMutex.Lock()

	hasTimeout := c.config.HandshakeTimeout.Nanoseconds() > 0

	doneChan := make(chan struct{}, 1)
	var timeoutChan <-chan time.Time
	if hasTimeout {
		timeoutChan = time.After(c.config.HandshakeTimeout)
	}

	if c.config.isClient {
		c.handshakeErr = c.runClientHandshake()
		doneChan <- struct{}{}
	} else {
		c.handshakeErr = c.runServerHandshake()
		doneChan <- struct{}{}
		if c.handshakeErr != nil {
			//fmt.Println(c.handshakeErr)
			//send plaintext error to client for debug
			c.writePacket([]byte{0xFF}) //don't care about result
		}
	}

	select {
	case <-doneChan:
		break
	case <-timeoutChan:
		c.handshakeErr = fmt.Errorf("Handshake timed out")
	}

	// Wake any other goroutines that are waiting for this handshake to
	// complete.
	c.handshakeCond.Broadcast()
	c.handshakeCond = nil

	return c.handshakeErr
}

func (c *Conn) runClientHandshake() error {

	var (
		msg         []byte
		state       *handshakeState
		err         error
		csIn, csOut *cipherState
	)

	state = newState(&handshakeConfig{
		Initiator:     true,
		LocalIdentity: c.config.LocalIdentity,
	})

	hsInit := composeHandshakeInitPacket()
	err = state.WriteMessage(hsInit, nil)
	if err != nil {
		return err
	}
	if _, err = c.writePacket(hsInit.Buf); err != nil {
		return err
	}

	//read noise message
	if err := c.readPacket(); err != nil {
		return err
	}

	msg = c.hand.Next(c.hand.Len())

	// cannot reuse msg for read, need another buf
	inBlock := c.in.newBlock()
	inBlock.reserve(len(msg))

	hshkResp := handshakeResponseFromBuf(msg)
	payload, err := state.ReadMessage(inBlock.data, hshkResp)
	if err != nil {
		c.in.freeBlock(inBlock)
		return err
	}

	c.in.freeBlock(inBlock)

	remoteID := state.PeerIdentity()
	if err := c.callVerifyCallback(remoteID, payload); err != nil {
		return err
	}

	b := c.out.newBlock()

	handshakeFinMsg := composeHandshakeFinPacket()
	if err = state.WriteMessage(handshakeFinMsg, pad(c.config.Payload)); err != nil {
		c.out.freeBlock(b)
		return err
	}
	b.data = handshakeFinMsg.Buf

	if _, err = c.writePacket(b.data); err != nil {
		c.out.freeBlock(b)
		return err
	}
	c.out.freeBlock(b)

	csOut, csIn, err = state.CipherStates()
	if err != nil {
		return err
	}

	if csIn == nil || csOut == nil {
		panic("not supported")
	}

	c.in.cs = csOut
	c.out.cs = csIn
	c.in.padding, c.out.padding = c.config.Padding, c.config.Padding
	c.channelBinding = state.ChannelBinding()
	c.handshakeComplete = true
	return nil
}

func (c *Conn) runServerHandshake() error {
	var (
		csOut, csIn *cipherState
	)

	hs := newState(&handshakeConfig{
		Initiator:     false,
		LocalIdentity: c.config.LocalIdentity,
	})

	if err := c.readPacket(); err != nil {
		return err
	}

	hndInit := handshakeInitFromBuf(c.hand.Next(c.hand.Len()))
	_, err := hs.ReadMessage(nil, hndInit)

	if err != nil {
		return err
	}

	b := c.out.newBlock()

	hndResp := composeHandshakeResponse()
	if err = hs.WriteMessage(hndResp, pad(c.config.Payload)); err != nil {
		c.out.freeBlock(b)
		return err
	}

	_, err = c.writePacket(hndResp.Buf)
	c.out.freeBlock(b)
	if err != nil {
		return err
	}

	if err := c.readPacket(); err != nil {
		return err
	}

	inBlock := c.in.newBlock()
	data := c.hand.Next(c.hand.Len())
	inBlock.reserve(len(data))

	hndFin := handshakeFinFromBuf(data)
	payload, err := hs.ReadMessage(nil, hndFin)
	c.in.freeBlock(inBlock)

	if err != nil {
		return err
	}

	remoteID := hs.PeerIdentity()
	if err := c.callVerifyCallback(remoteID, payload); err != nil {
		return err
	}

	csIn, csOut, err = hs.CipherStates()
	if err != nil {
		return err
	}

	if csIn == nil || csOut == nil {
		return errors.New("Not supported")
	}

	c.in.cs = csOut
	c.out.cs = csIn
	c.in.padding, c.out.padding = c.config.Padding, c.config.Padding
	c.channelBinding = hs.ChannelBinding()
	c.config.PeerStatic = hs.PeerIdentity()

	if err != nil {
		return err
	}

	c.handshakeComplete = true
	return nil
}

func (c *Conn) callVerifyCallback(id *Identity, payload []byte) error {
	if c.config.VerifyCallback == nil {
		return nil
	}
	return c.config.VerifyCallback(id, payload)
}

func pad(payload []byte) []byte {
	padBuf := make([]byte, 2+len(payload))
	copy(padBuf[2:], payload)
	return padBuf
}
