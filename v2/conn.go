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
const MaxPayloadSize = math.MaxUint16 - 16 /*mac size*/ - 2 /*stream id and command*/ - uint16Size /*data len*/

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
	IsClient bool
	Payload  []byte //additional certificates, configuration
	// LocalIdentity is this sides identity including the ed25519.PrivateKey
	LocalIdentity *PrivateIdentity
	// PeerStatic is the remotes static identity (a smolcert), received during the handshake
	PeerStatic *Identity
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

func DefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		MaxFrameLength:   1420,
		ReadTimeout:      time.Second * 10,
		WriteTimeout:     time.Second * 10,
		HandshakeTimeout: time.Second * 10,
	}
}

type Conn struct {
	netConn net.Conn

	strs              *streams
	currStreamWriteID int32
	nextStreamWriteID int32
	writeMtx          *sync.Mutex
	readMtx           *sync.Mutex
	currStreamReadID  int32

	handshakeCond     *sync.Cond
	handshakeMutex    *sync.Mutex
	handshakeComplete bool
	handshakeErr      error

	channelBinding []byte
	// TODO add halfconns
	csIn  *cipherState
	csOut *cipherState

	testBuf []byte

	config                *ConnectionConfig
	maxFramePayloadLength int
}

func NewConn(conf *ConnectionConfig) (*Conn, error) {
	maxFramePayloadLength := int(conf.MaxFrameLength) - 2 /*packet length*/ - frameHeaderSize - macSize
	if n := maxFramePayloadLength % 16; n != 0 {
		// Can't exceed maximum FrameLength (might be Layer2 limitation), so we substract here, to achieve a length
		// which doesn't require padding by default
		maxFramePayloadLength = maxFramePayloadLength - n
	}
	c := &Conn{
		currStreamWriteID: 0,
		writeMtx:          &sync.Mutex{},
		readMtx:           &sync.Mutex{},
		handshakeMutex:    &sync.Mutex{},
		strs:              newStreams(),
		config:            conf,
	}

	return c, nil
}

func (c *Conn) acquireConnForRead(streamID uint8) (err error) {

	if !atomic.CompareAndSwapInt32(&c.currStreamReadID, 0, int32(streamID)) {
		return errGoAway
	}
	c.readMtx.Lock()
	defer c.readMtx.Unlock()

	return nil
}

func (c *Conn) acquireConnForWrite(streamID uint8) (err error) {
	// If not busy allow one stream to move the round robin forward

	if !atomic.CompareAndSwapInt32(&c.currStreamWriteID, 0, int32(streamID)) {
		return errGoAway
	}
	fmt.Printf("Stream %d is handling write\n", streamID)
	//c.writeMtx.Lock()
	//defer c.writeMtx.Unlock()
	// we are not busy, so we select the next stream eligible to write
	var s *Stream
	nextStreamID := atomic.LoadInt32(&c.nextStreamWriteID)
	for {
		if nextStreamID >= 255 {
			nextStreamID = 1 // 0 is a special stream reserved for future use
		}
		s = c.strs.get(uint8(nextStreamID))
		if s != nil && s.needsWrite() {
			nextStreamID++
			break
		}
		nextStreamID++
	}
	fmt.Printf("Next stream ID is now %d\n", nextStreamID)
	atomic.StoreInt32(&c.nextStreamWriteID, nextStreamID)

	atomic.StoreInt32(&s.writeLock, 1)
	return nil
}

func (c *Conn) NewStream(id uint8) (*Stream, error) {
	s := &Stream{
		writeLock:      0,
		needsWriteFlag: 0,
		conn:           c,
		id:             id,
		inBufLock:      &sync.Mutex{},
		inBuf:          make([]byte, 0),
	}
	if err := c.strs.insert(id, s); err != nil {
		return nil, err
	}
	return s, nil
}

func (c *Conn) Handshake() error {
	c.handshakeMutex.Lock()

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

	c.handshakeCond = sync.NewCond(c.handshakeMutex)
	c.handshakeMutex.Unlock()

	//c.in.Lock()
	//defer c.in.Unlock()

	c.handshakeMutex.Lock()

	if c.config.IsClient {
		c.handshakeErr = c.runClientHandshake()
	} else {
		c.handshakeErr = c.runServerHandshake()
		if c.handshakeErr != nil {
			//fmt.Println(c.handshakeErr)
			//send plaintext error to client for debug
			// c.writePacket([]byte{0xFF}) //don't care about result
		}
	}

	c.handshakeCond.Broadcast()
	c.handshakeCond = nil

	return c.handshakeErr
}

func (c *Conn) writePacket(buf []byte) (int, error) {
	payloadLen := len(buf)
	lenBuf := make([]byte, 2)
	endianess.PutUint16(lenBuf, uint16(payloadLen))
	if _, err := c.netConn.Write(lenBuf); err != nil {
		return 0, err
	}
	return c.netConn.Write(buf)
}

func (c *Conn) readPacket() ([]byte, error) {
	lenBuf := make([]byte, 2)
	n, err := c.netConn.Read(lenBuf)
	if err != nil {
		return nil, err
	}
	if n != 2 {
		return nil, errors.New("Unable to read packet length from connection")
	}

	pktLen := endianess.Uint16(lenBuf)
	buf := make([]byte, pktLen)
	n, err = c.netConn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n != int(pktLen) {
		return nil, errors.New("Read incomplete packet")
	}
	return buf, nil
}

func (c *Conn) validateRemoteID(id *Identity, payload []byte) error {
	// TODO call callback, so the user can verify identity and payload
	return nil
}

func (c *Conn) runClientHandshake() error {
	var (
		msg   []byte
		state *handshakeState
		err   error
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

	msg, err = c.readPacket()
	if err != nil {
		return err
	}
	hshkResp := handshakeResponseFromBuf(msg)
	payload, err := state.ReadMessage([]byte{}, hshkResp)
	if err != nil {
		return err
	}

	remoteID := state.PeerIdentity()

	if err := c.validateRemoteID(remoteID, payload); err != nil {
		return fmt.Errorf("Validation of server id failed: %w", err)
	}

	handshakeFinMsg := composeHandshakeFinPacket()

	paddedPayload, _ := padPayload(c.config.Payload)
	if err = state.WriteMessage(handshakeFinMsg, paddedPayload); err != nil {
		return err
	}

	if _, err := c.writePacket(handshakeFinMsg.Buf); err != nil {
		return err
	}

	c.csIn, c.csOut, err = state.CipherStates()
	if err != nil {
		return err
	}

	if c.csOut == nil || c.csIn == nil {
		return errors.New("Failed to create cipher states")
	}

	c.channelBinding = state.ChannelBinding()
	c.handshakeComplete = true
	return nil
}

func (c *Conn) runServerHandshake() error {

	hs := newState(&handshakeConfig{
		Initiator:     false,
		LocalIdentity: c.config.LocalIdentity,
	})

	pkt, err := c.readPacket()
	if err != nil {
		return err
	}

	hndInit := handshakeInitFromBuf(pkt)
	_, err = hs.ReadMessage(nil, hndInit)
	if err != nil {
		return err
	}

	hndResp := composeHandshakeResponse()

	// TODO pad payload
	if err = hs.WriteMessage(hndResp, c.config.Payload); err != nil {
		return err
	}

	_, err = c.writePacket(hndResp.Buf)
	if err != nil {
		return err
	}

	pkt, err = c.readPacket()
	if err != nil {
		return err
	}

	hndFin := handshakeFinFromBuf(pkt)
	payload, err := hs.ReadMessage(nil, hndFin)
	if err != nil {
		return err
	}

	remoteID := hs.PeerIdentity()
	if err := c.validateRemoteID(remoteID, payload); err != nil {
		return err
	}

	c.csOut, c.csIn, err = hs.CipherStates()
	if err != nil {
		return err
	}

	c.channelBinding = hs.ChannelBinding()
	c.config.PeerStatic = remoteID
	c.handshakeComplete = true
	return nil
}
