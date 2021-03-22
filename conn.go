package krach

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
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
	// MaxFrameLength uint16
	// ReadTimeout sets a deadline to every read operation
	ReadTimeout time.Duration
	// WriteTimeout sets a deadline to every write operation
	WriteTimeout time.Duration
	// HandshakeTimeout specifies the maximum duration which a handshake is allowed to take
	HandshakeTimeout time.Duration
	// VerifyCallback can be called to validate the identity and received payload during the handshake
	VerifyCallback VerifyCallbackFunc

	Debug bool
}

func DefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		// MaxFrameLength:   1420,
		ReadTimeout:      time.Second * 10,
		WriteTimeout:     time.Second * 10,
		HandshakeTimeout: time.Second * 10,
	}
}

type Conn struct {
	netConn net.Conn

	handshakeCond     *sync.Cond
	handshakeMutex    *sync.Mutex
	handshakeComplete bool
	handshakeErr      error

	channelBinding []byte

	hcIn  *halfConn
	hcOut *halfConn

	config *ConnectionConfig
}

func NewConn(conf *ConnectionConfig, netConn net.Conn) (*Conn, error) {
	//maxFramePayloadLength := int(conf.MaxFrameLength) - 2 /*packet length*/ - frameHeaderSize - macSize
	// if n := maxFramePayloadLength % 16; n != 0 {
	// Can't exceed maximum FrameLength (might be Layer2 limitation), so we substract here, to achieve a length
	// which doesn't require padding by default
	//	maxFramePayloadLength = maxFramePayloadLength - n
	// }
	c := &Conn{

		handshakeMutex: &sync.Mutex{},
		config:         conf,
		netConn:        netConn,
	}

	return c, nil
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

// buf must contain a correctly formatted packet including the length prefix etc
func (c *Conn) writePacket(pkt writeableHandshakeMessage) (int, error) {
	return c.netConn.Write(pkt.Serialize())
}

func (c *Conn) readPacket(pkt readableHandshakeMessage) error {
	buf := make([]byte, 4096)
	var receivedPktType packetType
	pktLength := 0
	_, err := c.netConn.Read(buf[:1])
	if err != nil {
		return err
	}
	payloadOffset := 0

	if pkt.PacketType() == packetTypeHandshakeInit {
		payloadOffset = 4
		if KrachVersion != buf[0] {
			return errors.New("Unexpected protocol version")
		}
		_, err = c.netConn.Read(buf[1:4])
		if err != nil {
			return err
		}
		receivedPktType = packetType(buf[1])
		pktLength = int(endianess.Uint16(buf[2:4]))
	} else {
		payloadOffset = 3
		receivedPktType = packetType(buf[0])
		_, err = c.netConn.Read(buf[1:3])
		if err != nil {
			return err
		}
		pktLength = int(endianess.Uint16(buf[1:3]))
	}

	if receivedPktType != pkt.PacketType() {
		return fmt.Errorf("Received unexpected packet type during handshake. Expected %d, but got %d", pkt.PacketType(), receivedPktType)
	}
	n, err := c.netConn.Read(buf[payloadOffset:])
	if err != nil {
		return err
	}
	if n != pktLength {
		return fmt.Errorf("Failed to read complete packet. Expected to read %d bytes, but only got %d bytes", pktLength, n)
	}
	return pkt.Deserialize(buf[payloadOffset : n+payloadOffset])
}

func (c *Conn) validateRemoteID(id *Identity, payload []byte) error {
	// TODO call callback, so the user can verify identity and payload
	return nil
}

func (c *Conn) runClientHandshake() error {
	var (
		state *handshakeState
		err   error
	)

	state = newState(&handshakeConfig{
		Initiator:     true,
		LocalIdentity: c.config.LocalIdentity,
	})

	hsInit := &handshakeInitPacket{}
	err = state.WriteMessage(hsInit, nil)
	if err != nil {
		return err
	}
	if _, err = c.writePacket(hsInit); err != nil {
		return err
	}

	hshkResp := &handshakeResponsePacket{}
	err = c.readPacket(hshkResp)
	if err != nil {
		return err
	}

	payload, err := state.ReadMessage([]byte{}, hshkResp)
	if err != nil {
		return err
	}

	remoteID := state.PeerIdentity()

	if err := c.validateRemoteID(remoteID, payload); err != nil {
		return fmt.Errorf("Validation of server id failed: %w", err)
	}

	handshakeFinMsg := &handshakeFinPacket{}

	if err = state.WriteMessage(handshakeFinMsg, c.config.Payload); err != nil {
		return err
	}

	if _, err := c.writePacket(handshakeFinMsg); err != nil {
		return err
	}
	csIn, csOut, err := state.CipherStates()
	if err != nil {
		return err
	}

	if csOut == nil || csIn == nil {
		return errors.New("Failed to create cipher states")
	}

	c.hcIn = newHalfConn(c, csIn)
	c.hcOut = newHalfConn(c, csOut)

	c.channelBinding = state.ChannelBinding()
	c.handshakeComplete = true
	return nil
}

func (c *Conn) runServerHandshake() error {

	hs := newState(&handshakeConfig{
		Initiator:     false,
		LocalIdentity: c.config.LocalIdentity,
	})

	hsInit := &handshakeInitPacket{}

	err := c.readPacket(hsInit)
	if err != nil {
		return err
	}

	_, err = hs.ReadMessage(nil, hsInit)
	if err != nil {
		return err
	}

	hndResp := &handshakeResponsePacket{}

	if err = hs.WriteMessage(hndResp, c.config.Payload); err != nil {
		return err
	}

	_, err = c.writePacket(hndResp)
	if err != nil {
		return err
	}

	hndFin := &handshakeFinPacket{}
	err = c.readPacket(hndFin)
	if err != nil {
		return err
	}

	// TODO remove padding from payload
	payload, err := hs.ReadMessage(nil, hndFin)
	if err != nil {
		return err
	}

	remoteID := hs.PeerIdentity()
	if err := c.validateRemoteID(remoteID, payload); err != nil {
		return err
	}

	csOut, csIn, err := hs.CipherStates()
	if err != nil {
		return err
	}

	c.hcIn = newHalfConn(c, csIn)
	c.hcOut = newHalfConn(c, csOut)

	c.channelBinding = hs.ChannelBinding()
	c.config.PeerStatic = remoteID
	c.handshakeComplete = true
	return nil
}

var bytesPerLine = 16

func printBuf(buf []byte) {
	for i, b := range buf {
		fmt.Printf("0x%X ", b)
		if i%bytesPerLine == 0 {
			fmt.Printf("\n")
		}
	}
	fmt.Printf("\n")
}
