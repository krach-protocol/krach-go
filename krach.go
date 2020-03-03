package krach

import (
	"net"

	"github.com/pkg/errors"
)

const (
	// KrachVersion is the byte representation of the currently supported wire protocol format for Krach
	KrachVersion byte = 0x01
)

const errPrefix = "krach: "

// Some constants for packet sizing
const (
	// MaxPayloadSize = math.MaxUint16 - 16 /*mac size*/ - uint16Size /*data len*/
	MaxPacketLength   = 508  // 576 bytes minimum IPv4 reassembly buffer - 60 bytes max IP header - 8 bytes UDP header
	MinPacketLength   = 1    // Every packet smaller than this can only be invalid
	MaxV6PacketLength = 1212 // 1280 bytes - 60 bytes IPv6 header - 8 bytes UDP header
	HeaderLen         = 10   // Header length in bytes
	AuthTagLen        = 16   // Length of the AuthenticationTag in bytes
)

var (
	// A timeout error which should be similar enough to the timeout error used in the net package.
	timeoutError = &net.OpError{Err: errors.New("i/o timeout")}
)

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	certPool CertPool
	config   *ConnectionConfig
}

// Accept waits for and returns the next incoming connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &Conn{
		conn:     c,
		config:   *l.config,
		certPool: l.certPool,
	}, nil
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
func Listen(laddr string, config *ConnectionConfig, certPool CertPool) (net.Listener, error) {

	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}

	return &listener{
		Listener: l,
		config:   config,
		certPool: certPool,
	}, nil
}

func Dial(addr string, config *ConnectionConfig, certPool CertPool) (*Conn, error) {
	rawConn, err := new(net.Dialer).Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	config.isClient = true

	return &Conn{
		conn:     rawConn,
		config:   *config,
		certPool: certPool,
	}, nil
}
