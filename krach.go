package krach

import (
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"
)

var (
	ch = &codec.CborHandle{
		TimeRFC3339: false,
	}
)

const (
	// KrachVersion is the byte representation of the currently supported wire protocol format for Krach
	KrachVersion byte = 0x00
)

// configure the CBOR codec, so we serialize structs as arrays and have always the same byte representation of data
func init() {
	ch.EncodeOptions.Canonical = true
	ch.TimeNotBuiltin = false
}

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

// PeerIndex represents the 32 bit index each peer assigns to a session for identification independent
// from IP address and port
type PeerIndex uint32

// Uint32 returns the PeerIndex as an unsigned 32 bit integer to be used when serializing a packet
func (p PeerIndex) Uint32() uint32 {
	return uint32(p)
}

var (
	// DefaultReadDeadline how long we wait when polling the UDP socket. Essentially this controls
	// how quick we can react to state changes like closing a connection
	DefaultReadDeadline = time.Second * 5
)

var (
	// A timeout error which should be similar enough to the timeout error used in the net package.
	timeoutError = &net.OpError{Err: errors.New("i/o timeout")}
)
