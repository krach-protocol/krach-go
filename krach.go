package krach

import (
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/xtaci/smux"
	"gopkg.in/noisesocket.v0"
)

const errPrefix = "krach: "

//const MaxPayloadSize = math.MaxUint16 - 16 /*mac size*/ - uint16Size /*data len*/

const MaxPacketLength = 508    // 576 bytes minimum IPv4 reassembly buffer - 60 bytes max IP header - 8 bytes UDP header
const MaxV6PacketLength = 1212 // 1280 bytes - 60 bytes IPv6 header - 8 bytes UDP header
const HeaderLen = 10           // Header length in bytes
const AuthTagLen = 16          // Length of the AuthenticationTag in bytes

type Config struct {
	*noisesocket.ConnectionConfig
	*smux.Config
}

type Session struct {
	nsConn net.Conn
	sess   *smux.Session

	conns []*Conn
}

func newSession(conn net.Conn, sess *smux.Session) *Session {
	return &Session{
		nsConn: conn,
		sess:   sess,
		conns:  make([]*Conn, 0, 5),
	}
}

func (s *Session) Open() (*Conn, error) {
	stream, err := s.sess.OpenStream()
	if err != nil {
		return nil, errors.Wrapf(err, errPrefix+"Failed to open stream with %s", s.nsConn.RemoteAddr())
	}
	c := &Conn{
		stream: stream,
		sess:   s,
	}
	s.conns = append(s.conns, c)
	return c, nil
}

func (s *Session) Accept() (*Conn, error) {
	stream, err := s.sess.AcceptStream()
	if err != nil {
		return nil, errors.Wrapf(err, errPrefix+"Failed to accept stream from %s", s.nsConn.RemoteAddr())
	}
	c := &Conn{
		sess:   s,
		stream: stream,
	}
	s.conns = append(s.conns, c)
	return c, nil
}

func (s *Session) Close() (err error) {
	// Return at least the last non nil error, probably some multi error concept could be useful
	for _, c := range s.conns {
		if errr := c.Close(); errr != nil {
			err = errr
		}
	}
	return
}

func (s *Session) LocalAddr() net.Addr {
	return s.nsConn.LocalAddr()
}

func (s *Session) RemoteAddr() net.Addr {
	return s.nsConn.RemoteAddr()
}

type Conn struct {
	stream *smux.Stream
	sess   *Session
}

func (c *Conn) Close() error {
	return c.stream.Close()
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return c.stream.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return c.stream.Write(b)
}

func (c *Conn) LocalAddr() net.Addr {
	return c.stream.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.stream.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}
