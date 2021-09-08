//go:build !multiplexing
// +build !multiplexing

package krach

import (
	"net"
	"time"
)

func (c *Conn) Write(buf []byte) (n int, err error) {
	return c.hcOut.write(buf)
}

func (c *Conn) Read(buf []byte) (n int, err error) {
	return c.hcIn.read(buf)
}

func (c *Conn) Close() error {
	if c == nil {
		// This might be nil if connection is already closed or failed to start correctly
		return nil
	}
	if c.netConn != nil {
		// This might be nil if connection is already closed or failed to start correctly
		return c.netConn.Close()
	}
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	return c.netConn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.netConn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.netConn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.netConn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.netConn.SetWriteDeadline(t)
}

func Dial(address string, config *ConnectionConfig) (*Conn, error) {
	netConn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	config.IsClient = true // Ensure we are running in client mode
	conn, err := newConn(config, netConn)
	if err != nil {
		return nil, err
	}
	err = conn.runClientHandshake()
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func Server(netConn net.Conn, config *ConnectionConfig) (*Conn, error) {
	config.IsClient = false
	conn, err := newConn(config, netConn)
	if err != nil {
		return nil, err
	}
	if err := conn.runServerHandshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

type listener struct {
	netListener net.Listener
	config      *ConnectionConfig
}

// Listen returns a listener which listens on the specified port for new
// krach connections
func Listen(address string, config *ConnectionConfig) (net.Listener, error) {
	nl, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return &listener{
		netListener: nl,
		config:      config,
	}, nil
}

// Accept accepts new client connections on the specified address and
// return a krach connections once the handshake is completed
func (l *listener) Accept() (net.Conn, error) {
	netConn, err := l.netListener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(netConn, l.config)
}

// Close closes the listener, but does not handle already
// established connections. They encounter errors when trying
// to use the underlying network connection
func (l *listener) Close() error {
	return l.netListener.Close()
}

// Addr returns the listen address of this listener
func (l *listener) Addr() net.Addr {
	return l.netListener.Addr()
}
