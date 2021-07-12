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
