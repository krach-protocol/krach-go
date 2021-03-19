// +build !multiplexing

package krach

import (
	"net"
	"time"
)

func (c *Conn) Write(buf []byte) (n int, err error) {
	panic("Not implemented yet")
}

func (c *Conn) Read() (n int, err error) {
	panic("Not implemented yet")
}

func (c *Conn) Close() error {
	return c.netConn.Close()
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
