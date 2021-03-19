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
