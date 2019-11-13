package krach

import (
	"net"
)

type udpNetConn struct {
	net.PacketConn
}

func (u *udpNetConn) Close() error {
	return u.PacketConn.Close()
}

func (u *udpNetConn) WriteTo(b []byte, addr *net.UDPAddr) (int, error) {
	return u.PacketConn.WriteTo(b, addr)
}

func (u *udpNetConn) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	n, addr, err := u.PacketConn.ReadFrom(b)
	var udpAddr *net.UDPAddr
	if addr != nil {
		udpAddr = addr.(*net.UDPAddr)
	}
	return n, udpAddr, err
}

func listenUDPNetConn(listenAddr *net.UDPAddr) (*udpNetConn, error) {
	baseConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &udpNetConn{baseConn}, nil
}

func newUDPNetConn(remoteAddr *net.UDPAddr) (*udpNetConn, error) {
	baseConn, err := net.ListenUDP("udp", &net.UDPAddr{
		// FIXME this needs to become more flexible
		IP: net.ParseIP("127.0.0.1"),
	})
	if err != nil {
		return nil, err
	}
	return &udpNetConn{baseConn}, nil
}
