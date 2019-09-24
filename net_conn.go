package krach

import (
	"net"
)

type udpNetConn struct {
	net.PacketConn
}

func (u *udpNetConn) WriteTo(b []byte, addr *net.UDPAddr) (int, error) {
	return u.PacketConn.WriteTo(b, addr)
}

func (u *udpNetConn) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	n, addr, err := u.PacketConn.ReadFrom(b)
	return n, addr.(*net.UDPAddr), err
}

func listenUDPNetConn(listenAddr *net.UDPAddr) (*udpNetConn, error) {
	baseConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &udpNetConn{baseConn}, nil
}

func newUDPNetConn(remoteAddr *net.UDPAddr) (*udpNetConn, error) {
	baseConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	return &udpNetConn{baseConn}, nil
}
