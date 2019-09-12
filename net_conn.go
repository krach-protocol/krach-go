package krach

import (
	"net"
)

type udpNetConn struct {
	*net.UDPConn
}

func (u *udpNetConn) WriteTo(b []byte, addr *net.UDPAddr) (int, error) {
	return u.WriteToUDP(b, addr)
}

func (u *udpNetConn) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	return u.ReadFromUDP(b)
}

func newUDPNetConn(remoteAddr *net.UDPAddr) (*udpNetConn, error) {
	baseConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}
	return &udpNetConn{baseConn}, nil
}
