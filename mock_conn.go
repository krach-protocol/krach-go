package krach

import (
	"errors"
	"net"
	"sync"
)

type mockConnection struct {
	// string is the string represention of net.UDPAddr as net.UDPAddr can't be used as map key
	hosts  map[string]chan *mockPacket
	rwLock *sync.RWMutex
}

func (m *mockConnection) send(pkt *mockPacket, receiver *net.UDPAddr) error {
	m.rwLock.RLock()
	stringAddr := receiver.String()
	transmit, exists := m.hosts[stringAddr]
	if !exists {
		m.rwLock.RUnlock()
		m.rwLock.Lock()
		transmit = make(chan *mockPacket, 10)
		m.hosts[stringAddr] = transmit
		m.rwLock.Unlock()
	} else {
		m.rwLock.RUnlock()
	}
	select {
	case transmit <- pkt:
		return nil
	default:
		return errors.New("I/O error")
	}
}

func (m *mockConnection) Listen(localAddr *net.UDPAddr) (*halfConn, error) {
	m.rwLock.Lock()
	defer m.rwLock.Unlock()
	conn := &halfConn{
		localAddr: localAddr,
		mainConn:  m,
	}
	stringAddr := localAddr.String()
	receiveChan, exists := m.hosts[stringAddr]
	if !exists {
		receiveChan = make(chan *mockPacket, 10)
		m.hosts[stringAddr] = receiveChan
	}
	conn.recvChan = receiveChan
	return conn, nil
}

func (m *mockConnection) Close() error {
	m.rwLock.Lock()
	defer m.rwLock.Unlock()
	for name, packetChan := range m.hosts {
		close(packetChan)
		delete(m.hosts, name)
	}
	return nil
}

func newMockConnection() *mockConnection {
	return &mockConnection{
		hosts:  make(map[string]chan *mockPacket),
		rwLock: &sync.RWMutex{},
	}
}

type mockPacket struct {
	payload []byte
	sender  *net.UDPAddr
}

type halfConn struct {
	mainConn  *mockConnection
	localAddr *net.UDPAddr
	recvChan  chan *mockPacket
}

func (h *halfConn) Close() error {
	close(h.recvChan)
	return nil
}

func (h *halfConn) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	select {
	case pkt := <-h.recvChan:
		// Apparently it is possible to read nil from a closed connection
		if pkt != nil {
			if len(b) < len(pkt.payload) {
				return 0, nil, errors.New("Receive buffer too small")
			}
			n := copy(b, pkt.payload)
			return n, pkt.sender, nil
		}
		// Seems that the connection is closed
		return 0, nil, errors.New("i/o connection closed")

	default:
		return 0, nil, timeoutError
	}
}

func (h *halfConn) WriteTo(b []byte, addr *net.UDPAddr) (int, error) {
	pkt := &mockPacket{
		sender:  h.localAddr,
		payload: make([]byte, len(b)),
	}
	n := copy(pkt.payload, b)
	err := h.mainConn.send(pkt, addr)
	//n := len(b)
	if err != nil {
		n = 0
	}
	return n, err
}
