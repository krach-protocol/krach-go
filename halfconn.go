package krach

import "fmt"

type halfConn struct {
	cs   *cipherState
	conn *Conn
}

func newHalfConn(conn *Conn, cs *cipherState) *halfConn {
	return &halfConn{
		conn: conn,
		cs:   cs,
	}
}

func (h *halfConn) write(inBuf []byte) (n int, err error) {
	if len(inBuf) == 0 {
		return 0, nil
	}
	origLen := len(inBuf)
	packetBuf := bufPool.Get().(*buf)
	packetBuf.index = 1 // reserve space for packet length
	// TODO check max length
	packetBuf.resize(len(inBuf))
	packetBuf.copyInto(inBuf)
	packetBuf.pad()
	packetBuf.ensureCapacity(len(packetBuf.data) + macSize)

	packetBuf.data = h.cs.Encrypt(packetBuf.data[:0], nil, packetBuf.data)
	packetBuf.index = 0
	length := packetBuf.size()
	lenBuf := make([]byte, 2)
	endianess.PutUint16(lenBuf, length)
	_, err = h.conn.netConn.Write(lenBuf)
	if err != nil {
		return 0, err
	}
	for n < int(length) {
		n1, err := h.conn.netConn.Write(packetBuf.data[n+packetBuf.index:])
		if err != nil {
			return 0, err
		}
		n = n + n1
	}
	packetBuf.reset()
	bufPool.Put(packetBuf)
	return origLen, nil
}

func (h *halfConn) read(inBuf []byte) (n int, err error) {
	packetBuf := bufPool.Get().(*buf)
	packetBuf.index = 0
	packetBuf.ensureLength(2)
	n, err = h.conn.netConn.Read(packetBuf.data[packetBuf.index : packetBuf.index+2])
	if err != nil {
		return 0, err
	}
	expectedLength := endianess.Uint16(packetBuf.data[packetBuf.index : packetBuf.index+2])
	minPayloadLength := int(expectedLength) - macSize - 15 /*max padding bytes */ - 1 /*pad length field*/
	if len(inBuf) < minPayloadLength {
		return 0, fmt.Errorf("Buffer too small. Can't read %d expected bytes into a buffer of %d bytes", minPayloadLength, len(inBuf))
	}
	packetBuf.reset()
	packetBuf.index = 0
	packetBuf.ensureLength(int(expectedLength))
	n = 0
	for n < int(expectedLength) {
		n1, err := h.conn.netConn.Read(packetBuf.data[n:])
		if err != nil {
			return 0, err
		}
		n = n + n1
	}

	_, err = h.cs.Decrypt(packetBuf.data[:0], nil, packetBuf.data)
	if err != nil {
		return 0, err
	}
	packetBuf.data = packetBuf.data[0 : len(packetBuf.data)-macSize] /* Remove MAC data */
	packetBuf.index = 1
	packetBuf.copyOutUnpadded(inBuf)

	payloadLength := packetBuf.sizeUnpadded()
	packetBuf.reset()
	bufPool.Put(packetBuf)
	return int(payloadLength), nil
}
