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

func (h *halfConn) read(buf []byte) (n int, err error) {
	lengthBuf := make([]byte, 2)
	n, err = h.conn.netConn.Read(lengthBuf)
	if err != nil {
		return 0, err
	}
	expectedLength := endianess.Uint16(lengthBuf)
	minPayloadLength := int(expectedLength) - macSize - 15 /*max padding bytes */ - 1 /*pad length field*/
	if len(buf) < minPayloadLength {
		return 0, fmt.Errorf("Buffer too small. Can't read %d expected bytes into a buffer of %d bytes", minPayloadLength, len(buf))
	}
	readBuf := make([]byte, expectedLength)
	n = 0
	for n < int(expectedLength) {
		n1, err := h.conn.netConn.Read(readBuf[n:])
		if err != nil {
			return 0, err
		}
		n = n + n1
	}
	decryptedBuf, err := h.cs.Decrypt(nil, nil, readBuf)
	if err != nil {
		return 0, err
	}
	padBytes := decryptedBuf[0]
	copy(buf, decryptedBuf[1:len(decryptedBuf)-int(padBytes)])
	return len(decryptedBuf) - 1 - int(padBytes), nil
}
