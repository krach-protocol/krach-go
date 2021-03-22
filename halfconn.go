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

func (h *halfConn) write(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	origLen := len(buf)
	// TODO check max length
	paddedBuf := padPrefixPayload(buf)
	encBuf := h.cs.Encrypt(nil, nil, paddedBuf)
	length := len(encBuf)
	lengthBuf := make([]byte, 2)
	endianess.PutUint16(lengthBuf, uint16(length))
	_, err = h.conn.netConn.Write(lengthBuf)
	if err != nil {
		return 0, err
	}
	for n < length {
		n1, err := h.conn.netConn.Write(encBuf[n:])
		if err != nil {
			return 0, err
		}
		n = n + n1
	}
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
