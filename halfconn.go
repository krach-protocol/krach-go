package krach

import (
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
)

type halfConn struct {
	cs    *cipherState
	conn  *Conn
	lock  *sync.Mutex
	debug bool
}

func newHalfConn(conn *Conn, cs *cipherState) *halfConn {
	return &halfConn{
		conn:  conn,
		cs:    cs,
		lock:  &sync.Mutex{},
		debug: conn.config.Debug,
	}
}

func (h *halfConn) write(inBuf []byte) (n int, err error) {
	h.lock.Lock()
	defer h.lock.Unlock()
	if len(inBuf) == 0 {
		return 0, nil
	}
	if len(inBuf) > maxMsgLen-macSize-15 /*max amount of padding*/ -1 /*padding prefix */ {
		return 0, fmt.Errorf("%d bytes exceeds the maximum allowed message lnegth of %d bytes", len(inBuf), maxMsgLen)
	}
	origLen := len(inBuf)
	packetBuf := bufPool.Get().(*buf)
	packetBuf.index = 1
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
		if h.debug {
			logrus.WithFields(logrus.Fields{
				"lengthPrefix":      lenBuf,
				"packetData":        packetBuf.data[n+packetBuf.index:],
				"packetLength":      len(packetBuf.data[n+packetBuf.index:]),
				"totalPacketLength": len(packetBuf.data[n+packetBuf.index:]) + len(lenBuf),
			}).Debug("Writing encrypted packet")
		}
	}
	packetBuf.reset()
	bufPool.Put(packetBuf)
	return origLen, nil
}

func (h *halfConn) read(inBuf []byte) (n int, err error) {
	h.lock.Lock()
	defer h.lock.Unlock()
	packetBuf := bufPool.Get().(*buf)
	packetBuf.index = 0
	packetBuf.ensureLength(2)
	_, err = h.conn.netConn.Read(packetBuf.data[packetBuf.index : packetBuf.index+2])
	if err != nil {
		return 0, err
	}
	expectedLength := endianess.Uint16(packetBuf.data[packetBuf.index : packetBuf.index+2])
	minPayloadLength := int(expectedLength) - macSize - 15 /*max padding bytes */ - 1 /*pad length field*/
	if len(inBuf) < minPayloadLength {
		return 0, fmt.Errorf("buffer too small. Can't read %d expected bytes into a buffer of %d bytes", minPayloadLength, len(inBuf))
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
	_, err = h.cs.Decrypt(packetBuf.data[:0], nil, packetBuf.data[:n])
	if err != nil {
		return 0, err
	}
	packetBuf.data = packetBuf.data[0 : n-macSize] /* Remove MAC data */
	packetBuf.index = 1
	packetBuf.copyOutUnpadded(inBuf)

	payloadLength := packetBuf.sizeUnpadded()
	packetBuf.reset()
	bufPool.Put(packetBuf)
	return int(payloadLength), nil
}
