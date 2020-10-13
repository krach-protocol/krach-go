package krach

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Stream struct {
	writeLock      int32
	conn           *Conn
	needsWriteFlag int32
	id             uint8
}

func (s *Stream) needsWrite() bool {
	return atomic.LoadInt32(&s.needsWriteFlag) == 1
}

func (s *Stream) Write(buf []byte) (n int, err error) {
	defer func(err error, s *Stream) {
		if err != nil {
			if netErr, ok := err.(net.Error); ok {
				if !netErr.Temporary() {
					// TODO mark stream and connection as broken
				}
			}
		}
	}(err, s)
	if err = s.conn.Handshake(); err != nil {
		return 0, err
	}
	m := len(buf)

	for m > 0 {

		n1 := m
		if m > s.conn.maxFramePayloadLength {
			n1 = s.conn.maxFramePayloadLength
		}
		payloadBuf := make([]byte, n1+frameHeaderSize)
		payloadBuf[1] = s.id
		payloadBuf[2] = frameCmdPSH.Byte()
		copy(payloadBuf[3:], buf[:n])

		payloadBuf, padLen := padPayload(payloadBuf)
		payloadBuf[0] = padLen
		pktLength := len(payloadBuf) + macSize
		pktLengthBuf := make([]byte, 16) /* Pad also the ad with zero bytes, so we don't need to transmit padding information for ad */
		endianess.PutUint16(pktLengthBuf, uint16(pktLength))

		atomic.StoreInt32(&s.needsWriteFlag, 1)
		for !atomic.CompareAndSwapInt32(&s.writeLock, 1, 0) {
			s.conn.acquireConnForWrite(s.id)
		}

		encBuf := s.conn.csOut.Encrypt([]byte{}, pktLengthBuf, payloadBuf)
		n, err = s.conn.netConn.Write(pktLengthBuf[:2])
		if err != nil {
			return 0, err
		}
		n, err = s.conn.netConn.Write(encBuf)
		if err != nil {
			return 0, err
		}

		m = m - n1

		// TODO mark the stream and/or connection as broken after analyzing the error

		atomic.StoreInt32(&s.needsWriteFlag, 0)
		atomic.StoreInt32(&s.conn.currStreamWriteID, 0)
	}

	// Wait to be allowed to write
	// Ask if we are allowed
	// Write a frame
	// go back to top
	return
}

func (s *Stream) tryRead() error {
	if err := s.conn.acquireConnForRead(s.id); err != nil {
		return err
	}

	// set a short read timeout so we return fast if no data is available
	s.conn.netConn.SetReadDeadline(time.Now().Add(time.Millisecond * 10))

	atomic.StoreInt32(&s.conn.currStreamReadID, 0)
	return nil
}

type streams struct {
	s    [255]*Stream
	lock *sync.Mutex
}

func newStreams() *streams {
	return &streams{
		lock: &sync.Mutex{},
	}
}

func (s *streams) insert(id uint8, str *Stream) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.s[id] != nil {
		return fmt.Errorf("Stream ID %d is already taken", id)
	}
	s.s[id] = str
	return nil
}

func (s *streams) delete(id uint8) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.s[id] = nil
}

func (s *streams) get(id uint8) (str *Stream) {
	s.lock.Lock()
	defer s.lock.Unlock()
	str = s.s[id]
	return
}
