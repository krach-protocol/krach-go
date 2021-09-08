//go:build multiplexing
// +build multiplexing

package krach

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	InvalidFrameCommandError = errors.New("Invalid frame command")
)

type Stream struct {
	writeLock      int32
	conn           *Conn
	needsWriteFlag int32
	id             uint8

	dataAvailableFlag int32
	inBufLock         *sync.Mutex
	inBuf             []byte
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
	// The handshake is ensured when opening/accepting the underlying connection
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

		atomic.StoreInt32(&s.needsWriteFlag, 1)
		for !atomic.CompareAndSwapInt32(&s.writeLock, 1, 0) {
			s.conn.acquireConnForWrite(s.id)
		}
		atomic.StoreInt32(&s.needsWriteFlag, 0)

		n, err = s.conn.Write(payloadBuf)
		if err != nil {
			return 0, err
		}

		m = m - n1
		// TODO mark the stream and/or connection as broken after analyzing the error
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
	// Actually using epoll or something similar/better would be more efficient, but very platform specific
	s.conn.netConn.SetReadDeadline(time.Now().Add(time.Millisecond * 10))

	atomic.StoreInt32(&s.conn.currStreamReadID, 0)

	lengthBuf := make([]byte, 16)

	_, err := s.conn.netConn.Read(lengthBuf[:2])
	if err != nil {
		if netErr, ok := err.(net.Error); ok {
			// If we timed out, that's ok, the next go routine will try
			if netErr.Timeout() {
				return nil
			}
		}
		return err
	}
	// It seems we have data to read
	pktLength := endianess.Uint16(lengthBuf[:2])
	buf := make([]byte, pktLength)
	n, err := s.conn.netConn.Read(buf)
	if err != nil {
		return err
	}
	if n != int(pktLength) {
		return errors.New("Failed to read enough data")
	}

	pktBuf := make([]byte, pktLength-macSize)
	pktBuf, err = s.conn.csIn.Decrypt(pktBuf, lengthBuf, buf)
	if err != nil {
		return err
	}

	padLen := int(pktBuf[0])
	pktBuf = pktBuf[0 : len(pktBuf)-padLen]
	streamID := pktBuf[1]
	streamCmd := pktBuf[2]

	switch streamCmd {
	case frameCmdPSH.Byte():
		payload := pktBuf[3:]
		s := s.conn.strs.get(streamID)
		if s == nil {
			return errors.New("Received data for unknown stream")
		}
		s.inBufLock.Lock()
		// TODO Check if this efficient at all or we need to resize and copy
		s.inBuf = append(s.inBuf, payload...)
		s.inBufLock.Unlock()
	case frameCmdSYN.Byte():
		return errors.New("Unimplemented")
	case frameCmdSYNACK.Byte():
		return errors.New("Unimplemented")
	case frameCmdFIN.Byte():
		return errors.New("Unimplemented")
	default:
		return errors.New("Received unknown or invalid frame command")

	}
	return nil
}

func (s *Stream) Read(inBuf []byte) (n int, err error) {
	s.inBufLock.Lock()
	if len(s.inBuf) > 0 {
		// We have already data available
		n = copy(inBuf, s.inBuf)
		s.inBuf = s.inBuf[:n]
		s.inBufLock.Unlock()
		return n, nil
	}
	s.inBufLock.Unlock()

	// FIXME implement timeout
	for !atomic.CompareAndSwapInt32(&s.dataAvailableFlag, 0x01, 0x00) {
		if err := s.tryRead(); err != nil {
			if err == errGoAway {
				continue
			} else {
				return 0, err
			}
		}
	}

	if len(s.inBuf) > 0 {
		// We have already data available
		s.inBufLock.Lock()
		n = copy(inBuf, s.inBuf)
		s.inBuf = s.inBuf[:n]
		s.inBufLock.Unlock()
		return n, nil
	}
	return 0, errors.New("Didn't read any data, this is unexpected")
}

func (s *Stream) ID() uint8 {
	return s.id
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
