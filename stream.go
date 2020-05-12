package krach

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	streamClosed uint32 = 1 << iota
	streamHasData
	streamWriteReady
	streamReadReady
)

const (
	streamHandshakeFinished uint32 = 1 << iota
)

var (
	ErrorStreamClosed = errors.New("stream closed")
)

type Stream struct {
	sync.Mutex
	readMtx *sync.Mutex
	id      uint8
	conn    *Conn
	input   *buffer

	state          uint32
	readState      uint32
	handshakeState uint32

	activeCall int32
}

func (s *Stream) ID() uint8 {
	return s.id
}

func (s *Stream) handshakeFinished() bool {
	return atomic.LoadUint32(&s.handshakeState)&streamHandshakeFinished == streamHandshakeFinished
}

func (s *Stream) setHandshakeFinished() {
	atomic.StoreUint32(&s.handshakeState, streamHandshakeFinished)
}

func (s *Stream) Read(b []byte) (n int, err error) {
	s.Lock()
	// Copy available data out of current buffer and return if data was available
	if s.input != nil && len(s.input.data)-s.input.off > 0 {
		n = copy(b, s.input.data[s.input.off:])
		s.input.off = s.input.off + n
		if s.input.off == len(s.input.data) {
			s.conn.in.freeBlock(s.input)
			s.input = nil
		}

		s.Unlock()
		return
	}
	s.Unlock()

	// Check if the stream is closed, might need to return a different error to be compatible
	// with io.ReadAll etc.
	if x := atomic.LoadInt32(&s.activeCall); x&1 != 0 {
		return 0, ErrorStreamClosed
	}
	// Spin here to trigger reads on the underlying connection and wait until a read
	// has resulted in data being read into this streams buffer
	for !atomic.CompareAndSwapUint32(&s.readState, streamReadReady, 0) {
		if err = s.conn.readInternal(s.id); err != nil {
			return
		}
	}
	// If we are here, data has become available. Locking only to ensure that we are
	// not racing on the buffer here
	s.Lock()
	n = copy(b, s.input.data[s.input.off:])
	s.input.off = s.input.off + n
	if s.input.off == len(s.input.data) {
		// If we have read until the end of the buffer, free it.
		s.conn.in.freeBlock(s.input)
		s.input = nil
	}
	s.Unlock()
	return
}

// pushData pushes data into the stream to be read by the client
func (s *Stream) pushData(b *buffer) {
	s.Lock()
	defer s.Unlock()

	if s.input == nil {
		s.input = b
	} else {
		s.input.reserve(len(b.data) - b.off + len(s.input.data) - s.input.off)
		s.input.readFromUntil(b, len(b.data)-b.off)
		s.conn.in.freeBlock(b)
	}
}

func (s *Stream) notifyReadReady() {
	atomic.StoreUint32(&s.readState, streamReadReady)
}

func (s *Stream) pleaseWrite() bool {
	for !atomic.CompareAndSwapUint32(&s.state, streamWriteReady, 0) {
		s.conn.pleaseWrite()
	}
	return true
}

func (s *Stream) sendSYN() (err error) {
	s.signalNeedsWrite()
	s.pleaseWrite()
	_, err = s.conn.writeInternal(s.id, frameCmdSYN, nil)
	return
}

func (s *Stream) sendSYNACK() (err error) {
	s.signalNeedsWrite()
	s.pleaseWrite()
	_, err = s.conn.writeInternal(s.id, frameCmdSYNACK, nil)
	return
}

func (s *Stream) hasData() bool {
	x := atomic.LoadUint32(&s.state)
	return x&streamHasData == streamHasData
}

func (s *Stream) signalNeedsWrite() {
	atomic.StoreUint32(&s.state, streamHasData)
}

func (s *Stream) signalWrite() {
	atomic.StoreUint32(&s.state, streamWriteReady)
	//atomic.CompareAndSwapUint32(&s.state, streamHasData, 0|streamHasData|streamWriteReady)
}

func (s *Stream) Write(data []byte) (n int, err error) {
	// interlock with close of stream, hoping that we don't introduce additional blocking
	for {
		x := atomic.LoadInt32(&s.activeCall)
		if x&1 != 0 {
			return 0, ErrorStreamClosed
		}
		if atomic.CompareAndSwapInt32(&s.activeCall, x, x+2) {
			defer atomic.AddInt32(&s.activeCall, -2)
			break
		}
	}

	for len(data) > 0 {
		s.signalNeedsWrite()
		// Try to acquire our write lock and wait for us to be able to write
		s.pleaseWrite()

		m := len(data)
		maxPayloadSize := s.conn.maxPayloadSizeForFrame()
		if m > int(maxPayloadSize) {
			m = int(maxPayloadSize)
		}

		n1, err := s.conn.writeInternal(s.id, frameCmdPSH, data[:m])
		if err != nil {
			return n1, err
		}
		n += m
		data = data[m:]
	}
	//s.clearNeedsWrite()
	return n, nil
}

func (s *Stream) closeInternal() error {
	var x int32
	for {
		x = atomic.LoadInt32(&s.activeCall)
		if x&1 != 0 {
			return ErrorStreamClosed
		}
		if atomic.CompareAndSwapInt32(&s.activeCall, x, x|1) {
			break
		}
	}
	// Wait for active write calls to end
	for {
		x = atomic.LoadInt32(&s.activeCall)
		if x < 1 {
			break
		}
	}
	return nil
}

func (s *Stream) Close() error {
	// Sending the FIN command. This does not mean that data won't be read from the connection
	// or existing write operations won't complete. But this implementation is currently easier
	// than having special handling of fin commands
	s.signalNeedsWrite()
	s.pleaseWrite()
	_, err := s.conn.writeInternal(s.id, frameCmdFIN, nil)
	if err != nil {
		return err
	}
	//Wait for active calls to finish and mark this stream as closed

	err = s.closeInternal()
	s.conn.removeStream(s)
	return err
}

func (s *Stream) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *Stream) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *Stream) SetDeadline(t time.Time) error {
	return errors.New("Not implemented")
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return errors.New("Not implemented")
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	return errors.New("Not implemented")
}
