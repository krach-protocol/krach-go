package krach

import (
	"sync"
	"sync/atomic"
)

const (
	streamHasData uint32 = 1 << iota
	streamWriteReady
	streamReadReady
)

const (
	streamHandshakeFinished uint32 = 1 << iota
)

type Stream struct {
	readMtx  *sync.Mutex
	inputMtx *sync.Mutex
	//writeMtx *sync.Mutex
	id    uint8
	conn  *Conn
	input *buffer

	state          uint32
	readState      uint32
	handshakeState uint32
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

func (s *Stream) hasData() bool {
	x := atomic.LoadUint32(&s.state)
	return x&streamHasData == streamHasData
}

func (s *Stream) signalNeedsWrite() {
	x := atomic.LoadUint32(&s.state)
	atomic.StoreUint32(&s.state, x|streamHasData)
}

func (s *Stream) clearNeedsWrite() {
	x := atomic.LoadUint32(&s.state)
	atomic.StoreUint32(&s.state, x^streamHasData)
}

func (s *Stream) signalWrite() {
	x := atomic.LoadUint32(&s.state)
	atomic.StoreUint32(&s.state, x|streamWriteReady)
}

func (s *Stream) Read(b []byte) (n int, err error) {
	// FIXME currently b needs to be at least Frame length
	s.inputMtx.Lock()
	if s.input != nil && len(s.input.data) > 0 {
		n = copy(b, s.input.data[s.input.off:])
		s.input.off = s.input.off + n
		s.inputMtx.Unlock()
		return n, nil
	}
	s.inputMtx.Unlock()
	for !atomic.CompareAndSwapUint32(&s.readState, streamReadReady, 0) {
		if err = s.conn.readInternal(); err != nil {
			return
		}
	}
	// TODO check if we need to lock s.input so we can modify it in readInternal
	s.inputMtx.Lock()
	n = copy(b, s.input.data[s.input.off:])
	s.input.off = s.input.off + n
	if s.input.off == len(s.input.data) {
		s.conn.in.freeBlock(s.input)
		s.input = nil
	}
	s.inputMtx.Unlock()
	return
}

func (s *Stream) pushData(b *buffer) {
	s.inputMtx.Lock()
	defer s.inputMtx.Unlock()

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
	s.conn.pleaseWrite()
	return atomic.LoadUint32(&s.state)&streamWriteReady == streamWriteReady
}

func (s *Stream) sendSYN() (err error) {
	s.signalNeedsWrite()
	defer s.clearNeedsWrite()
	for !s.pleaseWrite() {

	}
	_, err = s.conn.writeInternal(s.id, frameCmdSYN, nil)
	return
}

func (s *Stream) sendSYNACK() (err error) {
	s.signalNeedsWrite()
	defer s.clearNeedsWrite()
	for !s.pleaseWrite() {

	}
	_, err = s.conn.writeInternal(s.id, frameCmdSYNACK, nil)
	return
}

func (s *Stream) Write(data []byte) (n int, err error) {

	s.signalNeedsWrite()
	for len(data) > 0 {
		m := len(data)

		maxPayloadSize := s.conn.maxPayloadSizeForFrame()
		if m > int(maxPayloadSize) {
			m = int(maxPayloadSize)
		}

		// Try to acquire our write lock and wait for us to be able to write
		for !s.pleaseWrite() {
			// Wait until underlying conn is ready
		}
		// Clear write read bit, we are now writing
		atomic.StoreUint32(&s.state, s.state^streamWriteReady)

		n1, err := s.conn.writeInternal(s.id, frameCmdPSH, data[:m])
		if err != nil {
			return n1, err
		}
		n += m
		data = data[m:]
	}
	s.clearNeedsWrite()
	return n, nil
}
