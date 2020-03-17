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

type Stream struct {
	readMtx  *sync.Mutex
	writeMtx *sync.Mutex
	id       uint8
	conn     *Conn
	input    *buffer

	state     uint32
	readState uint32
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
	// TODO notify conn to read
	for {
		s.conn.readInternal()
		x := atomic.LoadUint32(&s.readState)
		if (x & streamReadReady) == streamReadReady {
			defer atomic.StoreUint32(&s.readState, x^streamReadReady)
			break
		}
	}
	n = copy(b, s.input.data[s.input.off:])
	return
}

func (s *Stream) notifyReadReady() {
	atomic.SwapUint32(&s.readState, s.readState|streamReadReady)
}

func (s *Stream) pleaseWrite() bool {
	s.conn.pleaseWrite()
	return atomic.LoadUint32(&s.state)&streamWriteReady == streamWriteReady
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

		n1, err := s.conn.writeInternal(data[:m], s.id)
		if err != nil {
			return n1, err
		}
		n += m
		data = data[m:]
	}
	s.clearNeedsWrite()
	return n, nil
}
