package krach

import "sync"

type Stream struct {
	readMtx  *sync.Mutex
	writeMtx *sync.Mutex
	id       uint8
	conn     *Conn
	hasData  bool
}

func newStream(streamID uint8, conn *Conn) *Stream {
	return &Stream{
		readMtx:  &sync.Mutex{},
		writeMtx: &sync.Mutex{},
		id:       streamID,
		conn:     conn,
		hasData:  false,
	}
}

func (s *Stream) Write(data []byte) (n int, err error) {

	for len(data) > 0 {
		// Try to acquire our write lock and wait for us to be able to write
		s.writeMtx.Lock()
		s.hasData = true
		m := len(data)

		maxPayloadSize := s.conn.maxPayloadSizeForFrame()
		if m > int(maxPayloadSize) {
			m = int(maxPayloadSize)
		}

		n1, err := s.conn.writeInternal(data[:m], s.id)
		if err != nil {
			return n1, err
		}
		n += m
		data = data[m:]
	}
	s.hasData = false
	return 0, nil
}
