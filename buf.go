package krach

import "sync"

const defaultBufSize = 4096

var bufPool = &sync.Pool{
	New: func() interface{} {
		return &buf{
			index: 1, /*Since every payload will be prefixed by the padding length*/
			data:  make([]byte, defaultBufSize),
		}
	},
}

type buf struct {
	data  []byte
	index int
}

func (b *buf) size() uint16 {
	return uint16(len(b.data) - b.index)
}

func (b *buf) pad() {
	origDataLen := len(b.data)
	bytesToPad := 16 - (origDataLen % 16) /*always pad to 16 bytes as recommended by the specification of ChaCha2020 */
	if bytesToPad == 16 {
		// We don't need padding if the payload is already divisible by 16
		bytesToPad = 0
	}
	if bytesToPad > 0 {
		b.data = append(b.data, make([]byte, bytesToPad, bytesToPad)...)
	}
	b.data[0] = uint8(bytesToPad)
}

func (b *buf) reset() {
	b.index = 1
	b.data = b.data[0:1]
	b.data[0] = 0
}

func (b *buf) unpaddedPayload() []byte {
	padBytes := b.data[0]
	return b.data[1 : len(b.data)-int(padBytes)]
}

func (b *buf) resize(size int) {
	if size < len(b.data)-b.index {
		b.data = b.data[:b.index+size]
	} else {
		diff := size - (len(b.data) - b.index)
		b.data = append(b.data, make([]byte, diff, diff)...)
	}
}

func (b *buf) copyInto(inBuf []byte) {
	n := copy(b.data[b.index:], inBuf)
	if n < len(inBuf) {
		b.data = append(b.data, inBuf[n:]...)
	}
}

func (b *buf) ensureCapacity(capacity int) {
	if cap(b.data) < capacity {
		b.data = append(b.data[:cap(b.data)], append(make([]byte, capacity), b.data[cap(b.data):]...)...)
	}
}
