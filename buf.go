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

func (b *buf) sizeUnpadded() uint16 {
	paddedBytes := b.data[b.index-1]
	return b.size() - uint16(paddedBytes)
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
	b.data[b.index-1] = uint8(bytesToPad)
}

func (b *buf) reset() {
	b.index = 1
	b.data = b.data[0:1]
	b.data[0] = 0
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

func (b *buf) copyOutUnpadded(outBuf []byte) {
	if len(b.data) <= b.index-1 {
		// No valid padded data in buffer
		return
	}
	padBytes := b.data[b.index-1]
	copy(outBuf, b.data[b.index:len(b.data)-int(padBytes)])
}

func (b *buf) ensureCapacity(capacity int) {
	if cap(b.data) >= capacity {
		return
	}
	m := cap(b.data)
	if m == 0 {
		m = 1024
	}
	for m < capacity {
		m *= 2
	}
	data := make([]byte, len(b.data), m)
	copy(data, b.data)
	b.data = data
}

func (b *buf) ensureLength(size int) {
	if len(b.data)-b.index < size {
		b.resize(size)
	}
}
