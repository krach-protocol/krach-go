package krach

import (
	"encoding/binary"
)

const (
	uint16Size      = 2
	macSize         = 16
	frameHeaderSize = 3 /*stream id, stream command, padding size */
)

const (
	// KrachVersion is the byte representation of the currently supported wire protocol format for Krach
	KrachVersion byte = 0x01
)

var (
	endianess = binary.LittleEndian
)
