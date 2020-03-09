package krach

const (
	maxMTU = 1500

	versionSize  = 1
	streamIDSize = 1
	lenFieldSize = uint16Size

	headerSize = versionSize + streamIDSize + lenFieldSize

	// Educated guesstimate of how much bytes are used by the Ethernet header, IP header and TCP header
	ipTCPOverhead = 78

	defaultMaxFrameSize = maxMTU - (ipTCPOverhead + headerSize + macSize)
)

type frame struct {
	version  byte
	streamID uint8
	length   uint16
	buf      *buffer
}
