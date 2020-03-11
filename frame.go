package krach

const (
	maxMTU = 1500

	streamIDSize = 1
	lenFieldSize = uint16Size

	headerSize    = streamIDSize + lenFieldSize
	frameOverhead = headerSize + macSize

	// Educated guesstimate of how much bytes are used by the Ethernet header, IP header and TCP header
	ipTCPOverhead = 78

	// Allow to spread frames over two TCP packets
	defaultMaxFrameSize = 2 * (maxMTU - (2*ipTCPOverhead + frameOverhead))

	defaultStreamID = uint8(0)
)
