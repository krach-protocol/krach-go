package krach

import (
	"net"
)

func readLoop(logger Logger,
	closeChan chan bool, netConn packetNet,
	handleHandshakeInit func(packetBuf []byte, addr *net.UDPAddr),
	handleHandshakeResponse func(packetBuf []byte, addr *net.UDPAddr),
	handleTransportPacket func(packetBuf []byte, addr *net.UDPAddr)) {
	buf := make([]byte, DefaultReadBufferSize)
	for {
		select {
		case <-closeChan:
			// TODO probably send close messages to clients
			return
		default:
			n, addr, err := netConn.ReadFrom(buf)
			// TODO, we need to verify, that the UDPConn is still alive and kicking after an I/O Timeout. That
			// is the current expectation.
			if err != nil {
				if isPollTimeout(err) {
					continue
				} else {
					logger.WithError(err).Error("Failed to poll connection, closing session")
					return
				}
			}

			if n < MinPacketLength {
				continue
			}
			logger.WithFields(map[string]interface{}{
				"byteCount":  n,
				"remoteAddr": addr,
			}).Debug("Received raw packet")

			packetBuf := buf[:n]
			version := packetBuf[0]
			if !isVersionSupported(version) {
				continue
			}
			pktType := PacketType(packetBuf[PacketTypeOffset : PacketTypeOffset+1][0])
			switch pktType {
			case PacketTypeHandshakeInit:
				if handleHandshakeInit != nil {
					handleHandshakeInit(packetBuf, addr)
				}
			case PacketTypeHandshakeResponse:
				if handleHandshakeResponse != nil {
					handleHandshakeResponse(packetBuf, addr)
				}
			case PacketTypeTransport:
				if handleTransportPacket != nil {
					handleTransportPacket(packetBuf, addr)
				}
			default:
				logger.WithField("packetType", pktType.Byte()).Debug("Received packet with unknown packet type")
			}
		}
	}
}
