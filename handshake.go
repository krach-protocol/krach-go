package krach

import "time"

import "fmt"

const (
	MaxHandshakePacketSize = 2049 //FIXME we need to determine an actual useful upper bound for this
)

// Called on the initiator
func handshake_xx_phase0(sess *Session) error {
	initPacket := NewHandshakeInitPacket()

	_, _, err := sess.handshakeState.WriteMessage(initPacket, nil)
	if err != nil {
		return err
	}

	_, err = sess.netConn.WriteTo(initPacket.Serialize(), sess.RemoteAddr)
	if err != nil {
		return err
	}
	sess.lastPktReceived = time.Now()
	return nil
}

// Called on the responder
func handshake_xx_phase1(sess *Session) error {
	return nil
}

// Called on the initiator
func handshake_xx_phase2(sess *Session) error {
	pktBuf := make([]byte, MaxHandshakePacketSize)
	n, _, err := sess.netConn.ReadFrom(pktBuf)
	if err != nil {
		return fmt.Errorf("Unable to read handshake phase 2 packet: %w", err)
	}
	handshakeInitPkt, err := ParseHandshakeInitResponsePacket(pktBuf[:n])
	if err != nil {
		return fmt.Errorf("Unable to parse HandshakeInitResponse packet: %w", err)
	}
	return nil
}
