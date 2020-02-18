# krach

A noise protocol based, secure protocol for the IoT. Provides, roaming, multiplexing and end-to-end-security.

## Session and Connections

krach uses UDP as the base for the protocol and creates a "UDP connection" with a custom ARQ (see kcp-go). Inside these
connections we can have sessions which are multiplexed over these connections.

Connection -- Session

## PacketFormat

In this first iteration we repeat some of the data fields we have in the CBOR structure or in the certificate so we can use
them more easily during the handshake. To resolve this, we need to reimplement the noise handshake and feed things like DH 
keys, associated data etc manually to the handshake algorithm.

* 1 Byte Version
* 1 Byte PacketType (HandshakeInit, HandshakeResponse, Transport, Ack)

### HandshakeInit
(Assumptions: Handshake messages don't need fragmentation and can be transported sufficiently reliable without ARQ...)
* 1 byte Version
* 1 byte PacketType
* 32 bytes ephemeral public key

### HandshakeResponse

* 1 byte Version
* 1 byte PacketType
* 4 byte ReceiverIndex
* 32 bytes server ephemeral public key
* 2 bytes Server cert length
* n bytes Server cert
* 2 bytes payload length
* n bytes payload

### HandshakeFinPacket

* 1 byte Version
* 1 byte PacketType
* 4 byte ReceiverIndex
* 4 byte SenderIndex
* 2 bytes Client cert length
* n bytes Client cert
* 2 bytes payload length
* n bytes payload


### TransportPacket

* 1 byte Version
* 1 byte PacketType
* 4 byte SenderIndex (need to see if this is necessary after handshake)
* 4 byte ReceiverIndex 
* n bytes nonce
* Noise protocol encrypted data