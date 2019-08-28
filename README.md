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
* 4 byte Sender Index
* Noise protocol init data....
  * cbor array with
    * 4 byte SenderIndex (? is this usable as ID)
    * client certificate chain
    * connection config data

### HandshakeResponse

* 1 byte Version
* 1 byte PacketType
* 4 byte Sender Index
* 4 byte Receiver Index
* Noise protocol response data
    * cbor array with
        * SenderIndex
        * ReceiverIndex