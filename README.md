# krach [![CircleCI](https://circleci.com/gh/connctd/krach.svg?style=svg&circle-token=b0961925919f150e25c3148e6b8e5ba4e8ff4ab7)](https://circleci.com/gh/connctd/krach)

A noise protocol based, secure protocol for the IoT. Provides multiplexing and end-to-end-security.

## PacketFormat

### HandshakeInit
(Assumptions: Handshake messages don't need fragmentation and can be transported sufficiently reliable without ARQ...)
* 1 byte Version
* 1 byte PacketType
* 32 bytes ephemeral public key

### HandshakeResponse

* 1 byte Version
* 1 byte PacketType
* 32 bytes server ephemeral public key
* 2 bytes Server cert length
* n bytes Server cert
* 2 bytes payload length
* n bytes payload

### HandshakeFinPacket

* 1 byte Version
* 1 byte PacketType
* 2 bytes Client cert length
* n bytes Client cert
* 2 bytes payload length
* n bytes payload

### TransportPacket

* 2 byte length
* Noise protocol encrypted data