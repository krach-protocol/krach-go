# krach [![CircleCI](https://circleci.com/gh/connctd/krach.svg?style=svg&circle-token=b0961925919f150e25c3148e6b8e5ba4e8ff4ab7)](https://circleci.com/gh/connctd/krach)

A noise protocol based, secure protocol for the IoT. Provides multiplexing and end-to-end-security.

## PacketFormat

### HandshakeInit
* 1 byte Version
* 1 byte HandshakePacketType
* 32 bytes ephemeral public key

### HandshakeResponse

* 1 byte Version
* 1 byte HandshakePacketType
* 32 bytes server ephemeral public key
* 2 bytes Server cert length
* n bytes Server cert
* 2 bytes payload length
* n bytes payload

### HandshakeFinPacket

* 1 byte Version
* 1 byte HandshakePacketType
* 2 bytes Client cert length
* n bytes Client cert
* 2 bytes payload length
* n bytes payload

### TransportPacket

* 2 byte length
* Noise protocol encrypted data
  * 1 byte streamID
  * 1 byte stream command (SYN, SYNACK or PSH)
  * Raw data
  * 16 byte MAC

## Handshake

The Handshake follows the [NoiseProtocol XX Pattern](http://www.noiseprotocol.org/noise.html#handshake-patterns)
with a few minor modifications. The main modification here is that the static public key is replaced
by a [smolcert](https://github.com/smolcert). This is made possible by converting the ed25519 public signing key
to a curve25519 key used during the elliptic curve diffie hellman operation. The security of this has been discussed
on the [modern crypto mailinglist](https://moderncrypto.org/mail-archive/curves/2014/000293.html) and afaik has been
deemed secure enough for use case. Libsodium also 
[supports](https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519) this operation.
Doing this enables us to verify identities of each peer during handshake because each peer proves through
the elliptic curve diffie hellman operation that it is in possession of the private key belonging to to the
public ed25519 key in the smolcert.
After the handshake, two new secrets are derived, used to encrypt packets. One secret for each direction.

## Streams

The transport packet format reserves two bytes for a stream id and a stream command. This enables
multiplexing of multiple independent data streams over one TCP connection. This gives more direct
congestion control to the sending client.
The stream commands follow loosely the TCP semantic by providing a SYN command, for opening streams,
SYNACK for acknowledging that a stream is open on both sides, a FIN command to close a stream and
a PSH command to push data through the stream.
The congestion control heavily relies on the sender. In this implementation a simple round robin scheme
has been implemented. But depending on the use case other implementations like priority based queues 
might be preferable.
