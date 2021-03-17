# Packet Types

Since only a single version of krach exists, the Version field is always `0x01` for now. During
the handshake the field `Stream ID` is always set to `0x00` which is the default steam ID and reserved
for management of the connection and streams.
Since the current version of krach is based on TCP, we initialize the nonce on both sides with `1`
and expect reliable delivery of every packet, so we can manage the nonce on each side without having
it explicitly in the packet. Packet loss should disrupt the connection and invalidate the cipher state
requiring a new handshake (0-RTT handshakes are planned, but not specified).

`PacketLength` is always the amount of bytes to read from the connection. This means that
`PacketLength` does not include the two bytes describing the length of packet or preceding bytes
like the packet type.

## HandshakeInit

The HandshakeInit packet is sent from the Initiator (Client) to the Responder (server).
The field `HandshakeType` is set to the value `0x01` to signal that this is a HandshakeInit
packet. The rest of the packet contains a Ed25519 ephemeral (before connection startup randomly
generated) public key which is always 32 bytes in length. Since the length of this packet type is
static and well known there are no length fields, except for the overall packet length to simplify
packet parsing code in implementations. This packet also signals the protocol version the client supports
which is not repeated afterwards.

TODO: Think about SNI-like mechanism, which should also include something like a "Realm" for easier multi tenancy 
on single hosts.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    | Handshake Type|          Packetlength         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                       EphemeralPublicKey                      +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## HandshakeResponse

The Responder (Server) responds to HandshakeInit packets with HandshakeResponse packets.
This packet as well contains an ephemeral (randomly generated on start of the connection process)
public ed25519 key. Additionally this response packet contains a [SmolCert](https://github.com/smolcert)
from the server for the client to validate. Additionally (depending on the transported higher level protocols)
the server can send additional payloads which may be relevant for the connection setup. Both, the Smolcert
and the payload, are encrypted via an AEAD (ChaCha2020-Poly1305), so the encrypted payload contains
128 bytes authentication tag at the end.
The SmolCert and the encrypted payload are stored independently since they are encrypted with the handshake
symmetric cipher state at different points in time. The SmolCert is used as input to the mix and hash algorithms
to create a new symmetric cipher key which is then used to encrypt the payload.

TODO: Inspect if it is a risk to encrypt a 0 length array and add zhe generated hmac to the packet

The `Handshake Type` field must be set to `0x02`.

The SmolCert and and Encrypted Payload are both stored padded to the correct length (length divisible by 16),
with the padding information prefixing the unecrypted SmolCert/Payload:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Padding    |                    Payload                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Handshake Type|          Packetlength         |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                                                               |
+                                                               +
|                       EphemeralPublicKey                      |
+                                               +-+-+-+-+-+-+-+-+
|                                               |   ID length   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                  Encrypted Identity (n-bytes)                 |
+                                               +-+-+-+-+-+-+-+-+
|                                               | Payload lenght|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                  Encrypted Payload (n-bytes)                  +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## HandshakeFin

The Initiator sends the Handshake Fin packet after receiving the Handshake response
and constructing his view of the cipher state

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| HandshakeType |          PacketLength         |   ID length   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                  Encrypted Identity (n-bytes)                 |
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |         Payload length        |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                                                               |
+                       Payload (n-bytes)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Again the SmolCert and Payload are prefixed by the amount of padded bytes
and are padded to a suitable length:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Padding    |                    Payload                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## TransportPacket

As always the encrypted payload contains a 128 bytes
long authentication tag. The PacketLength is used as additional data
for the AEAD.

FIXME: Does the additional data need padding too?
The encrypted payload includes the 128 bit authentication tag.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Packetlength         |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                  Encrypted Payload (n-bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The encrypted payload has the following structure.
The field `Steam ID` here must not be `0x00` as this Stream ID is reserved
for management packets.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Padding    |    StreamID   |   StreamCMD   |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                                                               |
+                       Payload (n-bytes)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Stream Commands

There are several commands which enable handling of streams within the connection. Data transfer
can only happen within a stream which must be initiated from one side.

| Command | Value | Detail
|---------|-------|--------------------
| SYN     | 0x01  | Inform the peer that you want to initiate a stream with the specified StreamID
| SYNACK  | 0x02  | Accept and answer an incoming SYN command. The stream is now considered open
| PSH     | 0x03  | Data push, only the packets contain actual data
| FIN     | 0x04  | Inform the peer that this stream is now closed and further data on this stream will be discarded



## Encrypted payloads

Everytime we have an encrypted payload in a packet the payload is padded until the payload length
is divisible by 16. This means that a payload may be padded with up to 15 bytes.
Padding is always added at the end of the unencrypted payload. The amount of padding bytes
is indicated in the lower nibble of the first byte of the unecrypted payload.

This means that every time a payload is encrypted it is padded with up to 15 bytes until the payload
length is evenly divisible by 16 and the amount of padded bytes is then written as unsigned integer
to the lower nibble of a (new) first byte.

Equally after decryption of a payload the amount of padded bytes must be read from the lower nibble of 
the first byte. This amount of bytes must be truncated from the end of the payload as must be the first
byte to get the original unencrypted payload.
