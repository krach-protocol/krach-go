# Packet Types

Since only a single version of krach exists, the Version field is always `0x01` for now. During
the handshake the field `Stream ID` is always set to `0x00` which is the default steam ID and reserved
for management of the connection and streams.
Since the current version of krach is based on TCP, we initialize the nonce on both sides with `1`
and expect reliable delivery of every packet, so we can manage the nonce on each side without having
it explicitly in the packet. Packet loss should disrupt the connection and invalidate the cipher state
requiring a new handshake (0-RTT handshakes are planned, but not specified).

## HandshakeInit

The HandshakeInit packet is sent from the Initiator (Client) to the Responder (server).
The field `HandshakeType` is set to the value `0x01` to signal that this is a HandshakeInit
packet. The rest of the packet contains a Ed25519 ephemeral (before connection startup randomly
generated) public key which is always 32 bytes in length. Since the length of this packet type is
static and well known there are no length fields.

TODO: Think about SNI-like mechanism, which should also include something like a "Realm" for easier multi tennancy 
on single hosts.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Packetlength         |   Stream ID   |    Version    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Handshake Type|                                               |
+-+-+-+-+-+-+-+-+                                               +
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
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |
+-+-+-+-+-+-+-+-+

## HandshakeResponse

The Responder (Server) responds to HandshakeInit packets with HandshakeResponse packets.
This packet as well contains an ephemeral (randomly generated on start of the connection process)
public ed25519 key. Additionally this response packet contains a [SmolCert](https://github.com/smolcert)
from the server for the client to validate. Additionally (depending on the transported higher level protocols)
the server can send additional payloads which may be relevant for the connection setup. Both, the Smolcert
and the payload, are encrypted via an AEAD (ChaCha2020-Poly1305), so the encrypted payload contains
128 bytes authentication tag at the end.

FIXME: We should pad the encrypted payload and store the padded length at the beginning.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Packetlength         |   Stream ID   |    Version    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Handshake Type|                                               |
+-+-+-+-+-+-+-+-+                                               +
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
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                   Encrypted Payload (n-bytes)                 +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The decrypted form of the encrypted payload consists of a Smolcert and an optional payload,
both length prefixed.
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Smolcert length        |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                       Smolcert (n-bytes)                      |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |         Payload length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Payload (n-bytes)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
## HandshakeFin

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Packetlength         |   Stream ID   |    Version    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Handshake Type|                                               |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                  Encrypted Payload (n-bytes)                  +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Again the encrypted payload consists of a (client) Smolcert and an optional
payload:
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Smolcert length        |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                       Smolcert (n-bytes)                      |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |         Payload length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Payload (n-bytes)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

## TransportPacket

The field `Steam ID` here must not be `0x00` as this Stream ID is reserved
for management packets. As always the encrypted payload contains a 128 bytes
long authentication tag.

FIXME: We need to handle padding here as well.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Packetlength         |   Stream ID   |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                                                               |
+                  Encrypted Payload (n-bytes)                  +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
