# GhostMesh

GhostMesh is a peer-to-peer terminal messenger for Windows that communicates directly over Bluetooth Low Energy (BLE). It operates completely offline—requiring no internet, local Wi-Fi, Bluetooth pairing, or centralized servers.

Nearby machines discover one another through continuous BLE advertisement scanning, establish ephemeral GATT connections, and route encrypted packets across hops using an epidemic store-and-forward mesh.

---

## Features

- **True Peer-to-Peer**: Communicates device-to-device over standard Bluetooth Low Energy hardware.
- **End-to-End Encryption**: Authenticated encryption via Libsodium (X25519 key exchange + IETF ChaCha20-Poly1305 AEAD).
- **Recipient Anonymity**: Every packet uses a fresh ephemeral public key. Relays cannot tell who sent a message or who it is addressed to.
- **Multi-Hop Relaying**: Messages automatically hop across intermediate peers to extend physical range.
- **Deduplication Engine**: In-memory message hashing prevents broadcast storms and replay loops.
- **Native Windows Stack**: Built with modern .NET 8 and Windows Runtime (WinRT) Bluetooth APIs.

---

## How It Works

```text
  [ Node A (Sender) ]
         │
         │  1. Generate ephemeral X25519 keypair
         │  2. Compute shared secret via recipient's public key
         │  3. Encrypt payload with ChaCha20-Poly1305
         ▼
    [ Wire Packet ]
         │
         ▼  (GATT Write / BLE Mesh Flood)
  [ Node B (Relay) ]
         ├─► Deduplication check (Seen message hash before? Drop if duplicate)
         ├─► Trial decryption fails (Invalid MAC tag; reveals zero metadata)
         └─► Decrement TTL and forward to all other active BLE neighbors
         │
         ▼
  [ Node C (Recipient) ]
         ├─► Deduplication check (New message)
         ├─► Trial decryption succeeds using Node C's private key
         └─► Unpacks verified plaintext and sender's embedded public key
```

---

## System Requirements

- **Operating System**: Windows 10 (version 2004 / build 19041 or newer) or Windows 11.
- **Hardware**: Bluetooth 4.0+ adapter supporting BLE peripheral and central modes.
- **Development**: [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (only needed if building from source).

---

## Quick Start

### Building from Source

```powershell
git clone https://github.com/Xyferon/BleMeshMessenger.git
cd BleMeshMessenger
dotnet build
```

Run the application:

```powershell
dotnet run
```

### Self-Contained Binary (Zero Install)

To generate a standalone folder that runs on any compatible Windows PC without requiring .NET to be installed:

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -o ./standalone
```

Copy the `./standalone` folder to another machine and launch `BleMeshMessenger.exe`.

---

## Command Reference

| Command | Arguments | Description |
|---|---|---|
| `send` | `<PubKey_Hex> <Message>` | Encrypts payload with recipient's public key and broadcasts to mesh |
| `peers` | *(None)* | Lists all actively discovered BLE peers, RSSI, and last-seen times |
| `connect` | `<MAC_Address>` | Manually tests connection and registers a peer by MAC address |
| `key` | *(None)* | Displays this node's public key and current Bluetooth MAC |
| `newkey` | *(None)* | Generates a fresh cryptographic keypair for this machine |
| `diag` | *(None)* | Inspects local Bluetooth radio features and peripheral support |
| `clear` | *(None)* | Clears the terminal screen |
| `help` | *(None)* | Prints available commands |
| `exit` | *(None)* | Stops GATT services and shuts down cleanly |

---

## Usage Example

### 1. View your public key on Node 1:
```text
mesh> key
THIS NODE PUBLIC KEY (Hex):
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### 2. View peer discovery on Node 2:
```text
[+] Peer Registered in Mesh: E4:5F:01:23:45:67 (RSSI: -54 dBm)
```

### 3. Send an encrypted message from Node 2 to Node 1:
```text
mesh> send 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef Hello through the mesh!
```

### 4. Received message on Node 1:
```text
[MESSAGE RECEIVED]
  From:      abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
  Timestamp: 2026-10-11 22:45:10 UTC
  Hops Left: 5
  Content:   Hello through the mesh!
```

---

## Security Model

- **Confidentiality**: All application payloads are encrypted using standard IETF ChaCha20-Poly1305 with 256-bit keys derived through X25519 ECDH and BLAKE2b.
- **Forward Secrecy**: The sender creates an ephemeral X25519 keypair for each message, ensuring past traffic cannot be decrypted even if long-term identities are later exposed.
- **Metadata Protection**: Neither sender nor recipient public keys appear in unencrypted packet headers. Relays forward packets blindly without learning who is communicating.
- **Integrity & Authenticity**: Tampered packets immediately fail Poly1305 MAC tag verification and are dropped.
- **Replay Protection**: Messages are tracked by a SHA-256 hash of their ciphertext and timestamp; duplicate packets are discarded.

---

## Known Limitations

- **Address Randomization (RPA)**: Windows rotates its advertised BLE MAC address periodically (every 15–60 minutes) for user privacy. Node identities are tied to their 256-bit cryptographic public keys rather than hardware MAC addresses.
- **Payload Size**: Packets are formatted into single GATT writes under 512 bytes. This is optimized for short text messaging; large file transfers require packet chunking.
- **Physical Range**: Indoor BLE range is approximately 10–15 meters depending on walls and 2.4 GHz interference. Multi-hop relaying requires intermediate nodes positioned within that radius.
- **Sleep Mode**: Windows suspends Bluetooth adapter activities when entering sleep mode or connected standby. Relay nodes should have sleep timeouts disabled to remain active.

---

## License

Distributed under the [MIT License](LICENSE).
