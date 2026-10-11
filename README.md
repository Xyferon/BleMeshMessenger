# GhostMesh 👻📡

> **GhostMesh: Zero-Trust, Serverless, End-to-End Encrypted (E2EE) Bluetooth Low Energy Mesh Messenger for Windows**

[![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Libsodium](https://img.shields.io/badge/Crypto-Libsodium%20(X25519%20%2B%20ChaCha20--Poly1305)-4CAF50)](https://libsodium.gitbook.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An off-grid, zero-trust peer-to-peer messaging application designed to communicate directly between physical Windows devices over Bluetooth Low Energy. **No internet, No Wi-Fi, No cellular data, and No central servers or accounts required.**

---

## 🏗️ Architecture Overview

```
[ Sender: Alice ]
       │
       ▼ (1. Encrypt: Ephemeral-Static X25519 + ChaCha20-Poly1305 AEAD)
 [ Wire Packet ] ──► (2. BLE Advertisement / GATT Write)
       │
       ▼
 [ Relay Node: Mallory ]
       ├─► Deduplication check (SHA-256 Hash of Timestamp + Ciphertext)
       ├─► Trial Decrypt -> Fails (Invalid Poly1305 MAC tag; Zero plaintext/identity leaked)
       └─► Decrements TTL & Floods packet to all other active BLE neighbors
       │
       ▼
 [ Recipient: Bob ]
       ├─► Deduplication check (Seen? No -> Cache ID)
       ├─► Trial Decrypt -> Succeeds!
       └─► Verifies Alice's embedded Sender Public Key & unpacks plaintext
```

### Protocol Layers

1. **Cryptography Layer (`CryptoManager.cs`)**:
   - **Identity**: Each node possesses a persistent 256-bit X25519 Curve25519 keypair saved locally to `mesh_identity.key`.
   - **Key Agreement**: Fresh ephemeral X25519 keypair generated per message for **forward secrecy** and **recipient anonymity**.
   - **KDF**: 256-bit symmetric session key derived via **BLAKE2b**.
   - **Authenticated Encryption**: **IETF ChaCha20-Poly1305** AEAD (RFC 8439) with 96-bit nonce and 128-bit authentication tag.
   - **Trial Decryption**: Relays cannot determine recipient identity without attempting trial decryption. Non-matching private keys fail Poly1305 authentication in constant time, allowing the node to serve as an unaware relay.

2. **Wire Framing Layer (`MeshPacket.cs`)**:
   - Binary wire framing layout (56–64 bytes overhead):
     `[Version] [TTL] [SenderMac] [TimestampMs] [EphemeralPubKey] [Nonce] [CiphertextLength] [Ciphertext + Tag]`
   - Computes deterministic Message ID via `SHA-256(Ciphertext + TimestampMs)`.

3. **Transport & BLE Layer (`BleMeshTransport.cs`)**:
   - **Custom Service UUID**: `a7c4f100-38e2-491b-85d9-482f6e910001`.
   - **Local Mailbox GATT Server**: Hosts an unbonded writeable characteristic using `Windows.Devices.Bluetooth.GenericAttributeProfile.GattServiceProvider`.
   - **Background Discovery**: Active continuous scanning via `BluetoothLEAdvertisementWatcher`.
   - **Automatic Return-Path Learning**: Resolves remote device connection identities to automatically register peers that initiate writes.

4. **Mesh Routing Layer (`MeshRouter.cs`)**:
   - **Epidemic Store-and-Forward**: Floods outbound packets to all in-range neighbors.
   - **Deduplication Engine**: Caches message ID hashes in memory to prevent broadcast storms and routing loops.
   - **Hop-by-Hop TTL**: Decrements packet Time-To-Live on every relay hop.

5. **User Interface (`Program.cs`)**:
   - Interactive multi-threaded CLI with thread-safe live message alerts and peer status monitoring.

---

## 📋 Prerequisites

* **Operating System**: Windows 10 (Build 19041 / Version 2004 or newer) or Windows 11.
* **Hardware**: Bluetooth 4.0 or newer adapter with BLE support.
* **Development**: [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (only needed if building from source).

---

## 🚀 Quick Start

### 1. Clone & Build

```powershell
git clone https://github.com/Xyferon/BleMeshMessenger.git
cd BleMeshMessenger
dotnet build
```

### 2. Run Locally

```powershell
dotnet run
```

### 3. Build Standalone (Zero-Install Package for Other PCs)

To create a self-contained folder that can be copied to a second PC without needing .NET installed:

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -o ./standalone
```
Copy the `./standalone` folder to another PC and run `BleMeshMessenger.exe`.

---

## 💬 Command Reference

| Command | Arguments | Description |
|---|---|---|
| `send` | `<Recipient_PubKey_Hex> <Message>` | Encrypts payload with recipient's public key and floods to mesh |
| `peers` | *(None)* | Lists all active discovered BLE peers (MAC, RSSI, last seen) |
| `connect` | `<MAC_Address>` | Manually tests connection and registers a peer by MAC address |
| `key` | *(None)* | Displays this node's Public Key and MAC address |
| `newkey` | *(None)* | Generates a fresh, unique cryptographic keypair on this node |
| `diag` | *(None)* | Displays Bluetooth adapter hardware capabilities and roles |
| `clear` | *(None)* | Clears the console window |
| `help` | *(None)* | Displays the help menu |
| `exit` | *(None)* | Shuts down GATT server and scanner cleanly |

---

## 🧪 Testing Across Two PCs

1. **Launch on PC 1**:
   ```text
   mesh> key
   THIS NODE PUBLIC KEY (Hex):
   51fd5251c457328b9c1c6622f55fe10a26c6b80dfade6c220c5d75c88eab0f60
   ```

2. **Launch on PC 2**:
   - If PC 2 was copied from PC 1, generate a unique key:
     ```text
     mesh> newkey
     ```
   - Note PC 2's new Public Key.

3. **Verify Discovery**:
   - Within seconds, both consoles will report:
     ```text
     [+] Peer Registered in Mesh: E4:5F:01:23:45:67 (RSSI: -52 dBm)
     ```

4. **Send an Encrypted Message**:
   - On **PC 1**, enter:
     ```text
     mesh> send <PC2_PublicKey> Hello over decentralized BLE mesh!
     ```
   - On **PC 2**, the encrypted alert will illuminate in green:
     ```text
     ╔═════════════════════════════════════════════════════════════════════════════════════════╗
     ║                        *** NEW ENCRYPTED MESSAGE RECEIVED ***                                 ║
     ╚═════════════════════════════════════════════════════════════════════════════════════════╝
       From (Sender Key) : 51fd5251c457328b9c1c6622f55fe10a26c6b80dfade6c220c5d75c88eab0f60
       Timestamp         : 2026-10-11 22:45:10 UTC
       Message ID (Hash) : a3f892bc0187...
       Remaining TTL     : 5 hop(s)
       Content           : Hello over decentralized BLE mesh!
     ```

---

## 🔒 Security & Threat Model

* **Eavesdropping**: Intermediate nodes only observe ciphertext and random ephemeral keys. Without the recipient's private key, reversing ChaCha20-Poly1305 is computationally infeasible ($2^{256}$ keyspace).
* **Metadata Protection**: Neither the sender nor the recipient public keys are transmitted in unencrypted headers. The sender identity is sealed inside the authenticated payload.
* **Tampering**: Poly1305 MAC tag verification ensures any packet modification in transit results in immediate rejection.
* **Replay Attacks**: SHA-256 message deduplication and TTL expiration drop duplicate or replayed frames.
* **Key Storage**: Identity private keys are saved to `mesh_identity.key` with strict filesystem permissions.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
