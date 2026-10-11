using System;
using System.IO;
using System.Security.Cryptography;

namespace BleMeshMessenger
{
    /// <summary>
    /// Binary wire representation of a BLE Mesh packet.
    /// Wire layout (Version 1 & 2 compatible):
    /// [1 byte Version (0x01 or 0x02)]
    /// [1 byte TTL]
    /// (If Version 0x02: [8 bytes SenderMacAddress])
    /// [8 bytes TimestampMs (Unix Epoch)]
    /// [32 bytes EphemeralPublicKey]
    /// [12 bytes Nonce]
    /// [2 bytes CiphertextLength (Big-Endian)]
    /// [N bytes Ciphertext + Poly1305 Tag]
    /// </summary>
    public sealed class MeshPacket
    {
        public const byte Version1 = 0x01;
        public const byte Version2 = 0x02;
        public const byte DefaultTtl = 5;

        public byte Version { get; init; } = Version1;
        public byte Ttl { get; set; }
        public ulong SenderMac { get; init; }
        public long TimestampMs { get; init; }
        public byte[] EphemeralPublicKey { get; init; }
        public byte[] Nonce { get; init; }
        public byte[] Ciphertext { get; init; }

        public MeshPacket(
            byte ttl,
            ulong senderMac,
            long timestampMs,
            byte[] ephemeralPublicKey,
            byte[] nonce,
            byte[] ciphertext,
            byte version = Version1)
        {
            Version = version;
            Ttl = ttl;
            SenderMac = senderMac;
            TimestampMs = timestampMs;
            EphemeralPublicKey = ephemeralPublicKey ?? throw new ArgumentNullException(nameof(ephemeralPublicKey));
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
            Ciphertext = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));
        }

        public string ComputeMessageIdHex()
        {
            using var sha256 = SHA256.Create();
            byte[] tsBytes = BitConverter.GetBytes(TimestampMs);
            byte[] buffer = new byte[tsBytes.Length + Ciphertext.Length];
            Buffer.BlockCopy(tsBytes, 0, buffer, 0, tsBytes.Length);
            Buffer.BlockCopy(Ciphertext, 0, buffer, tsBytes.Length, Ciphertext.Length);
            byte[] hash = sha256.ComputeHash(buffer);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        public byte[] Serialize()
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write(Version);
            writer.Write(Ttl);
            if (Version >= Version2)
            {
                writer.Write(SenderMac);
            }
            writer.Write(TimestampMs);
            writer.Write(EphemeralPublicKey);
            writer.Write(Nonce);
            writer.Write((ushort)Ciphertext.Length);
            writer.Write(Ciphertext);

            return ms.ToArray();
        }

        public static MeshPacket Deserialize(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            if (data.Length < 56) // Minimum header size for v1
            {
                throw new InvalidDataException($"Packet data is too short ({data.Length} bytes). Minimum required is 56 bytes.");
            }

            using var ms = new MemoryStream(data);
            using var reader = new BinaryReader(ms);

            byte version = reader.ReadByte();
            byte ttl = reader.ReadByte();
            ulong senderMac = 0;

            if (version == Version2)
            {
                senderMac = reader.ReadUInt64();
            }
            else if (version != Version1)
            {
                throw new InvalidDataException($"Unsupported packet version: 0x{version:X2}.");
            }

            long timestampMs = reader.ReadInt64();
            byte[] ephemeralPublicKey = reader.ReadBytes(CryptoManager.PublicKeySize);
            byte[] nonce = reader.ReadBytes(CryptoManager.AeadNonceSize);
            ushort cipherLen = reader.ReadUInt16();

            if (ms.Length - ms.Position < cipherLen)
            {
                throw new InvalidDataException($"Packet truncated. Expected ciphertext length {cipherLen}, available {ms.Length - ms.Position}.");
            }

            byte[] ciphertext = reader.ReadBytes(cipherLen);

            return new MeshPacket(ttl, senderMac, timestampMs, ephemeralPublicKey, nonce, ciphertext, version);
        }

        public EncryptedEnvelope ToEnvelope() => new(EphemeralPublicKey, Nonce, Ciphertext);

        public static MeshPacket FromEnvelope(EncryptedEnvelope envelope, ulong senderMac = 0, byte ttl = DefaultTtl)
        {
            return new MeshPacket(
                ttl: ttl,
                senderMac: senderMac,
                timestampMs: DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ephemeralPublicKey: envelope.EphemeralPublicKey,
                nonce: envelope.Nonce,
                ciphertext: envelope.Ciphertext,
                version: Version1 // V1 wire format for universal compatibility
            );
        }
    }
}
