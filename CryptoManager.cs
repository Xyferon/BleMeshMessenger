using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace BleMeshMessenger
{
    /// <summary>
    /// Represents an encrypted cryptographic envelope ready for mesh transmission.
    /// Uses Ephemeral-Static X25519 ECDH + BLAKE2b KDF + IETF ChaCha20-Poly1305 AEAD.
    /// </summary>
    public sealed record EncryptedEnvelope(
        byte[] EphemeralPublicKey,
        byte[] Nonce,
        byte[] Ciphertext
    );

    /// <summary>
    /// Cryptography layer providing decentralized identity and End-to-End Authenticated
    /// Encryption (E2EE) for the BLE Mesh node using Libsodium.
    /// </summary>
    public sealed class CryptoManager
    {
        public const int PublicKeySize = 32;       // X25519 256-bit public key
        public const int PrivateKeySize = 32;      // X25519 256-bit private key
        public const int AeadNonceSize = 12;       // ChaCha20-Poly1305 IETF 96-bit nonce
        public const int AeadMacTagSize = 16;      // Poly1305 128-bit authentication tag

        private readonly KeyPair _nodeKeyPair;

        public byte[] PublicKey => _nodeKeyPair.PublicKey;
        public byte[] PrivateKey => _nodeKeyPair.PrivateKey;
        public string PublicKeyHex => Utilities.BinaryToHex(_nodeKeyPair.PublicKey);

        /// <summary>
        /// Loads an existing identity from a 32-byte private key file, or generates a new
        /// secure keypair and saves it to disk for persistent identity across restarts.
        /// </summary>
        public static CryptoManager LoadOrCreate(string keyFilePath)
        {
            if (File.Exists(keyFilePath))
            {
                try
                {
                    byte[] savedKey = File.ReadAllBytes(keyFilePath);
                    if (savedKey.Length == PrivateKeySize)
                    {
                        return new CryptoManager(savedKey);
                    }
                }
                catch { }
            }

            var fresh = new CryptoManager();
            try
            {
                File.WriteAllBytes(keyFilePath, fresh.PrivateKey);
            }
            catch { }
            return fresh;
        }

        /// <summary>
        /// Generates a brand new unique keypair, overwrites the key file on disk,
        /// and returns the fresh CryptoManager.
        /// </summary>
        public static CryptoManager CreateFresh(string keyFilePath)
        {
            var fresh = new CryptoManager();
            try
            {
                File.WriteAllBytes(keyFilePath, fresh.PrivateKey);
            }
            catch { }
            return fresh;
        }

        /// <summary>
        /// Initializes a new CryptoManager. If privateKey is provided, restores the keypair;
        /// otherwise generates a fresh cryptographically secure X25519 keypair.
        /// </summary>
        public CryptoManager(byte[]? privateKey = null)
        {
            if (privateKey != null)
            {
                if (privateKey.Length != PrivateKeySize)
                {
                    throw new ArgumentException($"Private key must be {PrivateKeySize} bytes.", nameof(privateKey));
                }
                _nodeKeyPair = PublicKeyBox.GenerateKeyPair(privateKey);
            }
            else
            {
                _nodeKeyPair = PublicKeyBox.GenerateKeyPair();
            }
        }

        /// <summary>
        /// Encrypts an outbound text message for a recipient specified by their X25519 public key.
        /// An ephemeral X25519 keypair is generated for forward secrecy and recipient anonymity.
        /// The local node's public key is bundled into the authenticated plaintext payload
        /// so the recipient can verify sender identity upon decryption.
        /// </summary>
        /// <param name="recipientPublicKey">The 32-byte X25519 public key of the intended receiver.</param>
        /// <param name="message">The plaintext message string.</param>
        /// <returns>The EncryptedEnvelope containing ephemeral public key, nonce, and ciphertext.</returns>
        public EncryptedEnvelope Encrypt(byte[] recipientPublicKey, string message)
        {
            ArgumentNullException.ThrowIfNull(recipientPublicKey);
            ArgumentNullException.ThrowIfNull(message);

            if (recipientPublicKey.Length != PublicKeySize)
            {
                throw new ArgumentException($"Recipient public key must be {PublicKeySize} bytes.", nameof(recipientPublicKey));
            }

            // 1. Generate an ephemeral X25519 key pair for this specific message
            var ephemeralKey = PublicKeyBox.GenerateKeyPair();

            // 2. Compute ECDH shared secret: Q = ephemeral_private * recipient_public
            byte[] sharedSecret = ScalarMult.Mult(ephemeralKey.PrivateKey, recipientPublicKey);

            // 3. Derive 256-bit symmetric AEAD session key using BLAKE2b KDF
            byte[] sessionKey = GenericHash.Hash(sharedSecret, (byte[]?)null, 32);

            // 4. Construct inner plaintext payload: [SenderPublicKey (32 bytes)] + [UTF8 Message]
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] innerPayload = new byte[PublicKeySize + messageBytes.Length];
            Buffer.BlockCopy(PublicKey, 0, innerPayload, 0, PublicKeySize);
            Buffer.BlockCopy(messageBytes, 0, innerPayload, PublicKeySize, messageBytes.Length);

            // 5. Generate unique 12-byte nonce for ChaCha20-Poly1305 IETF
            byte[] nonce = SecretAeadChaCha20Poly1305IETF.GenerateNonce();

            // 6. Encrypt with ChaCha20 and authenticate with Poly1305
            byte[] ciphertext = SecretAeadChaCha20Poly1305IETF.Encrypt(innerPayload, nonce, sessionKey, null);

            return new EncryptedEnvelope(
                EphemeralPublicKey: ephemeralKey.PublicKey,
                Nonce: nonce,
                Ciphertext: ciphertext
            );
        }

        /// <summary>
        /// Attempts trial decryption of an incoming mesh envelope using this node's private key.
        /// If this node is not the recipient, the Poly1305 MAC check will fail in constant time,
        /// throwing a CryptographicException which is caught, returning false.
        /// </summary>
        /// <param name="envelope">The received envelope.</param>
        /// <param name="decryptedMessage">The decrypted text message if successful.</param>
        /// <param name="senderPublicKey">The authenticated sender's public key if successful.</param>
        /// <returns>True if decrypted successfully (we are the recipient); False if failed.</returns>
        public bool TryDecrypt(
            EncryptedEnvelope envelope,
            out string? decryptedMessage,
            out byte[]? senderPublicKey)
        {
            decryptedMessage = null;
            senderPublicKey = null;

            if (envelope.EphemeralPublicKey.Length != PublicKeySize ||
                envelope.Nonce.Length != AeadNonceSize ||
                envelope.Ciphertext.Length < AeadMacTagSize + PublicKeySize)
            {
                return false;
            }

            try
            {
                // 1. Compute ECDH shared secret: Q = node_private * ephemeral_public
                byte[] sharedSecret = ScalarMult.Mult(_nodeKeyPair.PrivateKey, envelope.EphemeralPublicKey);

                // 2. Derive 256-bit symmetric AEAD session key
                byte[] sessionKey = GenericHash.Hash(sharedSecret, (byte[]?)null, 32);

                // 3. Decrypt and verify Poly1305 MAC tag
                byte[] decryptedPayload = SecretAeadChaCha20Poly1305IETF.Decrypt(
                    envelope.Ciphertext,
                    envelope.Nonce,
                    sessionKey,
                    null
                );

                if (decryptedPayload.Length < PublicKeySize)
                {
                    return false;
                }

                // 4. Extract sender identity (first 32 bytes)
                byte[] senderKey = new byte[PublicKeySize];
                Buffer.BlockCopy(decryptedPayload, 0, senderKey, 0, PublicKeySize);
                senderPublicKey = senderKey;

                // 5. Extract message text
                decryptedMessage = Encoding.UTF8.GetString(
                    decryptedPayload,
                    PublicKeySize,
                    decryptedPayload.Length - PublicKeySize
                );

                return true;
            }
            catch (CryptographicException)
            {
                // Authentication tag mismatch: we are not the intended recipient, or payload was corrupted
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Parses a 64-character hex string into a 32-byte public key.
        /// </summary>
        public static byte[] ParsePublicKeyHex(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex))
            {
                throw new ArgumentException("Hex string cannot be empty.", nameof(hex));
            }

            hex = hex.Trim();
            if (hex.Length != PublicKeySize * 2)
            {
                throw new ArgumentException($"Public key hex string must be {PublicKeySize * 2} characters long.", nameof(hex));
            }

            return Utilities.HexToBinary(hex);
        }

        /// <summary>
        /// Converts bytes to lowercase hex format.
        /// </summary>
        public static string ToHex(byte[] bytes)
        {
            return Utilities.BinaryToHex(bytes);
        }
    }
}
