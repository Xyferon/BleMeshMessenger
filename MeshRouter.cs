using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace BleMeshMessenger
{
    public sealed record ReceivedMessageInfo(
        string MessageId,
        byte[] SenderPublicKey,
        string SenderPublicKeyHex,
        string MessageText,
        DateTime TimestampUtc,
        byte RemainingTtl,
        ulong SenderMac
    );

    public sealed record RelayedPacketInfo(
        string MessageId,
        byte NewTtl,
        int PeerCount
    );

    /// <summary>
    /// Implements Epidemic Store-and-Forward Mesh Routing with SHA-256 deduplication,
    /// automatic return-path peer learning, trial decryption, and flooding.
    /// </summary>
    public sealed class MeshRouter : IAsyncDisposable
    {
        private CryptoManager _cryptoManager;
        private readonly BleMeshTransport _transport;
        
        // Thread-safe deduplication cache: MessageId -> FirstSeenTimestamp
        private readonly ConcurrentDictionary<string, DateTime> _seenMessageIds = new();
        private readonly Timer _cachePruneTimer;

        public event Action<ReceivedMessageInfo>? MessageReceivedForLocalNode;
        public event Action<RelayedPacketInfo>? PacketRelayed;
        public event Action<string>? LogMessage;

        public CryptoManager Crypto => _cryptoManager;
        public BleMeshTransport Transport => _transport;

        public void SetCrypto(CryptoManager cryptoManager)
        {
            _cryptoManager = cryptoManager ?? throw new ArgumentNullException(nameof(cryptoManager));
        }

        public MeshRouter(CryptoManager cryptoManager, BleMeshTransport transport)
        {
            _cryptoManager = cryptoManager ?? throw new ArgumentNullException(nameof(cryptoManager));
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));

            // Wire up incoming BLE GATT write packets to epidemic router
            _transport.RawPacketReceived += OnRawPacketReceived;

            // Prune deduplication cache entries older than 1 hour every 10 minutes
            _cachePruneTimer = new Timer(PruneDeduplicationCache, null, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));
        }

        public async Task StartAsync()
        {
            await _transport.StartAsync();
        }

        /// <summary>
        /// Sends an end-to-end encrypted message from this node into the BLE mesh network.
        /// </summary>
        public async Task<string> SendMessageAsync(byte[] recipientPublicKey, string messageText, byte ttl = MeshPacket.DefaultTtl)
        {
            ArgumentNullException.ThrowIfNull(recipientPublicKey);
            ArgumentNullException.ThrowIfNull(messageText);

            var peers = _transport.ActivePeers;
            if (peers.Count == 0)
            {
                throw new InvalidOperationException("No active BLE peers found in local mesh table. Cannot dispatch message.");
            }

            // 1. Authenticated E2EE Encryption (Ephemeral-Static X25519 + ChaCha20-Poly1305)
            var envelope = _cryptoManager.Encrypt(recipientPublicKey, messageText);

            // 2. Wrap in Mesh Wire Packet
            var packet = MeshPacket.FromEnvelope(envelope, _transport.LocalMacAddress, ttl);
            string messageId = packet.ComputeMessageIdHex();

            // 3. Mark in local deduplication cache so this node never re-relays its own message
            _seenMessageIds.TryAdd(messageId, DateTime.UtcNow);

            // 4. Serialize to wire bytes
            byte[] wireBytes = packet.Serialize();

            // 5. Flood to all currently discovered BLE mesh peers
            Log($"[Mesh Router] Dispatching message {messageId[..8]}... to {peers.Count} active peer(s) (TTL: {ttl}).");

            int successCount = 0;
            var sendTasks = peers.Select(async peer =>
            {
                bool success = await _transport.WriteToPeerAsync(peer.MacAddress, wireBytes);
                if (success)
                {
                    Interlocked.Increment(ref successCount);
                }
            });

            await Task.WhenAll(sendTasks);
            Log($"[Mesh Router] Message {messageId[..8]}... forwarded to {successCount}/{peers.Count} peer(s).");

            if (successCount == 0)
            {
                throw new InvalidOperationException($"BLE transmission failed to all {peers.Count} connected peer(s). Target may be temporarily out of range or busy.");
            }

            return messageId;
        }

        private void OnRawPacketReceived(object? sender, byte[] rawData)
        {
            try
            {
                // 1. Deserialize binary packet
                var packet = MeshPacket.Deserialize(rawData);
                string messageId = packet.ComputeMessageIdHex();

                // 2. Automatic return-path peer registration: Learn the sender MAC address
                if (packet.SenderMac != 0 && packet.SenderMac != _transport.LocalMacAddress)
                {
                    _transport.RegisterPeer(packet.SenderMac, -40);
                }

                // 3. Deduplication check: drop if seen before to prevent infinite routing loops
                if (!_seenMessageIds.TryAdd(messageId, DateTime.UtcNow))
                {
                    Log($"[Mesh Router] Dropping duplicate message {messageId[..8]}... (already processed).");
                    return;
                }

                Log($"[Mesh Router] Processing fresh packet {messageId[..8]}... (TTL: {packet.Ttl})");

                // 4. Attempt trial decryption using local node's private key
                bool isRecipient = _cryptoManager.TryDecrypt(
                    packet.ToEnvelope(),
                    out string? decryptedMessage,
                    out byte[]? senderPublicKey
                );

                if (isRecipient && decryptedMessage != null && senderPublicKey != null)
                {
                    // SUCCESS: This node is the intended recipient!
                    var msgInfo = new ReceivedMessageInfo(
                        MessageId: messageId,
                        SenderPublicKey: senderPublicKey,
                        SenderPublicKeyHex: CryptoManager.ToHex(senderPublicKey),
                        MessageText: decryptedMessage,
                        TimestampUtc: DateTimeOffset.FromUnixTimeMilliseconds(packet.TimestampMs).UtcDateTime,
                        RemainingTtl: packet.Ttl,
                        SenderMac: packet.SenderMac
                    );

                    MessageReceivedForLocalNode?.Invoke(msgInfo);
                }
                else
                {
                    // Relay node (not recipient)
                    Log($"[Mesh Relay] Packet {messageId[..8]}... trial decryption failed (message addressed to another node's Public Key).");

                    if (packet.Ttl > 0)
                    {
                        packet.Ttl--;

                        if (packet.Ttl > 0)
                        {
                            byte[] relayedBytes = packet.Serialize();
                            var peers = _transport.ActivePeers;

                            Log($"[Mesh Relay] Relaying message {messageId[..8]}... (new TTL: {packet.Ttl}) to {peers.Count} peer(s)...");

                            PacketRelayed?.Invoke(new RelayedPacketInfo(messageId, packet.Ttl, peers.Count));

                            // Flood to all discovered peers asynchronously
                            foreach (var peer in peers)
                            {
                                _ = Task.Run(async () =>
                                {
                                    await _transport.WriteToPeerAsync(peer.MacAddress, relayedBytes);
                                });
                            }
                        }
                        else
                        {
                            Log($"[Mesh Router] Packet {messageId[..8]}... reached TTL 0. Dropped.");
                        }
                    }
                    else
                    {
                        Log($"[Mesh Router] Packet {messageId[..8]}... expired (TTL=0). Dropped.");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"[Mesh Router Error] Failed to process packet: {ex.Message}");
            }
        }

        private void PruneDeduplicationCache(object? state)
        {
            var cutoff = DateTime.UtcNow.AddHours(-1);
            foreach (var kvp in _seenMessageIds)
            {
                if (kvp.Value < cutoff)
                {
                    _seenMessageIds.TryRemove(kvp.Key, out _);
                }
            }
        }

        private void Log(string message)
        {
            LogMessage?.Invoke(message);
        }

        public async ValueTask DisposeAsync()
        {
            _cachePruneTimer.Dispose();
            await _transport.DisposeAsync();
        }
    }
}
