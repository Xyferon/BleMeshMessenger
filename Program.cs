using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace BleMeshMessenger
{
    internal class Program
    {
        private static readonly object ConsoleLock = new();
        private const string KeyFileName = "mesh_identity.key";

        private static async Task Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            PrintBanner();

            // 1. Initialize Cryptographic Identity (load existing or generate fresh)
            var crypto = CryptoManager.LoadOrCreate(KeyFileName);

            // 2. Initialize Transport and Router
            var transport = new BleMeshTransport();
            var router = new MeshRouter(crypto, transport);

            // Wire UI Event Handlers
            router.LogMessage += msg =>
            {
                SafeLog($"[LOG] {msg}", ConsoleColor.DarkGray);
            };

            transport.PeerDiscovered += (s, peer) =>
            {
                SafeLog($"\n[+] Peer Registered in Mesh: {peer.FormattedMac} (RSSI: {peer.Rssi} dBm)", ConsoleColor.Cyan);
                Prompt();
            };

            transport.PeerExpired += (s, mac) =>
            {
                SafeLog($"\n[-] Peer Timed Out: {BleMeshTransport.FormatMac(mac)}", ConsoleColor.DarkYellow);
                Prompt();
            };

            router.MessageReceivedForLocalNode += msg =>
            {
                lock (ConsoleLock)
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("╔═════════════════════════════════════════════════════════════════════════════════════════════╗");
                    Console.WriteLine("║                        *** NEW ENCRYPTED MESSAGE RECEIVED ***                                 ║");
                    Console.WriteLine("╚═════════════════════════════════════════════════════════════════════════════════════════════╝");
                    Console.ResetColor();
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine($"  From (Sender Key) : {msg.SenderPublicKeyHex}");
                    if (msg.SenderMac != 0)
                    {
                        Console.WriteLine($"  From (Sender MAC) : {BleMeshTransport.FormatMac(msg.SenderMac)}");
                    }
                    Console.WriteLine($"  Timestamp         : {msg.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC");
                    Console.WriteLine($"  Message ID (Hash) : {msg.MessageId}");
                    Console.WriteLine($"  Remaining TTL     : {msg.RemainingTtl} hop(s)");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"  Content           : {msg.MessageText}");
                    Console.ResetColor();
                    Console.WriteLine(new string('-', 95));
                }
                Prompt();
            };

            router.PacketRelayed += relayed =>
            {
                SafeLog($"[RELAY] Hopped msg {relayed.MessageId[..8]}... (New TTL: {relayed.NewTtl}) to {relayed.PeerCount} peer(s).", ConsoleColor.DarkCyan);
            };

            // 3. Start BLE Mesh Services
            try
            {
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine("[*] Initializing WinRT Bluetooth Low Energy Mesh Stack...");
                Console.ResetColor();

                await router.StartAsync();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[✔] BLE Mesh Node is ACTIVE.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] Critical Bluetooth initialization failure: {ex.Message}");
                Console.WriteLine("    Please verify Bluetooth is enabled in Windows Settings.");
                Console.ResetColor();
                return;
            }

            // Print Node Identity & Diagnostics
            PrintNodeInfo(crypto, transport);

            // 4. Interactive CLI Loop
            bool running = true;
            while (running)
            {
                Prompt();
                string? input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input)) continue;

                string[] parts = input.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
                string command = parts[0].ToLowerInvariant();

                switch (command)
                {
                    case "send":
                        if (parts.Length < 3)
                        {
                            SafeLog("Usage: send <Recipient_PublicKey_Hex> <Message>", ConsoleColor.Yellow);
                            break;
                        }

                        string recipientHex = parts[1].Trim();
                        string messageText = parts[2].Trim();

                        if (recipientHex.Equals(crypto.PublicKeyHex, StringComparison.OrdinalIgnoreCase))
                        {
                            SafeLog("[!] WARNING: You entered THIS PC's own Public Key as the recipient!", ConsoleColor.Yellow);
                            SafeLog("    You must enter the Public Key of PC 2, otherwise PC 2 cannot decrypt it.", ConsoleColor.Yellow);
                        }

                        byte[] recipientKey;
                        try
                        {
                            recipientKey = CryptoManager.ParsePublicKeyHex(recipientHex);
                        }
                        catch (Exception ex)
                        {
                            SafeLog($"[Error] Invalid recipient public key: {ex.Message}", ConsoleColor.Red);
                            break;
                        }

                        SafeLog($"[*] Encrypting and transmitting to mesh...", ConsoleColor.Cyan);
                        try
                        {
                            string msgId = await router.SendMessageAsync(recipientKey, messageText);
                            SafeLog($"[✔] Message successfully transmitted over BLE! (ID: {msgId[..12]}...)", ConsoleColor.Green);
                        }
                        catch (Exception ex)
                        {
                            SafeLog($"[Error] Failed to send message: {ex.Message}", ConsoleColor.Red);
                        }
                        break;

                    case "peers":
                        var peers = transport.ActivePeers;
                        lock (ConsoleLock)
                        {
                            Console.WriteLine();
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine($"--- Active BLE Mesh Peers ({peers.Count}) ---");
                            Console.ResetColor();
                            if (peers.Count == 0)
                            {
                                Console.WriteLine("  (No peers in local table yet.)");
                                Console.WriteLine("  • If scanning hasn't discovered your peer yet, connect manually with:");
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine("    connect <Peer_MAC_Address>   (e.g., connect E4:5F:01:23:45:67)");
                                Console.ResetColor();
                            }
                            else
                            {
                                foreach (var p in peers)
                                {
                                    int secondsAgo = (int)(DateTime.UtcNow - p.LastSeenUtc).TotalSeconds;
                                    Console.WriteLine($"  • MAC: {p.FormattedMac}  |  RSSI: {p.Rssi,4} dBm  |  Last seen: {secondsAgo}s ago");
                                }
                            }
                            Console.WriteLine();
                        }
                        break;

                    case "connect":
                        if (parts.Length < 2)
                        {
                            SafeLog("Usage: connect <Peer_MAC_Address> (e.g. connect E4:5F:01:23:45:67)", ConsoleColor.Yellow);
                            break;
                        }

                        string macInput = parts[1].Trim();
                        try
                        {
                            ulong targetMac = BleMeshTransport.ParseMac(macInput);
                            SafeLog($"[*] Attempting direct connection to {BleMeshTransport.FormatMac(targetMac)}...", ConsoleColor.Cyan);
                            var (reached, details) = await transport.PingPeerAsync(targetMac);
                            if (reached)
                            {
                                SafeLog($"[✔] Successfully connected to {BleMeshTransport.FormatMac(targetMac)}! {details}", ConsoleColor.Green);
                            }
                            else
                            {
                                SafeLog($"[!] Could not connect to {BleMeshTransport.FormatMac(targetMac)}: {details}", ConsoleColor.Yellow);
                            }
                        }
                        catch (Exception ex)
                        {
                            SafeLog($"[Error] Invalid MAC format: {ex.Message}", ConsoleColor.Red);
                        }
                        break;

                    case "diag":
                        PrintDiagnostics(transport);
                        break;

                    case "newkey":
                        crypto = CryptoManager.CreateFresh(KeyFileName);
                        router.SetCrypto(crypto);
                        SafeLog("[✔] Generated brand new unique cryptographic identity!", ConsoleColor.Green);
                        PrintNodeInfo(crypto, transport);
                        break;

                    case "key":
                        PrintNodeInfo(crypto, transport);
                        break;

                    case "clear":
                        Console.Clear();
                        PrintBanner();
                        PrintNodeInfo(crypto, transport);
                        break;

                    case "help":
                        PrintHelp();
                        break;

                    case "exit":
                    case "quit":
                        running = false;
                        break;

                    default:
                        SafeLog($"Unknown command '{command}'. Type 'help' for instructions.", ConsoleColor.Yellow);
                        break;
                }
            }

            Console.WriteLine("[*] Shutting down BLE mesh node...");
            await router.DisposeAsync();
            Console.WriteLine("[✔] Shutdown complete. Goodbye.");
        }

        private static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
╔═════════════════════════════════════════════════════════════════════════════════════════╗
║                   DECENTRALIZED E2EE BLE MESH MESSENGER (.NET 8)                        ║
║     Zero-Trust Epidemic Store-and-Forward Mesh  •  X25519 + ChaCha20-Poly1305 AEAD      ║
╚═════════════════════════════════════════════════════════════════════════════════════════╝");
            Console.ResetColor();
        }

        private static void PrintNodeInfo(CryptoManager crypto, BleMeshTransport transport)
        {
            lock (ConsoleLock)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("─────────────────────────────────────────────────────────────────────────────────────────");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("THIS NODE BLUETOOTH MAC:  ");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine(transport.LocalMacFormatted);

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("THIS NODE PUBLIC KEY (Hex):");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(crypto.PublicKeyHex);

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("(Share your Public Key with your peer so they can send encrypted messages to you)");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("─────────────────────────────────────────────────────────────────────────────────────────");
                Console.WriteLine("Commands: send <PubKeyHex> <Msg> | peers | connect <MAC> | diag | help | exit");
                Console.ResetColor();
            }
        }

        private static void PrintDiagnostics(BleMeshTransport transport)
        {
            lock (ConsoleLock)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("--- Bluetooth Hardware Diagnostics ---");
                Console.ResetColor();

                var adapter = transport.Adapter;
                if (adapter != null)
                {
                    Console.WriteLine($"  Device ID:                   {adapter.DeviceId}");
                    Console.WriteLine($"  Local MAC:                   {transport.LocalMacFormatted}");
                    Console.WriteLine($"  Central Role (Scan/Connect): {(adapter.IsCentralRoleSupported ? "[✔] Supported" : "[✘] Not Supported")}");
                    Console.WriteLine($"  Peripheral Role (GATT Svr):  {(adapter.IsPeripheralRoleSupported ? "[✔] Supported" : "[✘] Not Supported")}");
                    Console.WriteLine($"  Advertisement Offloading:    {(adapter.IsAdvertisementOffloadSupported ? "[✔] Supported" : "[✘] Not Supported")}");
                    Console.WriteLine($"  Max Adv Data Length:         {adapter.MaxAdvertisementDataLength} bytes");
                }
                else
                {
                    Console.WriteLine("  No adapter details available.");
                }
                Console.WriteLine();
            }
        }

        private static void PrintHelp()
        {
            lock (ConsoleLock)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("Available Commands:");
                Console.ResetColor();
                Console.WriteLine("  send <PubKeyHex> <Msg>   Encrypt with X25519/ChaCha20-Poly1305 & flood to mesh");
                Console.WriteLine("  peers                    Display list of discovered active BLE peer MAC addresses");
                Console.WriteLine("  connect <MAC>            Directly connect & add a peer by MAC (e.g. connect E4:5F:01:23:45:67)");
                Console.WriteLine("  diag                     Show local Bluetooth adapter capabilities");
                Console.WriteLine("  key                      Show this node's Public Key and MAC Address");
                Console.WriteLine("  newkey                   Generate a brand new unique keypair on this node");
                Console.WriteLine("  clear                    Clear the console window");
                Console.WriteLine("  help                     Show this help guide");
                Console.WriteLine("  exit                     Disconnect and exit application");
                Console.WriteLine();
            }
        }

        private static void Prompt()
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write("mesh> ");
            Console.ResetColor();
        }

        private static void SafeLog(string text, ConsoleColor color)
        {
            lock (ConsoleLock)
            {
                Console.ForegroundColor = color;
                Console.WriteLine(text);
                Console.ResetColor();
            }
        }
    }
}
