using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace BleMeshMessenger
{
    public sealed record PeerNodeInfo(
        ulong MacAddress,
        string FormattedMac,
        short Rssi,
        DateTime LastSeenUtc
    );

    /// <summary>
    /// Transport layer implementing continuous BLE Beaconing, active peer discovery,
    /// automatic return-path peer learning, and GATT server/client communication.
    /// </summary>
    public sealed class BleMeshTransport : IAsyncDisposable
    {
        // Custom 128-bit UUIDs for the Mesh Network
        public static readonly Guid MeshServiceUuid = new("a7c4f100-38e2-491b-85d9-482f6e910001");
        public static readonly Guid MeshCharacteristicUuid = new("a7c4f101-38e2-491b-85d9-482f6e910001");
        public const ushort MeshCompanyId = 0xFFFE;
        public const string MeshBeaconLocalName = "BleMeshNode";

        private readonly ConcurrentDictionary<ulong, PeerNodeInfo> _activePeers = new();
        private readonly Timer _peerPruneTimer;

        private BluetoothLEAdvertisementPublisher? _beaconPublisher;
        private BluetoothLEAdvertisementWatcher? _watcher;
        private GattServiceProvider? _serviceProvider;
        private GattLocalCharacteristic? _mailboxCharacteristic;

        private bool _isDisposed;

        public event EventHandler<PeerNodeInfo>? PeerDiscovered;
        public event EventHandler<ulong>? PeerExpired;
        public event EventHandler<byte[]>? RawPacketReceived;
        public event Action<string>? LogMessage;

        public BluetoothAdapter? Adapter { get; private set; }
        public ulong LocalMacAddress { get; private set; }
        public string LocalMacFormatted => FormatMac(LocalMacAddress);

        public IReadOnlyCollection<PeerNodeInfo> ActivePeers => _activePeers.Values.ToList();

        public BleMeshTransport()
        {
            // Prune inactive peers every 10 seconds (peers not heard from in 120s)
            _peerPruneTimer = new Timer(PruneInactivePeers, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
        }

        public async Task StartAsync()
        {
            ObjectDisposedException.ThrowIf(_isDisposed, this);

            Log("[BLE] Initializing local Bluetooth adapter...");
            Adapter = await BluetoothAdapter.GetDefaultAsync();
            if (Adapter == null)
            {
                throw new PlatformNotSupportedException("No Bluetooth adapter found on this system.");
            }

            LocalMacAddress = Adapter.BluetoothAddress;
            Log($"[BLE Adapter] MAC: {LocalMacFormatted} | Central: {Adapter.IsCentralRoleSupported} | Peripheral: {Adapter.IsPeripheralRoleSupported}");

            // 1. Setup Local GATT Server Mailbox
            await InitializeGattServerAsync();

            // 2. Setup Background BLE Advertisement Watcher (Peer Discovery)
            InitializeWatcher();

            // 3. Setup Supplemental Presence Beacon Publisher
            InitializeBeaconPublisher();

            Log("[BLE Transport] Online. Beaconing and active scanning enabled.");
        }

        private async Task InitializeGattServerAsync()
        {
            Log("[BLE GATT] Creating Mesh GATT Service Provider...");
            var serviceResult = await GattServiceProvider.CreateAsync(MeshServiceUuid);
            if (serviceResult.Error != BluetoothError.Success)
            {
                Log($"[BLE GATT Error] Failed to create GATT Service: {serviceResult.Error}");
                return;
            }

            _serviceProvider = serviceResult.ServiceProvider;

            // Define Writeable Characteristic (Mesh Mailbox)
            var charParams = new GattLocalCharacteristicParameters
            {
                CharacteristicProperties = GattCharacteristicProperties.Write | 
                                           GattCharacteristicProperties.WriteWithoutResponse,
                WriteProtectionLevel = GattProtectionLevel.Plain,
                UserDescription = "Decentralized Mesh Mailbox"
            };

            var charResult = await _serviceProvider.Service.CreateCharacteristicAsync(MeshCharacteristicUuid, charParams);
            if (charResult.Error != BluetoothError.Success)
            {
                Log($"[BLE GATT Error] Failed to create characteristic: {charResult.Error}");
                return;
            }

            _mailboxCharacteristic = charResult.Characteristic;
            _mailboxCharacteristic.WriteRequested += Mailbox_WriteRequested;

            // Start Connectable Advertising
            var advParams = new GattServiceProviderAdvertisingParameters
            {
                IsConnectable = true,
                IsDiscoverable = true
            };

            _serviceProvider.AdvertisementStatusChanged += (s, e) =>
            {
                Log($"[BLE GATT Adv Status]: {e.Status} (Error: {e.Error})");
            };

            _serviceProvider.StartAdvertising(advParams);
            Log($"[BLE GATT Adv] Connectable advertising started (Status: {_serviceProvider.AdvertisementStatus})");
        }

        private void InitializeWatcher()
        {
            _watcher = new BluetoothLEAdvertisementWatcher
            {
                ScanningMode = BluetoothLEScanningMode.Active
            };

            _watcher.Received += Watcher_Received;
            _watcher.Stopped += (s, e) => Log($"[BLE Watcher] Stopped: {e.Error}");

            _watcher.Start();
            Log("[BLE Watcher] Scanning started.");
        }

        private void InitializeBeaconPublisher()
        {
            try
            {
                _beaconPublisher = new BluetoothLEAdvertisementPublisher();
                _beaconPublisher.Advertisement.LocalName = MeshBeaconLocalName;

                var mfg = new BluetoothLEManufacturerData { CompanyId = MeshCompanyId };
                var writer = new DataWriter();
                writer.WriteGuid(MeshServiceUuid);
                mfg.Data = writer.DetachBuffer();
                _beaconPublisher.Advertisement.ManufacturerData.Add(mfg);

                _beaconPublisher.StatusChanged += (s, e) =>
                {
                    if (e.Error != BluetoothError.Success)
                    {
                        Log($"[BLE Beacon Status]: {e.Status} (Error: {e.Error})");
                    }
                };

                _beaconPublisher.Start();
                Log("[BLE Beacon] Beacon publisher started.");
            }
            catch (Exception ex)
            {
                Log($"[BLE Beacon Info] Supplemental beacon skipped: {ex.Message}");
            }
        }

        private void Watcher_Received(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            // Do not register self if address matches
            if (args.BluetoothAddress == LocalMacAddress) return;

            bool isMeshNode = false;

            // Check 1: 128-bit Mesh Service UUID
            if (args.Advertisement.ServiceUuids.Contains(MeshServiceUuid))
            {
                isMeshNode = true;
            }
            // Check 2: Manufacturer Data
            if (!isMeshNode)
            {
                foreach (var mfg in args.Advertisement.ManufacturerData)
                {
                    if (mfg.CompanyId == MeshCompanyId)
                    {
                        isMeshNode = true;
                        break;
                    }
                }
            }
            // Check 3: Local Name
            if (!isMeshNode && !string.IsNullOrEmpty(args.Advertisement.LocalName))
            {
                if (args.Advertisement.LocalName.Contains("Mesh", StringComparison.OrdinalIgnoreCase))
                {
                    isMeshNode = true;
                }
            }

            if (isMeshNode)
            {
                RegisterPeer(args.BluetoothAddress, args.RawSignalStrengthInDBm);
            }
        }

        private async void Mailbox_WriteRequested(GattLocalCharacteristic sender, GattWriteRequestedEventArgs args)
        {
            var deferral = args.GetDeferral();
            try
            {
                // Automatic return-path discovery: Learn peer MAC from GATT Session
                if (args.Session != null)
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            var device = await BluetoothLEDevice.FromIdAsync(args.Session.DeviceId.Id);
                            if (device != null && device.BluetoothAddress != 0)
                            {
                                RegisterPeer(device.BluetoothAddress, -40);
                                Log($"[BLE Return-Path] Automatically paired with peer: {FormatMac(device.BluetoothAddress)}");
                            }
                        }
                        catch { }
                    });
                }

                var request = await args.GetRequestAsync();
                if (request != null)
                {
                    var reader = DataReader.FromBuffer(request.Value);
                    byte[] data = new byte[request.Value.Length];
                    reader.ReadBytes(data);

                    if (request.Option == GattWriteOption.WriteWithResponse)
                    {
                        request.Respond();
                    }

                    // Dispatch raw packet to Routing Layer asynchronously
                    _ = Task.Run(() => RawPacketReceived?.Invoke(this, data));
                }
            }
            catch (Exception ex)
            {
                Log($"[BLE Mailbox Error] Failed processing write: {ex.Message}");
            }
            finally
            {
                deferral.Complete();
            }
        }

        public void RegisterPeer(ulong mac, short rssi)
        {
            if (mac == 0 || mac == LocalMacAddress) return;

            string formattedMac = FormatMac(mac);
            var peer = new PeerNodeInfo(mac, formattedMac, rssi, DateTime.UtcNow);

            bool isNew = !_activePeers.ContainsKey(mac);
            _activePeers[mac] = peer;

            if (isNew)
            {
                Log($"[BLE Discovery] Discovered active mesh peer: {formattedMac} (RSSI: {rssi} dBm)");
                PeerDiscovered?.Invoke(this, peer);
            }
        }

        /// <summary>
        /// Writes an encrypted mesh packet payload to a peer's local mailbox characteristic over BLE GATT.
        /// </summary>
        public async Task<bool> WriteToPeerAsync(ulong peerMac, byte[] payload, CancellationToken ct = default)
        {
            BluetoothLEDevice? device = null;
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(6));

                device = await BluetoothLEDevice.FromBluetoothAddressAsync(peerMac);
                if (device == null)
                {
                    Log($"[BLE Send Error] Could not reach {FormatMac(peerMac)} (device null).");
                    return false;
                }

                var servicesResult = await device.GetGattServicesForUuidAsync(MeshServiceUuid, BluetoothCacheMode.Uncached);
                if (servicesResult.Status != GattCommunicationStatus.Success || servicesResult.Services.Count == 0)
                {
                    Log($"[BLE Send Error] Service discovery failed for {FormatMac(peerMac)}: {servicesResult.Status}");
                    return false;
                }

                using var service = servicesResult.Services[0];
                var charsResult = await service.GetCharacteristicsForUuidAsync(MeshCharacteristicUuid, BluetoothCacheMode.Uncached);
                if (charsResult.Status != GattCommunicationStatus.Success || charsResult.Characteristics.Count == 0)
                {
                    Log($"[BLE Send Error] Mailbox characteristic not found on {FormatMac(peerMac)}: {charsResult.Status}");
                    return false;
                }

                var characteristic = charsResult.Characteristics[0];

                var writer = new DataWriter();
                writer.WriteBytes(payload);
                var writeResult = await characteristic.WriteValueWithResultAsync(
                    writer.DetachBuffer(),
                    GattWriteOption.WriteWithResponse
                );

                if (writeResult.Status == GattCommunicationStatus.Success)
                {
                    return true;
                }
                else
                {
                    Log($"[BLE Send Error] Write failed to {FormatMac(peerMac)}: {writeResult.Status}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Log($"[BLE Write Exception to {FormatMac(peerMac)}]: {ex.Message}");
                return false;
            }
            finally
            {
                device?.Dispose();
            }
        }

        /// <summary>
        /// Manually connects and pings a peer MAC address, returning error details if unsuccessful.
        /// </summary>
        public async Task<(bool Success, string Message)> PingPeerAsync(ulong peerMac)
        {
            BluetoothLEDevice? device = null;
            try
            {
                device = await BluetoothLEDevice.FromBluetoothAddressAsync(peerMac);
                if (device == null)
                {
                    return (false, "Device could not be found via Bluetooth address. Make sure the target is advertising or paired.");
                }

                var services = await device.GetGattServicesForUuidAsync(MeshServiceUuid, BluetoothCacheMode.Uncached);
                if (services.Status == GattCommunicationStatus.Success && services.Services.Count > 0)
                {
                    RegisterPeer(peerMac, -45);
                    return (true, $"Connected! Mailbox service verified ({services.Services.Count} service(s) found).");
                }
                else
                {
                    return (false, $"Bluetooth connection status: {services.Status}. Device reached, but Mesh Service was not found.");
                }
            }
            catch (Exception ex)
            {
                return (false, $"Connection error: {ex.Message}");
            }
            finally
            {
                device?.Dispose();
            }
        }

        private void PruneInactivePeers(object? state)
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-120);
            foreach (var kvp in _activePeers)
            {
                if (kvp.Value.LastSeenUtc < cutoff)
                {
                    if (_activePeers.TryRemove(kvp.Key, out var removed))
                    {
                        Log($"[BLE Peer Lost] Peer {removed.FormattedMac} timed out.");
                        PeerExpired?.Invoke(this, kvp.Key);
                    }
                }
            }
        }

        public static string FormatMac(ulong address)
        {
            byte[] bytes = BitConverter.GetBytes(address);
            return $"{bytes[5]:X2}:{bytes[4]:X2}:{bytes[3]:X2}:{bytes[2]:X2}:{bytes[1]:X2}:{bytes[0]:X2}";
        }

        public static ulong ParseMac(string formattedMac)
        {
            string clean = formattedMac.Replace(":", "").Replace("-", "").Trim();
            if (clean.Length != 12) throw new ArgumentException("MAC address must be 12 hex characters (e.g. 00:11:22:33:44:55).");
            byte[] bytes = Convert.FromHexString(clean);
            byte[] ulongBytes = new byte[8];
            ulongBytes[0] = bytes[5];
            ulongBytes[1] = bytes[4];
            ulongBytes[2] = bytes[3];
            ulongBytes[3] = bytes[2];
            ulongBytes[4] = bytes[1];
            ulongBytes[5] = bytes[0];
            return BitConverter.ToUInt64(ulongBytes, 0);
        }

        private void Log(string message)
        {
            LogMessage?.Invoke(message);
        }

        public async ValueTask DisposeAsync()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            _peerPruneTimer.Dispose();

            if (_watcher != null)
            {
                _watcher.Stop();
                _watcher = null;
            }

            if (_beaconPublisher != null)
            {
                try { _beaconPublisher.Stop(); } catch { }
                _beaconPublisher = null;
            }

            if (_serviceProvider != null)
            {
                try { _serviceProvider.StopAdvertising(); } catch { }
                _serviceProvider = null;
            }

            await Task.CompletedTask;
        }
    }
}
