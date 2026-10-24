using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using WinWiFi.Interop;
using WinWiFi.Models;

namespace WinWiFi.Services
{
    public class NativeWifiService : INativeWifiService
    {
        private readonly SecurityAnalyzer _securityAnalyzer;
        private readonly SemaphoreSlim _scanLock = new(1, 1);
        private readonly ScanDiagnostics _diagnostics = new();
        private bool _disposed = false;

        public ScanTelemetryState CurrentState => _diagnostics.State;
        public event Action<ScanDiagnostics>? DiagnosticsUpdated;
        public event Action<ScanBatchResult>? ScanCompleted;

        public NativeWifiService(SecurityAnalyzer securityAnalyzer)
        {
            _securityAnalyzer = securityAnalyzer ?? throw new ArgumentNullException(nameof(securityAnalyzer));
            _diagnostics.NativeWlanAvailable = IsNativeWifiAvailable();
            _diagnostics.State = ScanTelemetryState.Idle;
        }

        public ScanDiagnostics GetDiagnostics()
        {
            lock (_diagnostics)
            {
                return new ScanDiagnostics
                {
                    State = _diagnostics.State,
                    ActiveAdapterId = _diagnostics.ActiveAdapterId,
                    ActiveAdapterName = _diagnostics.ActiveAdapterName,
                    TotalAdaptersDetected = _diagnostics.TotalAdaptersDetected,
                    LastScanDurationMs = _diagnostics.LastScanDurationMs,
                    LastDiscoveredBssCount = _diagnostics.LastDiscoveredBssCount,
                    TotalUniqueBssidsTracked = _diagnostics.TotalUniqueBssidsTracked,
                    TotalScanCycles = _diagnostics.TotalScanCycles,
                    LastError = _diagnostics.LastError,
                    LastScanTimestamp = _diagnostics.LastScanTimestamp,
                    NativeWlanAvailable = _diagnostics.NativeWlanAvailable,
                    NetshFallbackUsed = _diagnostics.NetshFallbackUsed,
                    StatusMessages = new List<string>(_diagnostics.StatusMessages)
                };
            }
        }

        private void UpdateTelemetryState(ScanTelemetryState state, string? message = null, string? error = null)
        {
            lock (_diagnostics)
            {
                _diagnostics.State = state;
                if (!string.IsNullOrEmpty(error))
                {
                    _diagnostics.LastError = error;
                }
                if (!string.IsNullOrEmpty(message))
                {
                    _diagnostics.StatusMessages.Add($"[{DateTime.UtcNow:HH:mm:ss.fff}] {message}");
                    if (_diagnostics.StatusMessages.Count > 100)
                    {
                        _diagnostics.StatusMessages.RemoveAt(0);
                    }
                }
            }
            try
            {
                DiagnosticsUpdated?.Invoke(GetDiagnostics());
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NativeWifiService] DiagnosticsUpdated event error: {ex.Message}");
            }
        }

        public bool IsNativeWifiAvailable()
        {
            try
            {
                uint version;
                IntPtr clientHandle;
                uint result = NativeWifi.WlanOpenHandle(NativeWifi.WLAN_CLIENT_VERSION_VISTA, IntPtr.Zero, out version, out clientHandle);
                if (result == NativeWifi.ERROR_SUCCESS)
                {
                    NativeWifi.WlanCloseHandle(clientHandle, IntPtr.Zero);
                    return true;
                }
            }
            catch
            {
                // wlanapi.dll not available or non-Windows environment
            }
            return false;
        }

        public async Task<List<WifiAdapter>> GetAdaptersAsync()
        {
            var adapters = new List<WifiAdapter>();

            try
            {
                uint negotiatedVersion;
                IntPtr clientHandle;
                uint result = NativeWifi.WlanOpenHandle(NativeWifi.WLAN_CLIENT_VERSION_VISTA, IntPtr.Zero, out negotiatedVersion, out clientHandle);

                if (result == NativeWifi.ERROR_SUCCESS)
                {
                    try
                    {
                        IntPtr pInterfaceList;
                        result = NativeWifi.WlanEnumInterfaces(clientHandle, IntPtr.Zero, out pInterfaceList);

                        if (result == NativeWifi.ERROR_SUCCESS && pInterfaceList != IntPtr.Zero)
                        {
                            try
                            {
                                var listHeader = Marshal.PtrToStructure<WLAN_INTERFACE_INFO_LIST>(pInterfaceList);
                                int infoSize = Marshal.SizeOf<WLAN_INTERFACE_INFO>();
                                IntPtr currentPtr = IntPtr.Add(pInterfaceList, Marshal.SizeOf<uint>() * 2);

                                for (int i = 0; i < listHeader.dwNumberOfItems; i++)
                                {
                                    var info = Marshal.PtrToStructure<WLAN_INTERFACE_INFO>(currentPtr);

                                    adapters.Add(new WifiAdapter
                                    {
                                        Id = info.InterfaceGuid.ToString(),
                                        InterfaceGuid = info.InterfaceGuid,
                                        Name = info.strInterfaceDescription,
                                        Description = $"{info.strInterfaceDescription} (Windows NDIS / WlanApi)",
                                        Status = info.isState.ToString().Replace("wlan_interface_state_", ""),
                                        SupportedBands = new List<string>(),
                                        MonitorModeSupported = false,
                                        PacketInjectionSupported = false,
                                        CurrentChannel = 0,
                                        IsChannelHopping = false,
                                        TxPowerDbm = 0
                                    });

                                    currentPtr = IntPtr.Add(currentPtr, infoSize);
                                }
                            }
                            finally
                            {
                                NativeWifi.WlanFreeMemory(pInterfaceList);
                            }
                        }
                        else
                        {
                            UpdateTelemetryState(ScanTelemetryState.DriverUnsupported, $"WlanEnumInterfaces error code: {result}");
                        }
                    }
                    finally
                    {
                        NativeWifi.WlanCloseHandle(clientHandle, IntPtr.Zero);
                    }
                }
                else
                {
                    UpdateTelemetryState(ScanTelemetryState.DriverUnsupported, $"WlanOpenHandle error code: {result}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NativeWifiService] Error enumerating Wlan interfaces: {ex.Message}");
            }

            // Fallback to netsh if no interfaces returned by WlanApi
            if (adapters.Count == 0)
            {
                adapters = await EnumerateNetshAdaptersAsync();
                if (adapters.Count > 0)
                {
                    lock (_diagnostics)
                    {
                        _diagnostics.NetshFallbackUsed = true;
                    }
                }
            }

            lock (_diagnostics)
            {
                _diagnostics.TotalAdaptersDetected = adapters.Count;
                if (adapters.Count > 0 && string.IsNullOrEmpty(_diagnostics.ActiveAdapterId))
                {
                    _diagnostics.ActiveAdapterId = adapters[0].Id;
                    _diagnostics.ActiveAdapterName = adapters[0].Name;
                }
            }

            if (adapters.Count == 0)
            {
                UpdateTelemetryState(ScanTelemetryState.AdapterUnavailable, "No Wi-Fi adapters detected on system.");
            }

            return adapters;
        }

        public async Task TriggerHardwareScanAsync(string adapterId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            await Task.Run(() =>
            {
                try
                {
                    uint negotiatedVersion;
                    IntPtr clientHandle;
                    uint openResult = NativeWifi.WlanOpenHandle(NativeWifi.WLAN_CLIENT_VERSION_VISTA, IntPtr.Zero, out negotiatedVersion, out clientHandle);
                    if (openResult == NativeWifi.ERROR_SUCCESS)
                    {
                        try
                        {
                            if (Guid.TryParse(adapterId, out Guid guid))
                            {
                                uint scanResult = NativeWifi.WlanScan(clientHandle, ref guid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                                if (scanResult != NativeWifi.ERROR_SUCCESS)
                                {
                                    Debug.WriteLine($"[NativeWifiService] WlanScan returned code: {scanResult}");
                                }
                            }
                        }
                        finally
                        {
                            NativeWifi.WlanCloseHandle(clientHandle, IntPtr.Zero);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[NativeWifiService] TriggerHardwareScanAsync error: {ex.Message}");
                }
            }, cancellationToken);
        }

        public async Task<List<AccessPoint>> ScanNetworksAsync(string adapterId, CancellationToken cancellationToken = default)
        {
            var result = await ScanNetworksExAsync(adapterId, cancellationToken);
            return result.AccessPoints;
        }

        public async Task<ScanBatchResult> ScanNetworksExAsync(string adapterId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var sw = Stopwatch.StartNew();
            var batchResult = new ScanBatchResult
            {
                AdapterId = adapterId,
                Timestamp = DateTime.UtcNow
            };

            // Prevent overlapping scans using SemaphoreSlim
            bool acquired = await _scanLock.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            if (!acquired)
            {
                batchResult.State = ScanTelemetryState.Error;
                batchResult.ErrorMessage = "Scan lock acquisition timed out (overlapping scan prevented).";
                return batchResult;
            }

            try
            {
                UpdateTelemetryState(ScanTelemetryState.Scanning, $"Initiating scan cycle on adapter {adapterId}");

                var accessPoints = new List<AccessPoint>();
                bool nativeScanSucceeded = false;

                try
                {
                    uint negotiatedVersion;
                    IntPtr clientHandle;
                    uint result = NativeWifi.WlanOpenHandle(NativeWifi.WLAN_CLIENT_VERSION_VISTA, IntPtr.Zero, out negotiatedVersion, out clientHandle);

                    if (result == NativeWifi.ERROR_SUCCESS)
                    {
                        try
                        {
                            if (Guid.TryParse(adapterId, out Guid guid))
                            {
                                IntPtr pBssList;
                                result = NativeWifi.WlanGetNetworkBssList(
                                    clientHandle,
                                    ref guid,
                                    IntPtr.Zero,
                                    DOT11_BSS_TYPE.dot11_BSS_type_any,
                                    false,
                                    IntPtr.Zero,
                                    out pBssList);

                                if (result == NativeWifi.ERROR_SUCCESS && pBssList != IntPtr.Zero)
                                {
                                    try
                                    {
                                        var bssList = Marshal.PtrToStructure<WLAN_BSS_LIST>(pBssList);
                                        long listStart = pBssList.ToInt64();
                                        long listEnd = listStart + bssList.dwTotalSize;
                                        long currentOffset = listStart + 8; // skip dwTotalSize (4) + dwNumberOfItems (4)

                                        int entryStructSize = Marshal.SizeOf<DOT11_BSS_ENTRY>();

                                        // Support complete result sets returned by Windows - zero artificial limits
                                        for (int i = 0; i < bssList.dwNumberOfItems; i++)
                                        {
                                            cancellationToken.ThrowIfCancellationRequested();

                                            if (currentOffset + entryStructSize > listEnd)
                                            {
                                                break; // Prevent reading past buffer boundary
                                            }

                                            IntPtr currentEntryPtr = new IntPtr(currentOffset);
                                            var entry = Marshal.PtrToStructure<DOT11_BSS_ENTRY>(currentEntryPtr);

                                            string bssid = entry.dot11Bssid.ToString();
                                            string ssid = entry.dot11Ssid.GetSsidString();
                                            bool isHidden = string.IsNullOrWhiteSpace(ssid);
                                            if (isHidden) ssid = "[Hidden SSID]";

                                            var (channel, band) = NativeWifi.FrequencyToChannel(entry.ulChCenterFrequency);

                                            var ap = new AccessPoint
                                            {
                                                Bssid = bssid,
                                                Ssid = ssid,
                                                IsHidden = isHidden,
                                                Channel = channel,
                                                Band = band,
                                                FrequencyMHz = (int)(entry.ulChCenterFrequency / 1000),
                                                Rssi = entry.lRssi,
                                                SignalQuality = entry.uLinkQuality,
                                                PhyType = FormatPhyType(entry.dot11BssPhyType),
                                                BeaconInterval = entry.usBeaconPeriod,
                                                CapabilityFlags = entry.usCapabilityInformation,
                                                BeaconCount = 1,
                                                DataPacketCount = 0,
                                                FirstSeen = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                                                LastSeen = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                                                LastSeenTime = DateTime.UtcNow,
                                                Vendor = OuiLookupService.ResolveVendor(bssid)
                                            };

                                            // Default Privacy bit check
                                            if ((entry.usCapabilityInformation & 0x0010) != 0)
                                            {
                                                ap.Security = "WEP";
                                                ap.Cipher = "WEP";
                                            }
                                            else
                                            {
                                                ap.Security = "Open";
                                                ap.Cipher = "None";
                                            }

                                            // Parse Information Elements safely with bounds checking
                                            long ieStart = currentOffset + entry.ulIeOffset;
                                            long ieEnd = ieStart + entry.ulIeSize;

                                            if (entry.ulIeSize > 0 && entry.ulIeOffset >= (uint)entryStructSize && ieEnd <= listEnd)
                                            {
                                                byte[] ieBytes = new byte[entry.ulIeSize];
                                                Marshal.Copy(new IntPtr(ieStart), ieBytes, 0, (int)entry.ulIeSize);
                                                ParseInformationElements(ieBytes, ap);
                                            }

                                            // Evaluate NIST SP 800-153 security posture
                                            _securityAnalyzer.EvaluateSecurityPosture(ap);

                                            accessPoints.Add(ap);

                                            // WLAN_BSS_LIST contains a contiguous array of fixed-size
                                            // WLAN_BSS_ENTRY structures. ulIeOffset points from this
                                            // entry to an IE blob elsewhere in the allocation; it is
                                            // not part of the next-entry stride. Using it as a stride
                                            // corrupts every record after the first one.
                                            currentOffset += entryStructSize;
                                        }

                                        nativeScanSucceeded = true;
                                    }
                                    finally
                                    {
                                        NativeWifi.WlanFreeMemory(pBssList);
                                    }
                                }
                                else if (result == NativeWifi.ERROR_INVALID_PARAMETER)
                                {
                                    UpdateTelemetryState(ScanTelemetryState.AdapterUnavailable, $"Adapter {adapterId} not found or disconnected.");
                                }
                            }
                        }
                        finally
                        {
                            NativeWifi.WlanCloseHandle(clientHandle, IntPtr.Zero);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    UpdateTelemetryState(ScanTelemetryState.Paused, "Scan operation cancelled.");
                    throw;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[NativeWifiService] ScanNetworksAsync WlanApi error: {ex.Message}");
                }

                // Some Windows drivers expose only a partial BSS list through
                // WlanGetNetworkBssList even after WlanScan has completed. Netsh
                // asks the same Windows WLAN service for its full visible-network
                // result, so reconcile it on every scan rather than using it only
                // when the native call returns zero rows. This preserves all BSSIDs
                // reported by Windows and avoids an artificial partial view.
                cancellationToken.ThrowIfCancellationRequested();
                var netshAps = await ScanViaNetshCliAsync(cancellationToken);
                if (netshAps.Count > 0)
                {
                    accessPoints = MergeWindowsScanResults(accessPoints, netshAps);
                    lock (_diagnostics)
                    {
                        _diagnostics.NetshFallbackUsed = !nativeScanSucceeded || netshAps.Count > accessPoints.Count;
                    }
                }

                sw.Stop();
                batchResult.AccessPoints = accessPoints;
                batchResult.DurationMs = (int)sw.ElapsedMilliseconds;

                lock (_diagnostics)
                {
                    _diagnostics.TotalScanCycles++;
                    _diagnostics.LastScanDurationMs = batchResult.DurationMs;
                    _diagnostics.LastDiscoveredBssCount = accessPoints.Count;
                    _diagnostics.LastScanTimestamp = DateTime.UtcNow;
                }

                if (accessPoints.Count == 0)
                {
                    batchResult.State = ScanTelemetryState.NoNetworksFound;
                    UpdateTelemetryState(ScanTelemetryState.NoNetworksFound, $"Scan completed in {sw.ElapsedMilliseconds}ms. No networks discovered.");
                }
                else
                {
                    batchResult.State = ScanTelemetryState.Idle;
                    UpdateTelemetryState(ScanTelemetryState.Idle, $"Scan completed: {accessPoints.Count} BSS entries discovered in {sw.ElapsedMilliseconds}ms.");
                }

                try
                {
                    ScanCompleted?.Invoke(batchResult);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[NativeWifiService] ScanCompleted event error: {ex.Message}");
                }

                return batchResult;
            }
            finally
            {
                _scanLock.Release();
            }
        }

        /// <summary>
        /// Produces one record per BSSID without imposing a result cap. The
        /// native BSS record is authoritative for information elements such as
        /// RSN capabilities, PMF and WPS. Netsh has no equivalent fields, so it
        /// can only add BSSIDs that the driver omitted; replacing native rows
        /// here silently erased security evidence and flattened risk scores.
        /// </summary>
        internal static List<AccessPoint> MergeWindowsScanResults(
            List<AccessPoint> nativeAccessPoints,
            List<AccessPoint> netshAccessPoints)
        {
            var merged = new Dictionary<string, AccessPoint>(StringComparer.OrdinalIgnoreCase);
            foreach (var ap in nativeAccessPoints.Where(ap => IsValidBssid(ap.Bssid)))
            {
                merged[ap.Bssid] = ap;
            }

            // Netsh may report BSSIDs that a particular driver has omitted from
            // WlanGetNetworkBssList. Keep those entries, while retaining the
            // native object whenever both sources identify the same BSSID.
            foreach (var ap in netshAccessPoints.Where(ap => IsValidBssid(ap.Bssid)))
            {
                if (!merged.ContainsKey(ap.Bssid))
                    merged[ap.Bssid] = ap;
            }

            var result = new List<AccessPoint>(merged.Values);
            result.Sort((left, right) => right.SignalQuality.CompareTo(left.SignalQuality));
            return result;
        }

        private static bool IsValidBssid(string? bssid) =>
            !string.IsNullOrWhiteSpace(bssid) &&
            Regex.IsMatch(bssid, "^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$");

        public async Task<Dictionary<string, ScanBatchResult>> ScanAllAdaptersAsync(CancellationToken cancellationToken = default)
        {
            var results = new Dictionary<string, ScanBatchResult>();
            var adapters = await GetAdaptersAsync();

            if (adapters.Count == 0)
            {
                UpdateTelemetryState(ScanTelemetryState.AdapterUnavailable, "No Wi-Fi adapters available for multi-adapter scan.");
                return results;
            }

            foreach (var adapter in adapters)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    // Trigger hardware scan first
                    await TriggerHardwareScanAsync(adapter.Id, cancellationToken);
                    // Dwell 1.2s to allow probe responses
                    await Task.Delay(1200, cancellationToken);
                    // Retrieve networks
                    var batch = await ScanNetworksExAsync(adapter.Id, cancellationToken);
                    batch.AdapterDescription = adapter.Description;
                    results[adapter.Id] = batch;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    results[adapter.Id] = new ScanBatchResult
                    {
                        AdapterId = adapter.Id,
                        AdapterDescription = adapter.Description,
                        State = ScanTelemetryState.Error,
                        ErrorMessage = ex.Message
                    };
                }
            }

            return results;
        }

        private void ParseInformationElements(byte[] ieBytes, AccessPoint ap)
        {
            try
            {
                int index = 0;
                while (index + 2 <= ieBytes.Length)
                {
                    byte tagNumber = ieBytes[index];
                    byte tagLength = ieBytes[index + 1];
                    index += 2;

                    if (index + tagLength > ieBytes.Length) break;

                    switch (tagNumber)
                    {
                        case 0: // SSID (if not captured from BSS entry)
                            if (ap.IsHidden && tagLength > 0)
                            {
                                string decoded = Encoding.UTF8.GetString(ieBytes, index, tagLength).Trim();
                                if (!string.IsNullOrWhiteSpace(decoded))
                                {
                                    ap.Ssid = decoded;
                                    ap.IsHidden = false;
                                }
                            }
                            break;

                        case 1: // Supported Rates
                        case 50: // Extended Supported Rates
                            for (int r = 0; r < tagLength; r++)
                            {
                                byte rateVal = (byte)(ieBytes[index + r] & 0x7F);
                                double rateMbps = rateVal * 0.5;
                                if (rateMbps > ap.MaxRateMbps) ap.MaxRateMbps = rateMbps;
                            }
                            break;

                        case 3: // DS Parameter Set (Channel)
                            if (tagLength >= 1)
                            {
                                int dsChannel = ieBytes[index];
                                if (dsChannel > 0 && dsChannel <= 196)
                                {
                                    ap.Channel = dsChannel;
                                }
                            }
                            break;

                        case 7: // Country Information
                            if (tagLength >= 2)
                            {
                                ap.CountryCode = Encoding.ASCII.GetString(ieBytes, index, 2).Trim();
                            }
                            break;

                        case 45: // HT Capabilities (802.11n)
                            if (ap.PhyType == "802.11b" || ap.PhyType == "802.11g" || ap.PhyType == "802.11a")
                            {
                                ap.PhyType = "802.11n (Wi-Fi 4)";
                            }
                            if (tagLength >= 2)
                            {
                                ushort htCapInfo = BitConverter.ToUInt16(ieBytes, index);
                                if ((htCapInfo & 0x0002) != 0) ap.ChannelWidth = Math.Max(ap.ChannelWidth, 40);
                            }
                            break;

                        case 61: // HT Operation (802.11n Channel Width & Secondary Offset)
                            if (tagLength >= 2)
                            {
                                byte secOffset = (byte)(ieBytes[index + 1] & 0x03);
                                if (secOffset == 1) ap.SecondaryChannelOffset = "+1 (Above)";
                                else if (secOffset == 3) ap.SecondaryChannelOffset = "-1 (Below)";
                                else ap.SecondaryChannelOffset = "None";

                                bool chWidth40 = (ieBytes[index + 1] & 0x04) != 0;
                                if (chWidth40) ap.ChannelWidth = Math.Max(ap.ChannelWidth, 40);
                            }
                            break;

                        case 191: // VHT Capabilities (802.11ac)
                            ap.PhyType = "802.11ac (Wi-Fi 5)";
                            ap.ChannelWidth = Math.Max(ap.ChannelWidth, 80);
                            break;

                        case 192: // VHT Operation
                            if (tagLength >= 1)
                            {
                                byte vhtWidth = ieBytes[index];
                                if (vhtWidth == 1) ap.ChannelWidth = Math.Max(ap.ChannelWidth, 80);
                                else if (vhtWidth == 2 || vhtWidth == 3) ap.ChannelWidth = Math.Max(ap.ChannelWidth, 160);
                            }
                            break;

                        case 255: // Extended Element (HE / 802.11ax Wi-Fi 6 & EHT / 802.11be Wi-Fi 7)
                            if (tagLength >= 1)
                            {
                                byte extTag = ieBytes[index];
                                if (extTag == 35) // HE Capabilities
                                {
                                    ap.PhyType = ap.Band == "6 GHz" ? "802.11ax (Wi-Fi 6E)" : "802.11ax (Wi-Fi 6)";
                                }
                                else if (extTag == 107 || extTag == 108) // EHT Capabilities
                                {
                                    ap.PhyType = "802.11be (Wi-Fi 7)";
                                }
                            }
                            break;

                        case 48: // RSN (802.11i / WPA2 / WPA3)
                            ParseRsnElement(ieBytes, index, tagLength, ap);
                            break;

                        case 221: // Vendor Specific (WPA1, WPS, WMM)
                            ParseVendorSpecificElement(ieBytes, index, tagLength, ap);
                            break;
                    }

                    index += tagLength;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NativeWifiService] IE parse error: {ex.Message}");
            }
        }

        private void ParseRsnElement(byte[] data, int offset, int length, AccessPoint ap)
        {
            if (length < 2) return;

            int curr = offset;
            int end = offset + length;

            ushort version = BitConverter.ToUInt16(data, curr);
            curr += 2;

            // Group Cipher Suite (4 bytes: OUI + type)
            if (curr + 4 <= end)
            {
                ap.GroupCipher = MapCipherSuite(data, curr);
                curr += 4;
            }

            // Pairwise Cipher Suites
            if (curr + 2 <= end)
            {
                ushort pairwiseCount = BitConverter.ToUInt16(data, curr);
                curr += 2;

                ap.PairwiseCiphers.Clear();
                for (int p = 0; p < pairwiseCount && curr + 4 <= end; p++)
                {
                    string cipher = MapCipherSuite(data, curr);
                    if (!ap.PairwiseCiphers.Contains(cipher)) ap.PairwiseCiphers.Add(cipher);
                    curr += 4;
                }

                if (ap.PairwiseCiphers.Count > 0)
                {
                    ap.Cipher = string.Join("/", ap.PairwiseCiphers);
                }
            }

            // AKM Suites
            bool hasWpa3Sae = false;
            bool hasWpa2Psk = false;
            bool hasEnterprise = false;
            bool hasOwe = false;

            if (curr + 2 <= end)
            {
                ushort akmCount = BitConverter.ToUInt16(data, curr);
                curr += 2;

                ap.AkmSuites.Clear();
                for (int a = 0; a < akmCount && curr + 4 <= end; a++)
                {
                    string akm = MapAkmSuite(data, curr);
                    if (!ap.AkmSuites.Contains(akm)) ap.AkmSuites.Add(akm);

                    if (akm.Contains("SAE")) hasWpa3Sae = true;
                    if (akm.Contains("PSK")) hasWpa2Psk = true;
                    if (akm.Contains("802.1X") || akm.Contains("Suite B")) hasEnterprise = true;
                    if (akm.Contains("OWE")) hasOwe = true;

                    curr += 4;
                }
            }

            // Determine Security String
            if (hasOwe)
            {
                ap.Security = "OWE (Enhanced Open)";
            }
            else if (hasWpa3Sae && hasWpa2Psk)
            {
                ap.Security = "WPA3-Personal / WPA2 Transition";
            }
            else if (hasWpa3Sae)
            {
                ap.Security = "WPA3-SAE (Personal)";
            }
            else if (hasEnterprise)
            {
                ap.Security = "WPA2-Enterprise (802.1X)";
            }
            else if (hasWpa2Psk)
            {
                ap.Security = "WPA2-PSK";
            }

            // RSN Capabilities (2 bytes)
            if (curr + 2 <= end)
            {
                ushort rsnCaps = BitConverter.ToUInt16(data, curr);
                // Bit 6: MFPC (PMF Capable), Bit 7: MFPR (PMF Required)
                ap.PmfInformationAvailable = true;
                ap.PmfCapable = (rsnCaps & 0x0040) != 0;
                ap.PmfRequired = (rsnCaps & 0x0080) != 0;
            }
        }

        private void ParseVendorSpecificElement(byte[] data, int offset, int length, AccessPoint ap)
        {
            if (length < 4) return;

            // Microsoft OUI 00:50:F2
            if (data[offset] == 0x00 && data[offset + 1] == 0x50 && data[offset + 2] == 0xF2)
            {
                byte type = data[offset + 3];

                // Type 1: WPA1 (TKIP/CCMP)
                if (type == 0x01 && ap.Security == "Open")
                {
                    ap.Security = "WPA-PSK";
                    ap.Cipher = "TKIP";
                }
                // Type 4: WPS (Wi-Fi Protected Setup)
                else if (type == 0x04)
                {
                    ap.IsWpsEnabled = true;
                    ParseWpsSubElements(data, offset + 4, length - 4, ap);
                }
            }
        }

        private void ParseWpsSubElements(byte[] data, int offset, int length, AccessPoint ap)
        {
            try
            {
                int curr = offset;
                int end = offset + length;

                while (curr + 4 <= end)
                {
                    ushort subType = (ushort)((data[curr] << 8) | data[curr + 1]);
                    ushort subLen = (ushort)((data[curr + 2] << 8) | data[curr + 3]);
                    curr += 4;

                    if (curr + subLen > end) break;

                    switch (subType)
                    {
                        case 0x104A: // Version
                            if (subLen >= 1)
                            {
                                byte ver = data[curr];
                                ap.WpsVersion = ver >= 0x20 ? "WPS 2.0" : "WPS 1.0";
                            }
                            break;

                        case 0x1044: // Wi-Fi Protected Setup State
                            if (subLen >= 1)
                            {
                                byte state = data[curr];
                                ap.WpsState = state == 2 ? "Configured" : (state == 1 ? "Unconfigured" : "Unknown");
                            }
                            break;

                        case 0x1057: // AP Setup Locked
                            if (subLen >= 1)
                            {
                                ap.IsWpsLocked = data[curr] != 0;
                            }
                            break;

                        case 0x1021: // Manufacturer
                            ap.WpsManufacturer = Encoding.UTF8.GetString(data, curr, subLen).Trim();
                            break;

                        case 0x1023: // Model Name
                            ap.WpsModelName = Encoding.UTF8.GetString(data, curr, subLen).Trim();
                            break;

                        case 0x1011: // Device Name
                            ap.WpsDeviceName = Encoding.UTF8.GetString(data, curr, subLen).Trim();
                            break;
                    }

                    curr += subLen;
                }
            }
            catch
            {
                // Ignore corrupt vendor WPS subelements
            }
        }

        private string MapCipherSuite(byte[] data, int offset)
        {
            if (data[offset] == 0x00 && data[offset + 1] == 0x0F && data[offset + 2] == 0xAC)
            {
                return data[offset + 3] switch
                {
                    1 => "WEP-40",
                    2 => "TKIP",
                    4 => "CCMP",
                    5 => "WEP-104",
                    8 => "GCMP-128",
                    9 => "GCMP-256",
                    _ => $"Cipher-0x{data[offset + 3]:X2}"
                };
            }
            return "Unknown-Cipher";
        }

        private string MapAkmSuite(byte[] data, int offset)
        {
            if (data[offset] == 0x00 && data[offset + 1] == 0x0F && data[offset + 2] == 0xAC)
            {
                return data[offset + 3] switch
                {
                    1 => "WPA2-Enterprise (802.1X)",
                    2 => "WPA2-PSK",
                    3 => "FT-802.1X (802.11r)",
                    4 => "FT-PSK (802.11r)",
                    5 => "WPA2-Enterprise-SHA256",
                    6 => "WPA2-PSK-SHA256",
                    8 => "WPA3-SAE",
                    9 => "FT-SAE (802.11r)",
                    11 => "WPA3-Enterprise (Suite B 192-bit)",
                    18 => "OWE (Enhanced Open)",
                    _ => $"AKM-0x{data[offset + 3]:X2}"
                };
            }
            return "Unknown-AKM";
        }

        private string FormatPhyType(DOT11_PHY_TYPE phyType)
        {
            return phyType switch
            {
                DOT11_PHY_TYPE.dot11_phy_type_dsss => "802.11b (DSSS)",
                DOT11_PHY_TYPE.dot11_phy_type_erp => "802.11g (ERP)",
                DOT11_PHY_TYPE.dot11_phy_type_ofdm => "802.11a (OFDM)",
                DOT11_PHY_TYPE.dot11_phy_type_hrdsss => "802.11b (HR-DSSS)",
                DOT11_PHY_TYPE.dot11_phy_type_ht => "802.11n (Wi-Fi 4)",
                DOT11_PHY_TYPE.dot11_phy_type_vht => "802.11ac (Wi-Fi 5)",
                DOT11_PHY_TYPE.dot11_phy_type_he => "802.11ax (Wi-Fi 6)",
                DOT11_PHY_TYPE.dot11_phy_type_eht => "802.11be (Wi-Fi 7)",
                _ => "802.11ax (Wi-Fi 6)"
            };
        }

        private async Task<List<AccessPoint>> ScanViaNetshCliAsync(CancellationToken cancellationToken = default)
        {
            var accessPoints = new List<AccessPoint>();

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "wlan show networks mode=bssid",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8
                };

                using var proc = Process.Start(psi);
                if (proc == null) return accessPoints;

                string output = await proc.StandardOutput.ReadToEndAsync(cancellationToken);
                await proc.WaitForExitAsync(cancellationToken);

                accessPoints = ParseNetshBssidOutput(output);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NativeWifiService] Netsh CLI parse error: {ex.Message}");
            }

            return accessPoints;
        }

        public List<AccessPoint> ParseNetshBssidOutput(string output)
        {
            var results = new List<AccessPoint>();
            if (string.IsNullOrWhiteSpace(output)) return results;

            output = output.Replace("\\r\\n", "\n").Replace("\\n", "\n").Replace("\r\n", "\n").Replace('\r', '\n');

            // Keep the SSID value in a capture group instead of splitting on the
            // label. A hidden network has an empty value after "SSID n :"; split
            // based parsing then accidentally used "Network type" as its name.
            var networkBlocks = Regex.Matches(
                output,
                @"(?ms)^[ \t]*SSID[ \t]+\d+[ \t]*:[ \t]*(?<ssid>[^\r\n]*)(?<body>.*?)(?=^[ \t]*SSID[ \t]+\d+[ \t]*:|\z)");

            foreach (Match networkBlock in networkBlocks)
            {
                string block = networkBlock.Groups["body"].Value;
                string ssid = networkBlock.Groups["ssid"].Value.Trim();
                bool isHidden = string.IsNullOrEmpty(ssid);
                if (isHidden) ssid = "[Hidden SSID]";

                string auth = "Open";
                string cipher = "None";

                var authMatch = Regex.Match(block, @"Authentication\s*:\s*([^\r\n]+)");
                if (authMatch.Success) auth = authMatch.Groups[1].Value.Trim();

                var cipherMatch = Regex.Match(block, @"Encryption\s*:\s*([^\r\n]+)");
                if (cipherMatch.Success) cipher = cipherMatch.Groups[1].Value.Trim();

                var bssidBlocks = Regex.Split(block, @"\bBSSID\s+\d+\s*:\s*");
                for (int bIdx = 1; bIdx < bssidBlocks.Length; bIdx++)
                {
                    string bssidChunk = bssidBlocks[bIdx];
                    var macMatch = Regex.Match(bssidChunk, @"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})");
                    if (!macMatch.Success) continue;

                    string bssid = macMatch.Groups[1].Value.ToUpper().Replace("-", ":");

                    uint quality = 50;
                    var sigMatch = Regex.Match(bssidChunk, @"Signal\s*:\s*(\d+)%");
                    if (sigMatch.Success && uint.TryParse(sigMatch.Groups[1].Value, out var q)) quality = q;

                    string radio = "802.11ac";
                    var radioMatch = Regex.Match(bssidChunk, @"Radio type\s*:\s*([^\r\n]+)");
                    if (radioMatch.Success) radio = radioMatch.Groups[1].Value.Trim();

                    int channel = 6;
                    var chMatch = Regex.Match(bssidChunk, @"Channel\s*:\s*(\d+)");
                    if (chMatch.Success && int.TryParse(chMatch.Groups[1].Value, out var ch)) channel = ch;

                    // Windows signal % to dBm: RSSI = (Signal / 2) - 100
                    int rssi = (int)(quality / 2) - 100;
                    string band = channel <= 14 ? "2.4 GHz" : (channel <= 177 ? "5 GHz" : "6 GHz");

                    var ap = new AccessPoint
                    {
                        Bssid = bssid,
                        Ssid = ssid,
                        IsHidden = isHidden,
                        Channel = channel,
                        Band = band,
                        FrequencyMHz = channel <= 14 ? 2407 + channel * 5 : 5000 + channel * 5,
                        Rssi = rssi,
                        SignalQuality = quality,
                        Security = auth,
                        Cipher = cipher,
                        PhyType = radio,
                        ChannelWidth = 20,
                        FirstSeen = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                        LastSeen = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                        LastSeenTime = DateTime.UtcNow,
                        BeaconCount = 1,
                        Vendor = OuiLookupService.ResolveVendor(bssid)
                    };

                    _securityAnalyzer.EvaluateSecurityPosture(ap);
                    results.Add(ap);
                }
            }

            return results;
        }

        private async Task<List<WifiAdapter>> EnumerateNetshAdaptersAsync()
        {
            var adapters = new List<WifiAdapter>();

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "wlan show interfaces",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8
                };

                using var proc = Process.Start(psi);
                if (proc == null) return adapters;

                string output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();

                var nameMatch = Regex.Match(output, @"Name\s*:\s*([^\r\n]+)");
                var descMatch = Regex.Match(output, @"Description\s*:\s*([^\r\n]+)");
                var guidMatch = Regex.Match(output, @"GUID\s*:\s*([^\r\n]+)");
                var macMatch = Regex.Match(output, @"Physical address\s*:\s*([^\r\n]+)");
                var stateMatch = Regex.Match(output, @"State\s*:\s*([^\r\n]+)");

                if (nameMatch.Success)
                {
                    Guid.TryParse(guidMatch.Groups[1].Value.Trim(), out var guid);
                    adapters.Add(new WifiAdapter
                    {
                        Id = guid != Guid.Empty ? guid.ToString() : "netsh-wlan-0",
                        InterfaceGuid = guid,
                        Name = nameMatch.Groups[1].Value.Trim(),
                        Description = descMatch.Success ? descMatch.Groups[1].Value.Trim() : "Windows WLAN Interface",
                        MacAddress = macMatch.Success ? macMatch.Groups[1].Value.Trim().ToUpper() : "00:00:00:00:00:00",
                        Status = stateMatch.Success ? stateMatch.Groups[1].Value.Trim() : "Ready",
                        SupportedBands = new List<string>(),
                        MonitorModeSupported = false,
                        PacketInjectionSupported = false,
                        CurrentChannel = 0,
                        TxPowerDbm = 0
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[NativeWifiService] EnumerateNetshAdaptersAsync error: {ex.Message}");
            }

            return adapters;
        }

        private static List<string> DetectSupportedBands(string description)
        {
            var bands = new List<string> { "2.4 GHz", "5 GHz" };
            string lower = (description ?? string.Empty).ToLowerInvariant();

            if (lower.Contains("6e") || lower.Contains("6-e") || lower.Contains("6 ghz") || 
                lower.Contains("wi-fi 7") || lower.Contains("wifi 7") || lower.Contains("tri-band") ||
                lower.Contains("ax210") || lower.Contains("ax211") || lower.Contains("ax411") ||
                lower.Contains("be200") || lower.Contains("be202") || lower.Contains("mt7922") ||
                lower.Contains("qcnfa765") || lower.Contains("wcn6856"))
            {
                bands.Add("6 GHz");
            }

            if (lower.Contains("single-band") || lower.Contains("2.4ghz only") || 
                (lower.Contains("b/g/n") && !lower.Contains("dual") && !lower.Contains("a/") && !lower.Contains("ac") && !lower.Contains("ax")))
            {
                bands.Remove("5 GHz");
            }

            return bands;
        }

        private bool DetectNpcapMonitorMode()
        {
            try
            {
                return File.Exists(@"C:\Windows\System32\Npcap\wpcap.dll") ||
                       File.Exists(@"C:\Windows\System32\wpcap.dll");
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                _scanLock.Dispose();
            }
            GC.SuppressFinalize(this);
        }
    }
}
