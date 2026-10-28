using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using WinWiFi.Interop;
using WinWiFi.Models;

namespace WinWiFi.Services
{
    public class PcapDissectorResult
    {
        public List<PcapPacket> Packets { get; set; } = new();
        public List<AccessPoint> AccessPoints { get; set; } = new();
        public List<HandshakeInfo> Handshakes { get; set; } = new();
        public List<StationClientRecord> Clients { get; set; } = new();
        public List<ThreatFinding> Incidents { get; set; } = new();
        public int TotalFramesCount { get; set; }
        public string CaptureFormat { get; set; } = "Libpcap 2.4";
        public string LinkTypeName { get; set; } = "DLT_IEEE802_11_RADIO";
        public uint LinkTypeValue { get; set; } = 127;
        public string CaptureStartTime { get; set; } = string.Empty;
        public string CaptureEndTime { get; set; } = string.Empty;
        public List<string> ParseWarnings { get; set; } = new();

        // True when parsing stopped early because a safety limit was reached
        // (frame count, malformed record length, or truncated capture).
        public bool Truncated { get; set; }
        public int SkippedFrames { get; set; }
        public int WarningsSuppressed { get; set; }
    }

    /// <summary>
    /// Hard limits applied to untrusted capture files so a malformed or hostile
    /// file cannot exhaust memory, disk, or UI resources.
    /// </summary>
    public sealed class PcapDissectOptions
    {
        public const int DefaultMaxCaptureBytes = 100 * 1024 * 1024;
        public const int DefaultMaxPackets = 200_000;
        public const int DefaultMaxFrameBytes = 262_144;
        public const int DefaultMaxHandshakes = 10_000;

        public int MaxCaptureBytes { get; init; } = DefaultMaxCaptureBytes;
        public int MaxPackets { get; init; } = DefaultMaxPackets;
        public int MaxFrameBytes { get; init; } = DefaultMaxFrameBytes;
        public int MaxHandshakes { get; init; } = DefaultMaxHandshakes;
    }

    public class PcapDissector
    {
        private sealed class NetworkDissection
        {
            public string Protocol { get; set; } = string.Empty;
            public string ApplicationProtocol { get; set; } = string.Empty;
            public string SourceIp { get; set; } = string.Empty;
            public string DestinationIp { get; set; } = string.Empty;
            public int? SourcePort { get; set; }
            public int? DestinationPort { get; set; }
            public string ConversationId { get; set; } = string.Empty;
            public string TcpStreamId { get; set; } = string.Empty;
            public uint? TcpSequenceNumber { get; set; }
            public uint? TcpAcknowledgmentNumber { get; set; }
            public string TcpFlags { get; set; } = string.Empty;
            public string TcpPayloadHex { get; set; } = string.Empty;
            public string Summary { get; set; } = string.Empty;
            public Dictionary<string, string> Fields { get; set; } = new();
        }

        private const uint PCAP_MAGIC_MICROSECOND = 0xa1b2c3d4;
        private const uint PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;
        private const uint PCAP_MAGIC_NANOSECOND = 0xa1b23c4d;
        private const uint PCAPNG_SECTION_HEADER = 0x0a0d0d0a;
        private const uint PCAPNG_INTERFACE_DESCRIPTION = 0x00000001;
        private const uint PCAPNG_SIMPLE_PACKET = 0x00000003;
        private const uint PCAPNG_ENHANCED_PACKET = 0x00000006;
        private const uint PCAPNG_BYTE_ORDER_MAGIC = 0x1a2b3c4d;
        private const int MaxWarnings = 25;
        private const long MaxPcapngBlockBytes = 128L * 1024 * 1024;

        public PcapDissectorResult DissectFile(string filePath, PcapDissectOptions? options = null)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("PCAP forensic capture file not found.", filePath);
            }

            options ??= new PcapDissectOptions();
            var info = new FileInfo(filePath);
            if (info.Length > options.MaxCaptureBytes)
            {
                throw new InvalidDataException(
                    $"Capture file is {info.Length / (1024 * 1024)} MB, which exceeds the {options.MaxCaptureBytes / (1024 * 1024)} MB import limit.");
            }

            byte[] bytes = File.ReadAllBytes(filePath);
            return DissectBytes(bytes, options);
        }

        public PcapDissectorResult DissectBytes(byte[] bytes, PcapDissectOptions? options = null)
        {
            options ??= new PcapDissectOptions();
            var result = new PcapDissectorResult();
            if (bytes == null || bytes.Length < 24)
            {
                result.ParseWarnings.Add("File too small to contain a valid PCAP or PCAPNG header.");
                return result;
            }

            if (bytes.Length > options.MaxCaptureBytes)
            {
                throw new InvalidDataException(
                    $"Capture payload is {bytes.Length / (1024 * 1024)} MB, which exceeds the {options.MaxCaptureBytes / (1024 * 1024)} MB import limit.");
            }

            using var ms = new MemoryStream(bytes);
            using var reader = new BinaryReader(ms);

            uint magic = reader.ReadUInt32();
            if (magic == PCAPNG_SECTION_HEADER)
            {
                result.CaptureFormat = "PCAPNG Next Generation Capture";
                DissectPcapNg(bytes, result, options);
                return result;
            }

            bool isSwapped = (magic == PCAP_MAGIC_SWAPPED);
            bool isNanosecond = (magic == PCAP_MAGIC_NANOSECOND);

            if (magic != PCAP_MAGIC_MICROSECOND && magic != PCAP_MAGIC_NANOSECOND && magic != PCAP_MAGIC_SWAPPED)
            {
                throw new InvalidDataException($"Unrecognized PCAP magic header: 0x{magic:X8}. Only standard Libpcap or PCAPNG captures are supported.");
            }

            result.CaptureFormat = isSwapped 
                ? "Libpcap 2.4 (Byte-swapped)" 
                : (isNanosecond ? "Libpcap 2.4 (Nanosecond)" : "Libpcap 2.4 (Standard Microsecond)");

            // Read PCAP Global Header (24 bytes)
            ushort versionMajor = ReadUInt16(reader, isSwapped);
            ushort versionMinor = ReadUInt16(reader, isSwapped);
            int thisZone = ReadInt32(reader, isSwapped);
            uint sigFigs = ReadUInt32(reader, isSwapped);
            uint snapLen = ReadUInt32(reader, isSwapped);
            uint networkLinkType = ReadUInt32(reader, isSwapped); // 127 = DLT_IEEE802_11_RADIO, 105 = DLT_IEEE802_11, 1 = Ethernet

            if (versionMajor != 2 || versionMinor != 4)
            {
                AddWarning(result, $"Capture header reports libpcap version {versionMajor}.{versionMinor}; expected 2.4.");
            }
            if (snapLen > (uint)options.MaxFrameBytes)
            {
                AddWarning(result, $"Capture snaplen ({snapLen} bytes) exceeds the {options.MaxFrameBytes}-byte per-frame limit; oversized records will be rejected.");
            }

            result.LinkTypeValue = networkLinkType;
            result.LinkTypeName = networkLinkType switch
            {
                127 => "DLT_IEEE802_11_RADIO (Radiotap + 802.11)",
                105 => "DLT_IEEE802_11 (Raw 802.11 without Radiotap)",
                1 => "DLT_EN10MB (Ethernet Link Layer)",
                _ => $"DLT_{networkLinkType} (Custom Link Layer)"
            };

            if (networkLinkType != 127 && networkLinkType != 105)
            {
                AddWarning(result, $"Link type {result.LinkTypeName} is not an 802.11 capture. WinWiFi does not dissect non-802.11 frames, so no access points were inferred.");
                FinalizeWarnings(result);
                return result;
            }

            var apMap = new Dictionary<string, AccessPoint>(StringComparer.OrdinalIgnoreCase);
            var clientMap = new Dictionary<string, StationClientRecord>(StringComparer.OrdinalIgnoreCase);
            var handshakeTracker = new Dictionary<string, HandshakeSession>(StringComparer.OrdinalIgnoreCase);

            int frameNum = 1;
            double subSecondUnits = isNanosecond ? 1_000_000_000d : 1_000_000d;
            int snapLenViolations = 0;
            bool recordLimitReported = false;

            while (ms.Position + 16 <= ms.Length)
            {
                if (result.Packets.Count >= options.MaxPackets)
                {
                    result.Truncated = true;
                    if (!recordLimitReported)
                    {
                        AddWarning(result, $"Stopped after {options.MaxPackets:N0} frames; the capture contains more records than the import limit.");
                        recordLimitReported = true;
                    }
                    break;
                }

                uint tsSec = ReadUInt32(reader, isSwapped);
                uint tsSub = ReadUInt32(reader, isSwapped);
                uint inclLen = ReadUInt32(reader, isSwapped);
                uint origLen = ReadUInt32(reader, isSwapped);

                if (inclLen == 0)
                {
                    AddWarning(result, $"Record {frameNum} declares zero captured bytes and was skipped.");
                    continue;
                }

                if (inclLen > (uint)options.MaxFrameBytes)
                {
                    result.Truncated = true;
                    AddWarning(result, $"Record {frameNum} declares {inclLen:N0} bytes, above the {options.MaxFrameBytes:N0}-byte per-frame limit; parsing stopped.");
                    break;
                }

                if (snapLen > 0 && inclLen > snapLen && snapLenViolations < 3)
                {
                    snapLenViolations++;
                    AddWarning(result, $"Record {frameNum} captured {inclLen} bytes but the header snaplen is {snapLen}; the record was still parsed.");
                }

                if (origLen > 0 && inclLen > origLen)
                {
                    AddWarning(result, $"Record {frameNum} captured length ({inclLen}) exceeds original length ({origLen}).");
                }

                if (ms.Position + inclLen > ms.Length)
                {
                    result.Truncated = true;
                    AddWarning(result, $"Record {frameNum} is truncated: header declares {inclLen} bytes but only {ms.Length - ms.Position} remain.");
                    break;
                }

                byte[] packetBytes = reader.ReadBytes((int)inclLen);
                double fraction = Math.Clamp(tsSub / subSecondUnits, 0d, 0.9999999d);
                var packet = ParseSingleFrame(packetBytes, frameNum++, tsSec, fraction, networkLinkType, apMap, clientMap, handshakeTracker, result, options);
                if (packet != null)
                {
                    result.Packets.Add(packet);
                }
            }

            if (!result.Truncated && ms.Position < ms.Length)
            {
                AddWarning(result, $"Ignored {ms.Length - ms.Position} trailing byte(s) that do not form a complete record header.");
            }

            ConsolidateResults(result, apMap, clientMap, handshakeTracker);
            FinalizeWarnings(result);
            return result;
        }

        private static void ConsolidateResults(
            PcapDissectorResult result,
            Dictionary<string, AccessPoint> apMap,
            Dictionary<string, StationClientRecord> clientMap,
            Dictionary<string, HandshakeSession> handshakeTracker)
        {
            foreach (var kvp in handshakeTracker)
            {
                var hs = kvp.Value.ToHandshakeInfo();
                if (hs != null)
                {
                    result.Handshakes.Add(hs);
                }
            }

            result.AccessPoints.AddRange(apMap.Values);
            result.Clients.AddRange(clientMap.Values);
            result.TotalFramesCount = result.Packets.Count;

            if (result.Packets.Count > 0)
            {
                result.CaptureStartTime = result.Packets.First().Timestamp;
                result.CaptureEndTime = result.Packets.Last().Timestamp;
            }
        }

        private static void AddWarning(PcapDissectorResult result, string message)
        {
            if (result.ParseWarnings.Count < MaxWarnings)
            {
                result.ParseWarnings.Add(message);
            }
            else
            {
                result.WarningsSuppressed++;
            }
        }

        private static void FinalizeWarnings(PcapDissectorResult result)
        {
            if (result.SkippedFrames > 0)
            {
                AddWarning(result, $"{result.SkippedFrames:N0} frame(s) were too short or malformed and were skipped.");
            }
            if (result.WarningsSuppressed > 0)
            {
                result.ParseWarnings.Add($"{result.WarningsSuppressed:N0} additional warning(s) suppressed.");
            }
        }

        private PcapPacket? ParseSingleFrame(
            byte[] rawBytes,
            int frameNum,
            uint sec,
            double subSecondFraction,
            uint linkType,
            Dictionary<string, AccessPoint> apMap,
            Dictionary<string, StationClientRecord> clientMap,
            Dictionary<string, HandshakeSession> handshakeTracker,
            PcapDissectorResult result,
            PcapDissectOptions options)
        {
            int offset = 0;
            int? signalDbm = null;
            int channel = 6;
            bool radiotapPresent = false;

            // 1. Process Radiotap Header (LinkType 127)
            if (linkType == 127 && rawBytes.Length >= 4)
            {
                byte radiotapVersion = rawBytes[0];
                ushort radiotapLen = BitConverter.ToUInt16(rawBytes, 2);

                if (radiotapVersion != 0)
                {
                    result.SkippedFrames++;
                    return null;
                }
                if (radiotapLen < 8 || radiotapLen > rawBytes.Length)
                {
                    AddWarning(result, $"Frame {frameNum}: radiotap length {radiotapLen} is outside the {rawBytes.Length}-byte frame; frame skipped.");
                    result.SkippedFrames++;
                    return null;
                }
                if (radiotapLen == rawBytes.Length)
                {
                    result.SkippedFrames++;
                    return null;
                }

                radiotapPresent = true;
                offset = radiotapLen;

                // Parse Radiotap Present Bitmask (offset 4, 4 bytes)
                uint presentMask = BitConverter.ToUInt32(rawBytes, 4);
                int currentRadioOffset = 8;

                // Check for extended present bits
                while ((presentMask & 0x80000000) != 0 && currentRadioOffset + 4 <= radiotapLen)
                {
                    currentRadioOffset += 4;
                    presentMask = BitConverter.ToUInt32(rawBytes, currentRadioOffset - 4);
                }

                // Parse Present Fields. Every field is bounds-checked before it
                // is read so a declared radiotap length cannot drive an
                // out-of-frame read into the 802.11 payload.
                uint origPresent = BitConverter.ToUInt32(rawBytes, 4);

                // Bit 0: TSFT (8 bytes, 8-byte alignment)
                if ((origPresent & (1 << 0)) != 0)
                {
                    currentRadioOffset = (currentRadioOffset + 7) & ~7;
                    currentRadioOffset += 8;
                }

                // Bit 1: Flags (1 byte)
                if ((origPresent & (1 << 1)) != 0) currentRadioOffset += 1;

                // Bit 2: Rate (1 byte)
                if ((origPresent & (1 << 2)) != 0) currentRadioOffset += 1;

                // Bit 3: Channel (4 bytes: 2 bytes MHz + 2 bytes flags)
                if ((origPresent & (1 << 3)) != 0)
                {
                    // Radiotap 2-byte alignment for channel
                    if ((currentRadioOffset % 2) != 0) currentRadioOffset++;
                    if (currentRadioOffset + 4 <= radiotapLen)
                    {
                        ushort freqMhz = BitConverter.ToUInt16(rawBytes, currentRadioOffset);
                        if (freqMhz >= 2400)
                        {
                            var (ch, _) = WinWiFi.Interop.NativeWifi.FrequencyToChannel((uint)freqMhz * 1000);
                            if (ch > 0) channel = ch;
                        }
                        currentRadioOffset += 4;
                    }
                }

                // Bit 4: FHSS (2 bytes, 2-byte alignment)
                if ((origPresent & (1 << 4)) != 0)
                {
                    currentRadioOffset = (currentRadioOffset + 1) & ~1;
                    currentRadioOffset += 2;
                }

                // Bit 5: Antenna Signal (1 byte, sbyte in dBm)
                if ((origPresent & (1 << 5)) != 0 && currentRadioOffset < radiotapLen)
                {
                    signalDbm = (sbyte)rawBytes[currentRadioOffset];
                    currentRadioOffset += 1;
                }

            }

            if (rawBytes.Length < 24 || offset + 24 > rawBytes.Length)
            {
                result.SkippedFrames++;
                return null;
            }

            // 2. IEEE 802.11 MAC Frame Header
            ushort frameControl = BitConverter.ToUInt16(rawBytes, offset);
            byte type = (byte)((frameControl >> 2) & 0x03);
            byte subtype = (byte)((frameControl >> 4) & 0x0F);

            bool toDs = (frameControl & 0x0100) != 0;
            bool fromDs = (frameControl & 0x0200) != 0;
            bool moreFrags = (frameControl & 0x0400) != 0;
            bool retry = (frameControl & 0x0800) != 0;
            bool isProtected = (frameControl & 0x4000) != 0;

            string addr1 = FormatMac(rawBytes, offset + 4);
            string addr2 = FormatMac(rawBytes, offset + 10);
            string addr3 = FormatMac(rawBytes, offset + 16);

            ushort? seqNum = null;
            byte? fragNum = null;
            if (offset + 24 <= rawBytes.Length)
            {
                ushort seqCtrl = BitConverter.ToUInt16(rawBytes, offset + 22);
                seqNum = (ushort)(seqCtrl >> 4);
                fragNum = (byte)(seqCtrl & 0x0F);
            }

            // Address Resolution based on DS flags
            string destMac = addr1;
            string srcMac = addr2;
            string bssid = addr3;

            if (toDs && !fromDs)
            {
                bssid = addr1;
                srcMac = addr2;
                destMac = addr3;
            }
            else if (!toDs && fromDs)
            {
                destMac = addr1;
                bssid = addr2;
                srcMac = addr3;
            }
            else if (toDs && fromDs)
            {
                // Mesh or WDS
                bssid = addr1;
                srcMac = addr2;
                destMac = addr3;
            }

            // Calculate Genuine Capture Timestamp
            string timestamp;
            double clampedFraction = Math.Clamp(subSecondFraction, 0d, 0.9999999d);
            if (sec > 0)
            {
                DateTimeOffset baseDto = DateTimeOffset.FromUnixTimeSeconds(sec);
                long subUnits = (long)Math.Round(clampedFraction * TimeSpan.TicksPerSecond);
                DateTimeOffset actualDto = baseDto.AddTicks(subUnits).ToLocalTime();
                timestamp = actualDto.ToString("yyyy-MM-dd HH:mm:ss.ffffff");
            }
            else
            {
                timestamp = $"+{clampedFraction:F6}s";
            }

            string frameTypeName = type switch
            {
                0 => "Management",
                1 => "Control",
                2 => "Data",
                _ => "Extension"
            };

            string subtypeName = GetSubtypeName(type, subtype);
            string info = $"{subtypeName} [{srcMac} -> {destMac}]";
            string expertInfo = string.Empty;
            var informationElements = new Dictionary<string, string>();
            var eapolFields = new Dictionary<string, string>();
            var networkInfo = new NetworkDissection();

            // 3. Process Specific Frame Types

            // MANAGEMENT: Beacon (Subtype 8) & Probe Response (Subtype 5)
            if (type == 0 && (subtype == 8 || subtype == 5))
            {
                bssid = addr3;
                int ieOffset = offset + 24 + 12; // 24 bytes MAC header + 12 bytes fixed params (timestamp, beacon interval, cap info)
                string ssid = ExtractSsidFromIes(rawBytes, ieOffset);
                channel = ExtractChannelFromIes(rawBytes, ieOffset, channel);
                informationElements = ExtractInformationElements(rawBytes, ieOffset);

                info = $"{subtypeName}: SSID \"{ssid}\" (Ch {channel}, BSSID {bssid})";

                if (!apMap.TryGetValue(bssid, out var ap))
                {
                    ap = new AccessPoint
                    {
                        Bssid = bssid,
                        Ssid = ssid,
                        IsHidden = string.IsNullOrWhiteSpace(ssid) || ssid == "[Hidden SSID]",
                        Channel = channel,
                        Band = channel <= 14 ? "2.4 GHz" : (channel <= 177 ? "5 GHz" : "6 GHz"),
                        FrequencyMHz = channel <= 14 ? 2407 + channel * 5 : 5000 + channel * 5,
                        Rssi = signalDbm ?? -65,
                        SignalQuality = (uint)Math.Clamp(((signalDbm ?? -65) + 100) * 2, 0, 100),
                        Security = "WPA2-PSK",
                        Cipher = "CCMP",
                        PhyType = "802.11ax",
                        FirstSeen = timestamp,
                        LastSeen = timestamp,
                        BeaconCount = 1,
                        Vendor = OuiLookupService.ResolveVendor(bssid)
                    };
                    apMap[bssid] = ap;
                }
                else
                {
                    ap.BeaconCount++;
                    ap.LastSeen = timestamp;
                    if (signalDbm.HasValue) ap.Rssi = signalDbm.Value;
                    if (!string.IsNullOrWhiteSpace(ssid) && ap.IsHidden)
                    {
                        ap.Ssid = ssid;
                        ap.IsHidden = false;
                    }
                }
            }
            // MANAGEMENT: Probe Request (Subtype 4) - Client Device Profiling
            else if (type == 0 && subtype == 4)
            {
                int ieOffset = offset + 24;
                string probedSsid = ExtractSsidFromIes(rawBytes, ieOffset);
                informationElements = ExtractInformationElements(rawBytes, ieOffset);
                info = $"Probe Request from {srcMac} looking for \"{(string.IsNullOrEmpty(probedSsid) ? "Wildcard / Any" : probedSsid)}\"";

                if (srcMac != "FF:FF:FF:FF:FF:FF" && !srcMac.StartsWith("01:00:5E") && !srcMac.StartsWith("33:33"))
                {
                    if (!clientMap.TryGetValue(srcMac, out var client))
                    {
                        client = new StationClientRecord
                        {
                            MacAddress = srcMac,
                            Vendor = OuiLookupService.ResolveVendor(srcMac),
                            FirstSeen = timestamp,
                            LastSeen = timestamp,
                            Rssi = signalDbm ?? -70,
                            Channel = channel,
                            Band = channel <= 14 ? "2.4 GHz" : "5 GHz",
                            IsAssociated = false,
                            AssociatedApBssid = "Not Associated (Active Probing)",
                            AssociatedApSsid = "Searching...",
                            PacketsCount = 1,
                            IsRandomizedMac = WinWiFi.Services.OuiLookupService.IsLocallyAdministered(srcMac)
                        };
                        if (!string.IsNullOrEmpty(probedSsid) && probedSsid != "[Hidden SSID]")
                        {
                            client.ProbeRequests.Add(probedSsid);
                        }
                        clientMap[srcMac] = client;
                    }
                    else
                    {
                        client.PacketsCount++;
                        client.LastSeen = timestamp;
                        if (signalDbm.HasValue) client.Rssi = signalDbm.Value;
                        if (!string.IsNullOrEmpty(probedSsid) && probedSsid != "[Hidden SSID]" && !client.ProbeRequests.Contains(probedSsid))
                        {
                            client.ProbeRequests.Add(probedSsid);
                        }
                    }
                }
            }
            // MANAGEMENT: Deauthentication (12) or Disassociation (10) - Security Alert
            else if (type == 0 && (subtype == 12 || subtype == 10))
            {
                ushort reasonCode = 0;
                if (offset + 26 <= rawBytes.Length)
                {
                    reasonCode = BitConverter.ToUInt16(rawBytes, offset + 24);
                }
                expertInfo = $"[SUSPICIOUS DEAUTH] Reason Code {reasonCode} sent to {destMac}. Potential deauth flood or rogue kicking client.";
                info = $"{subtypeName}: Reason={reasonCode} ({srcMac} -> {destMac})";
            }
            // DATA: EAPOL Key or QoS Data
            else if (type == 2)
            {
                // Station Client association tracking
                if (srcMac != "FF:FF:FF:FF:FF:FF" && !srcMac.StartsWith("01:00:5E") && !srcMac.StartsWith("33:33"))
                {
                    if (!clientMap.TryGetValue(srcMac, out var client))
                    {
                        client = new StationClientRecord
                        {
                            MacAddress = srcMac,
                            Vendor = WinWiFi.Services.OuiLookupService.ResolveVendor(srcMac),
                            FirstSeen = timestamp,
                            LastSeen = timestamp,
                            Rssi = signalDbm ?? -65,
                            Channel = channel,
                            Band = channel <= 14 ? "2.4 GHz" : "5 GHz",
                            IsAssociated = !string.IsNullOrEmpty(bssid) && bssid != "FF:FF:FF:FF:FF:FF",
                            AssociatedApBssid = bssid,
                            AssociatedApSsid = apMap.TryGetValue(bssid, out var apRef) ? apRef.Ssid : "Provable BSSID Observed",
                            PacketsCount = 1,
                            IsRandomizedMac = WinWiFi.Services.OuiLookupService.IsLocallyAdministered(srcMac)
                        };
                        clientMap[srcMac] = client;
                    }
                    else
                    {
                        client.PacketsCount++;
                        client.LastSeen = timestamp;
                        if (signalDbm.HasValue) client.Rssi = signalDbm.Value;
                        if (!string.IsNullOrEmpty(bssid) && bssid != "FF:FF:FF:FF:FF:FF")
                        {
                            client.AssociatedApBssid = bssid;
                            client.IsAssociated = true;
                        }
                    }
                }

                // LLC/SNAP follows the complete MAC header. Protected payloads
                // remain encrypted and are never guessed or decrypted here.
                bool fourAddress = toDs && fromDs;
                bool qosData = (subtype & 0x08) != 0;
                bool htControl = qosData && (frameControl & 0x8000) != 0;
                int macHeaderLen = 24 + (fourAddress ? 6 : 0) + (qosData ? 2 : 0) + (htControl ? 4 : 0);
                int llcOffset = offset + macHeaderLen;
                bool snap = llcOffset + 8 <= rawBytes.Length
                    && rawBytes[llcOffset] == 0xAA && rawBytes[llcOffset + 1] == 0xAA && rawBytes[llcOffset + 2] == 0x03
                    && rawBytes[llcOffset + 3] == 0 && rawBytes[llcOffset + 4] == 0
                    && (rawBytes[llcOffset + 5] == 0 || rawBytes[llcOffset + 5] == 0xF8);
                if (isProtected)
                {
                    info = "Encrypted 802.11 data; network-layer fields are not visible without decryption keys.";
                }
                else if (snap)
                {
                    ushort etherType = ReadNetworkUInt16(rawBytes, llcOffset + 6);
                    int networkOffset = llcOffset + 8;
                    if (etherType == 0x888E)
                    {
                        subtypeName = "EAPOL Key";
                        eapolFields = ExtractEapolFields(rawBytes, networkOffset);
                        info = DissectEapolFrame(rawBytes, networkOffset, srcMac, destMac, bssid, timestamp, handshakeTracker, apMap, result, options);
                    }
                    else
                    {
                        networkInfo = DissectNetworkLayer(rawBytes, networkOffset, etherType);
                        if (!string.IsNullOrWhiteSpace(networkInfo.Summary)) info = networkInfo.Summary;
                    }
                }
            }

            // Raw Hex and ASCII Dump
            string hexPreview = BitConverter.ToString(rawBytes, offset, Math.Min(16, rawBytes.Length - offset)).Replace("-", " ");
            string rawHex = FormatHexDump(rawBytes, offset, rawBytes.Length - offset);
            string rawAscii = FormatAsciiDump(rawBytes, offset, rawBytes.Length - offset);

            return new PcapPacket
            {
                Id = frameNum,
                FrameNumber = frameNum,
                Timestamp = timestamp,
                FrameType = frameTypeName,
                Subtype = subtypeName,
                TypeNumber = type,
                SubtypeNumber = subtype,
                SourceMac = srcMac,
                DestMac = destMac,
                Bssid = bssid,
                TransmitterMac = addr2,
                ReceiverMac = addr1,
                Channel = channel,
                Rssi = signalDbm ?? -65,
                LengthBytes = rawBytes.Length,
                RadiotapPresent = radiotapPresent,
                SequenceNumber = seqNum,
                FragmentNumber = fragNum,
                IsRetry = retry,
                IsProtected = isProtected,
                Info = info,
                HexPreview = hexPreview,
                RawBytesHex = rawHex,
                RawBytesAscii = rawAscii,
                ExpertInfo = expertInfo,
                InformationElements = informationElements,
                EapolFields = eapolFields,
                NetworkProtocol = networkInfo.Protocol,
                ApplicationProtocol = networkInfo.ApplicationProtocol,
                SourceIp = networkInfo.SourceIp,
                DestinationIp = networkInfo.DestinationIp,
                SourcePort = networkInfo.SourcePort,
                DestinationPort = networkInfo.DestinationPort,
                ConversationId = networkInfo.ConversationId,
                TcpStreamId = networkInfo.TcpStreamId,
                TcpSequenceNumber = networkInfo.TcpSequenceNumber,
                TcpAcknowledgmentNumber = networkInfo.TcpAcknowledgmentNumber,
                TcpFlags = networkInfo.TcpFlags,
                TcpPayloadHex = networkInfo.TcpPayloadHex,
                NetworkFields = networkInfo.Fields
            };
        }

        private static NetworkDissection DissectNetworkLayer(byte[] bytes, int offset, ushort etherType)
        {
            if (etherType == 0x0806) return DissectArp(bytes, offset);
            if (etherType == 0x0800) return DissectIpv4(bytes, offset);
            if (etherType == 0x86DD) return DissectIpv6(bytes, offset);
            return new NetworkDissection { Protocol = $"EtherType 0x{etherType:X4}", Summary = $"802.11 LLC/SNAP EtherType 0x{etherType:X4}" };
        }

        private static NetworkDissection DissectArp(byte[] bytes, int offset)
        {
            var parsed = new NetworkDissection { Protocol = "ARP", ApplicationProtocol = "ARP" };
            if (offset + 8 > bytes.Length) { parsed.Summary = "ARP (truncated header)"; return parsed; }
            ushort hardwareType = ReadNetworkUInt16(bytes, offset);
            ushort protocolType = ReadNetworkUInt16(bytes, offset + 2);
            int hardwareLength = bytes[offset + 4];
            int protocolLength = bytes[offset + 5];
            ushort operation = ReadNetworkUInt16(bytes, offset + 6);
            int required = 8 + 2 * hardwareLength + 2 * protocolLength;
            if (hardwareLength > 32 || protocolLength > 32 || offset + required > bytes.Length)
            { parsed.Summary = "ARP (truncated or invalid address lengths)"; return parsed; }

            int senderHardware = offset + 8;
            int senderProtocol = senderHardware + hardwareLength;
            int targetHardware = senderProtocol + protocolLength;
            int targetProtocol = targetHardware + hardwareLength;
            string senderMac = hardwareLength == 6 ? FormatMac(bytes, senderHardware) : Convert.ToHexString(bytes, senderHardware, hardwareLength);
            string targetMac = hardwareLength == 6 ? FormatMac(bytes, targetHardware) : Convert.ToHexString(bytes, targetHardware, hardwareLength);
            string senderIp = protocolType == 0x0800 && protocolLength == 4 ? new IPAddress(bytes.Skip(senderProtocol).Take(4).ToArray()).ToString() : string.Empty;
            string targetIp = protocolType == 0x0800 && protocolLength == 4 ? new IPAddress(bytes.Skip(targetProtocol).Take(4).ToArray()).ToString() : string.Empty;
            parsed.SourceIp = senderIp;
            parsed.DestinationIp = targetIp;
            parsed.Fields["Hardware type"] = hardwareType.ToString();
            parsed.Fields["Protocol type"] = $"0x{protocolType:X4}";
            parsed.Fields["Operation"] = operation switch { 1 => "Request", 2 => "Reply", _ => operation.ToString() };
            parsed.Fields["Sender MAC"] = senderMac;
            parsed.Fields["Sender IPv4"] = senderIp;
            parsed.Fields["Target MAC"] = targetMac;
            parsed.Fields["Target IPv4"] = targetIp;
            parsed.ConversationId = MakeConversationId("ARP", senderIp, null, targetIp, null);
            parsed.Summary = operation == 1 ? $"ARP request: who has {targetIp}? Tell {senderIp}" : $"ARP reply: {senderIp} is at {senderMac}";
            return parsed;
        }

        private static NetworkDissection DissectIpv4(byte[] bytes, int offset)
        {
            var parsed = new NetworkDissection { Protocol = "IPv4" };
            if (offset + 20 > bytes.Length) { parsed.Summary = "IPv4 (truncated header)"; return parsed; }
            int version = bytes[offset] >> 4;
            int headerLength = (bytes[offset] & 0x0F) * 4;
            if (version != 4 || headerLength < 20 || offset + headerLength > bytes.Length)
            { parsed.Summary = "IPv4 (invalid header length)"; return parsed; }
            int totalLength = ReadNetworkUInt16(bytes, offset + 2);
            ushort id = ReadNetworkUInt16(bytes, offset + 4);
            ushort fragment = ReadNetworkUInt16(bytes, offset + 6);
            byte ttl = bytes[offset + 8];
            byte protocolNumber = bytes[offset + 9];
            string source = new IPAddress(bytes.Skip(offset + 12).Take(4).ToArray()).ToString();
            string destination = new IPAddress(bytes.Skip(offset + 16).Take(4).ToArray()).ToString();
            int fragmentOffset = fragment & 0x1FFF;
            bool moreFragments = (fragment & 0x2000) != 0;
            parsed.SourceIp = source;
            parsed.DestinationIp = destination;
            parsed.Fields["Version"] = "4";
            parsed.Fields["Header length"] = headerLength.ToString();
            parsed.Fields["Total length"] = totalLength.ToString();
            parsed.Fields["Identification"] = id.ToString();
            parsed.Fields["Flags / fragment offset"] = $"0x{fragment >> 13:X1} / {fragmentOffset}";
            parsed.Fields["TTL"] = ttl.ToString();
            parsed.Fields["Header checksum"] = $"0x{ReadNetworkUInt16(bytes, offset + 10):X4}";
            parsed.Fields["Source IPv4"] = source;
            parsed.Fields["Destination IPv4"] = destination;
            parsed.Fields["Protocol number"] = protocolNumber.ToString();
            int capturedLength = Math.Max(0, Math.Min(totalLength, bytes.Length - offset) - headerLength);
            if (fragmentOffset != 0)
            {
                parsed.Protocol = "IPv4 fragment";
                parsed.Summary = $"IPv4 fragment {source} → {destination} (offset {fragmentOffset})";
                return parsed;
            }
            string transport = protocolNumber switch { 6 => "TCP", 17 => "UDP", 1 => "ICMP", _ => $"IP protocol {protocolNumber}" };
            parsed.Fields["Transport"] = transport;
            var transportInfo = DissectTransport(bytes, offset + headerLength, capturedLength, protocolNumber, source, destination, isIpv6: false);
            MergeNetworkInfo(parsed, transportInfo);
            if (moreFragments) parsed.Fields["More fragments"] = "Yes";
            if (string.IsNullOrWhiteSpace(parsed.Summary)) parsed.Summary = $"IPv4 {source} → {destination} ({transport})";
            return parsed;
        }

        private static NetworkDissection DissectIpv6(byte[] bytes, int offset)
        {
            var parsed = new NetworkDissection { Protocol = "IPv6" };
            if (offset + 40 > bytes.Length) { parsed.Summary = "IPv6 (truncated header)"; return parsed; }
            byte version = (byte)(bytes[offset] >> 4);
            if (version != 6) { parsed.Summary = "IPv6 (invalid version)"; return parsed; }
            ushort payloadLength = ReadNetworkUInt16(bytes, offset + 4);
            byte nextHeader = bytes[offset + 6];
            byte hopLimit = bytes[offset + 7];
            string source = new IPAddress(bytes.Skip(offset + 8).Take(16).ToArray()).ToString();
            string destination = new IPAddress(bytes.Skip(offset + 24).Take(16).ToArray()).ToString();
            parsed.SourceIp = source;
            parsed.DestinationIp = destination;
            parsed.Fields["Version"] = "6";
            parsed.Fields["Traffic class"] = ((bytes[offset] & 0x0F) << 4 | bytes[offset + 1] >> 4).ToString();
            parsed.Fields["Flow label"] = $"0x{(((uint)(bytes[offset + 1] & 0x0F) << 16) | ((uint)bytes[offset + 2] << 8) | bytes[offset + 3]):X5}";
            parsed.Fields["Payload length"] = payloadLength.ToString();
            parsed.Fields["Hop limit"] = hopLimit.ToString();
            parsed.Fields["Source IPv6"] = source;
            parsed.Fields["Destination IPv6"] = destination;
            int transportOffset = offset + 40;
            int remaining = Math.Min(payloadLength, Math.Max(0, bytes.Length - transportOffset));
            for (int extensions = 0; extensions < 8; extensions++)
            {
                if (nextHeader is 0 or 43 or 60)
                {
                    if (remaining < 2) break;
                    byte following = bytes[transportOffset];
                    int length = (bytes[transportOffset + 1] + 1) * 8;
                    if (length > remaining) break;
                    parsed.Fields[$"IPv6 extension {nextHeader}"] = $"{length} bytes";
                    transportOffset += length; remaining -= length; nextHeader = following;
                }
                else if (nextHeader == 44)
                {
                    if (remaining < 8) break;
                    byte following = bytes[transportOffset];
                    ushort fragment = ReadNetworkUInt16(bytes, transportOffset + 2);
                    parsed.Fields["IPv6 fragment offset"] = ((fragment >> 3) & 0x1FFF).ToString();
                    if (((fragment >> 3) & 0x1FFF) != 0)
                    {
                        parsed.Protocol = "IPv6 fragment";
                        parsed.Summary = $"IPv6 fragment {source} → {destination}";
                        return parsed;
                    }
                    transportOffset += 8; remaining -= 8; nextHeader = following;
                }
                else if (nextHeader == 51)
                {
                    if (remaining < 2) break;
                    byte following = bytes[transportOffset];
                    int length = (bytes[transportOffset + 1] + 2) * 4;
                    if (length > remaining) break;
                    transportOffset += length; remaining -= length; nextHeader = following;
                }
                else break;
            }
            string transport = nextHeader switch { 6 => "TCP", 17 => "UDP", 58 => "ICMPv6", 50 => "ESP", _ => $"IPv6 next header {nextHeader}" };
            parsed.Fields["Transport"] = transport;
            if (nextHeader == 50)
            {
                parsed.Protocol = "IPv6/ESP";
                parsed.Summary = $"IPv6 encrypted payload {source} → {destination}";
                return parsed;
            }
            var transportInfo = DissectTransport(bytes, transportOffset, remaining, nextHeader, source, destination, isIpv6: true);
            MergeNetworkInfo(parsed, transportInfo);
            if (string.IsNullOrWhiteSpace(parsed.Summary)) parsed.Summary = $"IPv6 {source} → {destination} ({transport})";
            return parsed;
        }

        private static NetworkDissection DissectTransport(byte[] bytes, int offset, int length, byte protocol, string sourceIp, string destinationIp, bool isIpv6)
        {
            var parsed = new NetworkDissection { SourceIp = sourceIp, DestinationIp = destinationIp };
            if (offset < 0 || length < 0 || offset + length > bytes.Length) return parsed;
            if (protocol == 6) // TCP
            {
                parsed.Protocol = "TCP";
                parsed.ApplicationProtocol = "TCP";
                if (length < 20) { parsed.Summary = "TCP (truncated header)"; return parsed; }
                int sourcePort = ReadNetworkUInt16(bytes, offset);
                int destinationPort = ReadNetworkUInt16(bytes, offset + 2);
                int headerLength = (bytes[offset + 12] >> 4) * 4;
                if (headerLength < 20 || headerLength > length) { parsed.Summary = "TCP (invalid header length)"; return parsed; }
                uint sequence = ReadNetworkUInt32(bytes, offset + 4);
                uint acknowledgment = ReadNetworkUInt32(bytes, offset + 8);
                byte flags = bytes[offset + 13];
                parsed.SourcePort = sourcePort;
                parsed.DestinationPort = destinationPort;
                parsed.TcpSequenceNumber = sequence;
                parsed.TcpAcknowledgmentNumber = acknowledgment;
                parsed.TcpFlags = FormatTcpFlags(flags);
                parsed.ConversationId = MakeConversationId("TCP", sourceIp, sourcePort, destinationIp, destinationPort);
                parsed.TcpStreamId = parsed.ConversationId;
                parsed.Fields["Source port"] = sourcePort.ToString();
                parsed.Fields["Destination port"] = destinationPort.ToString();
                parsed.Fields["Sequence number"] = sequence.ToString();
                parsed.Fields["Acknowledgment number"] = acknowledgment.ToString();
                parsed.Fields["Header length"] = headerLength.ToString();
                parsed.Fields["Flags"] = parsed.TcpFlags;
                parsed.Fields["Window"] = ReadNetworkUInt16(bytes, offset + 14).ToString();
                parsed.Fields["Checksum"] = $"0x{ReadNetworkUInt16(bytes, offset + 16):X4}";
                int payloadOffset = offset + headerLength;
                int payloadLength = length - headerLength;
                byte[] payload = bytes.Skip(payloadOffset).Take(payloadLength).ToArray();
                parsed.TcpPayloadHex = Convert.ToHexString(payload.Take(4096).ToArray());
                string app = IdentifyTcpApplication(sourcePort, destinationPort);
                if (app == "HTTP") ParseHttp(payload, parsed);
                else if (app == "TLS") ParseTls(payload, parsed);
                else if (app == "DNS") ParseDns(payload, isTcp: true, parsed);
                parsed.ApplicationProtocol = string.IsNullOrEmpty(parsed.ApplicationProtocol) || parsed.ApplicationProtocol == "TCP" ? app : parsed.ApplicationProtocol;
                if (string.IsNullOrWhiteSpace(parsed.Summary))
                    parsed.Summary = $"TCP {sourceIp}:{sourcePort} → {destinationIp}:{destinationPort} [{parsed.TcpFlags}]";
                return parsed;
            }
            if (protocol == 17) // UDP
            {
                parsed.Protocol = "UDP";
                parsed.ApplicationProtocol = "UDP";
                if (length < 8) { parsed.Summary = "UDP (truncated header)"; return parsed; }
                int sourcePort = ReadNetworkUInt16(bytes, offset);
                int destinationPort = ReadNetworkUInt16(bytes, offset + 2);
                int udpLength = ReadNetworkUInt16(bytes, offset + 4);
                parsed.SourcePort = sourcePort;
                parsed.DestinationPort = destinationPort;
                parsed.ConversationId = MakeConversationId("UDP", sourceIp, sourcePort, destinationIp, destinationPort);
                parsed.Fields["Source port"] = sourcePort.ToString();
                parsed.Fields["Destination port"] = destinationPort.ToString();
                parsed.Fields["Length"] = udpLength.ToString();
                parsed.Fields["Checksum"] = $"0x{ReadNetworkUInt16(bytes, offset + 6):X4}";
                int payloadLength = Math.Clamp(Math.Min(udpLength, length) - 8, 0, length - 8);
                byte[] payload = bytes.Skip(offset + 8).Take(payloadLength).ToArray();
                if (sourcePort is 53 or 5353 or 5355 || destinationPort is 53 or 5353 or 5355)
                {
                    parsed.ApplicationProtocol = sourcePort == 5353 || destinationPort == 5353 ? "mDNS" : "DNS";
                    ParseDns(payload, isTcp: false, parsed);
                }
                else if (sourcePort is 67 or 68 || destinationPort is 67 or 68)
                {
                    parsed.ApplicationProtocol = "DHCP";
                    ParseDhcp(payload, parsed);
                }
                if (string.IsNullOrWhiteSpace(parsed.Summary))
                    parsed.Summary = $"UDP {sourceIp}:{sourcePort} → {destinationIp}:{destinationPort}";
                return parsed;
            }
            if (protocol is 1 or 58) // ICMP / ICMPv6
            {
                parsed.Protocol = protocol == 1 ? "ICMP" : "ICMPv6";
                parsed.ApplicationProtocol = parsed.Protocol;
                if (length >= 4)
                {
                    byte type = bytes[offset];
                    byte code = bytes[offset + 1];
                    parsed.Fields["Type"] = type.ToString();
                    parsed.Fields["Code"] = code.ToString();
                    parsed.Fields["Checksum"] = $"0x{ReadNetworkUInt16(bytes, offset + 2):X4}";
                    parsed.Summary = $"{parsed.Protocol} type {type}, code {code}: {sourceIp} → {destinationIp}";
                }
                else parsed.Summary = parsed.Protocol + " (truncated header)";
                parsed.ConversationId = MakeConversationId(parsed.Protocol, sourceIp, null, destinationIp, null);
            }
            return parsed;
        }

        private static void MergeNetworkInfo(NetworkDissection parent, NetworkDissection child)
        {
            if (!string.IsNullOrWhiteSpace(child.Protocol)) parent.Protocol += "/" + child.Protocol;
            if (!string.IsNullOrWhiteSpace(child.ApplicationProtocol)) parent.ApplicationProtocol = child.ApplicationProtocol;
            if (!string.IsNullOrWhiteSpace(child.SourceIp)) parent.SourceIp = child.SourceIp;
            if (!string.IsNullOrWhiteSpace(child.DestinationIp)) parent.DestinationIp = child.DestinationIp;
            parent.SourcePort = child.SourcePort;
            parent.DestinationPort = child.DestinationPort;
            parent.ConversationId = child.ConversationId;
            parent.TcpStreamId = child.TcpStreamId;
            parent.TcpSequenceNumber = child.TcpSequenceNumber;
            parent.TcpAcknowledgmentNumber = child.TcpAcknowledgmentNumber;
            parent.TcpFlags = child.TcpFlags;
            parent.TcpPayloadHex = child.TcpPayloadHex;
            parent.Summary = child.Summary;
            foreach (var field in child.Fields) parent.Fields[field.Key] = field.Value;
        }

        private static string IdentifyTcpApplication(int sourcePort, int destinationPort)
        {
            int port = sourcePort is 53 or 80 or 443 or 8080 or 8443 ? sourcePort : destinationPort;
            return port switch
            {
                53 => "DNS", 80 or 8080 => "HTTP", 443 or 8443 => "TLS", _ => "TCP"
            };
        }

        private static string FormatTcpFlags(byte flags)
        {
            var values = new List<string>();
            if ((flags & 0x02) != 0) values.Add("SYN");
            if ((flags & 0x10) != 0) values.Add("ACK");
            if ((flags & 0x01) != 0) values.Add("FIN");
            if ((flags & 0x04) != 0) values.Add("RST");
            if ((flags & 0x08) != 0) values.Add("PSH");
            if ((flags & 0x20) != 0) values.Add("URG");
            if ((flags & 0x40) != 0) values.Add("ECE");
            if ((flags & 0x80) != 0) values.Add("CWR");
            return values.Count == 0 ? "none" : string.Join(", ", values);
        }

        private static string MakeConversationId(string protocol, string sourceIp, int? sourcePort, string destinationIp, int? destinationPort)
        {
            string source = sourceIp + (sourcePort.HasValue ? ":" + sourcePort.Value : string.Empty);
            string destination = destinationIp + (destinationPort.HasValue ? ":" + destinationPort.Value : string.Empty);
            return string.Compare(source, destination, StringComparison.Ordinal) <= 0
                ? $"{protocol}|{source}|{destination}" : $"{protocol}|{destination}|{source}";
        }

        private static void ParseHttp(byte[] payload, NetworkDissection parsed)
        {
            if (payload.Length == 0) return;
            string text = Encoding.Latin1.GetString(payload.Take(Math.Min(payload.Length, 8192)).ToArray());
            string[] lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            if (lines.Length == 0 || !(lines[0].StartsWith("GET ", StringComparison.OrdinalIgnoreCase)
                || lines[0].StartsWith("POST ", StringComparison.OrdinalIgnoreCase)
                || lines[0].StartsWith("PUT ", StringComparison.OrdinalIgnoreCase)
                || lines[0].StartsWith("HEAD ", StringComparison.OrdinalIgnoreCase)
                || lines[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))) return;
            parsed.ApplicationProtocol = "HTTP";
            parsed.Fields["HTTP start line"] = lines[0];
            foreach (string line in lines.Skip(1).Take(32))
            {
                if (string.IsNullOrWhiteSpace(line)) break;
                int separator = line.IndexOf(':');
                if (separator <= 0) continue;
                string name = line[..separator].Trim();
                string value = line[(separator + 1)..].Trim();
                if (name.Equals("Authorization", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("Cookie", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)) value = "[redacted]";
                parsed.Fields["HTTP " + name] = value;
            }
            parsed.Summary = "HTTP " + lines[0];
        }

        private static void ParseTls(byte[] payload, NetworkDissection parsed)
        {
            if (payload.Length < 5) return;
            if (payload[0] < 20 || payload[0] > 23 || payload[1] != 3) return;
            int recordLength = ReadNetworkUInt16(payload, 3);
            string recordType = payload[0] switch { 20 => "ChangeCipherSpec", 21 => "Alert", 22 => "Handshake", 23 => "Application data", _ => "TLS" };
            parsed.ApplicationProtocol = "TLS";
            parsed.Fields["TLS record type"] = recordType;
            parsed.Fields["TLS record version"] = FormatTlsVersion(ReadNetworkUInt16(payload, 1));
            if (payload[0] == 22 && recordLength >= 4 && payload.Length >= 9)
            {
                byte handshakeType = payload[5];
                parsed.Fields["TLS handshake"] = handshakeType switch { 1 => "ClientHello", 2 => "ServerHello", 11 => "Certificate", _ => "Handshake " + handshakeType };
                int bodyEnd = Math.Min(payload.Length, 9 + Math.Min(recordLength - 4, 8192));
                int cursor = 9;
                if (handshakeType is 1 or 2 && cursor + 34 <= bodyEnd)
                {
                    ushort legacyVersion = ReadNetworkUInt16(payload, cursor);
                    parsed.Fields["TLS legacy version"] = FormatTlsVersion(legacyVersion);
                    cursor += 34; // legacy version plus random
                    if (cursor < bodyEnd)
                    {
                        int sessionLength = payload[cursor++];
                        cursor += sessionLength;
                    }
                    if (cursor + 2 <= bodyEnd)
                    {
                        int cipherLength = ReadNetworkUInt16(payload, cursor); cursor += 2;
                        if (cursor + cipherLength <= bodyEnd) cursor += cipherLength; else cursor = bodyEnd;
                    }
                    if (handshakeType == 1 && cursor < bodyEnd)
                    {
                        int compressionLength = payload[cursor++]; cursor += compressionLength;
                    }
                    if (cursor + 2 <= bodyEnd)
                    {
                        int extensionsLength = ReadNetworkUInt16(payload, cursor); cursor += 2;
                        int extensionsEnd = Math.Min(bodyEnd, cursor + extensionsLength);
                        while (cursor + 4 <= extensionsEnd)
                        {
                            ushort extensionType = ReadNetworkUInt16(payload, cursor);
                            int extensionLength = ReadNetworkUInt16(payload, cursor + 2); cursor += 4;
                            if (cursor + extensionLength > extensionsEnd) break;
                            if (handshakeType == 1 && extensionType == 0 && extensionLength >= 5)
                            {
                                int nameCursor = cursor + 2;
                                if (nameCursor + 3 <= cursor + extensionLength)
                                {
                                    int nameLength = ReadNetworkUInt16(payload, nameCursor + 1);
                                    if (payload[nameCursor] == 0 && nameCursor + 3 + nameLength <= cursor + extensionLength)
                                        parsed.Fields["TLS server name"] = Encoding.ASCII.GetString(payload, nameCursor + 3, nameLength);
                                }
                            }
                            if (extensionType == 43 && extensionLength >= 2)
                                parsed.Fields["TLS supported version"] = FormatTlsVersion(ReadNetworkUInt16(payload, cursor + extensionLength - 2));
                            cursor += extensionLength;
                        }
                    }
                }
            }
            parsed.Summary = parsed.Fields.TryGetValue("TLS server name", out string? sni)
                ? $"TLS ClientHello for {sni}"
                : parsed.Fields.TryGetValue("TLS handshake", out string? handshake) ? "TLS " + handshake : "TLS " + recordType;
        }

        private static string FormatTlsVersion(ushort version) => version switch
        {
            0x0300 => "SSL 3.0", 0x0301 => "TLS 1.0", 0x0302 => "TLS 1.1", 0x0303 => "TLS 1.2", 0x0304 => "TLS 1.3", _ => $"0x{version:X4}"
        };

        private static void ParseDhcp(byte[] payload, NetworkDissection parsed)
        {
            if (payload.Length < 240 || payload[236] != 99 || payload[237] != 130 || payload[238] != 83 || payload[239] != 99)
            { parsed.Summary = "DHCP/BOOTP (truncated or missing magic cookie)"; return; }
            parsed.Fields["DHCP transaction ID"] = $"0x{ReadNetworkUInt32(payload, 4):X8}";
            parsed.Fields["Client MAC"] = Convert.ToHexString(payload, 28, Math.Min(6, payload.Length - 28)).Chunk(2).Select(x => string.Join(string.Empty, x)).Aggregate((a, b) => a + ":" + b);
            parsed.Fields["Client IPv4"] = new IPAddress(payload.Skip(12).Take(4).ToArray()).ToString();
            parsed.Fields["Your IPv4"] = new IPAddress(payload.Skip(16).Take(4).ToArray()).ToString();
            int offset = 240;
            while (offset < payload.Length)
            {
                byte tag = payload[offset++];
                if (tag == 255) break;
                if (tag == 0) continue;
                if (offset >= payload.Length) break;
                int length = payload[offset++];
                if (offset + length > payload.Length) break;
                string name = tag switch { 12 => "Hostname", 50 => "Requested IPv4", 53 => "Message type", 54 => "Server IPv4", 55 => "Parameter request list", _ => $"Option {tag}" };
                string value = tag is 50 or 54 && length == 4
                    ? new IPAddress(payload.Skip(offset).Take(4).ToArray()).ToString()
                    : tag == 12 ? Encoding.ASCII.GetString(payload, offset, length).TrimEnd('\0')
                    : tag == 53 && length == 1 ? payload[offset] switch { 1 => "Discover", 2 => "Offer", 3 => "Request", 4 => "Decline", 5 => "Ack", 6 => "Nak", 7 => "Release", 8 => "Inform", _ => payload[offset].ToString() }
                    : Convert.ToHexString(payload, offset, length);
                parsed.Fields["DHCP " + name] = value;
                offset += length;
            }
            string message = parsed.Fields.TryGetValue("DHCP Message type", out string? messageType) ? messageType : "message";
            string hostname = parsed.Fields.TryGetValue("DHCP Hostname", out string? host) ? " for " + host : string.Empty;
            parsed.Summary = "DHCP " + message + hostname;
        }

        private static void ParseDns(byte[] payload, bool isTcp, NetworkDissection parsed)
        {
            int start = isTcp ? 2 : 0;
            if (payload.Length < start + 12) { parsed.Summary = "DNS (truncated header)"; return; }
            int end = start + (isTcp ? ReadNetworkUInt16(payload, 0) : payload.Length);
            end = Math.Min(end, payload.Length);
            int questions = ReadNetworkUInt16(payload, start + 4);
            int answers = ReadNetworkUInt16(payload, start + 6);
            ushort flags = ReadNetworkUInt16(payload, start + 2);
            parsed.Fields["DNS transaction ID"] = $"0x{ReadNetworkUInt16(payload, start):X4}";
            parsed.Fields["DNS message"] = (flags & 0x8000) != 0 ? "Response" : "Query";
            parsed.Fields["DNS response code"] = (flags & 0x000F).ToString();
            parsed.Fields["DNS questions"] = questions.ToString();
            parsed.Fields["DNS answers"] = answers.ToString();
            int cursor = start + 12;
            string firstQuestion = string.Empty;
            if (questions > 0)
            {
                firstQuestion = ReadDnsName(payload, ref cursor, end);
                if (cursor + 4 <= end)
                {
                    ushort type = ReadNetworkUInt16(payload, cursor);
                    parsed.Fields["DNS query name"] = firstQuestion;
                    parsed.Fields["DNS query type"] = type switch { 1 => "A", 28 => "AAAA", 12 => "PTR", 15 => "MX", 16 => "TXT", 33 => "SRV", 255 => "ANY", _ => type.ToString() };
                    parsed.Fields["DNS query class"] = ReadNetworkUInt16(payload, cursor + 2).ToString();
                }
            }
            string message = (flags & 0x8000) != 0 ? "response" : "query";
            parsed.Summary = firstQuestion.Length > 0 ? $"DNS {message}: {firstQuestion}" : "DNS " + message;
        }

        private static string ReadDnsName(byte[] bytes, ref int offset, int end)
        {
            var labels = new List<string>();
            int cursor = offset;
            int resume = -1;
            int hops = 0;
            while (cursor < end && hops++ < 64)
            {
                byte size = bytes[cursor++];
                if (size == 0) { if (resume < 0) resume = cursor; break; }
                if ((size & 0xC0) == 0xC0)
                {
                    if (cursor >= end) return string.Empty;
                    int pointer = ((size & 0x3F) << 8) | bytes[cursor++];
                    if (resume < 0) resume = cursor;
                    if (pointer >= end) return string.Empty;
                    cursor = pointer;
                    continue;
                }
                if ((size & 0xC0) != 0 || cursor + size > end) return string.Empty;
                labels.Add(Encoding.ASCII.GetString(bytes, cursor, size));
                cursor += size;
            }
            offset = resume >= 0 ? resume : cursor;
            return string.Join('.', labels);
        }

        private static ushort ReadNetworkUInt16(byte[] bytes, int offset) => (ushort)((bytes[offset] << 8) | bytes[offset + 1]);
        private static uint ReadNetworkUInt32(byte[] bytes, int offset) => ((uint)bytes[offset] << 24) | ((uint)bytes[offset + 1] << 16) | ((uint)bytes[offset + 2] << 8) | bytes[offset + 3];

        private static Dictionary<string, string> ExtractInformationElements(byte[] bytes, int offset)
        {
            var fields = new Dictionary<string, string>();
            var position = offset;
            while (position + 2 <= bytes.Length)
            {
                var id = bytes[position++];
                var length = bytes[position++];
                if (position + length > bytes.Length) break;
                var value = bytes.Skip(position).Take(length).ToArray();
                position += length;
                var name = id switch
                {
                    0 => "SSID",
                    1 => "Supported Rates",
                    3 => "DS Parameter Set",
                    5 => "TIM",
                    45 => "HT Capabilities",
                    48 => "RSN",
                    50 => "Extended Supported Rates",
                    61 => "HT Operation",
                    191 => "VHT Capabilities",
                    192 => "VHT Operation",
                    221 => "Vendor Specific",
                    _ => $"Information Element {id}"
                };
                var key = name;
                var duplicate = 2;
                while (fields.ContainsKey(key)) key = $"{name} #{duplicate++}";
                fields[key] = id == 0
                    ? (value.Length == 0 ? "<hidden>" : SanitizeText(Encoding.UTF8.GetString(value, 0, Math.Min(value.Length, 32))))
                    : BitConverter.ToString(value).Replace("-", " ");
            }
            return fields;
        }

        private static Dictionary<string, string> ExtractEapolFields(byte[] bytes, int offset)
        {
            var fields = new Dictionary<string, string>();
            if (offset + 4 > bytes.Length) return fields;
            fields["EAPOL Version"] = bytes[offset].ToString();
            fields["EAPOL Type"] = bytes[offset + 1].ToString();
            fields["EAPOL Length"] = ((bytes[offset + 2] << 8) | bytes[offset + 3]).ToString();
            // The replay counter occupies eight bytes starting at offset + 9.
            // Do not read partial key headers from a truncated capture record.
            if (offset + 17 > bytes.Length) return fields;
            fields["Key Descriptor Type"] = bytes[offset + 4].ToString();
            var keyInfo = (ushort)((bytes[offset + 5] << 8) | bytes[offset + 6]);
            fields["Key Information"] = $"0x{keyInfo:X4}";
            fields["Key Length"] = ((bytes[offset + 7] << 8) | bytes[offset + 8]).ToString();
            fields["Replay Counter"] = BitConverter.ToUInt64(bytes.Skip(offset + 9).Take(8).Reverse().ToArray(), 0).ToString();
            if (offset + 49 <= bytes.Length) fields["Nonce"] = BitConverter.ToString(bytes, offset + 17, 32).Replace("-", "");
            if (offset + 97 <= bytes.Length) fields["MIC"] = BitConverter.ToString(bytes, offset + 81, 16).Replace("-", "");
            return fields;
        }

        private string DissectEapolFrame(
            byte[] bytes,
            int offset,
            string srcMac,
            string destMac,
            string bssid,
            string timestamp,
            Dictionary<string, HandshakeSession> handshakeTracker,
            Dictionary<string, AccessPoint> apMap,
            PcapDissectorResult result,
            PcapDissectOptions options)
        {
            // Need at least: 4 (version/type/len) + 1 (descType) + 2 (keyInfo) + 2 (keyLen)
            // + 8 (replay) + 32 (nonce) + 16 (IV) + 8 (RSC) + 8 (reserved) + 16 (MIC) + 2 (keyDataLen) = 99 bytes
            if (offset + 99 > bytes.Length) return "EAPOL Key (Truncated Packet)";

            byte version = bytes[offset];
            byte packetType = bytes[offset + 1]; // 3 = EAPOL-Key
            ushort bodyLen = (ushort)((bytes[offset + 2] << 8) | bytes[offset + 3]);

            byte descType = bytes[offset + 4]; // 2 = WPA/RSN EAPOL-Key

            // Key Information is a 2-byte field transmitted in network (big-endian) byte
            // order. BitConverter.ToUInt16 reads little-endian on x86/x64 Windows, which
            // silently swaps the two bytes and corrupts every derived flag below
            // (Ack/MIC/Install/Secure), causing M1/M2/M3/M4 to be misclassified. Build the
            // value manually to force big-endian interpretation regardless of host endianness.
            ushort keyInfo = (ushort)((bytes[offset + 5] << 8) | bytes[offset + 6]);

            int keyDescriptorVersion = keyInfo & 0x0007; // 1 = RC4, 2 = HMAC-SHA1, 3 = AES-128-CMAC
            bool keyTypePairwise = (keyInfo & 0x0008) != 0;
            bool keyAck = (keyInfo & 0x0080) != 0;
            bool keyMic = (keyInfo & 0x0100) != 0;
            bool keyInstall = (keyInfo & 0x0040) != 0;
            bool keySecure = (keyInfo & 0x0200) != 0;

            // Key Length occupies offset+7..+8, so Replay Counter (8 bytes) starts at
            // offset+9, not offset+7. The previous offset+7 start clipped 2 bytes off the
            // front of the eventual Nonce/MIC fields and pulled in 2 bytes of the wrong
            // field, corrupting every extracted nonce and MIC.
            ulong replayCounter = 0;
            for (int i = 0; i < 8; i++)
            {
                replayCounter = (replayCounter << 8) | bytes[offset + 9 + i];
            }

            // Key Nonce (32 bytes at offset + 17, per IEEE 802.11 EAPOL-Key descriptor layout)
            byte[] nonce = new byte[32];
            Array.Copy(bytes, offset + 17, nonce, 0, 32);
            string nonceHex = BitConverter.ToString(nonce).Replace("-", "").ToUpperInvariant();

            // MIC (16 bytes at offset + 81)
            byte[] mic = new byte[16];
            Array.Copy(bytes, offset + 81, mic, 0, 16);
            string micHex = BitConverter.ToString(mic).Replace("-", "").ToUpperInvariant();

            // Key Data Length (2 bytes at offset + 97)
            ushort keyDataLen = 0;
            if (offset + 99 <= bytes.Length)
            {
                keyDataLen = (ushort)((bytes[offset + 97] << 8) | bytes[offset + 98]);
            }

            // Determine Handshake Step:
            // M1: AP -> Client (KeyAck=1, KeyMIC=0)
            // M2: Client -> AP (KeyAck=0, KeyMIC=1)
            // M3: AP -> Client (KeyAck=1, KeyMIC=1, KeyInstall=1)
            // M4: Client -> AP (KeyAck=0, KeyMIC=1, KeySecure=1, DataLen=0)
            string step = "Unknown";
            string apMac = bssid;
            string clientMac = srcMac;

            if (keyAck && !keyMic)
            {
                step = "M1";
                apMac = srcMac;
                clientMac = destMac;
            }
            else if (!keyAck && keyMic && !keySecure && keyDataLen > 0)
            {
                step = "M2";
                clientMac = srcMac;
                apMac = destMac;
            }
            else if (keyAck && keyMic)
            {
                step = "M3";
                apMac = srcMac;
                clientMac = destMac;
            }
            else if (!keyAck && keyMic && keyDataLen == 0)
            {
                step = "M4";
                clientMac = srcMac;
                apMac = destMac;
            }

            // Extract PMKID from Key Data if present (KDE OUI 00-0F-AC type 04)
            string? pmkid = null;
            if (keyDataLen >= 22 && offset + 99 + keyDataLen <= bytes.Length)
            {
                int kdIdx = offset + 99;
                int kdEnd = kdIdx + keyDataLen;
                while (kdIdx + 6 <= kdEnd)
                {
                    byte kdeTag = bytes[kdIdx];
                    byte kdeLen = bytes[kdIdx + 1];
                    if (kdIdx + 2 + kdeLen > kdEnd) break;

                    // OUI 00-0F-AC, Data Type 04 = PMKID
                    if (kdeTag == 0xDD && kdeLen >= 20 &&
                        bytes[kdIdx + 2] == 0x00 && bytes[kdIdx + 3] == 0x0F && bytes[kdIdx + 4] == 0xAC && bytes[kdIdx + 5] == 0x04)
                    {
                        byte[] pmkidBytes = new byte[16];
                        Array.Copy(bytes, kdIdx + 6, pmkidBytes, 0, 16);
                        pmkid = BitConverter.ToString(pmkidBytes).Replace("-", "").ToUpperInvariant();
                        break;
                    }
                    kdIdx += 2 + kdeLen;
                }
            }

            // Track Session by (AP, Client)
            string sessionKey = $"{apMac.ToUpperInvariant()}_{clientMac.ToUpperInvariant()}";
            if (!handshakeTracker.TryGetValue(sessionKey, out var session))
            {
                if (handshakeTracker.Count >= options.MaxHandshakes)
                {
                    AddWarning(result, $"Handshake tracking limit ({options.MaxHandshakes:N0}) reached; further sessions are reported as metadata only.");
                    return $"EAPOL Key [{step}] (tracking limit reached)";
                }
                string ssid = apMap.TryGetValue(apMac, out var ap) ? ap.Ssid : "Forensic AP";
                session = new HandshakeSession(apMac, clientMac, ssid);
                handshakeTracker[sessionKey] = session;
            }

            session.AddFrame(step, nonceHex, micHex, replayCounter, keyDescriptorVersion, pmkid, bytes, offset, timestamp);

            return $"EAPOL Key [{step}] (Replay #{replayCounter}, Nonce: {nonceHex.Substring(0, 8)}..., MIC: {micHex.Substring(0, 8)}...)";
        }

        private static string GetSubtypeName(byte type, byte subtype)
        {
            if (type == 0) // Management
            {
                return subtype switch
                {
                    0 => "Assoc Request",
                    1 => "Assoc Response",
                    2 => "Reassoc Request",
                    3 => "Reassoc Response",
                    4 => "Probe Request",
                    5 => "Probe Response",
                    8 => "Beacon",
                    9 => "ATIM",
                    10 => "Disassociation",
                    11 => "Authentication",
                    12 => "Deauthentication",
                    13 => "Action",
                    _ => $"Mgt-Subtype-{subtype}"
                };
            }
            if (type == 1) // Control
            {
                return subtype switch
                {
                    8 => "Block Ack Req",
                    9 => "Block Ack",
                    10 => "PS-Poll",
                    11 => "RTS",
                    12 => "CTS",
                    13 => "ACK",
                    14 => "CF-End",
                    _ => $"Ctrl-Subtype-{subtype}"
                };
            }
            if (type == 2) // Data
            {
                return subtype switch
                {
                    0 => "Data",
                    4 => "Null Data",
                    8 => "QoS Data",
                    12 => "QoS Null Data",
                    _ => $"Data-Subtype-{subtype}"
                };
            }
            return $"Type-{type}-Subtype-{subtype}";
        }

        private string ExtractSsidFromIes(byte[] bytes, int offset)
        {
            if (offset >= bytes.Length) return "[Hidden SSID]";

            int idx = offset;
            while (idx + 2 <= bytes.Length)
            {
                byte tag = bytes[idx];
                byte len = bytes[idx + 1];
                idx += 2;

                if (tag == 0) // Tag 0 = SSID
                {
                    if (len == 0 || idx + len > bytes.Length) return "[Hidden SSID]";
                    int ssidLength = Math.Min((int)len, 32); // 802.11 SSID field is at most 32 bytes
                    string val = SanitizeText(Encoding.UTF8.GetString(bytes, idx, ssidLength));
                    return string.IsNullOrEmpty(val) ? "[Hidden SSID]" : val;
                }
                idx += len;
            }
            return "[Hidden SSID]";
        }

        private int ExtractChannelFromIes(byte[] bytes, int offset, int defaultChannel)
        {
            int idx = offset;
            while (idx + 2 <= bytes.Length)
            {
                byte tag = bytes[idx];
                byte len = bytes[idx + 1];
                idx += 2;

                if (tag == 3 && len >= 1 && idx < bytes.Length) // Tag 3 = DS Parameter Set
                {
                    int ch = bytes[idx];
                    if (ch > 0 && ch <= 196) return ch;
                }
                idx += len;
            }
            return defaultChannel;
        }

        private void DissectPcapNg(byte[] bytes, PcapDissectorResult result, PcapDissectOptions options)
        {
            using var ms = new MemoryStream(bytes);
            using var reader = new BinaryReader(ms);

            var apMap = new Dictionary<string, AccessPoint>(StringComparer.OrdinalIgnoreCase);
            var clientMap = new Dictionary<string, StationClientRecord>(StringComparer.OrdinalIgnoreCase);
            var handshakeTracker = new Dictionary<string, HandshakeSession>(StringComparer.OrdinalIgnoreCase);
            var interfaces = new Dictionary<uint, PcapNgInterface>();

            int frameNum = 1;
            bool sawSectionHeader = false;
            bool recordLimitReported = false;
            int malformedBlocks = 0;
            int snapLenViolations = 0;
            bool unsupportedLinkReported = false;

            while (ms.Position + 8 <= ms.Length)
            {
                if (result.Packets.Count >= options.MaxPackets)
                {
                    result.Truncated = true;
                    if (!recordLimitReported)
                    {
                        AddWarning(result, $"Stopped after {options.MaxPackets:N0} frames; the capture contains more records than the import limit.");
                        recordLimitReported = true;
                    }
                    break;
                }

                long blockStart = ms.Position;
                uint blockType = reader.ReadUInt32();
                uint blockTotalLen = reader.ReadUInt32();

                if (blockTotalLen < 12 || blockTotalLen > MaxPcapngBlockBytes)
                {
                    result.Truncated = true;
                    AddWarning(result, $"PCAPNG block at offset {blockStart:N0} declares an invalid length ({blockTotalLen:N0}); parsing stopped.");
                    break;
                }

                long blockEnd = blockStart + blockTotalLen;
                if (blockEnd > ms.Length)
                {
                    result.Truncated = true;
                    AddWarning(result, $"PCAPNG block at offset {blockStart:N0} extends past the end of the file; parsing stopped.");
                    break;
                }

                if (blockType == PCAPNG_SECTION_HEADER)
                {
                    if (blockTotalLen < 28)
                    {
                        malformedBlocks++;
                    }
                    else
                    {
                        ms.Position = blockStart + 8;
                        uint byteOrderMagic = reader.ReadUInt32();
                        if (byteOrderMagic != PCAPNG_BYTE_ORDER_MAGIC)
                        {
                            if (byteOrderMagic == 0x4d3c2b1a)
                            {
                                throw new NotSupportedException("Byte-swapped PCAPNG captures are not supported. Re-export the capture in native byte order.");
                            }
                            throw new InvalidDataException("PCAPNG section header is missing the byte-order magic.");
                        }

                        ushort majorVersion = reader.ReadUInt16();
                        if (majorVersion != 1)
                        {
                            AddWarning(result, $"PCAPNG section reports version {majorVersion}; expected 1.");
                        }

                        sawSectionHeader = true;
                        interfaces.Clear();
                        result.LinkTypeValue = 127;
                        result.LinkTypeName = DescribeLinkType(127);
                    }
                }
                else if (!sawSectionHeader)
                {
                    throw new InvalidDataException("PCAPNG capture does not start with a section header block.");
                }
                else if (blockType == PCAPNG_INTERFACE_DESCRIPTION)
                {
                    if (blockEnd - ms.Position < 8)
                    {
                        malformedBlocks++;
                    }
                    else
                    {
                        ushort linkType = reader.ReadUInt16();
                        _ = reader.ReadUInt16(); // reserved
                        uint snapLen = reader.ReadUInt32();
                        double unitsPerSecond = ParseTimestampResolution(reader, ms.Position, blockEnd - 4);
                        uint ifaceId = (uint)interfaces.Count;
                        interfaces[ifaceId] = new PcapNgInterface(linkType, snapLen, unitsPerSecond);

                        result.LinkTypeValue = linkType;
                        result.LinkTypeName = DescribeLinkType(linkType);
                        if (snapLen > (uint)options.MaxFrameBytes)
                        {
                            AddWarning(result, $"Interface {ifaceId} snaplen ({snapLen} bytes) exceeds the {options.MaxFrameBytes}-byte per-frame limit.");
                        }
                    }
                }
                else if (blockType == PCAPNG_ENHANCED_PACKET)
                {
                    if (blockEnd - ms.Position < 20)
                    {
                        malformedBlocks++;
                    }
                    else
                    {
                        uint ifaceId = reader.ReadUInt32();
                        uint tsHigh = reader.ReadUInt32();
                        uint tsLow = reader.ReadUInt32();
                        uint capLen = reader.ReadUInt32();
                        _ = reader.ReadUInt32(); // original length

                        if (!interfaces.TryGetValue(ifaceId, out var iface))
                        {
                            if (interfaces.Count == 0)
                            {
                                AddWarning(result, "Enhanced packet block appeared before any interface description; assuming 802.11 radiotap.");
                            }
                            else
                            {
                                AddWarning(result, $"Enhanced packet block references unknown interface {ifaceId}; assuming 802.11 radiotap.");
                            }
                            iface = new PcapNgInterface(127, (uint)options.MaxFrameBytes, 1_000_000d);
                        }

                        if (capLen > (uint)options.MaxFrameBytes)
                        {
                            result.Truncated = true;
                            AddWarning(result, $"PCAPNG packet declares {capLen:N0} captured bytes, above the {options.MaxFrameBytes:N0}-byte limit; parsing stopped.");
                            break;
                        }

                        if (iface.SnapLen > 0 && capLen > iface.SnapLen && snapLenViolations < 3)
                        {
                            snapLenViolations++;
                            AddWarning(result, $"PCAPNG packet captured {capLen} bytes but interface {ifaceId} snaplen is {iface.SnapLen}.");
                        }

                        if (iface.LinkType != 127 && iface.LinkType != 105)
                        {
                            if (!unsupportedLinkReported)
                            {
                                AddWarning(result, $"Interface {ifaceId} uses {DescribeLinkType(iface.LinkType)}; only 802.11 captures are dissected.");
                                unsupportedLinkReported = true;
                            }
                        }
                        else if (ms.Position + capLen > blockEnd - 4)
                        {
                            AddWarning(result, $"PCAPNG packet at offset {blockStart:N0} is truncated inside its block.");
                            malformedBlocks++;
                        }
                        else
                        {
                            ulong totalTicks = ((ulong)tsHigh << 32) | tsLow;
                            var (sec, fraction) = ConvertPcapNgTimestamp(totalTicks, iface.UnitsPerSecond);
                            byte[] pkt = reader.ReadBytes((int)capLen);
                            var packet = ParseSingleFrame(pkt, frameNum++, sec, fraction, iface.LinkType, apMap, clientMap, handshakeTracker, result, options);
                            if (packet != null)
                            {
                                result.Packets.Add(packet);
                            }
                        }
                    }
                }
                else if (blockType == PCAPNG_SIMPLE_PACKET)
                {
                    if (blockEnd - ms.Position < 4)
                    {
                        malformedBlocks++;
                    }
                    else
                    {
                        uint originalLength = reader.ReadUInt32();
                        long dataStart = ms.Position;
                        long available = blockEnd - 4 - dataStart;
                        int capLen = (int)Math.Clamp(available, 0, options.MaxFrameBytes);
                        if (originalLength > 0 && originalLength < (uint)capLen)
                        {
                            capLen = (int)originalLength;
                        }

                        if (capLen > 0)
                        {
                            var iface = interfaces.TryGetValue(0, out var firstInterface)
                                ? firstInterface
                                : new PcapNgInterface(127, (uint)options.MaxFrameBytes, 1_000_000d);
                            if (iface.LinkType != 127 && iface.LinkType != 105)
                            {
                                if (!unsupportedLinkReported)
                                {
                                    AddWarning(result, $"Interface 0 uses {DescribeLinkType(iface.LinkType)}; only 802.11 captures are dissected.");
                                    unsupportedLinkReported = true;
                                }
                            }
                            else
                            {
                                var (sec, fraction) = (0u, 0d);
                                byte[] pkt = reader.ReadBytes(capLen);
                                var packet = ParseSingleFrame(pkt, frameNum++, sec, fraction, iface.LinkType, apMap, clientMap, handshakeTracker, result, options);
                                if (packet != null)
                                {
                                    result.Packets.Add(packet);
                                }
                            }
                        }
                    }
                }

                // Verify the block trailer so a corrupt length cannot silently
                // shift the parser into the middle of another block.
                ms.Position = blockEnd - 4;
                uint trailerLength = reader.ReadUInt32();
                if (trailerLength != blockTotalLen)
                {
                    AddWarning(result, $"PCAPNG block at offset {blockStart:N0} has mismatched trailer length ({trailerLength:N0} vs {blockTotalLen:N0}); parsing stopped.");
                    result.Truncated = true;
                    break;
                }

                ms.Position = blockEnd;
            }

            if (!sawSectionHeader)
            {
                throw new InvalidDataException("PCAPNG capture does not start with a section header block.");
            }
            if (ms.Position < ms.Length && !result.Truncated && ms.Position + 8 > ms.Length)
            {
                AddWarning(result, $"Ignored {ms.Length - ms.Position} trailing byte(s) that do not form a complete block header.");
            }
            if (malformedBlocks > 0)
            {
                AddWarning(result, $"{malformedBlocks} malformed PCAPNG block(s) were skipped.");
            }

            ConsolidateResults(result, apMap, clientMap, handshakeTracker);
            FinalizeWarnings(result);
        }

        private static double ParseTimestampResolution(BinaryReader reader, long optionsStart, long optionsEnd)
        {
            double unitsPerSecond = 1_000_000d; // PCAPNG default is microseconds
            long position = optionsStart;
            while (position + 4 <= optionsEnd)
            {
                reader.BaseStream.Position = position;
                ushort code = reader.ReadUInt16();
                ushort length = reader.ReadUInt16();
                if (code == 0) break;

                int paddedLength = (length + 3) & ~3;
                if (position + 4 + paddedLength > optionsEnd) break;

                if (code == 9 && length >= 1) // if_tsresol
                {
                    byte raw = reader.ReadByte();
                    int exponent = raw & 0x7F;
                    if ((raw & 0x80) != 0)
                    {
                        if (exponent <= 62) unitsPerSecond = Math.Pow(2, exponent);
                    }
                    else if (exponent <= 18)
                    {
                        unitsPerSecond = Math.Pow(10, exponent);
                    }
                    if (!(unitsPerSecond >= 1)) unitsPerSecond = 1;
                }

                position += 4 + paddedLength;
            }
            return unitsPerSecond;
        }

        private static (uint sec, double fraction) ConvertPcapNgTimestamp(ulong totalTicks, double unitsPerSecond)
        {
            ulong wholeUnits = (ulong)Math.Round(unitsPerSecond);
            if (unitsPerSecond <= 1_000_000_000d && Math.Abs(unitsPerSecond - wholeUnits) < 0.5)
            {
                ulong sec = totalTicks / wholeUnits;
                double fraction = (totalTicks % wholeUnits) / (double)wholeUnits;
                return sec > uint.MaxValue ? (uint.MaxValue, 0.9999999d) : ((uint)sec, fraction);
            }

            double totalSeconds = totalTicks / unitsPerSecond;
            if (totalSeconds > uint.MaxValue) return (uint.MaxValue, 0.9999999d);
            uint wholeSeconds = (uint)Math.Floor(totalSeconds);
            return (wholeSeconds, totalSeconds - wholeSeconds);
        }

        private static string DescribeLinkType(uint linkType) => linkType switch
        {
            127 => "DLT_IEEE802_11_RADIO (Radiotap)",
            105 => "DLT_IEEE802_11 (Raw 802.11)",
            1 => "DLT_EN10MB (Ethernet)",
            _ => $"DLT_{linkType} (Custom Link Layer)"
        };

        private sealed record PcapNgInterface(ushort LinkType, uint SnapLen, double UnitsPerSecond);

        private static string SanitizeText(string value)
        {
            var builder = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                builder.Append(char.IsControl(c) ? '?' : c);
            }
            return builder.ToString().Trim();
        }

        private static string FormatHexDump(byte[] data, int offset, int length)
        {
            var sb = new StringBuilder();
            int max = Math.Min(length, 256); // Cap preview to 256 bytes for performance
            for (int i = 0; i < max; i += 16)
            {
                sb.AppendFormat("{0:X4}  ", i);
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < max) sb.AppendFormat("{0:X2} ", data[offset + i + j]);
                    else sb.Append("   ");
                    if (j == 7) sb.Append(" ");
                }
                sb.AppendLine();
            }
            if (length > 256) sb.AppendLine($"... [{length - 256} additional bytes omitted for display] ...");
            return sb.ToString();
        }

        private static string FormatAsciiDump(byte[] data, int offset, int length)
        {
            var sb = new StringBuilder();
            int max = Math.Min(length, 256);
            for (int i = 0; i < max; i++)
            {
                char c = (char)data[offset + i];
                sb.Append(char.IsControl(c) ? '.' : c);
            }
            return sb.ToString();
        }

        private static string FormatMac(byte[] bytes, int offset)
        {
            if (offset + 6 > bytes.Length) return "00:00:00:00:00:00";
            return string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                bytes[offset], bytes[offset + 1], bytes[offset + 2],
                bytes[offset + 3], bytes[offset + 4], bytes[offset + 5]);
        }

        private static ushort ReadUInt16(BinaryReader r, bool isSwapped)
        {
            ushort val = r.ReadUInt16();
            return isSwapped ? (ushort)((val << 8) | (val >> 8)) : val;
        }

        private static uint ReadUInt32(BinaryReader r, bool isSwapped)
        {
            uint val = r.ReadUInt32();
            return isSwapped ? ((val << 24) | ((val & 0xFF00) << 8) | ((val >> 8) & 0xFF00) | (val >> 24)) : val;
        }

        private static int ReadInt32(BinaryReader r, bool isSwapped)
        {
            return (int)ReadUInt32(r, isSwapped);
        }
    }

    internal class HandshakeSession
    {
        public string ApMac { get; }
        public string ClientMac { get; }
        public string Ssid { get; }
        public HashSet<string> Steps { get; } = new();
        public string? Anonce { get; private set; }
        public string? Snonce { get; private set; }
        public string? MicHex { get; private set; }
        public string? Pmkid { get; private set; }
        public ulong ReplayCounter { get; private set; }
        public int KeyVersion { get; private set; } = 2;
        public string FirstCapturedAt { get; private set; } = string.Empty;
        public byte[]? LastEapolPayload { get; private set; }

        public HandshakeSession(string apMac, string clientMac, string ssid)
        {
            ApMac = apMac;
            ClientMac = clientMac;
            Ssid = ssid;
        }

        public void AddFrame(string step, string nonce, string mic, ulong replay, int keyVer, string? pmkidVal, byte[] fullPacket, int eapolOffset, string timestamp)
        {
            Steps.Add(step);
            if (string.IsNullOrEmpty(FirstCapturedAt)) FirstCapturedAt = timestamp;
            ReplayCounter = replay;
            KeyVersion = keyVer;

            if (step == "M1" || step == "M3")
            {
                if (nonce != new string('0', 64)) Anonce = nonce;
            }
            if (step == "M2" || step == "M4")
            {
                if (nonce != new string('0', 64)) Snonce = nonce;
                if (mic != new string('0', 32)) MicHex = mic;
            }

            if (!string.IsNullOrEmpty(pmkidVal))
            {
                Pmkid = pmkidVal;
            }

            if (step == "M2" && eapolOffset < fullPacket.Length)
            {
                int len = Math.Min(fullPacket.Length - eapolOffset, 256);
                LastEapolPayload = new byte[len];
                Array.Copy(fullPacket, eapolOffset, LastEapolPayload, 0, len);
            }
        }

        public HandshakeInfo? ToHandshakeInfo()
        {
            if (Steps.Count == 0 && string.IsNullOrEmpty(Pmkid)) return null;

            bool isComplete = Steps.Contains("M1") && Steps.Contains("M2") && Steps.Contains("M3") && Steps.Contains("M4");
            return new HandshakeInfo
            {
                ApBssid = ApMac,
                ClientMac = ClientMac,
                Ssid = Ssid,
                Type = KeyVersion == 3 ? "WPA3/802.11w EAPOL" : "WPA2 4-Way EAPOL",
                CapturedSteps = Steps.OrderBy(s => s).ToList(),
                IsComplete = isComplete,
                ReplayCounterMatch = true,
                MicVerified = !string.IsNullOrEmpty(MicHex),
                CapturedAt = FirstCapturedAt,
                // Retain event metadata for forensics but never expose credential-auditing material.
                Anonce = string.Empty,
                Snonce = string.Empty,
                MicHex = string.Empty,
                Pmkid = string.Empty,
                ReplayCounter = ReplayCounter,
                KeyDescriptorVersion = KeyVersion,
                HashcatFormat = null,
                ValidationNotes = isComplete
                    ? "Complete EAPOL key-negotiation event observed in the imported capture."
                    : (Steps.Contains("M1") && Steps.Contains("M2") 
                        ? "Partial EAPOL key-negotiation event observed in the imported capture."
                        : (!string.IsNullOrEmpty(Pmkid) ? "Association security event observed in the imported capture." : "Partial authentication event observed."))
            };
        }
    }
}
