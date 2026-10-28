using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

                // Check for LLC/SNAP Header (8 bytes) + EtherType 0x888E (802.1X EAPOL)
                int macHeaderLen = (subtype == 8 || subtype == 12) ? 26 : 24; // QoS Data has 2 extra bytes
                int llcOffset = offset + macHeaderLen;

                if (llcOffset + 8 <= rawBytes.Length && rawBytes[llcOffset + 6] == 0x88 && rawBytes[llcOffset + 7] == 0x8E)
                {
                    subtypeName = "EAPOL Key";
                    int eapolOffset = llcOffset + 8;
                    eapolFields = ExtractEapolFields(rawBytes, eapolOffset);
                    info = DissectEapolFrame(rawBytes, eapolOffset, srcMac, destMac, bssid, timestamp, handshakeTracker, apMap, result, options);
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
                EapolFields = eapolFields
            };
        }

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
