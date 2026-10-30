using System;
using System.Collections.Generic;

namespace WinWiFi.Models
{
    public class HandshakeInfo
    {
        public string ApBssid { get; set; } = string.Empty;
        public string ClientMac { get; set; } = string.Empty;
        public string Ssid { get; set; } = string.Empty;
        public string Type { get; set; } = "WPA2 4-Way (EAPOL)";
        public List<string> CapturedSteps { get; set; } = new(); // ["M1", "M2", "M3", "M4"]
        public bool IsComplete { get; set; }
        public bool ReplayCounterMatch { get; set; }
        public bool MicVerified { get; set; }
        public string CapturedAt { get; set; } = string.Empty;

        // Cryptographic fields. Exactly one property per JSON name: the bridge
        // serializes with case-insensitive camelCase, so old PascalCase aliases
        // (AnonCe/SnonCe) collided with these and broke /api/networks.
        public string? Anonce { get; set; }
        public string? Snonce { get; set; }
        public string? MicHex { get; set; }
        public ulong ReplayCounter { get; set; }
        public int KeyDescriptorVersion { get; set; } = 2; // 1 = RC4, 2 = HMAC-SHA1/AES, 3 = AES-128-CMAC (WPA3/802.11w)
        public string KeyVersionDescription => KeyDescriptorVersion switch
        {
            1 => "ARC4 / MD5 (WPA1 Legacy)",
            2 => "HMAC-SHA1-128 / AES (WPA2)",
            3 => "AES-128-CMAC / SHA-256 (WPA3/802.11w PMF)",
            _ => $"KeyDescriptor-{KeyDescriptorVersion}"
        };

        public string? Pmkid { get; set; }
        public bool HasPmkid => !string.IsNullOrWhiteSpace(Pmkid);
        public bool HasAnonce => !string.IsNullOrWhiteSpace(Anonce);
        public bool HasSnonce => !string.IsNullOrWhiteSpace(Snonce);
        public bool HasMic => !string.IsNullOrWhiteSpace(MicHex);

        public string HandshakeCompleteness
        {
            get
            {
                if (CapturedSteps.Contains("M1") && CapturedSteps.Contains("M2") && CapturedSteps.Contains("M3") && CapturedSteps.Contains("M4"))
                    return "Full 4-Way (M1-M4)";
                if (CapturedSteps.Contains("M1") && CapturedSteps.Contains("M2"))
                    return "EAPOL Half-Handshake (M1+M2)";
                if (CapturedSteps.Contains("M2") && CapturedSteps.Contains("M3"))
                    return "Partial Handshake (M2+M3)";
                if (HasPmkid)
                    return "PMKID Captured (Zero-Client)";
                if (CapturedSteps.Count > 0)
                    return $"Partial ({string.Join("+", CapturedSteps)})";
                return "Incomplete";
            }
        }

        // The native importer deliberately withholds nonce/MIC material and does
        // not build hash lines, so an imported record is never export-ready.
        public bool IsExportReady => false;

        public string ExportReadiness => "Not available: WinWiFi does not emit Hashcat 22000 hash lines.";

        public string? HashcatFormat { get; set; } // Reserved. Native imports always leave this null.
        public string? EapolPayloadHex { get; set; }
        public string ValidationNotes { get; set; } = string.Empty;
    }

    public class PcapPacket
    {
        public long Id { get; set; }
        public string Timestamp { get; set; } = string.Empty;
        public int FrameNumber { get; set; }
        public string FrameType { get; set; } = string.Empty; // "Management", "Control", "Data"
        public string Subtype { get; set; } = string.Empty; // "Beacon", "Probe Req", "QoS Data", "EAPOL Key"
        public byte TypeNumber { get; set; }
        public byte SubtypeNumber { get; set; }
        public string SourceMac { get; set; } = string.Empty;
        public string DestMac { get; set; } = string.Empty;
        public string Bssid { get; set; } = string.Empty;
        public string TransmitterMac { get; set; } = string.Empty;
        public string ReceiverMac { get; set; } = string.Empty;
        public int Channel { get; set; }
        public int Rssi { get; set; }
        public int LengthBytes { get; set; }
        public bool RadiotapPresent { get; set; }
        public ushort? SequenceNumber { get; set; }
        public byte? FragmentNumber { get; set; }
        public bool IsRetry { get; set; }
        public bool IsProtected { get; set; }
        public string Info { get; set; } = string.Empty;
        public string HexPreview { get; set; } = string.Empty;
        public string RawBytesHex { get; set; } = string.Empty;
        public string RawBytesAscii { get; set; } = string.Empty;
        public string ExpertInfo { get; set; } = string.Empty;
        // Parsed directly from this frame's management IEs / EAPOL key payload.
        // Empty dictionaries mean the corresponding bytes were not present.
        public Dictionary<string, string> InformationElements { get; set; } = new();
        public Dictionary<string, string> EapolFields { get; set; } = new();
        public string NetworkProtocol { get; set; } = string.Empty;
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
        public Dictionary<string, string> NetworkFields { get; set; } = new();
    }

    public class WifiAdapter
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public Guid InterfaceGuid { get; set; }
        public string MacAddress { get; set; } = string.Empty;
        public string Vendor { get; set; } = "Unknown";
        public string Chipset { get; set; } = "Unknown";
        public string DriverVersion { get; set; } = string.Empty;
        public bool MonitorModeSupported { get; set; }
        public string MonitorModeReason { get; set; } = string.Empty;
        public bool PacketInjectionSupported { get; set; }
        public List<string> SupportedBands { get; set; } = new();
        public int CurrentChannel { get; set; }
        public bool IsChannelHopping { get; set; }
        public int TxPowerDbm { get; set; }
        public string Status { get; set; } = "Ready"; // "Ready", "Disabled", "Scanning", "Capturing"
    }

    public class AuditProject
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public string AuditorName { get; set; } = string.Empty;
        public string CreatedAt { get; set; } = string.Empty;
        public string UpdatedAt { get; set; } = string.Empty;
        public string Notes { get; set; } = string.Empty;
        public int SavedNetworksCount { get; set; }
        public int CapturedHandshakesCount { get; set; }
    }

    public class AuditLog
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Timestamp { get; set; } = DateTime.Now.ToString("HH:mm:ss.fff");
        public string Level { get; set; } = "INFO"; // "INFO", "WARN", "ERROR", "SUCCESS", "SEC_ALERT"
        public string Source { get; set; } = "SYSTEM";
        public string Message { get; set; } = string.Empty;
    }
}
