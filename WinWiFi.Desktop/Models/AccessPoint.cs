using System;
using System.Collections.Generic;

namespace WinWiFi.Models
{
    public class AccessPoint
    {
        public string Bssid { get; set; } = string.Empty;
        public string Ssid { get; set; } = string.Empty;
        public int Channel { get; set; }
        public string Band { get; set; } = "2.4 GHz"; // "2.4 GHz", "5 GHz", "6 GHz"
        public int FrequencyMHz { get; set; }
        public int Rssi { get; set; } // in dBm
        public uint SignalQuality { get; set; } // 0-100%
        public string Security { get; set; } = "Open";
        public string Cipher { get; set; } = "None";
        public string PhyType { get; set; } = "802.11ax";
        public int ChannelWidth { get; set; } = 20; // 20, 40, 80, 160 MHz
        public string SecondaryChannelOffset { get; set; } = "None";
        public string Vendor { get; set; } = "Unknown";
        public int BeaconCount { get; set; } = 1;
        public int DataPacketCount { get; set; }
        public int SecurityScore { get; set; } = 100; // 0 to 100
        public bool IsRogue { get; set; }
        public bool IsHidden { get; set; }

        // PMF (802.11w) Status
        public bool PmfRequired { get; set; }
        public bool PmfCapable { get; set; }
        public bool PmfInformationAvailable { get; set; }
        public string PmfStatus => PmfRequired ? "Required" : (PmfCapable ? "Capable" : "Unknown / Not Exposed / Unsupported");

        // WPS 1.0 / 2.0 Details
        public bool IsWpsEnabled { get; set; }
        public bool IsWpsLocked { get; set; }
        public string WpsVersion { get; set; } = "Unknown / Not Exposed / Unsupported";
        public string WpsState { get; set; } = "Unknown / Not Exposed / Unsupported";
        public string WpsDeviceName { get; set; } = string.Empty;
        public string WpsManufacturer { get; set; } = string.Empty;
        public string WpsModelName { get; set; } = string.Empty;

        // RSN Cryptographic Suites
        public List<string> AkmSuites { get; set; } = new();
        public List<string> PairwiseCiphers { get; set; } = new();
        public string GroupCipher { get; set; } = "None";

        // Radio & PHY Details
        public double MaxRateMbps { get; set; }
        public string CountryCode { get; set; } = string.Empty;
        public ushort CapabilityFlags { get; set; }
        public ushort BeaconInterval { get; set; } = 100;
        public string PhyCapabilitiesSummary { get; set; } = string.Empty;

        // History & Activity
        public string FirstSeen { get; set; } = string.Empty;
        public string LastSeen { get; set; } = string.Empty;
        public DateTime LastSeenTime { get; set; } = DateTime.UtcNow;
        public bool IsActiveInCurrentScan { get; set; } = true;
        public int DisappearedScanCycles { get; set; } = 0;
        public List<int> RssiHistory { get; set; } = new();
        public List<uint> SignalQualityHistory { get; set; } = new();

        // Enterprise Asset Classification & Audit
        public string Classification { get; set; } = "Unknown"; // "Corporate", "Guest", "IoT", "Unknown", "Suspicious", "Rogue", "Trusted"
        public string ApprovedStatus { get; set; } = "Pending Review"; // "Approved", "Unapproved", "Investigating", "Pending Review"
        public string Ownership { get; set; } = string.Empty;
        public string Site { get; set; } = string.Empty;
        public string Building { get; set; } = string.Empty;
        public string Floor { get; set; } = string.Empty;
        public string Notes { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = new();
        public int HistoricalObservationsCount { get; set; } = 1;

        public List<ConnectedClient> Clients { get; set; } = new();
        public List<SecurityIssue> SecurityIssues { get; set; } = new();
        public HandshakeInfo? Handshake { get; set; }

        public string SignalDisplay => $"{Rssi} dBm ({SignalQuality}%)";
        public string ChannelDisplay => $"Ch {Channel} ({Band}, {ChannelWidth} MHz)";
        public string SecuritySummary => $"{Security} [{Cipher}]";
    }

    public class ConnectedClient
    {
        public string MacAddress { get; set; } = string.Empty;
        public string Vendor { get; set; } = "Unknown";
        public int Rssi { get; set; }
        public int PacketsSent { get; set; }
        public string LastActivity { get; set; } = string.Empty;
        public List<string> ProbeRequests { get; set; } = new();
    }

    public class SecurityIssue
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Severity { get; set; } = "LOW"; // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
        public string Description { get; set; } = string.Empty;
        public string Remediation { get; set; } = string.Empty;
        public string StandardReference { get; set; } = "NIST SP 800-153";
    }
}
