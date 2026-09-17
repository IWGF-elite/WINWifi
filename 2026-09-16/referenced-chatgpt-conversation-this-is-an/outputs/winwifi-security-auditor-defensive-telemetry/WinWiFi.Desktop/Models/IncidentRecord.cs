using System;
using System.Collections.Generic;

namespace WinWiFi.Models
{
    public class IncidentRecord
    {
        public string Id { get; set; } = string.Empty; // e.g., "INC-00042"
        public string Title { get; set; } = string.Empty;
        public string Severity { get; set; } = "HIGH"; // "CRITICAL", "HIGH", "MEDIUM", "LOW"
        public int Confidence { get; set; } = 85; // 0-100%
        public string Status { get; set; } = "New"; // "New", "Investigating", "Confirmed", "False Positive", "Resolved", "Dismissed"
        public string CreatedAt { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        public string UpdatedAt { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        public string AssignedTo { get; set; } = "SecOps Wireless Triage";
        public string Summary { get; set; } = string.Empty;
        public string? BssidTarget { get; set; }
        public string? SsidTarget { get; set; }
        public string? ThreatFindingId { get; set; }
        public List<string> EvidenceIds { get; set; } = new();
        public List<IncidentTimelineItem> Timeline { get; set; } = new();
        public List<IncidentNote> Notes { get; set; } = new();
        public string? Resolution { get; set; }
    }

    public class IncidentTimelineItem
    {
        public string Timestamp { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        public string EventType { get; set; } = "STATUS_CHANGE"; // "DETECTION", "STATUS_CHANGE", "NOTE_ADDED", "EVIDENCE_ATTACHED", "RESOLVED"
        public string Description { get; set; } = string.Empty;
        public string Actor { get; set; } = "System";
    }

    public class IncidentNote
    {
        public string Timestamp { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        public string Author { get; set; } = string.Empty;
        public string Text { get; set; } = string.Empty;
    }

    public class ThreatFinding
    {
        public string Id { get; set; } = string.Empty; // e.g. "THR-802-01"
        public string Category { get; set; } = "Rogue AP"; // "Rogue AP", "Evil Twin", "Security Downgrade", "PMF Stripped", "WPS Exposed", "BSSID Spoofing", "Unapproved Hardware"
        public string Title { get; set; } = string.Empty;
        public string Severity { get; set; } = "HIGH"; // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
        public int Confidence { get; set; } = 85; // 0-100%
        public int RiskScore { get; set; } = 80; // 0-100
        public string DetectedAt { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        public string RelatedBssid { get; set; } = string.Empty;
        public string RelatedSsid { get; set; } = string.Empty;
        public string Evidence { get; set; } = string.Empty;
        public string Explanation { get; set; } = string.Empty;
        public string Remediation { get; set; } = string.Empty;
        public string Status { get; set; } = "New"; // "New", "Investigating", "Confirmed", "False Positive", "Resolved"
        public string StandardReference { get; set; } = "NIST SP 800-153 §4.2";
    }

    public class SecurityChange
    {
        public string Id { get; set; } = string.Empty;
        public string Bssid { get; set; } = string.Empty;
        public string Ssid { get; set; } = string.Empty;
        public string Timestamp { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        public string Type { get; set; } = "security_downgrade"; // "security_downgrade", "pmf_disabled", "wps_enabled", "channel_shift", "bssid_drift", "vendor_mismatch"
        public string Title { get; set; } = string.Empty;
        public string Before { get; set; } = string.Empty;
        public string After { get; set; } = string.Empty;
        public string RiskImpact { get; set; } = "HIGH"; // "CRITICAL", "HIGH", "MEDIUM", "LOW"
        public string? EvidenceId { get; set; }
        public List<string>? EvidenceIds { get; set; }
    }

    public class StationClientRecord
    {
        public string MacAddress { get; set; } = string.Empty;
        public string Vendor { get; set; } = "Unknown";
        public string FirstSeen { get; set; } = string.Empty;
        public string LastSeen { get; set; } = string.Empty;
        public int Rssi { get; set; } = -70;
        public int Channel { get; set; } = 6;
        public string Band { get; set; } = "2.4 GHz";
        public string AssociatedApBssid { get; set; } = "Unavailable (Windows NDIS)";
        public string AssociatedApSsid { get; set; } = "Not Provable from OS Scan";
        public bool IsAssociated { get; set; } = false;
        public List<string> ProbeRequests { get; set; } = new();
        public int PacketsCount { get; set; } = 1;
        public string RiskAssessment { get; set; } = "Low Risk (Standard Station)";
        public bool IsRandomizedMac { get; set; }
        public string DisplayProbeRequests => ProbeRequests.Count > 0 ? string.Join(", ", ProbeRequests) : "None observed";
    }

    public class EnterpriseAssetRecord
    {
        public string Id { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string Ssid { get; set; } = string.Empty;
        public string AssetType { get; set; } = "Access Point"; // "Access Point", "Client Station", "IoT Gateway", "Sensor"
        public string Classification { get; set; } = "Corporate"; // "Corporate", "Guest", "IoT", "Unknown", "Suspicious", "Rogue"
        public string ApprovalStatus { get; set; } = "Approved"; // "Approved", "Unapproved", "Under Investigation", "Decommissioned"
        public string Site { get; set; } = "HQ Primary Campus";
        public string Building { get; set; } = "Bldg A";
        public string AreaFloor { get; set; } = "Floor 2";
        public string OwnerDepartment { get; set; } = "Enterprise IT / NetOps";
        public string Vendor { get; set; } = "Unknown";
        public string Model { get; set; } = "Standard Enterprise AP";
        public string LastSeen { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        public string Notes { get; set; } = string.Empty;
    }

    public class ComplianceCheckItem
    {
        public string RuleId { get; set; } = string.Empty;
        public string Standard { get; set; } = "NIST SP 800-153";
        public string Section { get; set; } = "§4.2";
        public string Requirement { get; set; } = string.Empty;
        public string Status { get; set; } = "PASS"; // "PASS", "FAIL", "WARN", "MANUAL_REVIEW"
        public int ViolationsCount { get; set; } = 0;
        public string Severity { get; set; } = "HIGH";
        public string Recommendation { get; set; } = string.Empty;
    }

    public class EvidenceItem
    {
        public string EvidenceId { get; set; } = string.Empty; // e.g. "EVD-001"
        public string Type { get; set; } = "LIVE_THREAT_FINDING";
        public string Title { get; set; } = string.Empty;
        public string Source { get; set; } = "Live Windows WLAN";
        public string Timestamp { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        public string AssociatedIncidentId { get; set; } = string.Empty;
        public string Sha256Checksum { get; set; } = string.Empty;
        public string PayloadSummary { get; set; } = string.Empty;
    }

}
