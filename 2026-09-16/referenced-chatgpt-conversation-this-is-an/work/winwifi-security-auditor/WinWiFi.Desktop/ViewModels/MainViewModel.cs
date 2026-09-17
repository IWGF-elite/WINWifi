using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinWiFi.Data;
using WinWiFi.Models;
using WinWiFi.Services;
using WinWiFi.Tests;

namespace WinWiFi.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        private readonly INativeWifiService _wifiService;
        private readonly SqliteStorageService _storage;
        private readonly PcapDissector _pcapDissector;
        private readonly SecurityAnalyzer _securityAnalyzer;
        private readonly ReportGenerator _reportGenerator;
        private readonly WifiBackgroundScanner _backgroundScanner;

        private Dictionary<string, AccessPoint> _baselineAps = new(StringComparer.OrdinalIgnoreCase);

        // Core Observables
        [ObservableProperty]
        private ObservableCollection<AccessPoint> _accessPoints = new();

        [ObservableProperty]
        private AccessPoint? _selectedAccessPoint;

        [ObservableProperty]
        private ObservableCollection<StationClientRecord> _stationClients = new();

        [ObservableProperty]
        private StationClientRecord? _selectedStationClient;

        [ObservableProperty]
        private ObservableCollection<ThreatFinding> _threatFindings = new();

        [ObservableProperty]
        private ThreatFinding? _selectedThreatFinding;

        [ObservableProperty]
        private ObservableCollection<SecurityChange> _securityDrifts = new();

        [ObservableProperty]
        private ObservableCollection<IncidentRecord> _incidents = new();

        [ObservableProperty]
        private IncidentRecord? _selectedIncident;

        [ObservableProperty]
        private ObservableCollection<EnterpriseAssetRecord> _enterpriseAssets = new();

        [ObservableProperty]
        private EnterpriseAssetRecord? _selectedEnterpriseAsset;

        [ObservableProperty]
        private ObservableCollection<WifiAdapter> _adapters = new();

        [ObservableProperty]
        private WifiAdapter? _selectedAdapter;

        [ObservableProperty]
        private ObservableCollection<PcapPacket> _packets = new();

        [ObservableProperty]
        private PcapPacket? _selectedPacket;

        [ObservableProperty]
        private ObservableCollection<HandshakeInfo> _handshakes = new();

        [ObservableProperty]
        private HandshakeInfo? _selectedHandshake;

        [ObservableProperty]
        private ObservableCollection<AuditProject> _projects = new();

        [ObservableProperty]
        private AuditProject? _currentProject;

        [ObservableProperty]
        private ObservableCollection<AuditLog> _logs = new();

        [ObservableProperty]
        private ObservableCollection<ComplianceCheckItem> _complianceItems = new();

        [ObservableProperty]
        private ObservableCollection<EvidenceItem> _evidenceItems = new();

        [ObservableProperty]
        private ObservableCollection<OfflineLabScenario> _labScenarios = new();

        [ObservableProperty]
        private OfflineLabScenario? _selectedLabScenario;

        [ObservableProperty]
        private string _newIncidentNoteText = string.Empty;

        // UI State
        [ObservableProperty]
        private bool _isScanning = true;

        [ObservableProperty]
        private int _currentChannel = 6;

        [ObservableProperty]
        private string _activeTab = "Dashboard"; // "Dashboard", "Discovery", "Clients", "Threats", "Drift", "RF", "Packets", "Handshakes", "Incidents", "Assets", "Database", "Tests"

        [ObservableProperty]
        private string _dataSourceProfile = "Native WlanApi / NDIS Scan";

        [ObservableProperty]
        private bool _isDarkMode = true;

        [ObservableProperty]
        private bool _isExpertMode = false;

        [ObservableProperty]
        private ScanTelemetryState _telemetryState = ScanTelemetryState.Idle;

        [ObservableProperty]
        private string _scanDiagnosticsText = "Ready";

        [ObservableProperty]
        private bool _isInitializing = true;

        [ObservableProperty]
        private string _initializationStatus = "Initializing...";

        [ObservableProperty]
        private int _initializationProgress = 0;

        // Metric Card Summaries
        [ObservableProperty]
        private int _totalApsCount;

        [ObservableProperty]
        private int _rogueApsCount;

        [ObservableProperty]
        private int _stationsCount;

        [ObservableProperty]
        private int _threatsCount;

        [ObservableProperty]
        private int _openIncidentsCount;

        [ObservableProperty]
        private int _handshakesCount;

        [ObservableProperty]
        private int _overallRiskScore;

        [ObservableProperty]
        private int _band24Count;

        [ObservableProperty]
        private int _band5Count;

        [ObservableProperty]
        private int _band6Count;

        [ObservableProperty]
        private string _rfCongestionSummary = "Normal";

        private void RunOnUi(Action action)
        {
            if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
            {
                dispatcher.Invoke(action);
            }
            else
            {
                action();
            }
        }

        public MainViewModel(
            INativeWifiService wifiService,
            SqliteStorageService storage,
            PcapDissector pcapDissector,
            SecurityAnalyzer securityAnalyzer,
            ReportGenerator reportGenerator,
            WifiBackgroundScanner backgroundScanner)
        {
            _wifiService = wifiService;
            _storage = storage;
            _pcapDissector = pcapDissector;
            _securityAnalyzer = securityAnalyzer;
            _reportGenerator = reportGenerator;
            _backgroundScanner = backgroundScanner;

            _backgroundScanner.ChannelHopped += ch =>
            {
                RunOnUi(() => CurrentChannel = ch);
            };
            _backgroundScanner.NetworksDiscovered += OnNetworksDiscovered;
            _backgroundScanner.StateChanged += state =>
            {
                RunOnUi(() =>
                {
                    TelemetryState = state;
                    ScanDiagnosticsText = $"Scanner: {state}";
                });
            };
            _backgroundScanner.DiagnosticsUpdated += diag =>
            {
                RunOnUi(() =>
                {
                    ScanDiagnosticsText = $"Scanner: {diag.State} | BSS: {diag.LastDiscoveredBssCount} | Dur: {diag.LastScanDurationMs}ms | Cycles: {diag.TotalScanCycles}";
                });
            };
        }

        public async Task InitializeAsync()
        {
            var totalSw = System.Diagnostics.Stopwatch.StartNew();
            IsInitializing = true;
            InitializationProgress = 5;
            InitializationStatus = "Starting diagnostic subsystems...";
            AddLog("INFO", "STARTUP", "Starting asynchronous application subsystem initialization...");

            // 1. Load Projects from SQLite
            InitializationProgress = 20;
            InitializationStatus = "Connecting to SQLite audit database...";
            var pSw = System.Diagnostics.Stopwatch.StartNew();
            var projs = await _storage.GetProjectsAsync();
            pSw.Stop();
            Projects = new ObservableCollection<AuditProject>(projs);
            CurrentProject = Projects.FirstOrDefault() ?? new AuditProject
            {
                Id = "proj-default",
                Name = "Default Wireless Audit Workspace",
                Location = "HQ Campus",
                AuditorName = "Senior SecOps Engineer"
            };
            _backgroundScanner.SetActiveProject(CurrentProject.Id);
            AddLog("INFO", "STARTUP", $"SQLite repository verified ({projs.Count} project(s) in {pSw.ElapsedMilliseconds}ms).");

            // 2. Load Historical Data for Current Project
            InitializationProgress = 45;
            InitializationStatus = "Loading historical baseline & incidents...";
            var hSw = System.Diagnostics.Stopwatch.StartNew();
            if (CurrentProject != null)
            {
                int removedInvalidRows = await _storage.RemoveInvalidAccessPointsAsync(CurrentProject.Id);
                if (removedInvalidRows > 0)
                {
                    AddLog("WARN", "DATA_QUALITY", $"Removed {removedInvalidRows} malformed legacy Wi-Fi record(s) from the local audit history.");
                }
                var storedAps = await _storage.GetAccessPointsAsync(CurrentProject.Id);
                if (storedAps.Count > 0)
                {
                    AccessPoints = new ObservableCollection<AccessPoint>(storedAps);
                    SelectedAccessPoint = AccessPoints.FirstOrDefault();
                    foreach (var ap in storedAps)
                    {
                        _baselineAps[ap.Bssid] = ap;
                    }
                }

                var storedClients = await _storage.GetStationClientsAsync(CurrentProject.Id);
                StationClients = new ObservableCollection<StationClientRecord>(storedClients);

                var storedIncidents = await _storage.GetIncidentsAsync(CurrentProject.Id);
                Incidents = new ObservableCollection<IncidentRecord>(storedIncidents);

                var storedDrifts = await _storage.GetSecurityChangesAsync(CurrentProject.Id);
                SecurityDrifts = new ObservableCollection<SecurityChange>(storedDrifts);

                var storedAssets = await _storage.GetEnterpriseAssetsAsync(CurrentProject.Id);
                EnterpriseAssets = new ObservableCollection<EnterpriseAssetRecord>(storedAssets);

                var storedHandshakes = await _storage.GetHandshakesAsync(CurrentProject.Id);
                Handshakes = new ObservableCollection<HandshakeInfo>(storedHandshakes);
            }
            hSw.Stop();
            AddLog("INFO", "STARTUP", $"Historical baseline loaded ({AccessPoints.Count} APs, {Incidents.Count} incidents in {hSw.ElapsedMilliseconds}ms).");

            // 3. Enumerate Native Wi-Fi Adapters
            InitializationProgress = 70;
            InitializationStatus = "Querying wireless hardware interfaces...";
            var aSw = System.Diagnostics.Stopwatch.StartNew();
            var adapterList = await _wifiService.GetAdaptersAsync();
            aSw.Stop();
            Adapters = new ObservableCollection<WifiAdapter>(adapterList);
            SelectedAdapter = Adapters.FirstOrDefault();

            if (SelectedAdapter != null)
            {
                _backgroundScanner.SetActiveAdapter(SelectedAdapter.Id);
                AddLog("SUCCESS", "ADAPTER_MGR", $"Bound to physical wireless adapter: {SelectedAdapter.Name} ({SelectedAdapter.Vendor}) in {aSw.ElapsedMilliseconds}ms");
            }
            else
            {
                AddLog("WARN", "ADAPTER_MGR", $"No physical Wi-Fi interface detected or running without elevation ({aSw.ElapsedMilliseconds}ms). PCAP & Netsh analysis ready.");
            }

            // 4. Initialize Offline Lab Scenarios
            InitializationProgress = 90;
            InitializationStatus = "Configuring lab scenarios & metrics...";
            LabScenarios = new ObservableCollection<OfflineLabScenario>
            {
                new() { Id = "LAB-01", Title = "Modern Enterprise Baseline (WPA3-SAE / PMF)", Category = "Compliant", Difficulty = "Beginner", Description = "Enterprise deployment adhering to NIST SP 800-153 with mandatory PMF.", LearningObjective = "Verify SAE and MFPR bit flags.", ApCount = 2, TargetThreat = "None" },
                new() { Id = "LAB-02", Title = "Evil Twin Rogue AP Downgrade", Category = "Attack Scenario", Difficulty = "Intermediate", Description = "Attacker broadcasts corporate SSID with Open / WEP encryption to harvest credentials.", LearningObjective = "Identify security profile divergence.", ApCount = 2, TargetThreat = "Rogue AP / Clone" },
                new() { Id = "LAB-03", Title = "Legacy WEP Warehouse Network", Category = "Vulnerability", Difficulty = "Beginner", Description = "Deprecated WEP-128 static shared key in logistics warehouse.", LearningObjective = "Detect unencrypted IVs and NIST §4.2 failure.", ApCount = 1, TargetThreat = "Insecure Encryption" },
                new() { Id = "LAB-04", Title = "WPS External Registrar PIN Flaw", Category = "Vulnerability", Difficulty = "Intermediate", Description = "Access Point with active WPS registrar susceptible to Pixie Dust offline brute force.", LearningObjective = "Decode Tag 221 sub-element 0x1044.", ApCount = 1, TargetThreat = "WPS Active" },
                new() { Id = "LAB-05", Title = "Missing PMF & Deauth Vulnerability", Category = "Vulnerability", Difficulty = "Intermediate", Description = "High-density AP without 802.11w support vulnerable to Layer-2 deauth injection.", LearningObjective = "Verify RSN Capabilities Bit 6 & 7.", ApCount = 1, TargetThreat = "PMF Disabled" },
                new() { Id = "LAB-06", Title = "EAPOL 4-Way Handshake Capture", Category = "Forensics", Difficulty = "Advanced", Description = "Complete Message 1-4 exchange for offline Hashcat Mode 22000 verification.", LearningObjective = "Inspect ANonce, SNonce, and MIC validation.", ApCount = 1, TargetThreat = "Key Exchange" }
            };
            SelectedLabScenario = LabScenarios.FirstOrDefault();

            RecalculateMetrics();

            totalSw.Stop();
            InitializationProgress = 100;
            InitializationStatus = "Ready";
            IsInitializing = false;
            AddLog("SUCCESS", "STARTUP", $"Application initialization completed in {totalSw.ElapsedMilliseconds}ms.");
        }

        partial void OnSelectedAdapterChanged(WifiAdapter? value)
        {
            if (value == null)
            {
                return;
            }

            _backgroundScanner.SetActiveAdapter(value.Id);
            AddLog("INFO", "ADAPTER_MGR", $"Live telemetry adapter changed to {value.Name} ({value.Id}).");
        }

        [RelayCommand]
        public async Task RefreshAdapters()
        {
            try
            {
                string? previouslySelectedId = SelectedAdapter?.Id;
                var adapterList = await _wifiService.GetAdaptersAsync();
                Adapters = new ObservableCollection<WifiAdapter>(adapterList);
                SelectedAdapter = Adapters.FirstOrDefault(adapter => adapter.Id.Equals(previouslySelectedId, StringComparison.OrdinalIgnoreCase))
                    ?? Adapters.FirstOrDefault();

                if (SelectedAdapter == null)
                {
                    ScanDiagnosticsText = "No Wi-Fi adapter detected. Verify that Wi-Fi is enabled, then refresh.";
                    AddLog("WARN", "ADAPTER_MGR", "Adapter refresh returned no wireless interfaces.");
                    return;
                }

                ScanDiagnosticsText = $"Ready: {SelectedAdapter.Name} ({SelectedAdapter.Status})";
                AddLog("SUCCESS", "ADAPTER_MGR", $"Refreshed {Adapters.Count} wireless adapter(s); using {SelectedAdapter.Name}.");
            }
            catch (Exception exception)
            {
                ScanDiagnosticsText = $"Adapter refresh failed: {exception.Message}";
                AddLog("ERROR", "ADAPTER_MGR", $"Adapter refresh failed: {exception.Message}");
            }
        }

        private void OnNetworksDiscovered(List<AccessPoint> networks)
        {
            RunOnUi(() =>
            {
                foreach (var net in networks)
                {
                    _securityAnalyzer.EvaluateSecurityPosture(net);

                    var existing = AccessPoints.FirstOrDefault(a => a.Bssid.Equals(net.Bssid, StringComparison.OrdinalIgnoreCase));
                    if (existing != null)
                    {
                        existing.Rssi = net.Rssi;
                        existing.SignalQuality = net.SignalQuality;
                        existing.LastSeen = net.LastSeen;
                        existing.HistoricalObservationsCount++;
                        existing.Security = net.Security;
                        existing.Cipher = net.Cipher;
                        existing.Channel = net.Channel;
                        existing.Band = net.Band;
                        existing.PmfRequired = net.PmfRequired;
                        existing.PmfCapable = net.PmfCapable;
                        existing.IsWpsEnabled = net.IsWpsEnabled;
                        existing.IsWpsLocked = net.IsWpsLocked;
                        existing.SecurityScore = net.SecurityScore;
                        existing.SecurityIssues = net.SecurityIssues;

                        existing.RssiHistory.Add(net.Rssi);
                        if (existing.RssiHistory.Count > 30) existing.RssiHistory.RemoveAt(0);
                        existing.SignalQualityHistory.Add(net.SignalQuality);
                        if (existing.SignalQualityHistory.Count > 30) existing.SignalQualityHistory.RemoveAt(0);
                    }
                    else
                    {
                        net.HistoricalObservationsCount = 1;
                        net.RssiHistory.Add(net.Rssi);
                        net.SignalQualityHistory.Add(net.SignalQuality);
                        AccessPoints.Add(net);
                        SelectedAccessPoint ??= net;
                    }
                }

                // Run Multi-Factor Threat & Drift Detection
                RunThreatAnalysis();

                // Persist current observation snapshot to SQLite asynchronously with exception guard
                if (CurrentProject != null)
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await _storage.SaveAccessPointsAsync(CurrentProject.Id, networks);
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"[MainViewModel] Failed to save APs to SQLite: {ex.Message}");
                        }
                    });
                }

                RecalculateMetrics();
            });
        }

        private void RunThreatAnalysis()
        {
            var analysis = _securityAnalyzer.AnalyzeThreatsAndDrift(AccessPoints.ToList(), _baselineAps);

            // Synchronize findings
            ThreatFindings.Clear();
            foreach (var f in analysis.Findings)
            {
                ThreatFindings.Add(f);
            }

            // Synchronize drifts
            foreach (var drift in analysis.DetectedDrifts)
            {
                if (!SecurityDrifts.Any(d => d.Bssid.Equals(drift.Bssid, StringComparison.OrdinalIgnoreCase) && d.Type == drift.Type))
                {
                    SecurityDrifts.Insert(0, drift);
                    if (CurrentProject != null)
                    {
                        _ = _storage.SaveSecurityChangesAsync(CurrentProject.Id, new[] { drift });
                    }
                }
            }

            OverallRiskScore = analysis.OverallRiskScore;
        }

        public void RecalculateMetrics()
        {
            TotalApsCount = AccessPoints.Count;
            RogueApsCount = AccessPoints.Count(a => a.IsRogue) + ThreatFindings.Count(t => t.Category == "Rogue AP" || t.Category == "Evil Twin");
            StationsCount = StationClients.Count;
            ThreatsCount = ThreatFindings.Count;
            OpenIncidentsCount = Incidents.Count(i => i.Status == "New" || i.Status == "Investigating" || i.Status == "Confirmed");
            HandshakesCount = Handshakes.Count;

            Band24Count = AccessPoints.Count(a => a.Band.Contains("2.4"));
            Band5Count = AccessPoints.Count(a => a.Band.Contains("5"));
            Band6Count = AccessPoints.Count(a => a.Band.Contains("6"));

            // Calculate RF Congestion
            var ch1Count = AccessPoints.Count(a => a.Channel == 1);
            var ch6Count = AccessPoints.Count(a => a.Channel == 6);
            var ch11Count = AccessPoints.Count(a => a.Channel == 11);
            int maxChCount = Math.Max(ch1Count, Math.Max(ch6Count, ch11Count));
            RfCongestionSummary = maxChCount > 6 ? "High Congestion" : (maxChCount > 3 ? "Moderate Occupancy" : "Clean RF Medium");

            RefreshComplianceAndEvidence();
        }

        public void RefreshComplianceAndEvidence()
        {
            int openCount = AccessPoints.Count(a => a.Security.Contains("Open") || a.Security.Contains("None"));
            int legacyCount = AccessPoints.Count(a => a.Security.Contains("WEP") || a.Cipher.Contains("TKIP") || a.Security.Contains("TKIP"));
            int wpsCount = AccessPoints.Count(a => a.IsWpsEnabled);
            int noPmfCount = AccessPoints.Count(a => !a.PmfRequired && !a.PmfCapable);
            int rogueCount = RogueApsCount;

            ComplianceItems.Clear();
            ComplianceItems.Add(new ComplianceCheckItem
            {
                RuleId = "NIST-01",
                Standard = "NIST SP 800-153",
                Section = "§4.1",
                Requirement = "Prohibit unencrypted / cleartext open wireless networks",
                Status = openCount > 0 ? "FAIL" : "PASS",
                ViolationsCount = openCount,
                Severity = "CRITICAL",
                Recommendation = "Enforce 802.11i WPA2-Enterprise or WPA3-SAE on all corporate SSIDs."
            });
            ComplianceItems.Add(new ComplianceCheckItem
            {
                RuleId = "NIST-02",
                Standard = "NIST SP 800-153",
                Section = "§4.2",
                Requirement = "Prohibit deprecated legacy ciphers (WEP and WPA-TKIP)",
                Status = legacyCount > 0 ? "FAIL" : "PASS",
                ViolationsCount = legacyCount,
                Severity = "CRITICAL",
                Recommendation = "Migrate legacy client profiles to CCMP (AES-128) or GCMP-256."
            });
            ComplianceItems.Add(new ComplianceCheckItem
            {
                RuleId = "NIST-03",
                Standard = "NIST SP 800-153",
                Section = "§4.3",
                Requirement = "Disable Wi-Fi Protected Setup (WPS) external registrar",
                Status = wpsCount > 0 ? "WARN" : "PASS",
                ViolationsCount = wpsCount,
                Severity = "HIGH",
                Recommendation = "Disable WPS PIN and PBC modes in AP firmware to prevent brute force."
            });
            ComplianceItems.Add(new ComplianceCheckItem
            {
                RuleId = "NIST-04",
                Standard = "NIST SP 800-153",
                Section = "§4.4",
                Requirement = "Enforce 802.11w Protected Management Frames (PMF) on unicast/mgmt",
                Status = noPmfCount > 0 ? "WARN" : "PASS",
                ViolationsCount = noPmfCount,
                Severity = "HIGH",
                Recommendation = "Set PMF (MFPR / MFPC) to Required or Capable to prevent deauthentication floods."
            });
            ComplianceItems.Add(new ComplianceCheckItem
            {
                RuleId = "PCI-01",
                Standard = "PCI-DSS v4.0",
                Section = "Req 11.2.1",
                Requirement = "Detect and identify all unauthorized / rogue wireless access points",
                Status = rogueCount > 0 ? "FAIL" : "PASS",
                ViolationsCount = rogueCount,
                Severity = "CRITICAL",
                Recommendation = "Physically locate and decommission unauthorized transmitters within Cardholder Data Environment."
            });

            EvidenceItems.Clear();
            foreach (var th in ThreatFindings)
            {
                EvidenceItems.Add(new EvidenceItem
                {
                    EvidenceId = $"EVD-THR-{th.Id}",
                    Type = "THREAT_FINDING",
                    Title = th.Title,
                    Source = $"Security Engine / {th.RelatedBssid}",
                    Timestamp = th.DetectedAt,
                    AssociatedIncidentId = th.Id,
                    Sha256Checksum = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(th.Evidence + th.RelatedBssid))).Substring(0, 16),
                    PayloadSummary = th.Evidence
                });
            }
            foreach (var hs in Handshakes)
            {
                EvidenceItems.Add(new EvidenceItem
                {
                    EvidenceId = $"EVD-HSH-{hs.ApBssid.Replace(":", "")}",
                    Type = "CRYPTOGRAPHIC_KEY_EXCHANGE",
                    Title = $"EAPOL Handshake ({hs.Ssid})",
                    Source = $"Radio Capture / {hs.ClientMac}",
                    Timestamp = hs.CapturedAt,
                    AssociatedIncidentId = "N/A",
                    Sha256Checksum = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(hs.HashcatFormat ?? hs.ApBssid))).Substring(0, 16),
                    PayloadSummary = $"ANonce: {(hs.AnonCe != null && hs.AnonCe.Length >= 16 ? hs.AnonCe.Substring(0, 16) : hs.AnonCe)}... MIC: {hs.MicHex}"
                });
            }
        }

        [RelayCommand]
        public void SwitchTab(string tabName)
        {
            ActiveTab = tabName;
            AddLog("INFO", "NAVIGATION", $"Switched to workspace: {tabName}");
        }

        [RelayCommand]
        public void ToggleExpertMode()
        {
            IsExpertMode = !IsExpertMode;
            AddLog("INFO", "UI_MODE", IsExpertMode ? "Switched to Expert Presentation Layer (Raw cryptographic bits, IE tags, frame dissections)." : "Switched to Beginner Presentation Layer (Executive summaries, plain-English guidance).");
        }

        [RelayCommand]
        public void ToggleScan()
        {
            IsScanning = !IsScanning;
            _backgroundScanner.SetScanningState(IsScanning);
            AddLog("INFO", "SCAN_CONTROL", IsScanning ? "Resumed live Windows WLAN telemetry." : "Paused scanning engine.");
        }

        [RelayCommand]
        public void SetBaselineFromCurrent()
        {
            _baselineAps.Clear();
            foreach (var ap in AccessPoints)
            {
                _baselineAps[ap.Bssid] = new AccessPoint
                {
                    Bssid = ap.Bssid,
                    Ssid = ap.Ssid,
                    Channel = ap.Channel,
                    Band = ap.Band,
                    Security = ap.Security,
                    Cipher = ap.Cipher,
                    Vendor = ap.Vendor,
                    PmfRequired = ap.PmfRequired,
                    PmfCapable = ap.PmfCapable,
                    IsWpsEnabled = ap.IsWpsEnabled,
                    Classification = ap.Classification,
                    ApprovedStatus = ap.ApprovedStatus
                };
            }

            RunThreatAnalysis();
            AddLog("SUCCESS", "DRIFT_MONITOR", $"Established new baseline snapshot with {_baselineAps.Count} authorized access points.");
        }

        [RelayCommand]
        public async Task PromoteThreatToIncident(ThreatFinding? finding)
        {
            if (finding == null && SelectedThreatFinding != null) finding = SelectedThreatFinding;
            if (finding == null || CurrentProject == null) return;

            var inc = new IncidentRecord
            {
                Id = $"INC-{DateTime.UtcNow:yyyyMMdd}-{Incidents.Count + 1:D3}",
                Title = finding.Title,
                Severity = finding.Severity,
                Confidence = finding.Confidence,
                Status = "New",
                AssignedTo = "SecOps Wireless Triage",
                Summary = $"{finding.Explanation}\n\nEvidence: {finding.Evidence}\n\nRecommended Remediation: {finding.Remediation}",
                BssidTarget = finding.RelatedBssid,
                SsidTarget = finding.RelatedSsid,
                ThreatFindingId = finding.Id,
                EvidenceIds = new List<string> { finding.Id, finding.RelatedBssid },
                CreatedAt = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                UpdatedAt = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
            };

            inc.Timeline.Add(new IncidentTimelineItem
            {
                EventType = "DETECTION",
                Description = $"Automated detection via heuristic rule {finding.StandardReference}: {finding.Evidence}",
                Actor = "Security Engine"
            });

            Incidents.Insert(0, inc);
            SelectedIncident = inc;
            finding.Status = "Investigating";

            await _storage.SaveIncidentAsync(CurrentProject.Id, inc);
            AddLog("SEC_ALERT", "INCIDENT_MGR", $"Created new security incident {inc.Id}: {inc.Title}");
            ActiveTab = "Incidents";
        }

        [RelayCommand]
        public async Task UpdateIncidentStatus(string newStatus)
        {
            if (SelectedIncident == null || CurrentProject == null) return;

            SelectedIncident.Status = newStatus;
            SelectedIncident.UpdatedAt = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            SelectedIncident.Timeline.Add(new IncidentTimelineItem
            {
                EventType = "STATUS_CHANGE",
                Description = $"Status changed to {newStatus}",
                Actor = "Lead Auditor"
            });

            await _storage.SaveIncidentAsync(CurrentProject.Id, SelectedIncident);
            RecalculateMetrics();
            AddLog("INFO", "INCIDENT_MGR", $"Incident {SelectedIncident.Id} marked as '{newStatus}'.");
        }

        [RelayCommand]
        public async Task AddIncidentNote()
        {
            if (SelectedIncident == null || string.IsNullOrWhiteSpace(NewIncidentNoteText) || CurrentProject == null) return;

            var note = new IncidentNote
            {
                Timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                Author = CurrentProject.AuditorName,
                Text = NewIncidentNoteText.Trim()
            };

            SelectedIncident.Notes.Add(note);
            SelectedIncident.UpdatedAt = note.Timestamp;
            SelectedIncident.Timeline.Add(new IncidentTimelineItem
            {
                Timestamp = note.Timestamp,
                EventType = "NOTE_ADDED",
                Description = $"Note by {note.Author}: {note.Text}",
                Actor = note.Author
            });

            NewIncidentNoteText = string.Empty;
            await _storage.SaveIncidentAsync(CurrentProject.Id, SelectedIncident);
            AddLog("INFO", "INCIDENT_MGR", $"Added note to incident {SelectedIncident.Id}");
        }

        [RelayCommand]
        public async Task AddEnterpriseAsset()
        {
            if (SelectedAccessPoint == null || CurrentProject == null) return;

            var existing = EnterpriseAssets.FirstOrDefault(a => a.MacAddress.Equals(SelectedAccessPoint.Bssid, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                existing.Classification = "Corporate";
                existing.ApprovalStatus = "Approved";
                existing.LastSeen = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
                await _storage.SaveEnterpriseAssetsAsync(CurrentProject.Id, new[] { existing });
                AddLog("SUCCESS", "ASSET_MGR", $"Updated asset record for {existing.MacAddress} ({existing.Ssid})");
            }
            else
            {
                var asset = new EnterpriseAssetRecord
                {
                    Id = $"AST-{EnterpriseAssets.Count + 1:D4}",
                    MacAddress = SelectedAccessPoint.Bssid,
                    Ssid = SelectedAccessPoint.Ssid,
                    AssetType = "Access Point",
                    Classification = "Corporate",
                    ApprovalStatus = "Approved",
                    Site = "HQ Primary Campus",
                    Building = "Bldg A",
                    AreaFloor = "Floor 2",
                    OwnerDepartment = "Enterprise IT / NetOps",
                    Vendor = SelectedAccessPoint.Vendor,
                    Model = SelectedAccessPoint.PhyType,
                    LastSeen = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                    Notes = "Approved infrastructure AP via WinWiFi native manager."
                };

                EnterpriseAssets.Insert(0, asset);
                SelectedAccessPoint.Classification = "Corporate";
                SelectedAccessPoint.ApprovedStatus = "Approved";

                await _storage.SaveEnterpriseAssetsAsync(CurrentProject.Id, new[] { asset });
                AddLog("SUCCESS", "ASSET_MGR", $"Enrolled BSSID {asset.MacAddress} ({asset.Ssid}) into enterprise asset repository.");
            }
        }

        [RelayCommand]
        public void ImportPcap(string filePath)
        {
            try
            {
                var result = _pcapDissector.DissectFile(filePath);
                Packets = new ObservableCollection<PcapPacket>(result.Packets);

                foreach (var ap in result.AccessPoints)
                {
                    _securityAnalyzer.EvaluateSecurityPosture(ap);
                    var existing = AccessPoints.FirstOrDefault(a => a.Bssid.Equals(ap.Bssid, StringComparison.OrdinalIgnoreCase));
                    if (existing != null)
                    {
                        existing.BeaconCount += ap.BeaconCount;
                        existing.LastSeen = ap.LastSeen;
                    }
                    else
                    {
                        AccessPoints.Add(ap);
                    }
                }

                foreach (var client in result.Clients)
                {
                    var existing = StationClients.FirstOrDefault(c => c.MacAddress.Equals(client.MacAddress, StringComparison.OrdinalIgnoreCase));
                    if (existing != null)
                    {
                        existing.PacketsCount += client.PacketsCount;
                        existing.LastSeen = client.LastSeen;
                        foreach (var probe in client.ProbeRequests)
                        {
                            if (!existing.ProbeRequests.Contains(probe)) existing.ProbeRequests.Add(probe);
                        }
                    }
                    else
                    {
                        StationClients.Add(client);
                    }
                }

                foreach (var hs in result.Handshakes)
                {
                    if (!Handshakes.Any(h => h.ApBssid.Equals(hs.ApBssid, StringComparison.OrdinalIgnoreCase) && h.ClientMac.Equals(hs.ClientMac, StringComparison.OrdinalIgnoreCase)))
                    {
                        Handshakes.Add(hs);
                        if (CurrentProject != null)
                        {
                            _ = _storage.SaveHandshakeAsync(CurrentProject.Id, hs);
                        }
                    }
                }

                // Run Threat Analysis on newly ingested data
                RunThreatAnalysis();

                DataSourceProfile = $"PCAP Forensic ({Path.GetFileName(filePath)})";
                AddLog("SUCCESS", "PCAP_INGEST", $"Dissected {result.Packets.Count} frames ({result.LinkTypeName}): {result.AccessPoints.Count} APs, {result.Clients.Count} station clients, {result.Handshakes.Count} handshakes from {Path.GetFileName(filePath)}");

                if (CurrentProject != null)
                {
                    _ = _storage.SaveAccessPointsAsync(CurrentProject.Id, AccessPoints.ToList());
                    _ = _storage.SaveStationClientsAsync(CurrentProject.Id, StationClients.ToList());
                }

                RecalculateMetrics();
            }
            catch (Exception ex)
            {
                AddLog("ERROR", "PCAP_INGEST", $"Failed to parse PCAP file: {ex.Message}");
            }
        }

        [RelayCommand]
        public void CopyHashcatFormat(HandshakeInfo? hs)
        {
            if (hs == null && SelectedHandshake != null) hs = SelectedHandshake;
            if (hs == null || string.IsNullOrWhiteSpace(hs.HashcatFormat))
            {
                AddLog("WARN", "CRYPTO_EXPORT", "No Hashcat Mode 22000 format available for incomplete handshake.");
                return;
            }

            Clipboard.SetText(hs.HashcatFormat);
            AddLog("SUCCESS", "CRYPTO_EXPORT", $"Copied Hashcat 22000 hash line to clipboard for BSSID {hs.ApBssid}.");
        }

        [RelayCommand]
        public async Task RunSelfTests()
        {
            AddLog("INFO", "TEST_RUNNER", "Starting automated 7-point native verification self-test suite...");
            var runner = new NativeSelfTests();
            var results = await runner.RunAllTestsAsync();

            int passed = results.Count(r => r.Passed);
            foreach (var r in results)
            {
                AddLog(r.Passed ? "SUCCESS" : "ERROR", r.TestId, $"{r.Name}: {r.Details} ({r.DurationMs}ms)");
            }
            AddLog("INFO", "TEST_RUNNER", $"Completed self-tests: {passed}/{results.Count} passed.");
            ActiveTab = "Tests";
        }

        [RelayCommand]
        public void ExportReport()
        {
            if (CurrentProject == null) return;
            try
            {
                string path = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    $"WinWiFi_Audit_Report_{DateTime.Now:yyyyMMdd_HHmmss}.html");

                _reportGenerator.SaveReportToFile(path, CurrentProject, AccessPoints.ToList());
                AddLog("SUCCESS", "REPORT_GEN", $"Exported HTML Executive Audit Report to {path}");
            }
            catch (Exception ex)
            {
                AddLog("ERROR", "REPORT_GEN", $"Failed to export report: {ex.Message}");
            }
        }

        public void AddLog(string level, string source, string message)
        {
            var log = new AuditLog { Level = level, Source = source, Message = message };
            RunOnUi(() =>
            {
                Logs.Insert(0, log);
                if (Logs.Count > 1000) Logs.RemoveAt(Logs.Count - 1);
            });

            _ = Task.Run(async () =>
            {
                try
                {
                    await _storage.InsertLogAsync(log);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[MainViewModel] Failed to insert audit log: {ex.Message}");
                }
            });
        }
    }
}
