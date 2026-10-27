using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using WinWiFi.Models;
using WinWiFi.Services;

namespace WinWiFi.Data
{
    public class SqliteStorageService : IDisposable
    {
        private readonly string _connectionString;
        private readonly string _dbPath;
        private readonly System.Threading.SemaphoreSlim _writeLock = new(1, 1);
        private bool _isDisposed;

        public SqliteStorageService(string? customDbPath = null)
        {
            string rawPath = customDbPath?.Trim() ?? string.Empty;

            // If a full connection string (e.g. 'Data Source=...') was supplied, extract only the filesystem DataSource
            if (rawPath.StartsWith("Data Source=", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var parsedBuilder = new SqliteConnectionStringBuilder(rawPath);
                    rawPath = parsedBuilder.DataSource;
                }
                catch
                {
                    rawPath = rawPath.Substring("Data Source=".Length).Trim('\"', '\'', ' ', ';');
                }
            }

            if (string.IsNullOrWhiteSpace(rawPath))
            {
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (string.IsNullOrEmpty(localAppData))
                {
                    localAppData = AppContext.BaseDirectory;
                }
                string winWifiDir = Path.Combine(localAppData, "WinWiFi");
                if (!Directory.Exists(winWifiDir))
                {
                    Directory.CreateDirectory(winWifiDir);
                }
                _dbPath = Path.Combine(winWifiDir, "winwifi_audit.db");
            }
            else
            {
                rawPath = rawPath.Trim('\"', '\'');
                _dbPath = Path.GetFullPath(rawPath);
                string? dir = Path.GetDirectoryName(_dbPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
            }

            var csBuilder = new SqliteConnectionStringBuilder
            {
                DataSource = _dbPath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Cache = SqliteCacheMode.Private,
                DefaultTimeout = 30
            };

            _connectionString = csBuilder.ToString();
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();

            // Set Write-Ahead Logging (WAL) and busy timeout to avoid concurrency locks
            using (var pragmaCmd = new SqliteCommand("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;", conn))
            {
                pragmaCmd.ExecuteNonQuery();
            }

            string ddl = @"
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    location TEXT,
                    auditor_name TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS access_points (
                    bssid TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    ssid TEXT,
                    channel INTEGER,
                    band TEXT,
                    frequency_mhz INTEGER,
                    rssi INTEGER,
                    signal_quality INTEGER,
                    security TEXT,
                    cipher TEXT,
                    security_score INTEGER,
                    is_rogue INTEGER,
                    is_wps INTEGER,
                    is_wps_locked INTEGER DEFAULT 0,
                    pmf_required INTEGER,
                    pmf_capable INTEGER DEFAULT 0,
                    channel_width INTEGER DEFAULT 20,
                    phy_type TEXT,
                    vendor TEXT,
                    akm_suites TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    observations_count INTEGER DEFAULT 1,
                    classification TEXT DEFAULT 'Unknown',
                    approval_status TEXT DEFAULT 'Pending Review',
                    site TEXT DEFAULT '',
                    building TEXT DEFAULT '',
                    floor TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    PRIMARY KEY (bssid, project_id)
                );

                CREATE TABLE IF NOT EXISTS scan_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    adapter_id TEXT,
                    scan_cycle INTEGER,
                    bssid TEXT NOT NULL,
                    ssid TEXT,
                    channel INTEGER,
                    band TEXT,
                    frequency_mhz INTEGER,
                    rssi INTEGER,
                    signal_quality INTEGER,
                    security TEXT,
                    cipher TEXT,
                    phy_type TEXT,
                    channel_width INTEGER,
                    observed_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_obs_bssid ON scan_observations(bssid);
                CREATE INDEX IF NOT EXISTS idx_obs_project ON scan_observations(project_id);

                CREATE TABLE IF NOT EXISTS handshakes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    ap_bssid TEXT NOT NULL,
                    client_mac TEXT NOT NULL,
                    ssid TEXT,
                    handshake_type TEXT,
                    mic_hex TEXT,
                    hashcat_format TEXT,
                    captured_at TEXT
                );

                CREATE TABLE IF NOT EXISTS station_clients (
                    mac_address TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    vendor TEXT,
                    associated_bssid TEXT,
                    associated_ssid TEXT,
                    rssi INTEGER,
                    channel INTEGER DEFAULT 6,
                    band TEXT DEFAULT '2.4 GHz',
                    packets_sent INTEGER,
                    first_seen TEXT,
                    last_activity TEXT,
                    probed_ssids TEXT,
                    PRIMARY KEY (mac_address, project_id)
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence INTEGER DEFAULT 80,
                    status TEXT DEFAULT 'New',
                    assigned_to TEXT,
                    summary TEXT,
                    bssid_target TEXT,
                    ssid_target TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    resolution TEXT
                );

                CREATE TABLE IF NOT EXISTS security_changes (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    ssid TEXT,
                    timestamp TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    before_state TEXT,
                    after_state TEXT,
                    risk_impact TEXT DEFAULT 'HIGH',
                    evidence_ids TEXT
                );

                CREATE TABLE IF NOT EXISTS enterprise_assets (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    ssid TEXT,
                    asset_type TEXT DEFAULT 'Access Point',
                    classification TEXT DEFAULT 'Corporate',
                    approval_status TEXT DEFAULT 'Approved',
                    site TEXT,
                    building TEXT,
                    area_floor TEXT,
                    owner_department TEXT,
                    vendor TEXT,
                    model TEXT,
                    last_seen TEXT,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    level TEXT,
                    source TEXT,
                    message TEXT
                );
            ";

            using var cmd = new SqliteCommand(ddl, conn);
            cmd.ExecuteNonQuery();

            // Older installations may already have an access_points table. CREATE TABLE IF NOT EXISTS
            // does not add columns to it, so migrate newer fields in place and keep existing audit data.
            EnsureColumnExists(conn, "access_points", "pmf_capable", "INTEGER NOT NULL DEFAULT 0");
            EnsureColumnExists(conn, "access_points", "channel_width", "INTEGER NOT NULL DEFAULT 20");
            EnsureColumnExists(conn, "access_points", "phy_type", "TEXT");
            EnsureColumnExists(conn, "access_points", "vendor", "TEXT");
            EnsureColumnExists(conn, "access_points", "akm_suites", "TEXT");
            EnsureColumnExists(conn, "access_points", "first_seen", "TEXT");
            EnsureColumnExists(conn, "access_points", "observations_count", "INTEGER NOT NULL DEFAULT 1");
            EnsureColumnExists(conn, "access_points", "classification", "TEXT NOT NULL DEFAULT 'Unknown'");
            EnsureColumnExists(conn, "access_points", "approval_status", "TEXT NOT NULL DEFAULT 'Pending Review'");
            EnsureColumnExists(conn, "access_points", "site", "TEXT NOT NULL DEFAULT ''");
            EnsureColumnExists(conn, "access_points", "building", "TEXT NOT NULL DEFAULT ''");
            EnsureColumnExists(conn, "access_points", "floor", "TEXT NOT NULL DEFAULT ''");
            EnsureColumnExists(conn, "access_points", "notes", "TEXT NOT NULL DEFAULT ''");

            using var backfill = new SqliteCommand(
                "UPDATE access_points SET first_seen = COALESCE(NULLIF(first_seen, ''), last_seen, datetime('now')) WHERE first_seen IS NULL OR first_seen = '';",
                conn);
            backfill.ExecuteNonQuery();

            // Asset records are keyed by project + MAC. Normalize legacy casing,
            // collapse pre-existing duplicates, then enforce the invariant.
            using (var normalizeAssets = new SqliteCommand(
                "UPDATE enterprise_assets SET mac_address = upper(trim(mac_address)) WHERE mac_address IS NOT NULL AND mac_address <> upper(trim(mac_address));",
                conn))
            {
                normalizeAssets.ExecuteNonQuery();
            }
            using (var dedupeAssets = new SqliteCommand(
                "DELETE FROM enterprise_assets WHERE rowid NOT IN (SELECT MAX(rowid) FROM enterprise_assets GROUP BY project_id, mac_address);",
                conn))
            {
                dedupeAssets.ExecuteNonQuery();
            }
            using (var assetIndex = new SqliteCommand(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_enterprise_assets_project_mac ON enterprise_assets(project_id, mac_address);",
                conn))
            {
                assetIndex.ExecuteNonQuery();
            }
        }

        private static void EnsureColumnExists(SqliteConnection connection, string tableName, string columnName, string columnDeclaration)
        {
            bool exists = false;
            using (var inspect = new SqliteCommand($"PRAGMA table_info({tableName});", connection))
            using (var reader = inspect.ExecuteReader())
            {
                while (reader.Read())
                {
                    if (string.Equals(reader.GetString(1), columnName, StringComparison.OrdinalIgnoreCase))
                    {
                        exists = true;
                        break;
                    }
                }
            }

            if (!exists)
            {
                using var alter = new SqliteCommand($"ALTER TABLE {tableName} ADD COLUMN {columnName} {columnDeclaration};", connection);
                alter.ExecuteNonQuery();
            }
        }

        private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
        {
            if (_isDisposed) throw new ObjectDisposedException(nameof(SqliteStorageService));
            var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync(cancellationToken);
            using (var cmd = new SqliteCommand("PRAGMA busy_timeout = 5000;", conn))
            {
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            return conn;
        }

        private static void ValidateProjectId(string projectId)
        {
            if (string.IsNullOrWhiteSpace(projectId))
            {
                throw new ArgumentException("Project ID cannot be null, empty, or whitespace.", nameof(projectId));
            }
        }

        public async Task<List<AuditProject>> GetProjectsAsync(CancellationToken cancellationToken = default)
        {
            var list = new List<AuditProject>();
            using var conn = await OpenConnectionAsync(cancellationToken);

            string query = @"
                SELECT p.id, p.name, p.location, p.auditor_name, p.created_at, p.updated_at, p.notes,
                       (SELECT COUNT(*) FROM access_points ap WHERE ap.project_id = p.id) as ap_count,
                       (SELECT COUNT(*) FROM handshakes h WHERE h.project_id = p.id) as hs_count
                FROM projects p
                ORDER BY p.updated_at DESC;";

            using var cmd = new SqliteCommand(query, conn);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);

            while (await reader.ReadAsync())
            {
                list.Add(new AuditProject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1),
                    Location = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    AuditorName = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    CreatedAt = reader.IsDBNull(4) ? "" : reader.GetString(4),
                    UpdatedAt = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    Notes = reader.IsDBNull(6) ? "" : reader.GetString(6),
                    SavedNetworksCount = reader.GetInt32(7),
                    CapturedHandshakesCount = reader.GetInt32(8)
                });
            }

            return list;
        }

        public async Task SaveProjectAsync(AuditProject project, CancellationToken cancellationToken = default)
        {            if (project == null) throw new ArgumentNullException(nameof(project));
            ValidateProjectId(project.Id);

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);

                string sql = @"
                    INSERT INTO projects (id, name, location, auditor_name, created_at, updated_at, notes)
                    VALUES (@id, @name, @loc, @auditor, @created, @updated, @notes)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name,
                        location = excluded.location,
                        auditor_name = excluded.auditor_name,
                        updated_at = excluded.updated_at,
                        notes = excluded.notes;";

                using var cmd = new SqliteCommand(sql, conn);
                cmd.Parameters.AddWithValue("@id", project.Id);
                cmd.Parameters.AddWithValue("@name", project.Name);
                cmd.Parameters.AddWithValue("@loc", project.Location ?? "");
                cmd.Parameters.AddWithValue("@auditor", project.AuditorName ?? "");
                cmd.Parameters.AddWithValue("@created", string.IsNullOrEmpty(project.CreatedAt) ? DateTime.UtcNow.ToString("o") : project.CreatedAt);
                cmd.Parameters.AddWithValue("@updated", DateTime.UtcNow.ToString("o"));
                cmd.Parameters.AddWithValue("@notes", project.Notes ?? "");

                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        /// <summary>Create the project row on demand when the dashboard starts persisting scans for it.</summary>
        public async Task EnsureProjectAsync(string projectId, string? projectName, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);
                const string sql = @"
                    INSERT INTO projects (id, name, location, auditor_name, created_at, updated_at, notes)
                    VALUES (@id, @name, '', '', datetime('now'), datetime('now'), '')
                    ON CONFLICT(id) DO UPDATE SET
                        name = CASE WHEN excluded.name = '' OR excluded.name IS NULL THEN projects.name ELSE excluded.name END,
                        updated_at = datetime('now');";
                using var cmd = new SqliteCommand(sql, conn);
                cmd.Parameters.AddWithValue("@id", projectId);
                cmd.Parameters.AddWithValue("@name", string.IsNullOrWhiteSpace(projectName) ? projectId : projectName.Trim());
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task SaveAccessPointsAsync(string projectId, IEnumerable<AccessPoint> accessPoints, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (accessPoints == null) return;

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);

                using var trans = conn.BeginTransaction();
                string sql = @"
                    INSERT INTO access_points (
                        bssid, project_id, ssid, channel, band, frequency_mhz, rssi, signal_quality,
                        security, cipher, security_score, is_rogue, is_wps, is_wps_locked, pmf_required, pmf_capable,
                        channel_width, phy_type, vendor, akm_suites, first_seen, last_seen, observations_count,
                        classification, approval_status, site, building, floor, notes
                    ) VALUES (
                        @bssid, @project_id, @ssid, @channel, @band, @frequency_mhz, @rssi, @signal_quality,
                        @security, @cipher, @security_score, @is_rogue, @is_wps, @is_wps_locked, @pmf_required, @pmf_capable,
                        @channel_width, @phy_type, @vendor, @akm_suites, @first_seen, @last_seen, 1,
                        @classification, @approval_status, @site, @building, @floor, @notes
                    )
                    ON CONFLICT(bssid, project_id) DO UPDATE SET
                        ssid = excluded.ssid,
                        channel = excluded.channel,
                        band = excluded.band,
                        frequency_mhz = excluded.frequency_mhz,
                        rssi = excluded.rssi,
                        signal_quality = excluded.signal_quality,
                        security = excluded.security,
                        cipher = excluded.cipher,
                        security_score = excluded.security_score,
                        is_rogue = excluded.is_rogue,
                        is_wps = excluded.is_wps,
                        is_wps_locked = excluded.is_wps_locked,
                        pmf_required = excluded.pmf_required,
                        pmf_capable = excluded.pmf_capable,
                        channel_width = excluded.channel_width,
                        phy_type = excluded.phy_type,
                        vendor = excluded.vendor,
                        akm_suites = excluded.akm_suites,
                        last_seen = excluded.last_seen,
                        observations_count = access_points.observations_count + 1;";

                foreach (var ap in accessPoints)
                {
                    using var cmd = new SqliteCommand(sql, conn, trans);
                    cmd.Parameters.AddWithValue("@bssid", ap.Bssid);
                    cmd.Parameters.AddWithValue("@project_id", projectId);
                    cmd.Parameters.AddWithValue("@ssid", ap.Ssid ?? "");
                    cmd.Parameters.AddWithValue("@channel", ap.Channel);
                    cmd.Parameters.AddWithValue("@band", ap.Band ?? "2.4 GHz");
                    cmd.Parameters.AddWithValue("@frequency_mhz", ap.FrequencyMHz);
                    cmd.Parameters.AddWithValue("@rssi", ap.Rssi);
                    cmd.Parameters.AddWithValue("@signal_quality", (int)ap.SignalQuality);
                    cmd.Parameters.AddWithValue("@security", ap.Security ?? "Open");
                    cmd.Parameters.AddWithValue("@cipher", ap.Cipher ?? "None");
                    cmd.Parameters.AddWithValue("@security_score", ap.SecurityScore);
                    cmd.Parameters.AddWithValue("@is_rogue", ap.IsRogue ? 1 : 0);
                    cmd.Parameters.AddWithValue("@is_wps", ap.IsWpsEnabled ? 1 : 0);
                    cmd.Parameters.AddWithValue("@is_wps_locked", ap.IsWpsLocked ? 1 : 0);
                    cmd.Parameters.AddWithValue("@pmf_required", ap.PmfRequired ? 1 : 0);
                    cmd.Parameters.AddWithValue("@pmf_capable", ap.PmfCapable ? 1 : 0);
                    cmd.Parameters.AddWithValue("@channel_width", ap.ChannelWidth);
                    cmd.Parameters.AddWithValue("@phy_type", ap.PhyType ?? "802.11ax");
                    cmd.Parameters.AddWithValue("@vendor", ap.Vendor ?? "Unknown");
                    cmd.Parameters.AddWithValue("@akm_suites", string.Join(";", ap.AkmSuites));
                    cmd.Parameters.AddWithValue("@first_seen", string.IsNullOrEmpty(ap.FirstSeen) ? DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") : ap.FirstSeen);
                    cmd.Parameters.AddWithValue("@last_seen", string.IsNullOrEmpty(ap.LastSeen) ? DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") : ap.LastSeen);
                    cmd.Parameters.AddWithValue("@classification", ap.Classification ?? "Unknown");
                    cmd.Parameters.AddWithValue("@approval_status", ap.ApprovedStatus ?? "Pending Review");
                    cmd.Parameters.AddWithValue("@site", ap.Site ?? "");
                    cmd.Parameters.AddWithValue("@building", ap.Building ?? "");
                    cmd.Parameters.AddWithValue("@floor", ap.Floor ?? "");
                    cmd.Parameters.AddWithValue("@notes", ap.Notes ?? "");

                    await cmd.ExecuteNonQueryAsync(cancellationToken);
                }

                trans.Commit();
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task SaveScanObservationsBatchAsync(string projectId, string adapterId, int scanCycle, IEnumerable<AccessPoint> accessPoints, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (accessPoints == null) return;

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);

                using var trans = conn.BeginTransaction();
                string sql = @"
                    INSERT INTO scan_observations (
                        project_id, adapter_id, scan_cycle, bssid, ssid, channel, band,
                        frequency_mhz, rssi, signal_quality, security, cipher, phy_type,
                        channel_width, observed_at
                    ) VALUES (
                        @project_id, @adapter_id, @scan_cycle, @bssid, @ssid, @channel, @band,
                        @frequency_mhz, @rssi, @signal_quality, @security, @cipher, @phy_type,
                        @channel_width, @observed_at
                    );";

                string nowStr = DateTime.UtcNow.ToString("o");
                foreach (var ap in accessPoints)
                {
                    using var cmd = new SqliteCommand(sql, conn, trans);
                    cmd.Parameters.AddWithValue("@project_id", projectId);
                    cmd.Parameters.AddWithValue("@adapter_id", adapterId ?? "");
                    cmd.Parameters.AddWithValue("@scan_cycle", scanCycle);
                    cmd.Parameters.AddWithValue("@bssid", ap.Bssid);
                    cmd.Parameters.AddWithValue("@ssid", ap.Ssid ?? "");
                    cmd.Parameters.AddWithValue("@channel", ap.Channel);
                    cmd.Parameters.AddWithValue("@band", ap.Band ?? "Unknown");
                    cmd.Parameters.AddWithValue("@frequency_mhz", ap.FrequencyMHz);
                    cmd.Parameters.AddWithValue("@rssi", ap.Rssi);
                    cmd.Parameters.AddWithValue("@signal_quality", (int)ap.SignalQuality);
                    cmd.Parameters.AddWithValue("@security", ap.Security ?? "Unknown");
                    cmd.Parameters.AddWithValue("@cipher", ap.Cipher ?? "None");
                    cmd.Parameters.AddWithValue("@phy_type", ap.PhyType ?? "Unknown");
                    cmd.Parameters.AddWithValue("@channel_width", ap.ChannelWidth);
                    cmd.Parameters.AddWithValue("@observed_at", nowStr);

                    await cmd.ExecuteNonQueryAsync(cancellationToken);
                }

                trans.Commit();
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task<List<ScanObservationRecord>> GetScanObservationsAsync(string projectId, string? bssid = null, int limit = 500, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            var list = new List<ScanObservationRecord>();
            using var conn = await OpenConnectionAsync(cancellationToken);

            string sql = string.IsNullOrEmpty(bssid)
                ? @"SELECT id, project_id, adapter_id, scan_cycle, bssid, ssid, channel, band,
                           frequency_mhz, rssi, signal_quality, security, cipher, phy_type, channel_width, observed_at
                    FROM scan_observations
                    WHERE project_id = @pid
                    ORDER BY id DESC LIMIT @limit;"
                : @"SELECT id, project_id, adapter_id, scan_cycle, bssid, ssid, channel, band,
                           frequency_mhz, rssi, signal_quality, security, cipher, phy_type, channel_width, observed_at
                    FROM scan_observations
                    WHERE project_id = @pid AND bssid = @bssid
                    ORDER BY id DESC LIMIT @limit;";

            using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@limit", limit);
            if (!string.IsNullOrEmpty(bssid))
            {
                cmd.Parameters.AddWithValue("@bssid", bssid);
            }

            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                list.Add(new ScanObservationRecord
                {
                    Id = reader.GetInt64(0),
                    ProjectId = reader.GetString(1),
                    AdapterId = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    ScanCycle = reader.GetInt32(3),
                    Bssid = reader.GetString(4),
                    Ssid = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    Channel = reader.GetInt32(6),
                    Band = reader.IsDBNull(7) ? "Unknown" : reader.GetString(7),
                    FrequencyMHz = reader.GetInt32(8),
                    Rssi = reader.GetInt32(9),
                    SignalQuality = (uint)reader.GetInt32(10),
                    Security = reader.IsDBNull(11) ? "Unknown" : reader.GetString(11),
                    Cipher = reader.IsDBNull(12) ? "None" : reader.GetString(12),
                    PhyType = reader.IsDBNull(13) ? "Unknown" : reader.GetString(13),
                    ChannelWidth = reader.GetInt32(14),
                    ObservedAt = reader.GetString(15)
                });
            }

            return list;
        }

        public async Task<int> GetTotalObservationsCountAsync(string projectId, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            using var conn = await OpenConnectionAsync(cancellationToken);

            string sql = "SELECT COUNT(*) FROM scan_observations WHERE project_id = @pid;";
            using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            var result = await cmd.ExecuteScalarAsync(cancellationToken);
            return result != null && result != DBNull.Value ? Convert.ToInt32(result) : 0;
        }

        public async Task<List<AccessPoint>> GetAccessPointsAsync(string projectId, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            var list = new List<AccessPoint>();
            using var conn = await OpenConnectionAsync(cancellationToken);

            string sql = @"
                SELECT bssid, ssid, channel, band, frequency_mhz, rssi, signal_quality,
                       security, cipher, security_score, is_rogue, is_wps, is_wps_locked, pmf_required, pmf_capable,
                       channel_width, phy_type, vendor, akm_suites, first_seen, last_seen, observations_count,
                       classification, approval_status, site, building, floor, notes
                FROM access_points
                WHERE project_id = @pid
                ORDER BY rssi DESC;";

            using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);

            while (await reader.ReadAsync(cancellationToken))
            {
                var ap = new AccessPoint
                {
                    Bssid = reader.GetString(0),
                    Ssid = reader.GetString(1),
                    Channel = reader.GetInt32(2),
                    Band = reader.GetString(3),
                    FrequencyMHz = reader.GetInt32(4),
                    Rssi = reader.GetInt32(5),
                    SignalQuality = (uint)reader.GetInt32(6),
                    Security = reader.GetString(7),
                    Cipher = reader.GetString(8),
                    SecurityScore = reader.GetInt32(9),
                    IsRogue = reader.GetInt32(10) == 1,
                    IsWpsEnabled = reader.GetInt32(11) == 1,
                    IsWpsLocked = reader.GetInt32(12) == 1,
                    PmfRequired = reader.GetInt32(13) == 1,
                    PmfCapable = reader.GetInt32(14) == 1,
                    ChannelWidth = reader.GetInt32(15),
                    PhyType = reader.IsDBNull(16) ? "802.11ax" : reader.GetString(16),
                    Vendor = reader.IsDBNull(17) ? "Unknown" : reader.GetString(17),
                    FirstSeen = reader.IsDBNull(19) ? "" : reader.GetString(19),
                    LastSeen = reader.IsDBNull(20) ? "" : reader.GetString(20),
                    HistoricalObservationsCount = reader.GetInt32(21),
                    Classification = reader.IsDBNull(22) ? "Unknown" : reader.GetString(22),
                    ApprovedStatus = reader.IsDBNull(23) ? "Pending Review" : reader.GetString(23),
                    Site = reader.IsDBNull(24) ? "" : reader.GetString(24),
                    Building = reader.IsDBNull(25) ? "" : reader.GetString(25),
                    Floor = reader.IsDBNull(26) ? "" : reader.GetString(26),
                    Notes = reader.IsDBNull(27) ? "" : reader.GetString(27)
                };

                if (!reader.IsDBNull(18))
                {
                    string akms = reader.GetString(18);
                    if (!string.IsNullOrEmpty(akms))
                    {
                        ap.AkmSuites.AddRange(akms.Split(';', StringSplitOptions.RemoveEmptyEntries));
                    }
                }

                list.Add(ap);
            }

            return list;
        }

        public async Task SaveStationClientsAsync(string projectId, IEnumerable<StationClientRecord> clients, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (clients == null) return;

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);

                using var trans = conn.BeginTransaction();
                string sql = @"
                    INSERT INTO station_clients (
                        mac_address, project_id, vendor, associated_bssid, associated_ssid,
                        rssi, channel, band, packets_sent, first_seen, last_activity, probed_ssids
                    ) VALUES (
                        @mac, @pid, @vendor, @bssid, @ssid, @rssi, @channel, @band, @packets, @first, @last, @probed
                    )
                    ON CONFLICT(mac_address, project_id) DO UPDATE SET
                        vendor = excluded.vendor,
                        associated_bssid = excluded.associated_bssid,
                        associated_ssid = excluded.associated_ssid,
                        rssi = excluded.rssi,
                        channel = excluded.channel,
                        band = excluded.band,
                        packets_sent = station_clients.packets_sent + excluded.packets_sent,
                        last_activity = excluded.last_activity,
                        probed_ssids = excluded.probed_ssids;";

                foreach (var client in clients)
                {
                    using var cmd = new SqliteCommand(sql, conn, trans);
                    cmd.Parameters.AddWithValue("@mac", client.MacAddress);
                    cmd.Parameters.AddWithValue("@pid", projectId);
                    cmd.Parameters.AddWithValue("@vendor", client.Vendor ?? "Unknown");
                    cmd.Parameters.AddWithValue("@bssid", client.AssociatedApBssid ?? "Unavailable");
                    cmd.Parameters.AddWithValue("@ssid", client.AssociatedApSsid ?? "Not Observed");
                    cmd.Parameters.AddWithValue("@rssi", client.Rssi);
                    cmd.Parameters.AddWithValue("@channel", client.Channel);
                    cmd.Parameters.AddWithValue("@band", client.Band ?? "2.4 GHz");
                    cmd.Parameters.AddWithValue("@packets", client.PacketsCount);
                    cmd.Parameters.AddWithValue("@first", string.IsNullOrEmpty(client.FirstSeen) ? DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") : client.FirstSeen);
                    cmd.Parameters.AddWithValue("@last", string.IsNullOrEmpty(client.LastSeen) ? DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") : client.LastSeen);
                    cmd.Parameters.AddWithValue("@probed", string.Join(";", client.ProbeRequests));

                    await cmd.ExecuteNonQueryAsync(cancellationToken);
                }

                trans.Commit();
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task<List<StationClientRecord>> GetStationClientsAsync(string projectId, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            var list = new List<StationClientRecord>();
            using var conn = await OpenConnectionAsync(cancellationToken);

            string sql = @"
                SELECT mac_address, vendor, associated_bssid, associated_ssid, rssi, channel, band, packets_sent, first_seen, last_activity, probed_ssids
                FROM station_clients
                WHERE project_id = @pid
                ORDER BY last_activity DESC;";

            using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);

            while (await reader.ReadAsync(cancellationToken))
            {
                var client = new StationClientRecord
                {
                    MacAddress = reader.GetString(0),
                    Vendor = reader.IsDBNull(1) ? "Unknown" : reader.GetString(1),
                    AssociatedApBssid = reader.IsDBNull(2) ? "Unavailable (Windows NDIS)" : reader.GetString(2),
                    AssociatedApSsid = reader.IsDBNull(3) ? "Not Provable" : reader.GetString(3),
                    Rssi = reader.GetInt32(4),
                    Channel = reader.GetInt32(5),
                    Band = reader.IsDBNull(6) ? "2.4 GHz" : reader.GetString(6),
                    PacketsCount = reader.GetInt32(7),
                    FirstSeen = reader.IsDBNull(8) ? "" : reader.GetString(8),
                    LastSeen = reader.IsDBNull(9) ? "" : reader.GetString(9)
                };

                client.IsAssociated = !string.IsNullOrEmpty(client.AssociatedApBssid) && !client.AssociatedApBssid.Contains("Unavailable");
                client.IsRandomizedMac = WinWiFi.Services.OuiLookupService.IsLocallyAdministered(client.MacAddress);

                if (!reader.IsDBNull(10))
                {
                    string probed = reader.GetString(10);
                    if (!string.IsNullOrEmpty(probed))
                    {
                        client.ProbeRequests.AddRange(probed.Split(';', StringSplitOptions.RemoveEmptyEntries));
                    }
                }

                list.Add(client);
            }

            return list;
        }

        public async Task SaveIncidentAsync(string projectId, IncidentRecord incident, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (incident == null) throw new ArgumentNullException(nameof(incident));

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);

                string sql = @"
                    INSERT INTO incidents (id, project_id, title, severity, confidence, status, assigned_to, summary, bssid_target, ssid_target, created_at, updated_at, resolution)
                    VALUES (@id, @pid, @title, @sev, @conf, @stat, @assigned, @sum, @bssid, @ssid, @created, @updated, @res)
                    ON CONFLICT(id) DO UPDATE SET
                        title = excluded.title,
                        severity = excluded.severity,
                        confidence = excluded.confidence,
                        status = excluded.status,
                        assigned_to = excluded.assigned_to,
                        summary = excluded.summary,
                        updated_at = excluded.updated_at,
                        resolution = excluded.resolution;";

                using var cmd = new SqliteCommand(sql, conn);
                cmd.Parameters.AddWithValue("@id", incident.Id);
                cmd.Parameters.AddWithValue("@pid", projectId);
                cmd.Parameters.AddWithValue("@title", incident.Title);
                cmd.Parameters.AddWithValue("@sev", incident.Severity);
                cmd.Parameters.AddWithValue("@conf", incident.Confidence);
                cmd.Parameters.AddWithValue("@stat", incident.Status);
                cmd.Parameters.AddWithValue("@assigned", incident.AssignedTo ?? "SecOps");
                cmd.Parameters.AddWithValue("@sum", incident.Summary ?? "");
                cmd.Parameters.AddWithValue("@bssid", incident.BssidTarget ?? "");
                cmd.Parameters.AddWithValue("@ssid", incident.SsidTarget ?? "");
                cmd.Parameters.AddWithValue("@created", incident.CreatedAt);
                cmd.Parameters.AddWithValue("@updated", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
                cmd.Parameters.AddWithValue("@res", incident.Resolution ?? "");

                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task<List<IncidentRecord>> GetIncidentsAsync(string projectId, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            var list = new List<IncidentRecord>();
            using var conn = await OpenConnectionAsync(cancellationToken);

            string sql = @"SELECT id, title, severity, confidence, status, assigned_to, summary, bssid_target, ssid_target, created_at, updated_at, resolution
                           FROM incidents WHERE project_id = @pid ORDER BY created_at DESC;";

            using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);

            while (await reader.ReadAsync(cancellationToken))
            {
                list.Add(new IncidentRecord
                {
                    Id = reader.GetString(0),
                    Title = reader.GetString(1),
                    Severity = reader.GetString(2),
                    Confidence = reader.GetInt32(3),
                    Status = reader.GetString(4),
                    AssignedTo = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    Summary = reader.IsDBNull(6) ? "" : reader.GetString(6),
                    BssidTarget = reader.IsDBNull(7) ? "" : reader.GetString(7),
                    SsidTarget = reader.IsDBNull(8) ? "" : reader.GetString(8),
                    CreatedAt = reader.IsDBNull(9) ? "" : reader.GetString(9),
                    UpdatedAt = reader.IsDBNull(10) ? "" : reader.GetString(10),
                    Resolution = reader.IsDBNull(11) ? "" : reader.GetString(11)
                });
            }

            return list;
        }

        public async Task SaveSecurityChangesAsync(string projectId, IEnumerable<SecurityChange> changes, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (changes == null) return;

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);

                using var trans = conn.BeginTransaction();
                string sql = @"
                    INSERT OR IGNORE INTO security_changes (id, project_id, bssid, ssid, timestamp, change_type, title, before_state, after_state, risk_impact, evidence_ids)
                    VALUES (@id, @pid, @bssid, @ssid, @ts, @type, @title, @before, @after, @risk, @evidence);";

                foreach (var ch in changes)
                {
                    using var cmd = new SqliteCommand(sql, conn, trans);
                    cmd.Parameters.AddWithValue("@id", ch.Id);
                    cmd.Parameters.AddWithValue("@pid", projectId);
                    cmd.Parameters.AddWithValue("@bssid", ch.Bssid);
                    cmd.Parameters.AddWithValue("@ssid", ch.Ssid ?? "");
                    cmd.Parameters.AddWithValue("@ts", ch.Timestamp);
                    cmd.Parameters.AddWithValue("@type", ch.Type);
                    cmd.Parameters.AddWithValue("@title", ch.Title);
                    cmd.Parameters.AddWithValue("@before", ch.Before ?? "");
                    cmd.Parameters.AddWithValue("@after", ch.After ?? "");
                    cmd.Parameters.AddWithValue("@risk", ch.RiskImpact ?? "HIGH");
                    cmd.Parameters.AddWithValue("@evidence", ch.EvidenceId ?? "");

                    await cmd.ExecuteNonQueryAsync(cancellationToken);
                }

                trans.Commit();
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task<List<SecurityChange>> GetSecurityChangesAsync(string projectId, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            var list = new List<SecurityChange>();
            using var conn = await OpenConnectionAsync(cancellationToken);

            string sql = "SELECT id, bssid, ssid, timestamp, change_type, title, before_state, after_state, risk_impact FROM security_changes WHERE project_id = @pid ORDER BY timestamp DESC;";
            using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);

            while (await reader.ReadAsync(cancellationToken))
            {
                list.Add(new SecurityChange
                {
                    Id = reader.GetString(0),
                    Bssid = reader.GetString(1),
                    Ssid = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Timestamp = reader.GetString(3),
                    Type = reader.GetString(4),
                    Title = reader.GetString(5),
                    Before = reader.IsDBNull(6) ? "" : reader.GetString(6),
                    After = reader.IsDBNull(7) ? "" : reader.GetString(7),
                    RiskImpact = reader.IsDBNull(8) ? "HIGH" : reader.GetString(8)
                });
            }

            return list;
        }

        public async Task SaveEnterpriseAssetsAsync(string projectId, IEnumerable<EnterpriseAssetRecord> assets, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (assets == null) return;

            // Normalize at the storage boundary so no caller can create a
            // duplicate asset by spelling the same MAC differently.
            var normalized = new Dictionary<string, EnterpriseAssetRecord>(StringComparer.OrdinalIgnoreCase);
            foreach (var asset in assets)
            {
                var record = AssetRegistryCsv.NormalizeAsset(asset, out string? error)
                    ?? throw new ArgumentException(error, nameof(assets));
                normalized[record.MacAddress] = record;
            }
            if (normalized.Count == 0) return;

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);

                using var trans = conn.BeginTransaction();
                string sql = @"
                    INSERT INTO enterprise_assets (id, project_id, mac_address, ssid, asset_type, classification, approval_status, site, building, area_floor, owner_department, vendor, model, last_seen, notes)
                    VALUES (@id, @pid, @mac, @ssid, @type, @class, @status, @site, @bldg, @floor, @dept, @vendor, @model, @seen, @notes)
                    ON CONFLICT(project_id, mac_address) DO UPDATE SET
                        ssid = excluded.ssid,
                        asset_type = excluded.asset_type,
                        classification = excluded.classification,
                        approval_status = excluded.approval_status,
                        site = excluded.site,
                        building = excluded.building,
                        area_floor = excluded.area_floor,
                        owner_department = excluded.owner_department,
                        vendor = excluded.vendor,
                        model = excluded.model,
                        last_seen = excluded.last_seen,
                        notes = excluded.notes;";

                foreach (var a in normalized.Values)
                {
                    using var cmd = new SqliteCommand(sql, conn, trans);
                    cmd.Parameters.AddWithValue("@id", a.Id);
                    cmd.Parameters.AddWithValue("@pid", projectId);
                    cmd.Parameters.AddWithValue("@mac", a.MacAddress);
                    cmd.Parameters.AddWithValue("@ssid", a.Ssid ?? "");
                    cmd.Parameters.AddWithValue("@type", a.AssetType ?? "Access Point");
                    cmd.Parameters.AddWithValue("@class", a.Classification ?? "Unknown");
                    cmd.Parameters.AddWithValue("@status", a.ApprovalStatus ?? "Pending Review");
                    cmd.Parameters.AddWithValue("@site", a.Site ?? "");
                    cmd.Parameters.AddWithValue("@bldg", a.Building ?? "");
                    cmd.Parameters.AddWithValue("@floor", a.AreaFloor ?? "");
                    cmd.Parameters.AddWithValue("@dept", a.OwnerDepartment ?? "");
                    cmd.Parameters.AddWithValue("@vendor", a.Vendor ?? "Unknown");
                    cmd.Parameters.AddWithValue("@model", a.Model ?? "");
                    cmd.Parameters.AddWithValue("@seen", a.LastSeen);
                    cmd.Parameters.AddWithValue("@notes", a.Notes ?? "");

                    await cmd.ExecuteNonQueryAsync(cancellationToken);
                }

                trans.Commit();
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task DeleteEnterpriseAssetAsync(string projectId, string macAddress, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            string? normalizedMac = AssetRegistryCsv.NormalizeMac(macAddress);
            if (normalizedMac is null) throw new ArgumentException("A valid unicast 48-bit MAC address is required.", nameof(macAddress));

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);
                using var cmd = new SqliteCommand(
                    "DELETE FROM enterprise_assets WHERE project_id = @pid AND mac_address = @mac;", conn);
                cmd.Parameters.AddWithValue("@pid", projectId);
                cmd.Parameters.AddWithValue("@mac", normalizedMac);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task<List<EnterpriseAssetRecord>> GetEnterpriseAssetsAsync(string projectId, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            var list = new List<EnterpriseAssetRecord>();
            using var conn = await OpenConnectionAsync(cancellationToken);

            string sql = @"SELECT id, mac_address, ssid, asset_type, classification, approval_status, site, building, area_floor, owner_department, vendor, model, last_seen, notes
                           FROM enterprise_assets WHERE project_id = @pid ORDER BY last_seen DESC;";

            using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);

            while (await reader.ReadAsync(cancellationToken))
            {
                list.Add(new EnterpriseAssetRecord
                {
                    Id = reader.GetString(0),
                    MacAddress = reader.GetString(1),
                    Ssid = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    AssetType = reader.IsDBNull(3) ? "Access Point" : reader.GetString(3),
                    Classification = reader.IsDBNull(4) ? "Corporate" : reader.GetString(4),
                    ApprovalStatus = reader.IsDBNull(5) ? "Approved" : reader.GetString(5),
                    Site = reader.IsDBNull(6) ? "" : reader.GetString(6),
                    Building = reader.IsDBNull(7) ? "" : reader.GetString(7),
                    AreaFloor = reader.IsDBNull(8) ? "" : reader.GetString(8),
                    OwnerDepartment = reader.IsDBNull(9) ? "" : reader.GetString(9),
                    Vendor = reader.IsDBNull(10) ? "Unknown" : reader.GetString(10),
                    Model = reader.IsDBNull(11) ? "" : reader.GetString(11),
                    LastSeen = reader.IsDBNull(12) ? "" : reader.GetString(12),
                    Notes = reader.IsDBNull(13) ? "" : reader.GetString(13)
                });
            }

            return list;
        }

        public async Task SaveHandshakeAsync(string projectId, HandshakeInfo hs, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (hs == null) throw new ArgumentNullException(nameof(hs));

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);

                string sql = @"
                    INSERT INTO handshakes (project_id, ap_bssid, client_mac, ssid, handshake_type, mic_hex, hashcat_format, captured_at)
                    VALUES (@pid, @bssid, @client, @ssid, @type, @mic, @hashcat, @at);";

                using var cmd = new SqliteCommand(sql, conn);
                cmd.Parameters.AddWithValue("@pid", projectId);
                cmd.Parameters.AddWithValue("@bssid", hs.ApBssid);
                cmd.Parameters.AddWithValue("@client", hs.ClientMac);
                cmd.Parameters.AddWithValue("@ssid", hs.Ssid);
                cmd.Parameters.AddWithValue("@type", hs.Type);
                cmd.Parameters.AddWithValue("@mic", hs.MicHex ?? "");
                cmd.Parameters.AddWithValue("@hashcat", hs.HashcatFormat ?? "");
                cmd.Parameters.AddWithValue("@at", hs.CapturedAt);

                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task<List<HandshakeInfo>> GetHandshakesAsync(string projectId, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            var list = new List<HandshakeInfo>();
            using var conn = await OpenConnectionAsync(cancellationToken);

            string sql = "SELECT ap_bssid, client_mac, ssid, handshake_type, mic_hex, hashcat_format, captured_at FROM handshakes WHERE project_id = @pid ORDER BY captured_at DESC;";
            using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);

            while (await reader.ReadAsync(cancellationToken))
            {
                list.Add(new HandshakeInfo
                {
                    ApBssid = reader.GetString(0),
                    ClientMac = reader.GetString(1),
                    Ssid = reader.GetString(2),
                    Type = reader.GetString(3),
                    MicHex = reader.IsDBNull(4) ? "" : reader.GetString(4),
                    HashcatFormat = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    CapturedAt = reader.IsDBNull(6) ? "" : reader.GetString(6)
                });
            }

            return list;
        }

        public async Task InsertLogAsync(AuditLog log, CancellationToken cancellationToken = default)
        {
            if (log == null) return;
            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);

                string sql = "INSERT INTO audit_logs (id, timestamp, level, source, message) VALUES (@id, @ts, @lvl, @src, @msg);";
                using var cmd = new SqliteCommand(sql, conn);
                cmd.Parameters.AddWithValue("@id", log.Id);
                cmd.Parameters.AddWithValue("@ts", log.Timestamp);
                cmd.Parameters.AddWithValue("@lvl", log.Level);
                cmd.Parameters.AddWithValue("@src", log.Source);
                cmd.Parameters.AddWithValue("@msg", log.Message);

                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public static void ReleaseAllPools()
        {
            SqliteConnection.ClearAllPools();
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
            try
            {
                // Wait up to 3 seconds for active write lock to complete
                _writeLock.Wait(TimeSpan.FromSeconds(3));
                _writeLock.Dispose();
            }
            catch
            {
                // Safe disposal
            }
            SqliteConnection.ClearAllPools();
        }
    }
}
