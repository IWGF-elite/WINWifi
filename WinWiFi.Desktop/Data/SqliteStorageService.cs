using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
                    observed_at TEXT NOT NULL,
                    event_type TEXT NOT NULL DEFAULT 'OBSERVATION',
                    last_seen_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_obs_bssid ON scan_observations(bssid);
                CREATE INDEX IF NOT EXISTS idx_obs_project ON scan_observations(project_id);
                CREATE INDEX IF NOT EXISTS idx_obs_project_time ON scan_observations(project_id, observed_at);
                CREATE INDEX IF NOT EXISTS idx_obs_project_bssid_id ON scan_observations(project_id, bssid, id DESC);

                CREATE TABLE IF NOT EXISTS scan_observation_state (
                    project_id TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    adapter_id TEXT NOT NULL DEFAULT '',
                    scan_cycle INTEGER NOT NULL DEFAULT 0,
                    ssid TEXT NOT NULL DEFAULT '',
                    channel INTEGER NOT NULL DEFAULT 0,
                    band TEXT NOT NULL DEFAULT 'Unknown',
                    frequency_mhz INTEGER NOT NULL DEFAULT 0,
                    rssi INTEGER NOT NULL DEFAULT 0,
                    signal_quality INTEGER NOT NULL DEFAULT 0,
                    security TEXT NOT NULL DEFAULT 'Unknown',
                    cipher TEXT NOT NULL DEFAULT 'Unknown',
                    phy_type TEXT NOT NULL DEFAULT 'Unknown',
                    channel_width INTEGER NOT NULL DEFAULT 20,
                    last_seen_at TEXT NOT NULL,
                    last_observation_at TEXT NOT NULL,
                    missed_scans INTEGER NOT NULL DEFAULT 0,
                    is_present INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY(project_id, bssid)
                );
                CREATE TABLE IF NOT EXISTS scan_observation_migrations (
                    project_id TEXT PRIMARY KEY,
                    initialized_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS network_timeline_events (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_key TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    before_state_json TEXT NOT NULL DEFAULT '{}',
                    after_state_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_network_timeline_project_time ON network_timeline_events(project_id, occurred_at);
                CREATE INDEX IF NOT EXISTS idx_network_timeline_entity ON network_timeline_events(project_id, entity_type, entity_key, occurred_at);
                CREATE TABLE IF NOT EXISTS network_timeline_presence (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_key TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    ended_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_network_timeline_presence_scope ON network_timeline_presence(project_id, entity_type, entity_key, first_seen_at);

                CREATE TABLE IF NOT EXISTS walk_signal_readings (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    ssid TEXT NOT NULL,
                    location_name TEXT NOT NULL,
                    rssi_dbm INTEGER NOT NULL,
                    signal_quality INTEGER NOT NULL,
                    captured_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_walk_signal_project_time ON walk_signal_readings(project_id, captured_at);
                CREATE INDEX IF NOT EXISTS idx_walk_signal_project_bssid ON walk_signal_readings(project_id, bssid, captured_at);

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

                CREATE TABLE IF NOT EXISTS lan_devices (
                    project_id TEXT NOT NULL,
                    network_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT NOT NULL DEFAULT '',
                    hostname TEXT NOT NULL DEFAULT '',
                    vendor TEXT NOT NULL DEFAULT 'Unknown',
                    device_type TEXT NOT NULL DEFAULT 'Unknown',
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    ports_json TEXT NOT NULL DEFAULT '[]',
                    is_online INTEGER NOT NULL DEFAULT 0,
                    is_known INTEGER NOT NULL DEFAULT 0,
                    is_randomized_mac INTEGER NOT NULL DEFAULT 0,
                    ping_ttl INTEGER,
                    os_guess TEXT NOT NULL DEFAULT 'Unknown',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL DEFAULT '',
                    checked_at TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (project_id, network_id, ip_address)
                );

                CREATE TABLE IF NOT EXISTS browser_storage_snapshots (
                    import_id TEXT NOT NULL,
                    storage_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    record_count INTEGER NOT NULL,
                    imported_at TEXT NOT NULL,
                    PRIMARY KEY (import_id, storage_key)
                );

                CREATE TABLE IF NOT EXISTS network_fingerprints (
                    project_id TEXT NOT NULL,
                    ssid TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    gateway_ip TEXT NOT NULL,
                    gateway_mac TEXT NOT NULL DEFAULT '',
                    dns_servers_json TEXT NOT NULL,
                    security TEXT NOT NULL,
                    cipher TEXT NOT NULL,
                    authorized_ap_pattern_json TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    PRIMARY KEY (project_id, ssid)
                );
            ";

            using var cmd = new SqliteCommand(ddl, conn);
            cmd.ExecuteNonQuery();
            EnsureColumnExists(conn, "scan_observations", "event_type", "TEXT NOT NULL DEFAULT 'OBSERVATION'");
            EnsureColumnExists(conn, "scan_observations", "last_seen_at", "TEXT");
            EnsureColumnExists(conn, "lan_devices", "ping_ttl", "INTEGER");
            EnsureColumnExists(conn, "lan_devices", "os_guess", "TEXT NOT NULL DEFAULT 'Unknown'");
            EnsureColumnExists(conn, "lan_devices", "checked_at", "TEXT NOT NULL DEFAULT ''");

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

        private sealed record TimelineApState(string Bssid, string Ssid, int Channel, string Band, int FrequencyMhz,
            int Rssi, uint SignalQuality, string Security, string Cipher, int ChannelWidth, string Vendor, string FirstSeenAt, string LastSeenAt)
        {
            public static TimelineApState From(AccessPoint ap, string now) => new(ap.Bssid, ap.Ssid ?? string.Empty, ap.Channel,
                ap.Band ?? "Unknown", ap.FrequencyMHz, ap.Rssi, ap.SignalQuality, ap.Security ?? "Unknown", ap.Cipher ?? "Unknown", ap.ChannelWidth,
                ap.Vendor ?? "Unknown", string.IsNullOrWhiteSpace(ap.FirstSeen) ? now : ap.FirstSeen,
                string.IsNullOrWhiteSpace(ap.LastSeen) ? now : ap.LastSeen);

            public Dictionary<string, object?> ToDictionary() => new()
            {
                ["bssid"] = Bssid, ["ssid"] = Ssid, ["channel"] = Channel, ["band"] = Band,
                ["frequencyMhz"] = FrequencyMhz, ["rssi"] = Rssi, ["signalQuality"] = SignalQuality, ["security"] = Security, ["cipher"] = Cipher,
                ["channelWidth"] = ChannelWidth, ["vendor"] = Vendor, ["firstSeenAt"] = FirstSeenAt,
                ["lastSeenAt"] = LastSeenAt, ["isPresent"] = true
            };

            public List<string> ChangedFields(TimelineApState current)
            {
                var changed = new List<string>();
                if (!string.Equals(Ssid, current.Ssid, StringComparison.Ordinal)) changed.Add("SSID");
                if (Channel != current.Channel) changed.Add("channel");
                if (!string.Equals(Band, current.Band, StringComparison.OrdinalIgnoreCase)) changed.Add("band");
                if (FrequencyMhz != current.FrequencyMhz) changed.Add("frequency");
                if (!string.Equals(Security, current.Security, StringComparison.OrdinalIgnoreCase)) changed.Add("security");
                if (!string.Equals(Cipher, current.Cipher, StringComparison.OrdinalIgnoreCase)) changed.Add("cipher");
                if (ChannelWidth != current.ChannelWidth) changed.Add("channel width");
                if (!string.Equals(Vendor, current.Vendor, StringComparison.OrdinalIgnoreCase)) changed.Add("vendor");
                return changed;
            }
        }

        private sealed record ScanObservationState(string Bssid, string AdapterId, int ScanCycle, string Ssid, int Channel,
            string Band, int FrequencyMHz, int Rssi, uint SignalQuality, string Security, string Cipher, string PhyType,
            int ChannelWidth, string LastSeenAt, string LastObservationAt, int MissedScans, bool IsPresent)
        {
            public static ScanObservationState From(AccessPoint ap, string adapterId, int scanCycle, string timestamp) => new(
                ap.Bssid.Trim().ToUpperInvariant(), adapterId, scanCycle, ap.Ssid ?? string.Empty, ap.Channel,
                ap.Band ?? "Unknown", ap.FrequencyMHz, ap.Rssi, ap.SignalQuality, ap.Security ?? "Unknown",
                ap.Cipher ?? "Unknown", ap.PhyType ?? "Unknown", ap.ChannelWidth, timestamp, timestamp, 0, true);
        }

        private sealed record TimelineDeviceState(string IpAddress, string MacAddress, string Hostname, string Vendor, string DeviceType,
            bool IsOnline, string FirstSeenAt, string LastSeenAt)
        {
            public static TimelineDeviceState From(LanDeviceRecord device, string now, bool isOnline) => new(device.IpAddress,
                device.MacAddress ?? string.Empty, device.Hostname ?? string.Empty, device.Vendor ?? string.Empty,
                device.DeviceType ?? string.Empty, isOnline,
                string.IsNullOrWhiteSpace(device.FirstSeen) ? now : device.FirstSeen,
                string.IsNullOrWhiteSpace(device.LastSeen) ? now : device.LastSeen);

            public Dictionary<string, object?> ToDictionary() => new()
            {
                ["entityType"] = "DEVICE", ["entityKey"] = IpAddress, ["ipAddress"] = IpAddress,
                ["macAddress"] = MacAddress, ["hostname"] = Hostname, ["vendor"] = Vendor,
                ["deviceType"] = DeviceType, ["isOnline"] = IsOnline, ["isPresent"] = true,
                ["firstSeenAt"] = FirstSeenAt, ["lastSeenAt"] = LastSeenAt
            };

            public List<string> ChangedFields(TimelineDeviceState current)
            {
                var changed = new List<string>();
                if (!string.Equals(MacAddress, current.MacAddress, StringComparison.OrdinalIgnoreCase)) changed.Add("MAC address");
                if (!string.Equals(Hostname, current.Hostname, StringComparison.OrdinalIgnoreCase)) changed.Add("hostname");
                if (!string.Equals(Vendor, current.Vendor, StringComparison.OrdinalIgnoreCase)) changed.Add("vendor");
                if (!string.Equals(DeviceType, current.DeviceType, StringComparison.OrdinalIgnoreCase)) changed.Add("device type");
                return changed;
            }
        }

        private static async Task<TimelineApState?> ReadTimelineApStateAsync(SqliteConnection connection, SqliteTransaction transaction,
            string projectId, string bssid, CancellationToken cancellationToken)
        {
            using var cmd = new SqliteCommand(@"SELECT bssid, ssid, channel, band, frequency_mhz, rssi, signal_quality, security, cipher, channel_width, vendor, first_seen, last_seen
                FROM access_points WHERE project_id=@pid AND bssid=@bssid LIMIT 1;", connection, transaction);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@bssid", bssid);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) return null;
            return new TimelineApState(reader.GetString(0), reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                reader.GetInt32(2), reader.GetString(3), reader.GetInt32(4), reader.GetInt32(5), (uint)reader.GetInt32(6),
                reader.GetString(7), reader.GetString(8), reader.GetInt32(9), reader.IsDBNull(10) ? string.Empty : reader.GetString(10),
                reader.IsDBNull(11) ? string.Empty : reader.GetString(11), reader.GetString(12));
        }

        private static async Task<TimelineDeviceState?> ReadTimelineDeviceStateAsync(SqliteConnection connection, SqliteTransaction transaction,
            string projectId, string networkId, string ipAddress, CancellationToken cancellationToken)
        {
            using var cmd = new SqliteCommand(@"SELECT ip_address, mac_address, hostname, vendor, device_type, is_online, first_seen, last_seen
                FROM lan_devices WHERE project_id=@pid AND network_id=@network AND ip_address=@ip LIMIT 1;", connection, transaction);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@network", networkId);
            cmd.Parameters.AddWithValue("@ip", ipAddress);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) return null;
            return new TimelineDeviceState(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                reader.GetString(4), reader.GetInt32(5) != 0, reader.GetString(6), reader.GetString(7));
        }

        private static async Task<bool> HasOpenTimelinePresenceAsync(SqliteConnection connection, SqliteTransaction transaction,
            string projectId, string entityType, string entityKey, CancellationToken cancellationToken)
        {
            using var cmd = new SqliteCommand("SELECT EXISTS(SELECT 1 FROM network_timeline_presence WHERE project_id=@pid AND entity_type=@type AND entity_key=@key AND ended_at IS NULL);", connection, transaction);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@type", entityType);
            cmd.Parameters.AddWithValue("@key", entityKey);
            return Convert.ToInt32(await cmd.ExecuteScalarAsync(cancellationToken)) != 0;
        }

        private static async Task<bool> HasTimelineEntityAsync(SqliteConnection connection, SqliteTransaction transaction,
            string projectId, string entityType, string entityKey, CancellationToken cancellationToken)
        {
            using var cmd = new SqliteCommand("SELECT EXISTS(SELECT 1 FROM network_timeline_events WHERE project_id=@pid AND entity_type=@type AND entity_key=@key);", connection, transaction);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@type", entityType);
            cmd.Parameters.AddWithValue("@key", entityKey);
            return Convert.ToInt32(await cmd.ExecuteScalarAsync(cancellationToken)) != 0;
        }

        private static async Task<bool> WasRecentlyMarkedAbsentAsync(SqliteConnection connection, SqliteTransaction transaction,
            string projectId, string entityType, string entityKey, string? lastSeenAt, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(lastSeenAt)) return false;
            using var cmd = new SqliteCommand(@"SELECT EXISTS(SELECT 1 FROM network_timeline_events
                WHERE project_id=@pid AND entity_type=@type AND entity_key=@key
                AND event_type IN ('AP_DISAPPEARED','DEVICE_NOT_OBSERVED') AND julianday(occurred_at) > julianday(@lastSeen));", connection, transaction);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@type", entityType);
            cmd.Parameters.AddWithValue("@key", entityKey);
            cmd.Parameters.AddWithValue("@lastSeen", lastSeenAt);
            return Convert.ToInt32(await cmd.ExecuteScalarAsync(cancellationToken)) != 0;
        }

        private static async Task InsertNetworkTimelineEventAsync(SqliteConnection connection, SqliteTransaction transaction,
            string projectId, string occurredAt, string entityType, string entityKey, string eventType, string summary,
            object? beforeState, object? afterState, CancellationToken cancellationToken)
        {
            using var cmd = new SqliteCommand(@"INSERT INTO network_timeline_events
                (id, project_id, occurred_at, entity_type, entity_key, event_type, summary, before_state_json, after_state_json)
                VALUES (@id,@pid,@at,@entityType,@entityKey,@eventType,@summary,@before,@after);", connection, transaction);
            cmd.Parameters.AddWithValue("@id", Guid.NewGuid().ToString("N"));
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@at", occurredAt);
            cmd.Parameters.AddWithValue("@entityType", entityType);
            cmd.Parameters.AddWithValue("@entityKey", entityKey);
            cmd.Parameters.AddWithValue("@eventType", eventType);
            cmd.Parameters.AddWithValue("@summary", summary);
            cmd.Parameters.AddWithValue("@before", beforeState is null ? "{}" : JsonSerializer.Serialize(beforeState));
            cmd.Parameters.AddWithValue("@after", afterState is null ? "{}" : JsonSerializer.Serialize(afterState));
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }

        private static async Task RecordTimelinePresenceAsync(SqliteConnection connection, SqliteTransaction transaction,
            string projectId, string entityType, string entityKey, string now, CancellationToken cancellationToken)
        {
            using var open = new SqliteCommand(@"SELECT id FROM network_timeline_presence
                WHERE project_id=@pid AND entity_type=@type AND entity_key=@key AND ended_at IS NULL LIMIT 1;", connection, transaction);
            open.Parameters.AddWithValue("@pid", projectId);
            open.Parameters.AddWithValue("@type", entityType);
            open.Parameters.AddWithValue("@key", entityKey);
            string? id = (string?)await open.ExecuteScalarAsync(cancellationToken);
            if (id is null)
            {
                using var insert = new SqliteCommand(@"INSERT INTO network_timeline_presence
                    (id, project_id, entity_type, entity_key, first_seen_at, last_seen_at, ended_at)
                    VALUES (@id,@pid,@type,@key,@at,@at,NULL);", connection, transaction);
                insert.Parameters.AddWithValue("@id", Guid.NewGuid().ToString("N"));
                insert.Parameters.AddWithValue("@pid", projectId);
                insert.Parameters.AddWithValue("@type", entityType);
                insert.Parameters.AddWithValue("@key", entityKey);
                insert.Parameters.AddWithValue("@at", now);
                await insert.ExecuteNonQueryAsync(cancellationToken);
            }
            else
            {
                using var update = new SqliteCommand("UPDATE network_timeline_presence SET last_seen_at=@at WHERE id=@id;", connection, transaction);
                update.Parameters.AddWithValue("@at", now);
                update.Parameters.AddWithValue("@id", id);
                await update.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        private static async Task CloseTimelinePresenceAsync(SqliteConnection connection, SqliteTransaction transaction,
            string projectId, string entityType, string entityKey, CancellationToken cancellationToken)
        {
            using var cmd = new SqliteCommand(@"UPDATE network_timeline_presence SET ended_at=last_seen_at
                WHERE project_id=@pid AND entity_type=@type AND entity_key=@key AND ended_at IS NULL;", connection, transaction);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@type", entityType);
            cmd.Parameters.AddWithValue("@key", entityKey);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
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

        public async Task<BrowserStorageSnapshotImportResult> ImportBrowserStorageSnapshotAsync(
            string importId, IEnumerable<BrowserStorageSnapshotEntry> entries, CancellationToken cancellationToken = default)
        {
            if (!Guid.TryParse(importId, out _)) throw new ArgumentException("A valid import ID is required.", nameof(importId));
            var snapshotEntries = entries?.ToList() ?? throw new ArgumentNullException(nameof(entries));
            if (snapshotEntries.Count is 0 or > 500) throw new ArgumentOutOfRangeException(nameof(entries), "Snapshot must contain between 1 and 500 storage records.");
            foreach (var entry in snapshotEntries)
            {
                if (entry is null || string.IsNullOrEmpty(entry.StorageKey) || entry.PayloadJson is null
                    || !entry.StorageKey.StartsWith("winwifi_sqlite_", StringComparison.Ordinal)
                    || entry.StorageKey.Length > 256 || entry.PayloadJson.Length > 5 * 1024 * 1024 || entry.RecordCount < 0)
                    throw new ArgumentException("Snapshot contains an invalid or oversized browser storage record.", nameof(entries));
                using var parsed = JsonDocument.Parse(entry.PayloadJson);
            }

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);
                using var transaction = conn.BeginTransaction();
                try
                {
                    const string sql = @"INSERT INTO browser_storage_snapshots (import_id, storage_key, payload_json, record_count, imported_at)
                        VALUES (@import, @key, @payload, @count, @time);";
                    int recordTotal = 0;
                    string importedAt = DateTimeOffset.UtcNow.ToString("O");
                    foreach (var entry in snapshotEntries)
                    {
                        using var cmd = new SqliteCommand(sql, conn, transaction);
                        cmd.Parameters.AddWithValue("@import", importId);
                        cmd.Parameters.AddWithValue("@key", entry.StorageKey);
                        cmd.Parameters.AddWithValue("@payload", entry.PayloadJson);
                        cmd.Parameters.AddWithValue("@count", entry.RecordCount);
                        cmd.Parameters.AddWithValue("@time", importedAt);
                        await cmd.ExecuteNonQueryAsync(cancellationToken);
                        recordTotal = checked(recordTotal + entry.RecordCount);
                    }
                    transaction.Commit();
                    return new BrowserStorageSnapshotImportResult(importId, snapshotEntries.Count, recordTotal, importedAt);
                }
                catch
                {
                    transaction.Rollback();
                    throw;
                }
            }
            finally { _writeLock.Release(); }
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
            var observedAccessPoints = accessPoints.Where(ap => ap is not null && !string.IsNullOrWhiteSpace(ap.Bssid))
                .GroupBy(ap => ap.Bssid, StringComparer.OrdinalIgnoreCase).Select(group => group.Last()).ToList();

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

                string now = DateTimeOffset.UtcNow.ToString("O");
                foreach (var ap in observedAccessPoints)
                {
                    var previous = await ReadTimelineApStateAsync(conn, trans, projectId, ap.Bssid, cancellationToken);
                    var afterState = TimelineApState.From(ap, now);
                    bool hadTimelineState = await HasTimelineEntityAsync(conn, trans, projectId, "AP", ap.Bssid, cancellationToken);
                    if (!hadTimelineState)
                    {
                        string eventType = previous is null ? "AP_FIRST_SEEN" : "AP_BASELINE";
                        string summary = previous is null ? $"Access point {ap.Ssid} was first observed." : $"Access point {ap.Ssid} history began with its currently observed configuration.";
                        await InsertNetworkTimelineEventAsync(conn, trans, projectId, now, "AP", ap.Bssid, eventType, summary,
                            previous?.ToDictionary(), afterState.ToDictionary(), cancellationToken);
                    }
                    else if (await WasRecentlyMarkedAbsentAsync(conn, trans, projectId, "AP", ap.Bssid, previous?.LastSeenAt, cancellationToken))
                    {
                        await InsertNetworkTimelineEventAsync(conn, trans, projectId, now, "AP", ap.Bssid, "AP_REAPPEARED",
                            $"Access point {ap.Ssid} was observed again.", previous?.ToDictionary(), afterState.ToDictionary(), cancellationToken);
                    }
                    if (previous is not null)
                    {
                        var changedFields = previous.ChangedFields(afterState);
                        if (changedFields.Count > 0)
                        {
                            await InsertNetworkTimelineEventAsync(conn, trans, projectId, now, "AP", ap.Bssid, "AP_CONFIGURATION_CHANGED",
                                $"Access point configuration changed: {string.Join(", ", changedFields)}.",
                                previous.ToDictionary(), afterState.ToDictionary(), cancellationToken);
                        }
                    }
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
                    await RecordTimelinePresenceAsync(conn, trans, projectId, "AP", ap.Bssid, now, cancellationToken);
                }

                var seenBssids = observedAccessPoints.Select(ap => ap.Bssid).ToHashSet(StringComparer.OrdinalIgnoreCase);
                var persistedAps = new List<TimelineApState>();
                using (var staleQuery = new SqliteCommand(@"SELECT bssid, ssid, channel, band, frequency_mhz, rssi, signal_quality, security, cipher, channel_width, vendor, first_seen, last_seen
                    FROM access_points WHERE project_id=@pid AND julianday(last_seen) <= julianday('now','-12 seconds');", conn, trans))
                {
                    staleQuery.Parameters.AddWithValue("@pid", projectId);
                    using var reader = await staleQuery.ExecuteReaderAsync(cancellationToken);
                    while (await reader.ReadAsync(cancellationToken))
                    {
                        persistedAps.Add(new TimelineApState(reader.GetString(0), reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                            reader.GetInt32(2), reader.GetString(3), reader.GetInt32(4), reader.GetInt32(5), (uint)reader.GetInt32(6),
                            reader.GetString(7), reader.GetString(8), reader.GetInt32(9), reader.IsDBNull(10) ? string.Empty : reader.GetString(10),
                            reader.IsDBNull(11) ? string.Empty : reader.GetString(11), reader.GetString(12)));
                    }
                }
                foreach (var stale in persistedAps.Where(ap => !seenBssids.Contains(ap.Bssid)))
                {
                    if (await WasRecentlyMarkedAbsentAsync(conn, trans, projectId, "AP", stale.Bssid, stale.LastSeenAt, cancellationToken)) continue;
                    await InsertNetworkTimelineEventAsync(conn, trans, projectId, now, "AP", stale.Bssid, "AP_DISAPPEARED",
                        $"Access point {stale.Ssid} was no longer observed in consecutive scans.", stale.ToDictionary(),
                        new Dictionary<string, object?> { ["bssid"] = stale.Bssid, ["ssid"] = stale.Ssid, ["isPresent"] = false, ["lastSeenAt"] = stale.LastSeenAt }, cancellationToken);
                    await CloseTimelinePresenceAsync(conn, trans, projectId, "AP", stale.Bssid, cancellationToken);
                }

                trans.Commit();
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public const int SignalChangeThresholdDbm = 5;
        public const int MissingScanThreshold = 3;
        public static readonly TimeSpan ObservationHeartbeatInterval = TimeSpan.FromHours(1);

        /// <summary>
        /// Stores a compact history: material changes, first sightings, disappearances,
        /// and hourly heartbeats become observations; every scan only refreshes the
        /// lightweight per-BSSID last-seen state otherwise.
        /// </summary>
        public async Task SaveScanObservationsBatchAsync(string projectId, string adapterId, int scanCycle, IEnumerable<AccessPoint> accessPoints, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (accessPoints == null) return;
            var observed = accessPoints
                .Where(ap => ap is not null && !string.IsNullOrWhiteSpace(ap.Bssid))
                .GroupBy(ap => ap.Bssid, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.Last())
                .ToList();

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);
                using var trans = conn.BeginTransaction();
                var now = DateTimeOffset.UtcNow;
                string nowText = now.ToString("O");

                // Existing databases have detailed snapshots but no compact state.
                // Seed each BSSID from its latest historical row once, without
                // rewriting or deleting the user's existing history.
                using (var migrationCheck = new SqliteCommand("SELECT EXISTS(SELECT 1 FROM scan_observation_migrations WHERE project_id=@pid);", conn, trans))
                {
                    migrationCheck.Parameters.AddWithValue("@pid", projectId);
                    if (Convert.ToInt32(await migrationCheck.ExecuteScalarAsync(cancellationToken)) == 0)
                    {
                        using var seed = new SqliteCommand(@"
                            INSERT OR IGNORE INTO scan_observation_state (
                                project_id, bssid, adapter_id, scan_cycle, ssid, channel, band, frequency_mhz,
                                rssi, signal_quality, security, cipher, phy_type, channel_width,
                                last_seen_at, last_observation_at, missed_scans, is_present)
                            SELECT o.project_id, upper(o.bssid), COALESCE(o.adapter_id,''), COALESCE(o.scan_cycle,0),
                                COALESCE(o.ssid,''), COALESCE(o.channel,0), COALESCE(o.band,'Unknown'),
                                COALESCE(o.frequency_mhz,0), COALESCE(o.rssi,0), COALESCE(o.signal_quality,0),
                                COALESCE(o.security,'Unknown'), COALESCE(o.cipher,'Unknown'),
                                COALESCE(o.phy_type,'Unknown'), COALESCE(o.channel_width,20),
                                COALESCE(o.last_seen_at,o.observed_at), o.observed_at, 0,
                                CASE WHEN o.event_type='AP_DISAPPEARED' THEN 0 ELSE 1 END
                            FROM scan_observations o
                            WHERE o.project_id=@pid
                              AND o.id=(SELECT MAX(latest.id) FROM scan_observations latest
                                        WHERE latest.project_id=o.project_id AND upper(latest.bssid)=upper(o.bssid));", conn, trans);
                        seed.Parameters.AddWithValue("@pid", projectId);
                        await seed.ExecuteNonQueryAsync(cancellationToken);

                        using var mark = new SqliteCommand("INSERT OR IGNORE INTO scan_observation_migrations(project_id,initialized_at) VALUES(@pid,@at);", conn, trans);
                        mark.Parameters.AddWithValue("@pid", projectId);
                        mark.Parameters.AddWithValue("@at", nowText);
                        await mark.ExecuteNonQueryAsync(cancellationToken);
                    }
                }

                var states = new Dictionary<string, ScanObservationState>(StringComparer.OrdinalIgnoreCase);
                using (var stateQuery = new SqliteCommand(@"SELECT bssid,adapter_id,scan_cycle,ssid,channel,band,frequency_mhz,
                        rssi,signal_quality,security,cipher,phy_type,channel_width,last_seen_at,last_observation_at,missed_scans,is_present
                    FROM scan_observation_state WHERE project_id=@pid;", conn, trans))
                {
                    stateQuery.Parameters.AddWithValue("@pid", projectId);
                    using var reader = await stateQuery.ExecuteReaderAsync(cancellationToken);
                    while (await reader.ReadAsync(cancellationToken))
                    {
                        var state = new ScanObservationState(
                            reader.GetString(0), reader.IsDBNull(1) ? string.Empty : reader.GetString(1), reader.GetInt32(2),
                            reader.IsDBNull(3) ? string.Empty : reader.GetString(3), reader.GetInt32(4),
                            reader.IsDBNull(5) ? "Unknown" : reader.GetString(5), reader.GetInt32(6), reader.GetInt32(7),
                            (uint)reader.GetInt32(8), reader.IsDBNull(9) ? "Unknown" : reader.GetString(9),
                            reader.IsDBNull(10) ? "Unknown" : reader.GetString(10), reader.IsDBNull(11) ? "Unknown" : reader.GetString(11),
                            reader.GetInt32(12), reader.GetString(13), reader.GetString(14), reader.GetInt32(15), reader.GetInt32(16) != 0);
                        states[state.Bssid] = state;
                    }
                }

                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var ap in observed)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    string bssid = ap.Bssid.Trim().ToUpperInvariant();
                    seen.Add(bssid);
                    var sample = ScanObservationState.From(ap, adapterId ?? string.Empty, scanCycle, nowText);
                    states.TryGetValue(bssid, out var previous);
                    string? eventType = GetObservationEventType(previous, sample, now);

                    if (eventType is not null)
                    {
                        await InsertScanObservationAsync(conn, trans, projectId, sample, eventType, nowText, nowText, cancellationToken);
                    }

                    // On ordinary scans only last-seen, cycle, and miss-count change.
                    // The comparison baseline remains the last recorded observation,
                    // so small RSSI shifts can accumulate until they are meaningful.
                    var recorded = eventType is null && previous is not null ? previous : sample;
                    var next = recorded with
                    {
                        AdapterId = adapterId ?? string.Empty,
                        ScanCycle = scanCycle,
                        LastSeenAt = nowText,
                        LastObservationAt = eventType is null && previous is not null ? previous.LastObservationAt : nowText,
                        MissedScans = 0,
                        IsPresent = true
                    };
                    await UpsertScanObservationStateAsync(conn, trans, projectId, next, cancellationToken);
                    states[bssid] = next;
                }

                foreach (var previous in states.Values.Where(state => state.IsPresent && !seen.Contains(state.Bssid)).ToList())
                {
                    int missedScans = previous.MissedScans + 1;
                    if (missedScans >= MissingScanThreshold)
                    {
                        await InsertScanObservationAsync(conn, trans, projectId, previous, "AP_DISAPPEARED", nowText, previous.LastSeenAt, cancellationToken);
                        var absent = previous with { LastObservationAt = nowText, MissedScans = missedScans, IsPresent = false };
                        await UpsertScanObservationStateAsync(conn, trans, projectId, absent, cancellationToken);
                        states[previous.Bssid] = absent;
                    }
                    else
                    {
                        var waiting = previous with { MissedScans = missedScans };
                        await UpsertScanObservationStateAsync(conn, trans, projectId, waiting, cancellationToken);
                        states[previous.Bssid] = waiting;
                    }
                }

                await trans.CommitAsync(cancellationToken);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        private static string? GetObservationEventType(ScanObservationState? previous, ScanObservationState current, DateTimeOffset now)
        {
            if (previous is null) return "AP_FIRST_SEEN";
            if (!previous.IsPresent) return "AP_APPEARED";

            bool configurationChanged = !string.Equals(previous.Ssid, current.Ssid, StringComparison.Ordinal)
                || previous.Channel != current.Channel
                || !string.Equals(previous.Band, current.Band, StringComparison.OrdinalIgnoreCase)
                || previous.FrequencyMHz != current.FrequencyMHz
                || !string.Equals(previous.Security, current.Security, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(previous.Cipher, current.Cipher, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(previous.PhyType, current.PhyType, StringComparison.OrdinalIgnoreCase)
                || previous.ChannelWidth != current.ChannelWidth;
            if (configurationChanged) return "CONFIGURATION_CHANGED";
            if (Math.Abs(current.Rssi - previous.Rssi) >= SignalChangeThresholdDbm) return "SIGNAL_CHANGED";
            if (DateTimeOffset.TryParse(previous.LastObservationAt, out var lastObservation)
                && now - lastObservation >= ObservationHeartbeatInterval) return "HEARTBEAT";
            return null;
        }

        private static async Task InsertScanObservationAsync(SqliteConnection conn, SqliteTransaction trans, string projectId,
            ScanObservationState sample, string eventType, string observedAt, string lastSeenAt, CancellationToken cancellationToken)
        {
            using var cmd = new SqliteCommand(@"INSERT INTO scan_observations (
                    project_id,adapter_id,scan_cycle,bssid,ssid,channel,band,frequency_mhz,rssi,signal_quality,
                    security,cipher,phy_type,channel_width,observed_at,event_type,last_seen_at)
                VALUES (@project,@adapter,@cycle,@bssid,@ssid,@channel,@band,@frequency,@rssi,@quality,
                    @security,@cipher,@phy,@width,@observed,@event,@lastSeen);", conn, trans);
            cmd.Parameters.AddWithValue("@project", projectId);
            cmd.Parameters.AddWithValue("@adapter", sample.AdapterId);
            cmd.Parameters.AddWithValue("@cycle", sample.ScanCycle);
            cmd.Parameters.AddWithValue("@bssid", sample.Bssid);
            cmd.Parameters.AddWithValue("@ssid", sample.Ssid);
            cmd.Parameters.AddWithValue("@channel", sample.Channel);
            cmd.Parameters.AddWithValue("@band", sample.Band);
            cmd.Parameters.AddWithValue("@frequency", sample.FrequencyMHz);
            cmd.Parameters.AddWithValue("@rssi", sample.Rssi);
            cmd.Parameters.AddWithValue("@quality", (int)sample.SignalQuality);
            cmd.Parameters.AddWithValue("@security", sample.Security);
            cmd.Parameters.AddWithValue("@cipher", sample.Cipher);
            cmd.Parameters.AddWithValue("@phy", sample.PhyType);
            cmd.Parameters.AddWithValue("@width", sample.ChannelWidth);
            cmd.Parameters.AddWithValue("@observed", observedAt);
            cmd.Parameters.AddWithValue("@event", eventType);
            cmd.Parameters.AddWithValue("@lastSeen", lastSeenAt);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }

        private static async Task UpsertScanObservationStateAsync(SqliteConnection conn, SqliteTransaction trans, string projectId,
            ScanObservationState state, CancellationToken cancellationToken)
        {
            using var cmd = new SqliteCommand(@"INSERT INTO scan_observation_state (
                    project_id,bssid,adapter_id,scan_cycle,ssid,channel,band,frequency_mhz,rssi,signal_quality,
                    security,cipher,phy_type,channel_width,last_seen_at,last_observation_at,missed_scans,is_present)
                VALUES (@project,@bssid,@adapter,@cycle,@ssid,@channel,@band,@frequency,@rssi,@quality,
                    @security,@cipher,@phy,@width,@lastSeen,@lastObservation,@missed,@present)
                ON CONFLICT(project_id,bssid) DO UPDATE SET
                    adapter_id=excluded.adapter_id,scan_cycle=excluded.scan_cycle,ssid=excluded.ssid,
                    channel=excluded.channel,band=excluded.band,frequency_mhz=excluded.frequency_mhz,
                    rssi=excluded.rssi,signal_quality=excluded.signal_quality,security=excluded.security,
                    cipher=excluded.cipher,phy_type=excluded.phy_type,channel_width=excluded.channel_width,
                    last_seen_at=excluded.last_seen_at,last_observation_at=excluded.last_observation_at,
                    missed_scans=excluded.missed_scans,is_present=excluded.is_present;", conn, trans);
            cmd.Parameters.AddWithValue("@project", projectId);
            cmd.Parameters.AddWithValue("@bssid", state.Bssid);
            cmd.Parameters.AddWithValue("@adapter", state.AdapterId);
            cmd.Parameters.AddWithValue("@cycle", state.ScanCycle);
            cmd.Parameters.AddWithValue("@ssid", state.Ssid);
            cmd.Parameters.AddWithValue("@channel", state.Channel);
            cmd.Parameters.AddWithValue("@band", state.Band);
            cmd.Parameters.AddWithValue("@frequency", state.FrequencyMHz);
            cmd.Parameters.AddWithValue("@rssi", state.Rssi);
            cmd.Parameters.AddWithValue("@quality", (int)state.SignalQuality);
            cmd.Parameters.AddWithValue("@security", state.Security);
            cmd.Parameters.AddWithValue("@cipher", state.Cipher);
            cmd.Parameters.AddWithValue("@phy", state.PhyType);
            cmd.Parameters.AddWithValue("@width", state.ChannelWidth);
            cmd.Parameters.AddWithValue("@lastSeen", state.LastSeenAt);
            cmd.Parameters.AddWithValue("@lastObservation", state.LastObservationAt);
            cmd.Parameters.AddWithValue("@missed", state.MissedScans);
            cmd.Parameters.AddWithValue("@present", state.IsPresent ? 1 : 0);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }

        public async Task<List<ScanObservationRecord>> GetScanObservationsAsync(string projectId, string? bssid = null, int limit = 500, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            var list = new List<ScanObservationRecord>();
            using var conn = await OpenConnectionAsync(cancellationToken);

            string sql = string.IsNullOrEmpty(bssid)
                ? @"SELECT id, project_id, adapter_id, scan_cycle, bssid, ssid, channel, band,
                           frequency_mhz, rssi, signal_quality, security, cipher, phy_type, channel_width, observed_at,
                           event_type, COALESCE(last_seen_at,observed_at)
                    FROM scan_observations
                    WHERE project_id = @pid
                    ORDER BY id DESC LIMIT @limit;"
                : @"SELECT id, project_id, adapter_id, scan_cycle, bssid, ssid, channel, band,
                           frequency_mhz, rssi, signal_quality, security, cipher, phy_type, channel_width, observed_at,
                           event_type, COALESCE(last_seen_at,observed_at)
                    FROM scan_observations
                    WHERE project_id = @pid AND upper(bssid) = upper(@bssid)
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
                    ObservedAt = reader.GetString(15),
                    EventType = reader.IsDBNull(16) ? "OBSERVATION" : reader.GetString(16),
                    LastSeenAt = reader.IsDBNull(17) ? reader.GetString(15) : reader.GetString(17)
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

        public async Task<NetworkTimelineBounds> GetNetworkTimelineBoundsAsync(string projectId, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            using var conn = await OpenConnectionAsync(cancellationToken);
            var bounds = new NetworkTimelineBounds
            {
                LegacyObservationCount = await GetTotalObservationsCountAsync(projectId, cancellationToken)
            };
            using (var changes = new SqliteCommand("SELECT COUNT(*), MIN(occurred_at), MAX(occurred_at) FROM network_timeline_events WHERE project_id=@pid;", conn))
            {
                changes.Parameters.AddWithValue("@pid", projectId);
                using var reader = await changes.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken))
                {
                    bounds.ChangeCount = reader.GetInt32(0);
                    if (!reader.IsDBNull(1)) bounds.EarliestAt = reader.GetString(1);
                    if (!reader.IsDBNull(2)) bounds.LatestAt = reader.GetString(2);
                }
            }
            using (var observations = new SqliteCommand("SELECT MIN(observed_at), MAX(observed_at) FROM scan_observations WHERE project_id=@pid;", conn))
            {
                observations.Parameters.AddWithValue("@pid", projectId);
                using var reader = await observations.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken))
                {
                    string? earliest = reader.IsDBNull(0) ? null : reader.GetString(0);
                    string? latest = reader.IsDBNull(1) ? null : reader.GetString(1);
                    bounds.EarliestAt = MinTimestamp(bounds.EarliestAt, earliest);
                    bounds.LatestAt = MaxTimestamp(bounds.LatestAt, latest);
                }
            }
            bounds.HasData = bounds.EarliestAt is not null && bounds.LatestAt is not null;
            bounds.Message = bounds.HasData ? string.Empty : "No saved scan observations or network changes exist for this project yet.";
            return bounds;
        }

        public async Task<WalkSignalReading> SaveWalkSignalReadingAsync(string projectId, WalkSignalReadingRequest request, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            string normalizedProjectId = projectId?.Trim() ?? string.Empty;
            string bssid = request.Bssid?.Trim().ToUpperInvariant() ?? string.Empty;
            string ssid = request.Ssid?.Trim() ?? string.Empty;
            string location = request.LocationName?.Trim() ?? string.Empty;
            if (normalizedProjectId.Length == 0 || bssid.Length == 0 || location.Length == 0)
                throw new ArgumentException("Project, access point, and location are required.");
            if (location.Length > 128 || request.RssiDbm is < -127 or > 0 || request.SignalQuality > 100)
                throw new ArgumentOutOfRangeException(nameof(request), "Location or signal measurement is outside the allowed range.");

            var reading = new WalkSignalReading
            {
                Id = Guid.NewGuid().ToString("N"),
                ProjectId = normalizedProjectId,
                Bssid = bssid,
                Ssid = ssid,
                LocationName = location,
                RssiDbm = request.RssiDbm,
                SignalQuality = request.SignalQuality,
                CapturedAt = DateTimeOffset.UtcNow.ToString("O")
            };

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = new SqliteConnection(_connectionString);
                await conn.OpenAsync(cancellationToken);
                using var transaction = conn.BeginTransaction();
                using var cmd = new SqliteCommand(@"INSERT INTO walk_signal_readings
                    (id, project_id, bssid, ssid, location_name, rssi_dbm, signal_quality, captured_at)
                    VALUES (@id, @project, @bssid, @ssid, @location, @rssi, @quality, @at);", conn, transaction);
                cmd.Parameters.AddWithValue("@id", reading.Id);
                cmd.Parameters.AddWithValue("@project", reading.ProjectId);
                cmd.Parameters.AddWithValue("@bssid", reading.Bssid);
                cmd.Parameters.AddWithValue("@ssid", reading.Ssid);
                cmd.Parameters.AddWithValue("@location", reading.LocationName);
                cmd.Parameters.AddWithValue("@rssi", reading.RssiDbm);
                cmd.Parameters.AddWithValue("@quality", (int)reading.SignalQuality);
                cmd.Parameters.AddWithValue("@at", reading.CapturedAt);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            finally { _writeLock.Release(); }
            return reading;
        }

        public async Task<List<WalkSignalReading>> GetWalkSignalReadingsAsync(string projectId, int limit = 1000, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            var readings = new List<WalkSignalReading>();
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync(cancellationToken);
            using var cmd = new SqliteCommand(@"SELECT id, project_id, bssid, ssid, location_name, rssi_dbm, signal_quality, captured_at
                FROM walk_signal_readings WHERE project_id=@project ORDER BY captured_at DESC LIMIT @limit;", conn);
            cmd.Parameters.AddWithValue("@project", projectId);
            cmd.Parameters.AddWithValue("@limit", Math.Clamp(limit, 1, 5000));
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                readings.Add(new WalkSignalReading
                {
                    Id = reader.GetString(0), ProjectId = reader.GetString(1), Bssid = reader.GetString(2),
                    Ssid = reader.GetString(3), LocationName = reader.GetString(4), RssiDbm = reader.GetInt32(5),
                    SignalQuality = (uint)reader.GetInt32(6), CapturedAt = reader.GetString(7)
                });
            }
            return readings;
        }

        public async Task<NetworkTimelineState> GetNetworkTimeMachineStateAsync(string projectId, string at, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (!DateTimeOffset.TryParse(at, out var parsedAt)) throw new ArgumentException("A valid point in time is required.", nameof(at));
            string asOf = parsedAt.ToUniversalTime().ToString("O");
            string? snapshotAt = null;
            var accessPoints = new Dictionary<string, NetworkTimelineEntityState>(StringComparer.OrdinalIgnoreCase);
            var devices = new Dictionary<string, NetworkTimelineEntityState>(StringComparer.OrdinalIgnoreCase);
            var state = new NetworkTimelineState { AsOf = asOf };
            using var conn = await OpenConnectionAsync(cancellationToken);

            using (var latest = new SqliteCommand("SELECT MAX(observed_at) FROM scan_observations WHERE project_id=@pid AND observed_at<=@at;", conn))
            {
                latest.Parameters.AddWithValue("@pid", projectId);
                latest.Parameters.AddWithValue("@at", asOf);
                var value = await latest.ExecuteScalarAsync(cancellationToken);
                snapshotAt = value is null || value == DBNull.Value ? null : Convert.ToString(value);
            }

            if (!string.IsNullOrWhiteSpace(snapshotAt))
            {
                using var snapshot = new SqliteCommand(@"SELECT o.bssid,o.ssid,o.channel,o.band,o.frequency_mhz,o.rssi,o.signal_quality,
                        o.security,o.cipher,o.phy_type,o.channel_width,o.observed_at,o.event_type,COALESCE(o.last_seen_at,o.observed_at)
                    FROM scan_observations o
                    WHERE o.project_id=@pid AND o.observed_at<=@at
                      AND o.id=(SELECT MAX(latest.id) FROM scan_observations latest
                                WHERE latest.project_id=o.project_id AND upper(latest.bssid)=upper(o.bssid) AND latest.observed_at<=@at);", conn);
                snapshot.Parameters.AddWithValue("@pid", projectId);
                snapshot.Parameters.AddWithValue("@at", asOf);
                using var reader = await snapshot.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken))
                {
                    string eventType = reader.IsDBNull(12) ? "OBSERVATION" : reader.GetString(12);
                    var ap = new NetworkTimelineEntityState
                    {
                        EntityType = "AP", EntityKey = reader.GetString(0), Bssid = reader.GetString(0),
                        Ssid = reader.IsDBNull(1) ? string.Empty : reader.GetString(1), Channel = reader.GetInt32(2),
                        Band = reader.IsDBNull(3) ? "Unknown" : reader.GetString(3), FrequencyMhz = reader.GetInt32(4),
                        Rssi = reader.GetInt32(5), SignalQuality = (uint)reader.GetInt32(6),
                        Security = reader.IsDBNull(7) ? "Unknown" : reader.GetString(7), Cipher = reader.IsDBNull(8) ? "Unknown" : reader.GetString(8),
                        Vendor = string.Empty, ChannelWidth = reader.GetInt32(10),
                        FirstSeenAt = reader.GetString(11), LastSeenAt = reader.GetString(13), IsPresent = eventType != "AP_DISAPPEARED"
                    };
                    if (!string.IsNullOrWhiteSpace(ap.EntityKey)) accessPoints[ap.EntityKey] = ap;
                }

                using var firstLast = new SqliteCommand(@"SELECT upper(bssid), MIN(observed_at), MAX(COALESCE(last_seen_at,observed_at)) FROM scan_observations
                    WHERE project_id=@pid AND observed_at<=@at GROUP BY upper(bssid);", conn);
                firstLast.Parameters.AddWithValue("@pid", projectId);
                firstLast.Parameters.AddWithValue("@at", asOf);
                using var history = await firstLast.ExecuteReaderAsync(cancellationToken);
                while (await history.ReadAsync(cancellationToken))
                {
                    if (accessPoints.TryGetValue(history.GetString(0), out var ap))
                    {
                        ap.FirstSeenAt = history.IsDBNull(1) ? string.Empty : history.GetString(1);
                        ap.LastSeenAt = history.IsDBNull(2) ? string.Empty : history.GetString(2);
                    }
                }
            }

            var changes = await ReadTimelineEventsAsync(conn, projectId, snapshotAt, asOf, cancellationToken);
            foreach (var change in changes)
            {
                if (change.EntityType.Equals("AP", StringComparison.OrdinalIgnoreCase))
                {
                    if (change.EventType == "AP_DISAPPEARED")
                    {
                        if (accessPoints.TryGetValue(change.EntityKey, out var ap)) ap.IsPresent = false;
                        else if (TryReadTimelineEntity(change.AfterStateJson, change.EntityType, change.EntityKey, out var disappeared))
                        {
                            disappeared.IsPresent = false;
                            accessPoints[change.EntityKey] = disappeared;
                        }
                    }
                    else if (TryReadTimelineEntity(change.AfterStateJson, change.EntityType, change.EntityKey, out var changedAp))
                    {
                        if (accessPoints.TryGetValue(change.EntityKey, out var existing))
                        {
                            MergeTimelineEntity(existing, changedAp);
                            existing.IsPresent = true;
                        }
                        else accessPoints[change.EntityKey] = changedAp;
                    }
                }
                else if (change.EntityType.Equals("DEVICE", StringComparison.OrdinalIgnoreCase))
                {
                    if (change.EventType == "DEVICE_NOT_OBSERVED")
                    {
                        if (devices.TryGetValue(change.EntityKey, out var device)) device.IsPresent = false;
                    }
                    else if (TryReadTimelineEntity(change.AfterStateJson, change.EntityType, change.EntityKey, out var changedDevice))
                    {
                        if (devices.TryGetValue(change.EntityKey, out var existing))
                        {
                            MergeTimelineEntity(existing, changedDevice);
                            existing.IsPresent = true;
                        }
                        else devices[change.EntityKey] = changedDevice;
                    }
                }
            }

            await ApplyTimelinePresenceAsync(conn, projectId, asOf, accessPoints, devices, cancellationToken);
            state.AccessPoints = accessPoints.Values.OrderBy(entity => entity.Ssid, StringComparer.OrdinalIgnoreCase).ThenBy(entity => entity.Bssid).ToList();
            state.Devices = devices.Values.OrderBy(entity => entity.IpAddress, StringComparer.OrdinalIgnoreCase).ToList();
            state.Changes = changes;
            state.HasData = state.AccessPoints.Count > 0 || state.Devices.Count > 0 || changes.Count > 0;
            state.Source = snapshotAt is null ? "Change records" : "Saved scan observations with later change records";
            state.Message = state.HasData ? string.Empty : "No saved network data exists at or before this time.";
            return state;
        }

        private static async Task<List<NetworkTimelineEvent>> ReadTimelineEventsAsync(SqliteConnection conn, string projectId,
            string? after, string through, CancellationToken cancellationToken)
        {
            var events = new List<NetworkTimelineEvent>();
            using (var cmd = new SqliteCommand(@"SELECT id, project_id, occurred_at, entity_type, entity_key, event_type, summary, before_state_json, after_state_json
                FROM network_timeline_events WHERE project_id=@pid AND (@after IS NULL OR occurred_at>@after) AND occurred_at<=@through
                ORDER BY occurred_at, id;", conn))
            {
                cmd.Parameters.AddWithValue("@pid", projectId);
                cmd.Parameters.AddWithValue("@after", (object?)after ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@through", through);
                using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken))
                {
                    events.Add(new NetworkTimelineEvent
                    {
                        Id = reader.GetString(0), ProjectId = reader.GetString(1), OccurredAt = reader.GetString(2),
                        EntityType = reader.GetString(3), EntityKey = reader.GetString(4), EventType = reader.GetString(5),
                        Summary = reader.GetString(6), BeforeStateJson = reader.GetString(7), AfterStateJson = reader.GetString(8)
                    });
                }
            }
            using (var cmd = new SqliteCommand(@"SELECT id, project_id, timestamp, 'AP', bssid, change_type, title, before_state, after_state
                FROM security_changes WHERE project_id=@pid AND (@after IS NULL OR timestamp>@after) AND timestamp<=@through
                ORDER BY timestamp, id;", conn))
            {
                cmd.Parameters.AddWithValue("@pid", projectId);
                cmd.Parameters.AddWithValue("@after", (object?)after ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@through", through);
                using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken))
                {
                    events.Add(new NetworkTimelineEvent
                    {
                        Id = reader.GetString(0), ProjectId = reader.GetString(1), OccurredAt = reader.GetString(2),
                        EntityType = reader.GetString(3), EntityKey = reader.GetString(4), EventType = reader.GetString(5),
                        Summary = reader.GetString(6), BeforeStateJson = reader.IsDBNull(7) ? "{}" : reader.GetString(7),
                        AfterStateJson = reader.IsDBNull(8) ? "{}" : reader.GetString(8)
                    });
                }
            }
            return events.OrderBy(e => e.OccurredAt, StringComparer.Ordinal).ThenBy(e => e.Id, StringComparer.Ordinal).ToList();
        }

        private static bool TryReadTimelineEntity(string json, string entityType, string entityKey, out NetworkTimelineEntityState entity)
        {
            try
            {
                entity = JsonSerializer.Deserialize<NetworkTimelineEntityState>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
                entity.EntityType = entityType;
                entity.EntityKey = entityKey;
                if (entityType == "AP" && string.IsNullOrWhiteSpace(entity.Bssid)) entity.Bssid = entityKey;
                if (entityType == "DEVICE" && string.IsNullOrWhiteSpace(entity.IpAddress)) entity.IpAddress = entityKey.Split('|').LastOrDefault() ?? entityKey;
                return true;
            }
            catch { entity = new(); return false; }
        }

        private static void MergeTimelineEntity(NetworkTimelineEntityState target, NetworkTimelineEntityState source)
        {
            if (!string.IsNullOrWhiteSpace(source.Ssid)) target.Ssid = source.Ssid;
            if (source.Channel.HasValue) target.Channel = source.Channel;
            if (!string.IsNullOrWhiteSpace(source.Band)) target.Band = source.Band;
            if (source.FrequencyMhz.HasValue) target.FrequencyMhz = source.FrequencyMhz;
            if (source.Rssi.HasValue) target.Rssi = source.Rssi;
            if (source.SignalQuality.HasValue) target.SignalQuality = source.SignalQuality;
            if (!string.IsNullOrWhiteSpace(source.Security)) target.Security = source.Security;
            if (!string.IsNullOrWhiteSpace(source.Cipher)) target.Cipher = source.Cipher;
            if (!string.IsNullOrWhiteSpace(source.Vendor)) target.Vendor = source.Vendor;
            if (source.ChannelWidth.HasValue) target.ChannelWidth = source.ChannelWidth;
            if (!string.IsNullOrWhiteSpace(source.IpAddress)) target.IpAddress = source.IpAddress;
            if (!string.IsNullOrWhiteSpace(source.MacAddress)) target.MacAddress = source.MacAddress;
            if (!string.IsNullOrWhiteSpace(source.Hostname)) target.Hostname = source.Hostname;
            if (!string.IsNullOrWhiteSpace(source.DeviceType)) target.DeviceType = source.DeviceType;
            if (!string.IsNullOrWhiteSpace(source.FirstSeenAt)) target.FirstSeenAt = source.FirstSeenAt;
            if (!string.IsNullOrWhiteSpace(source.LastSeenAt)) target.LastSeenAt = source.LastSeenAt;
            target.IsOnline = source.IsOnline;
        }

        private static async Task ApplyTimelinePresenceAsync(SqliteConnection conn, string projectId, string at,
            Dictionary<string, NetworkTimelineEntityState> accessPoints, Dictionary<string, NetworkTimelineEntityState> devices,
            CancellationToken cancellationToken)
        {
            using var cmd = new SqliteCommand(@"SELECT entity_type, entity_key, first_seen_at, last_seen_at FROM network_timeline_presence
                WHERE project_id=@pid AND first_seen_at<=@at AND (ended_at IS NULL OR ended_at>@at);", conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@at", at);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                string type = reader.GetString(0), key = reader.GetString(1);
                var map = type == "AP" ? accessPoints : devices;
                if (!map.TryGetValue(key, out var entity)) continue;
                entity.IsPresent = true;
                entity.FirstSeenAt = reader.GetString(2);
                string lastSeen = reader.GetString(3);
                entity.LastSeenAt = string.CompareOrdinal(lastSeen, at) > 0 ? at : lastSeen;
            }
        }

        private static string? MinTimestamp(string? left, string? right) => left is null ? right : right is null ? left
            : string.CompareOrdinal(left, right) <= 0 ? left : right;
        private static string? MaxTimestamp(string? left, string? right) => left is null ? right : right is null ? left
            : string.CompareOrdinal(left, right) >= 0 ? left : right;

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

        public async Task<List<LanDeviceRecord>> GetLanDevicesAsync(string projectId, string networkId, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            var records = new List<LanDeviceRecord>();
            using var conn = await OpenConnectionAsync(cancellationToken);
            using var cmd = new SqliteCommand(@"SELECT ip_address, mac_address, hostname, vendor, device_type, evidence_json, ports_json, is_online, is_known, is_randomized_mac, ping_ttl, os_guess, first_seen, last_seen, checked_at
                FROM lan_devices WHERE project_id = @pid AND network_id = @network ORDER BY is_online DESC, ip_address;", conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@network", networkId);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                records.Add(new LanDeviceRecord
                {
                    NetworkId = networkId,
                    IpAddress = reader.GetString(0),
                    MacAddress = reader.IsDBNull(1) ? "" : reader.GetString(1),
                    Hostname = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Vendor = reader.IsDBNull(3) ? "Unknown" : reader.GetString(3),
                    DeviceType = reader.IsDBNull(4) ? "Unknown" : reader.GetString(4),
                    Evidence = reader.IsDBNull(5) ? new() : JsonSerializer.Deserialize<List<string>>(reader.GetString(5)) ?? new(),
                    OpenPorts = reader.IsDBNull(6) ? new() : JsonSerializer.Deserialize<List<LanOpenPort>>(reader.GetString(6)) ?? new(),
                    IsOnline = reader.GetInt32(7) != 0,
                    IsKnown = reader.GetInt32(8) != 0,
                    IsRandomizedMac = reader.GetInt32(9) != 0,
                    PingTtl = reader.IsDBNull(10) ? null : reader.GetInt32(10),
                    OsGuess = reader.IsDBNull(11) ? "Unknown" : reader.GetString(11),
                    FirstSeen = reader.IsDBNull(12) ? "" : reader.GetString(12),
                    LastSeen = reader.IsDBNull(13) ? "" : reader.GetString(13),
                    LastCheckedAt = reader.IsDBNull(14) ? "" : reader.GetString(14)
                });
            }
            return records;
        }

        public async Task SaveLanDevicesAsync(string projectId, string networkId, IEnumerable<LanDeviceRecord> devices, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (devices is null) return;
            var observedDevices = devices.Where(device => device is not null && !string.IsNullOrWhiteSpace(device.IpAddress))
                .GroupBy(device => device.IpAddress, StringComparer.OrdinalIgnoreCase).Select(group => group.Last()).ToList();
            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);
                using var trans = conn.BeginTransaction();
                const string sql = @"INSERT INTO lan_devices (
                    project_id, network_id, ip_address, mac_address, hostname, vendor, device_type,
                    evidence_json, ports_json, is_online, is_randomized_mac, ping_ttl, os_guess, first_seen, last_seen, checked_at
                ) VALUES (@pid,@network,@ip,@mac,@hostname,@vendor,@type,@evidence,@ports,@online,@randomized,@ttl,@os,@first,@last,@checked)
                ON CONFLICT(project_id, network_id, ip_address) DO UPDATE SET
                    mac_address=excluded.mac_address, hostname=excluded.hostname, vendor=excluded.vendor,
                    device_type=excluded.device_type, evidence_json=excluded.evidence_json, ports_json=excluded.ports_json,
                    is_online=excluded.is_online, is_randomized_mac=excluded.is_randomized_mac,
                    ping_ttl=excluded.ping_ttl, os_guess=excluded.os_guess,
                    first_seen=CASE WHEN lan_devices.first_seen='' THEN excluded.first_seen ELSE lan_devices.first_seen END,
                    last_seen=CASE WHEN excluded.is_online=1 THEN excluded.last_seen ELSE lan_devices.last_seen END,
                    checked_at=excluded.checked_at;";
                string now = DateTimeOffset.UtcNow.ToString("O");
                foreach (var device in observedDevices)
                {
                    var previous = await ReadTimelineDeviceStateAsync(conn, trans, projectId, networkId, device.IpAddress, cancellationToken);
                    bool notObserved = device.Evidence.Any(evidence => evidence.Contains("Not observed in the latest scan", StringComparison.OrdinalIgnoreCase));
                    var afterState = TimelineDeviceState.From(device, now, !notObserved);
                    bool hadTimelineState = await HasTimelineEntityAsync(conn, trans, projectId, "DEVICE", networkId + "|" + device.IpAddress, cancellationToken);
                    if (!notObserved)
                    {
                        if (!hadTimelineState)
                        {
                            string eventType = previous is null ? "DEVICE_FIRST_SEEN" : "DEVICE_BASELINE";
                            string summary = previous is null ? $"Device {device.IpAddress} was first observed on this network." : $"Device {device.IpAddress} history began from a live network scan.";
                            await InsertNetworkTimelineEventAsync(conn, trans, projectId, now, "DEVICE", networkId + "|" + device.IpAddress,
                                eventType, summary, previous?.ToDictionary(), afterState.ToDictionary(), cancellationToken);
                        }
                        else if (await WasRecentlyMarkedAbsentAsync(conn, trans, projectId, "DEVICE", networkId + "|" + device.IpAddress,
                            previous?.LastSeenAt, cancellationToken))
                        {
                            await InsertNetworkTimelineEventAsync(conn, trans, projectId, now, "DEVICE", networkId + "|" + device.IpAddress,
                                "DEVICE_REAPPEARED", $"Device {device.IpAddress} was observed again.", previous?.ToDictionary(), afterState.ToDictionary(), cancellationToken);
                        }
                        if (previous is not null && previous.IsOnline != device.IsOnline)
                        {
                            await InsertNetworkTimelineEventAsync(conn, trans, projectId, now, "DEVICE", networkId + "|" + device.IpAddress,
                                device.IsOnline ? "DEVICE_ONLINE" : "DEVICE_OFFLINE", $"Device {device.IpAddress} changed online state.",
                                previous.ToDictionary(), afterState.ToDictionary(), cancellationToken);
                        }
                        if (previous is not null)
                        {
                            var changedFields = previous.ChangedFields(afterState);
                            if (changedFields.Count > 0)
                                await InsertNetworkTimelineEventAsync(conn, trans, projectId, now, "DEVICE", networkId + "|" + device.IpAddress,
                                    "DEVICE_DETAILS_CHANGED", $"Device details changed: {string.Join(", ", changedFields)}.", previous.ToDictionary(), afterState.ToDictionary(), cancellationToken);
                        }
                        await RecordTimelinePresenceAsync(conn, trans, projectId, "DEVICE", networkId + "|" + device.IpAddress, now, cancellationToken);
                    }
                    else if (await HasOpenTimelinePresenceAsync(conn, trans, projectId, "DEVICE", networkId + "|" + device.IpAddress, cancellationToken))
                    {
                        if (!await WasRecentlyMarkedAbsentAsync(conn, trans, projectId, "DEVICE", networkId + "|" + device.IpAddress, previous?.LastSeenAt, cancellationToken))
                            await InsertNetworkTimelineEventAsync(conn, trans, projectId, now, "DEVICE", networkId + "|" + device.IpAddress,
                                "DEVICE_NOT_OBSERVED", $"Device {device.IpAddress} was not observed in the latest local network scan.",
                                previous?.ToDictionary(), new Dictionary<string, object?> { ["ipAddress"] = device.IpAddress, ["isPresent"] = false }, cancellationToken);
                        await CloseTimelinePresenceAsync(conn, trans, projectId, "DEVICE", networkId + "|" + device.IpAddress, cancellationToken);
                    }
                    using var cmd = new SqliteCommand(sql, conn, trans);
                    cmd.Parameters.AddWithValue("@pid", projectId);
                    cmd.Parameters.AddWithValue("@network", networkId);
                    cmd.Parameters.AddWithValue("@ip", device.IpAddress);
                    cmd.Parameters.AddWithValue("@mac", device.MacAddress ?? "");
                    cmd.Parameters.AddWithValue("@hostname", device.Hostname ?? "");
                    cmd.Parameters.AddWithValue("@vendor", device.Vendor ?? "Unknown");
                    cmd.Parameters.AddWithValue("@type", device.DeviceType ?? "Unknown");
                    cmd.Parameters.AddWithValue("@evidence", JsonSerializer.Serialize(device.Evidence));
                    cmd.Parameters.AddWithValue("@ports", JsonSerializer.Serialize(device.OpenPorts));
                    cmd.Parameters.AddWithValue("@online", device.IsOnline ? 1 : 0);
                    cmd.Parameters.AddWithValue("@randomized", device.IsRandomizedMac ? 1 : 0);
                    cmd.Parameters.AddWithValue("@ttl", (object?)device.PingTtl ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("@os", device.OsGuess ?? "Unknown");
                    cmd.Parameters.AddWithValue("@first", device.FirstSeen ?? DateTimeOffset.UtcNow.ToString("O"));
                    cmd.Parameters.AddWithValue("@last", device.LastSeen ?? "");
                    cmd.Parameters.AddWithValue("@checked", string.IsNullOrWhiteSpace(device.LastCheckedAt) ? now : device.LastCheckedAt);
                    await cmd.ExecuteNonQueryAsync(cancellationToken);
                }
                trans.Commit();
            }
            finally { _writeLock.Release(); }
        }

        public async Task SetLanDeviceKnownAsync(string projectId, string networkId, string ipAddress, bool isKnown, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            using var conn = await OpenConnectionAsync(cancellationToken);
            using var cmd = new SqliteCommand("UPDATE lan_devices SET is_known=@known WHERE project_id=@pid AND network_id=@network AND ip_address=@ip;", conn);
            cmd.Parameters.AddWithValue("@known", isKnown ? 1 : 0);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@network", networkId);
            cmd.Parameters.AddWithValue("@ip", ipAddress);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
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

        public async Task<NetworkFingerprint?> GetNetworkFingerprintAsync(string projectId, string ssid, CancellationToken cancellationToken = default)
        {
            ValidateProjectId(projectId);
            if (string.IsNullOrWhiteSpace(ssid)) return null;
            using var conn = await OpenConnectionAsync(cancellationToken);
            using var cmd = new SqliteCommand(@"SELECT project_id, ssid, bssid, gateway_ip, gateway_mac, dns_servers_json, security, cipher, authorized_ap_pattern_json, first_seen_at, last_seen_at
                FROM network_fingerprints WHERE project_id = @pid AND ssid = @ssid COLLATE NOCASE LIMIT 1;", conn);
            cmd.Parameters.AddWithValue("@pid", projectId);
            cmd.Parameters.AddWithValue("@ssid", ssid);
            using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) return null;
            return new NetworkFingerprint
            {
                ProjectId = reader.GetString(0),
                Ssid = reader.GetString(1),
                Bssid = reader.GetString(2),
                GatewayIp = reader.GetString(3),
                GatewayMac = reader.GetString(4),
                DnsServers = JsonSerializer.Deserialize<List<string>>(reader.GetString(5)) ?? new List<string>(),
                Security = reader.GetString(6),
                Cipher = reader.GetString(7),
                AuthorizedApPattern = JsonSerializer.Deserialize<List<string>>(reader.GetString(8)) ?? new List<string>(),
                FirstSeenAt = reader.GetString(9),
                LastSeenAt = reader.GetString(10)
            };
        }

        public async Task SaveNetworkFingerprintAsync(NetworkFingerprint fingerprint, CancellationToken cancellationToken = default)
        {
            if (fingerprint is null) throw new ArgumentNullException(nameof(fingerprint));
            ValidateProjectId(fingerprint.ProjectId);
            if (string.IsNullOrWhiteSpace(fingerprint.Ssid) || string.IsNullOrWhiteSpace(fingerprint.Bssid)
                || string.IsNullOrWhiteSpace(fingerprint.GatewayIp) || string.IsNullOrWhiteSpace(fingerprint.Security)
                || string.Equals(fingerprint.Security, "Unknown", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("A fingerprint requires live SSID, BSSID, gateway, and security values.", nameof(fingerprint));

            await _writeLock.WaitAsync(cancellationToken);
            try
            {
                using var conn = await OpenConnectionAsync(cancellationToken);
                using var cmd = new SqliteCommand(@"INSERT INTO network_fingerprints
                    (project_id, ssid, bssid, gateway_ip, gateway_mac, dns_servers_json, security, cipher, authorized_ap_pattern_json, first_seen_at, last_seen_at)
                    VALUES (@pid, @ssid, @bssid, @gateway, @gatewayMac, @dns, @security, @cipher, @pattern, @firstSeen, @lastSeen)
                    ON CONFLICT(project_id, ssid) DO UPDATE SET bssid = excluded.bssid, gateway_ip = excluded.gateway_ip,
                    gateway_mac = excluded.gateway_mac, dns_servers_json = excluded.dns_servers_json, security = excluded.security,
                    cipher = excluded.cipher, authorized_ap_pattern_json = excluded.authorized_ap_pattern_json,
                    last_seen_at = excluded.last_seen_at;", conn);
                cmd.Parameters.AddWithValue("@pid", fingerprint.ProjectId);
                cmd.Parameters.AddWithValue("@ssid", fingerprint.Ssid);
                cmd.Parameters.AddWithValue("@bssid", fingerprint.Bssid);
                cmd.Parameters.AddWithValue("@gateway", fingerprint.GatewayIp);
                cmd.Parameters.AddWithValue("@gatewayMac", fingerprint.GatewayMac ?? string.Empty);
                cmd.Parameters.AddWithValue("@dns", JsonSerializer.Serialize(fingerprint.DnsServers));
                cmd.Parameters.AddWithValue("@security", fingerprint.Security);
                cmd.Parameters.AddWithValue("@cipher", fingerprint.Cipher ?? string.Empty);
                cmd.Parameters.AddWithValue("@pattern", JsonSerializer.Serialize(fingerprint.AuthorizedApPattern));
                cmd.Parameters.AddWithValue("@firstSeen", string.IsNullOrWhiteSpace(fingerprint.FirstSeenAt) ? DateTimeOffset.UtcNow.ToString("O") : fingerprint.FirstSeenAt);
                cmd.Parameters.AddWithValue("@lastSeen", string.IsNullOrWhiteSpace(fingerprint.LastSeenAt) ? DateTimeOffset.UtcNow.ToString("O") : fingerprint.LastSeenAt);
                await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            finally
            {
                _writeLock.Release();
            }
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
