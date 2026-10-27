using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using WinWiFi.Models;

namespace WinWiFi.Services
{
    public sealed class ParsedAssetRow
    {
        public EnterpriseAssetRecord Asset { get; init; } = new();
        public HashSet<string> ProvidedFields { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int RowNumber { get; init; }
    }

    public sealed class AssetCsvParseResult
    {
        public List<ParsedAssetRow> Rows { get; } = new();
        public List<string> Warnings { get; } = new();
        public List<string> Rejected { get; } = new();
        public int RowsRead { get; set; }
        public string? FatalError { get; set; }
    }

    /// <summary>
    /// Canonical asset-registry values and RFC 4180-style CSV handling.
    /// Registry MAC addresses are compared in one canonical form so imported
    /// rows update existing assets instead of creating duplicates.
    /// </summary>
    public static class AssetRegistryCsv
    {
        public const int MaxRows = 5000;
        public const int MaxWarnings = 50;

        public static readonly string[] AssetTypes = { "Access Point", "Client Station", "IoT Gateway", "Sensor", "Other" };
        public static readonly string[] Classifications = { "Corporate", "Guest", "IoT", "Unknown", "Suspicious", "Rogue" };
        public static readonly string[] ApprovalStatuses = { "Approved", "Unapproved", "Under Investigation", "Decommissioned", "Pending Review" };

        public const string FieldId = "id";
        public const string FieldMac = "macAddress";
        public const string FieldSsid = "ssid";
        public const string FieldAssetType = "assetType";
        public const string FieldClassification = "classification";
        public const string FieldApprovalStatus = "approvalStatus";
        public const string FieldSite = "site";
        public const string FieldBuilding = "building";
        public const string FieldAreaFloor = "areaFloor";
        public const string FieldOwnerDepartment = "ownerDepartment";
        public const string FieldVendor = "vendor";
        public const string FieldModel = "model";
        public const string FieldLastSeen = "lastSeen";
        public const string FieldNotes = "notes";

        private static readonly string[] ExportColumns =
        {
            FieldMac, FieldSsid, FieldAssetType, FieldClassification, FieldApprovalStatus,
            FieldSite, FieldBuilding, FieldAreaFloor, FieldOwnerDepartment, FieldVendor,
            FieldModel, FieldLastSeen, FieldNotes
        };

        private static readonly Dictionary<string, string> HeaderAliases = new(StringComparer.Ordinal)
        {
            ["macaddress"] = FieldMac,
            ["mac"] = FieldMac,
            ["bssid"] = FieldMac,
            ["hardwareaddress"] = FieldMac,
            ["address"] = FieldMac,
            ["assetid"] = FieldId,
            ["id"] = FieldId,
            ["ssid"] = FieldSsid,
            ["networkname"] = FieldSsid,
            ["assettype"] = FieldAssetType,
            ["type"] = FieldAssetType,
            ["devicetype"] = FieldAssetType,
            ["classification"] = FieldClassification,
            ["class"] = FieldClassification,
            ["category"] = FieldClassification,
            ["approvalstatus"] = FieldApprovalStatus,
            ["approval"] = FieldApprovalStatus,
            ["status"] = FieldApprovalStatus,
            ["site"] = FieldSite,
            ["location"] = FieldSite,
            ["building"] = FieldBuilding,
            ["areafloor"] = FieldAreaFloor,
            ["floor"] = FieldAreaFloor,
            ["ownerdepartment"] = FieldOwnerDepartment,
            ["owner"] = FieldOwnerDepartment,
            ["department"] = FieldOwnerDepartment,
            ["vendor"] = FieldVendor,
            ["manufacturer"] = FieldVendor,
            ["model"] = FieldModel,
            ["devicemodel"] = FieldModel,
            ["lastseen"] = FieldLastSeen,
            ["lastobserved"] = FieldLastSeen,
            ["timestamp"] = FieldLastSeen,
            ["notes"] = FieldNotes,
            ["note"] = FieldNotes,
            ["comment"] = FieldNotes
        };

        public static string NewAssetId() => ("AST-" + Guid.NewGuid().ToString("N")).Substring(0, 16).ToUpperInvariant();

        /// <summary>Returns canonical colon-separated uppercase MAC, or null when invalid.</summary>
        public static string? NormalizeMac(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return null;
            var hex = new StringBuilder(12);
            foreach (char c in input)
            {
                if (Uri.IsHexDigit(c))
                {
                    hex.Append(char.ToUpperInvariant(c));
                }
                else if (c is ':' or '-' or '.' or ' ' or '\t')
                {
                    continue;
                }
                else
                {
                    return null;
                }
            }
            if (hex.Length != 12) return null;
            string compact = hex.ToString();
            if (compact == "000000000000" || compact == "FFFFFFFFFFFF") return null;
            return string.Join(":", Enumerable.Range(0, 6).Select(i => compact.Substring(i * 2, 2)));
        }

        public static string SanitizeText(string? value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            var sb = new StringBuilder(Math.Min(value.Length, maxLength));
            foreach (char c in value)
            {
                if (sb.Length >= maxLength) break;
                sb.Append(char.IsControl(c) ? '?' : c);
            }
            return sb.ToString().Trim();
        }

        /// <summary>Notes may span lines; every other control character is still replaced.</summary>
        public static string SanitizeMultilineText(string? value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            var sb = new StringBuilder(Math.Min(value.Length, maxLength));
            foreach (char c in value)
            {
                if (sb.Length >= maxLength) break;
                sb.Append(char.IsControl(c) && c is not ('\r' or '\n' or '\t') ? '?' : c);
            }
            return sb.ToString().Trim();
        }

        public static string? CanonicalAssetType(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "Access Point";
            return AssetTypes.FirstOrDefault(v => v.Equals(value.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        public static string? CanonicalClassification(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "Unknown";
            return Classifications.FirstOrDefault(v => v.Equals(value.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        public static string? CanonicalApprovalStatus(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "Pending Review";
            string trimmed = value.Trim();
            if (trimmed.Equals("Investigating", StringComparison.OrdinalIgnoreCase)) return "Under Investigation";
            return ApprovalStatuses.FirstOrDefault(v => v.Equals(trimmed, StringComparison.OrdinalIgnoreCase));
        }

        public static string NormalizeTimestamp(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            string[] formats = { "yyyy-MM-dd HH:mm:ss", "yyyy-MM-ddTHH:mm:ss", "yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-dd", "MM/dd/yyyy HH:mm:ss", "MM/dd/yyyy" };
            if (DateTime.TryParseExact(value.Trim(), formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed) ||
                DateTime.TryParse(value.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out parsed))
            {
                return parsed.ToString("yyyy-MM-dd HH:mm:ss");
            }
            return DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        }

        /// <summary>
        /// Validates and canonicalizes a record. Returns null with a human-readable
        /// error when the row cannot be stored honestly.
        /// </summary>
        public static EnterpriseAssetRecord? NormalizeAsset(EnterpriseAssetRecord? input, out string? error)
        {
            error = null;
            if (input is null)
            {
                error = "Asset record is empty.";
                return null;
            }

            string? mac = NormalizeMac(input.MacAddress);
            if (mac is null)
            {
                error = $"'{SanitizeText(input.MacAddress, 40)}' is not a valid unicast 48-bit MAC address.";
                return null;
            }

            string? assetType = CanonicalAssetType(input.AssetType);
            if (assetType is null)
            {
                error = $"Asset type '{SanitizeText(input.AssetType, 40)}' is not one of: {string.Join(", ", AssetTypes)}.";
                return null;
            }

            string? classification = CanonicalClassification(input.Classification);
            if (classification is null)
            {
                error = $"Classification '{SanitizeText(input.Classification, 40)}' is not one of: {string.Join(", ", Classifications)}.";
                return null;
            }

            string? approval = CanonicalApprovalStatus(input.ApprovalStatus);
            if (approval is null)
            {
                error = $"Approval status '{SanitizeText(input.ApprovalStatus, 40)}' is not one of: {string.Join(", ", ApprovalStatuses)}.";
                return null;
            }

            return new EnterpriseAssetRecord
            {
                Id = string.IsNullOrWhiteSpace(input.Id) ? NewAssetId() : SanitizeText(input.Id, 64),
                MacAddress = mac,
                Ssid = SanitizeText(input.Ssid, 32),
                AssetType = assetType,
                Classification = classification,
                ApprovalStatus = approval,
                Site = SanitizeText(input.Site, 120),
                Building = SanitizeText(input.Building, 120),
                AreaFloor = SanitizeText(input.AreaFloor, 40),
                OwnerDepartment = SanitizeText(input.OwnerDepartment, 120),
                Vendor = SanitizeText(input.Vendor, 120),
                Model = SanitizeText(input.Model, 120),
                LastSeen = NormalizeTimestamp(input.LastSeen),
                Notes = SanitizeMultilineText(input.Notes, 500)
            };
        }

        public static string Serialize(IEnumerable<EnterpriseAssetRecord> assets)
        {
            var sb = new StringBuilder();
            sb.AppendLine(string.Join(",", ExportColumns.Select(EscapeCsvCell)));
            foreach (var asset in assets)
            {
                sb.AppendLine(string.Join(",", new[]
                {
                    asset.MacAddress, asset.Ssid, asset.AssetType, asset.Classification,
                    asset.ApprovalStatus, asset.Site, asset.Building, asset.AreaFloor,
                    asset.OwnerDepartment, asset.Vendor, asset.Model, asset.LastSeen, asset.Notes
                }.Select(EscapeCsvCell)));
            }
            return sb.ToString();
        }

        public static AssetCsvParseResult Parse(string? csv)
        {
            var result = new AssetCsvParseResult();
            if (string.IsNullOrWhiteSpace(csv))
            {
                result.FatalError = "The CSV file is empty.";
                return result;
            }

            string text = csv.TrimStart('\uFEFF');
            var rows = ReadRows(text, out bool rowLimitHit, out string? parserError);
            if (parserError is not null) AddWarning(result, parserError);
            if (rowLimitHit) AddWarning(result, $"Only the first {MaxRows} data rows were imported.");

            if (rows.Count == 0)
            {
                result.FatalError = "The CSV file does not contain a header row.";
                return result;
            }

            var header = rows[0];
            var columnMap = new string?[header.Count];
            bool hasMac = false;
            var unknownHeaders = new List<string>();
            for (int i = 0; i < header.Count; i++)
            {
                string key = NormalizeHeader(header[i]);
                if (key.Length == 0) continue;
                if (HeaderAliases.TryGetValue(key, out var canonical))
                {
                    if (columnMap.Contains(canonical, StringComparer.OrdinalIgnoreCase))
                    {
                        AddWarning(result, $"Duplicate column '{header[i]}' was ignored.");
                        continue;
                    }
                    columnMap[i] = canonical;
                    if (canonical == FieldMac) hasMac = true;
                }
                else
                {
                    unknownHeaders.Add(header[i].Trim());
                }
            }

            if (unknownHeaders.Count > 0)
                AddWarning(result, $"Ignored unrecognized column(s): {string.Join(", ", unknownHeaders.Select(h => $"'{SanitizeText(h, 40)}'"))}.");

            if (!hasMac)
            {
                result.FatalError = "The CSV must contain a MAC/BSSID column (for example 'macAddress').";
                return result;
            }

            var merged = new Dictionary<string, ParsedAssetRow>(StringComparer.OrdinalIgnoreCase);
            for (int r = 1; r < rows.Count && r <= MaxRows; r++)
            {
                var cells = rows[r];
                if (cells.All(string.IsNullOrWhiteSpace)) continue;
                result.RowsRead++;

                var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                for (int c = 0; c < cells.Count && c < columnMap.Length; c++)
                {
                    if (columnMap[c] is string field)
                        values[field] = UnescapeCsvCell(cells[c]);
                }

                values.TryGetValue(FieldMac, out string? rawMac);
                string? mac = NormalizeMac(rawMac);
                if (mac is null)
                {
                    result.Rejected.Add($"Row {r + 1}: '{SanitizeText(rawMac, 40)}' is not a valid unicast 48-bit MAC address.");
                    continue;
                }

                var candidate = new EnterpriseAssetRecord
                {
                    Id = values.GetValueOrDefault(FieldId, string.Empty),
                    MacAddress = mac,
                    Ssid = values.GetValueOrDefault(FieldSsid, string.Empty),
                    AssetType = values.GetValueOrDefault(FieldAssetType, string.Empty),
                    Classification = values.GetValueOrDefault(FieldClassification, string.Empty),
                    ApprovalStatus = values.GetValueOrDefault(FieldApprovalStatus, string.Empty),
                    Site = values.GetValueOrDefault(FieldSite, string.Empty),
                    Building = values.GetValueOrDefault(FieldBuilding, string.Empty),
                    AreaFloor = values.GetValueOrDefault(FieldAreaFloor, string.Empty),
                    OwnerDepartment = values.GetValueOrDefault(FieldOwnerDepartment, string.Empty),
                    Vendor = values.GetValueOrDefault(FieldVendor, string.Empty),
                    Model = values.GetValueOrDefault(FieldModel, string.Empty),
                    LastSeen = values.GetValueOrDefault(FieldLastSeen, string.Empty),
                    Notes = values.GetValueOrDefault(FieldNotes, string.Empty)
                };

                var normalized = NormalizeAsset(candidate, out string? error);
                if (normalized is null)
                {
                    result.Rejected.Add($"Row {r + 1}: {error}");
                    continue;
                }

                var parsedRow = new ParsedAssetRow { Asset = normalized, RowNumber = r + 1 };
                foreach (var field in values.Keys) parsedRow.ProvidedFields.Add(field);

                if (merged.ContainsKey(mac))
                    AddWarning(result, $"Row {r + 1}: duplicate MAC {mac} replaced the earlier row.");
                merged[mac] = parsedRow;
            }

            result.Rows.AddRange(merged.Values.OrderBy(row => row.RowNumber));
            return result;
        }

        public static EnterpriseAssetRecord MergeMissingFields(EnterpriseAssetRecord existing, ParsedAssetRow incoming)
        {
            var merged = new EnterpriseAssetRecord
            {
                Id = existing.Id,
                MacAddress = existing.MacAddress,
                Ssid = existing.Ssid,
                AssetType = existing.AssetType,
                Classification = existing.Classification,
                ApprovalStatus = existing.ApprovalStatus,
                Site = existing.Site,
                Building = existing.Building,
                AreaFloor = existing.AreaFloor,
                OwnerDepartment = existing.OwnerDepartment,
                Vendor = existing.Vendor,
                Model = existing.Model,
                LastSeen = existing.LastSeen,
                Notes = existing.Notes
            };

            foreach (var field in incoming.ProvidedFields)
            {
                switch (field)
                {
                    case FieldSsid: merged.Ssid = incoming.Asset.Ssid; break;
                    case FieldAssetType: merged.AssetType = incoming.Asset.AssetType; break;
                    case FieldClassification: merged.Classification = incoming.Asset.Classification; break;
                    case FieldApprovalStatus: merged.ApprovalStatus = incoming.Asset.ApprovalStatus; break;
                    case FieldSite: merged.Site = incoming.Asset.Site; break;
                    case FieldBuilding: merged.Building = incoming.Asset.Building; break;
                    case FieldAreaFloor: merged.AreaFloor = incoming.Asset.AreaFloor; break;
                    case FieldOwnerDepartment: merged.OwnerDepartment = incoming.Asset.OwnerDepartment; break;
                    case FieldVendor: merged.Vendor = incoming.Asset.Vendor; break;
                    case FieldModel: merged.Model = incoming.Asset.Model; break;
                    case FieldLastSeen: merged.LastSeen = incoming.Asset.LastSeen; break;
                    case FieldNotes: merged.Notes = incoming.Asset.Notes; break;
                }
            }
            return merged;
        }

        public static string EscapeCsvCell(string? value)
        {
            string text = value ?? string.Empty;
            if (text.Length > 0 && (text[0] is '=' or '+' or '-' or '@' or '\t' or '\r'))
                text = "'" + text;
            return $"\"{text.Replace("\"", "\"\"")}\"";
        }

        private static string UnescapeCsvCell(string value)
        {
            if (value.Length >= 2 && value[0] == '\'' && value[1] is '=' or '+' or '-' or '@' or '\t' or '\r')
                return value.Substring(1);
            return value;
        }

        private static string NormalizeHeader(string value)
        {
            var sb = new StringBuilder();
            foreach (char c in value)
            {
                if (char.IsLetterOrDigit(c)) sb.Append(char.ToLowerInvariant(c));
            }
            return sb.ToString();
        }

        private static List<List<string>> ReadRows(string text, out bool rowLimitHit, out string? parserError)
        {
            var rows = new List<List<string>>();
            var row = new List<string>();
            var field = new StringBuilder();
            bool inQuotes = false;
            rowLimitHit = false;
            parserError = null;

            void EndRow()
            {
                row.Add(field.ToString());
                field.Clear();
                if (rows.Count == 0 || row.Any(cell => !string.IsNullOrWhiteSpace(cell)))
                    rows.Add(row);
                row = new List<string>();
            }

            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (inQuotes)
                {
                    if (c == '"')
                    {
                        if (i + 1 < text.Length && text[i + 1] == '"')
                        {
                            field.Append('"');
                            i++;
                        }
                        else
                        {
                            inQuotes = false;
                        }
                    }
                    else
                    {
                        field.Append(c);
                    }
                    continue;
                }

                switch (c)
                {
                    case '"':
                        if (field.Length == 0) inQuotes = true;
                        else field.Append('"');
                        break;
                    case ',':
                        row.Add(field.ToString());
                        field.Clear();
                        break;
                    case '\r':
                        if (i + 1 < text.Length && text[i + 1] == '\n') i++;
                        EndRow();
                        if (rows.Count > MaxRows + 1) { rowLimitHit = true; return rows; }
                        break;
                    case '\n':
                        EndRow();
                        if (rows.Count > MaxRows + 1) { rowLimitHit = true; return rows; }
                        break;
                    default:
                        field.Append(c);
                        break;
                }
            }

            if (inQuotes) parserError = "The CSV ends inside a quoted field; the final row may be incomplete.";
            if (field.Length > 0 || row.Count > 0) EndRow();
            return rows;
        }

        private static void AddWarning(AssetCsvParseResult result, string message)
        {
            if (result.Warnings.Count < MaxWarnings) result.Warnings.Add(message);
            else if (result.Warnings.Count == MaxWarnings) result.Warnings.Add($"Additional warnings were suppressed after {MaxWarnings} entries.");
        }
    }
}
