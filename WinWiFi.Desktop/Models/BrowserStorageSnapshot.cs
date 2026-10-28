namespace WinWiFi.Models;

public sealed class BrowserStorageSnapshotEntry
{
    public string StorageKey { get; set; } = string.Empty;
    public string PayloadJson { get; set; } = string.Empty;
    public int RecordCount { get; set; }
}

public sealed record BrowserStorageSnapshotImportResult(
    string ImportId,
    int ImportedKeys,
    int ImportedRecords,
    string ImportedAt);
