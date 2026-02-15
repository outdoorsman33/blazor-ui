using System.Collections.Concurrent;
using System.Text.Json;
using WrestlingPlatform.Application.Contracts;

namespace WrestlingPlatform.Api.Services;

public interface ISecurityAuditTrailService
{
    void Record(SecurityAuditRecord record);

    IReadOnlyList<SecurityAuditRecord> GetRecent(int take);
}

public sealed class SecurityAuditTrailService : ISecurityAuditTrailService
{
    private const int MaxEntries = 10_000;
    private readonly ConcurrentQueue<SecurityAuditRecord> _entries = new();
    private readonly ILogger<SecurityAuditTrailService> _logger;
    private readonly string _auditFilePath;
    private readonly object _fileLock = new();
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web);

    public SecurityAuditTrailService(
        IWebHostEnvironment environment,
        IConfiguration configuration,
        ILogger<SecurityAuditTrailService> logger)
    {
        _logger = logger;
        var configuredPath = configuration["Security:Audit:FilePath"];
        _auditFilePath = ResolveAuditPath(environment.ContentRootPath, configuredPath);
        LoadExistingEntries();
    }

    public void Record(SecurityAuditRecord record)
    {
        _entries.Enqueue(record);

        while (_entries.Count > MaxEntries && _entries.TryDequeue(out _))
        {
            // Bound in-memory history.
        }

        TryAppend(record);
    }

    public IReadOnlyList<SecurityAuditRecord> GetRecent(int take)
    {
        var safeTake = Math.Clamp(take, 1, 1000);
        return _entries
            .Reverse()
            .Take(safeTake)
            .ToList();
    }

    private void LoadExistingEntries()
    {
        try
        {
            if (!File.Exists(_auditFilePath))
            {
                return;
            }

            var lines = File.ReadLines(_auditFilePath).TakeLast(MaxEntries);
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var record = JsonSerializer.Deserialize<SecurityAuditRecord>(line, _jsonOptions);
                if (record is not null)
                {
                    _entries.Enqueue(record);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load security audit history.");
        }
    }

    private void TryAppend(SecurityAuditRecord record)
    {
        try
        {
            lock (_fileLock)
            {
                var directory = Path.GetDirectoryName(_auditFilePath);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var line = JsonSerializer.Serialize(record, _jsonOptions);
                File.AppendAllText(_auditFilePath, line + Environment.NewLine);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write security audit record.");
        }
    }

    private static string ResolveAuditPath(string contentRoot, string? configuredPath)
    {
        var path = string.IsNullOrWhiteSpace(configuredPath)
            ? "App_Data/security/audit-log.jsonl"
            : configuredPath.Trim();

        return Path.IsPathRooted(path) ? path : Path.Combine(contentRoot, path);
    }
}

