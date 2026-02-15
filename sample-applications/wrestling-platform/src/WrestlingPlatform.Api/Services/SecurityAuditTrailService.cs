using System.Collections.Concurrent;
using WrestlingPlatform.Application.Contracts;

namespace WrestlingPlatform.Api.Services;

public interface ISecurityAuditTrailService
{
    void Record(SecurityAuditRecord record);

    IReadOnlyList<SecurityAuditRecord> GetRecent(int take);
}

public sealed class SecurityAuditTrailService : ISecurityAuditTrailService
{
    private const int MaxEntries = 5000;
    private readonly ConcurrentQueue<SecurityAuditRecord> _entries = new();

    public void Record(SecurityAuditRecord record)
    {
        _entries.Enqueue(record);

        while (_entries.Count > MaxEntries && _entries.TryDequeue(out _))
        {
            // Keep queue bounded in memory.
        }
    }

    public IReadOnlyList<SecurityAuditRecord> GetRecent(int take)
    {
        var safeTake = Math.Clamp(take, 1, 500);
        return _entries
            .Reverse()
            .Take(safeTake)
            .ToList();
    }
}
