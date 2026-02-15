using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using WrestlingPlatform.Application.Contracts;

namespace WrestlingPlatform.Api.Services;

public sealed class RequestSecurityPolicyOptions
{
    public bool EnableResponseSecurityHeaders { get; set; } = true;

    public bool EnforceHttpsInProduction { get; set; } = true;

    public string[] BlockedUserAgentSubstrings { get; set; } = [];

    public string[] BlockedIpCidrs { get; set; } = [];

    public string[] AdminApiAllowCidrs { get; set; } = [];
}

public sealed class RequestSecurityPolicyMiddleware(
    RequestDelegate next,
    IOptions<RequestSecurityPolicyOptions> options,
    ILogger<RequestSecurityPolicyMiddleware> logger)
{
    private readonly RequestDelegate _next = next;
    private readonly RequestSecurityPolicyOptions _options = options.Value;
    private readonly ILogger<RequestSecurityPolicyMiddleware> _logger = logger;
    private readonly List<CidrRange> _blockedRanges = ParseCidrs(options.Value.BlockedIpCidrs);
    private readonly List<CidrRange> _adminAllowRanges = ParseCidrs(options.Value.AdminApiAllowCidrs);

    public async Task Invoke(HttpContext context, ISecurityAuditTrailService auditTrail, IWebHostEnvironment environment)
    {
        if (!IsAllowed(context, environment, out var reason, out var statusCode))
        {
            auditTrail.Record(new SecurityAuditRecord(
                Guid.NewGuid(),
                DateTime.UtcNow,
                context.Request.Method,
                context.Request.Path,
                statusCode,
                context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value,
                context.User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value,
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                "Blocked",
                context.TraceIdentifier));

            context.Response.StatusCode = statusCode;
            await context.Response.WriteAsync(reason);
            return;
        }

        if (_options.EnableResponseSecurityHeaders)
        {
            ApplyHeaders(context.Response.Headers);
        }

        await _next(context);
    }

    private bool IsAllowed(HttpContext context, IWebHostEnvironment environment, out string reason, out int statusCode)
    {
        reason = string.Empty;
        statusCode = StatusCodes.Status403Forbidden;

        if (_options.EnforceHttpsInProduction && environment.IsProduction())
        {
            var forwardedProto = context.Request.Headers["X-Forwarded-Proto"].ToString();
            var isHttps = context.Request.IsHttps || string.Equals(forwardedProto, "https", StringComparison.OrdinalIgnoreCase);
            if (!isHttps)
            {
                reason = "HTTPS is required.";
                statusCode = StatusCodes.Status400BadRequest;
                return false;
            }
        }

        var userAgent = context.Request.Headers.UserAgent.ToString();
        if (!string.IsNullOrWhiteSpace(userAgent)
            && _options.BlockedUserAgentSubstrings.Any(token =>
                !string.IsNullOrWhiteSpace(token)
                && userAgent.Contains(token, StringComparison.OrdinalIgnoreCase)))
        {
            reason = "Request blocked by security policy.";
            statusCode = StatusCodes.Status403Forbidden;
            return false;
        }

        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp is not null && _blockedRanges.Any(range => range.Contains(remoteIp)))
        {
            reason = "Source IP is blocked by security policy.";
            statusCode = StatusCodes.Status403Forbidden;
            return false;
        }

        if (_adminAllowRanges.Count > 0 && context.Request.Path.StartsWithSegments("/api/security", StringComparison.OrdinalIgnoreCase))
        {
            if (remoteIp is null || !_adminAllowRanges.Any(range => range.Contains(remoteIp)))
            {
                reason = "Admin API IP policy denied this request.";
                statusCode = StatusCodes.Status403Forbidden;
                return false;
            }
        }

        return true;
    }

    private static void ApplyHeaders(IHeaderDictionary headers)
    {
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        headers["X-Permitted-Cross-Domain-Policies"] = "none";
    }

    private static List<CidrRange> ParseCidrs(IEnumerable<string> source)
    {
        var ranges = new List<CidrRange>();
        foreach (var raw in source)
        {
            if (CidrRange.TryParse(raw, out var range))
            {
                ranges.Add(range);
            }
        }

        return ranges;
    }

    private sealed class CidrRange
    {
        private readonly byte[] _networkBytes;
        private readonly byte[] _maskBytes;

        private CidrRange(byte[] networkBytes, byte[] maskBytes, AddressFamily family)
        {
            _networkBytes = networkBytes;
            _maskBytes = maskBytes;
            Family = family;
        }

        public AddressFamily Family { get; }

        public bool Contains(IPAddress address)
        {
            var candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
            if (candidate.AddressFamily != Family)
            {
                return false;
            }

            var candidateBytes = candidate.GetAddressBytes();
            for (var index = 0; index < candidateBytes.Length; index++)
            {
                if ((candidateBytes[index] & _maskBytes[index]) != _networkBytes[index])
                {
                    return false;
                }
            }

            return true;
        }

        public static bool TryParse(string? value, out CidrRange range)
        {
            range = null!;
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            var parts = value.Trim().Split('/', 2, StringSplitOptions.TrimEntries);
            if (!IPAddress.TryParse(parts[0], out var ipAddress))
            {
                return false;
            }

            var normalizedIp = ipAddress.IsIPv4MappedToIPv6 ? ipAddress.MapToIPv4() : ipAddress;
            var maxBits = normalizedIp.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            var prefixLength = maxBits;

            if (parts.Length == 2 && (!int.TryParse(parts[1], out prefixLength) || prefixLength < 0 || prefixLength > maxBits))
            {
                return false;
            }

            var mask = BuildMask(normalizedIp.AddressFamily, prefixLength);
            var networkBytes = normalizedIp.GetAddressBytes();
            for (var index = 0; index < networkBytes.Length; index++)
            {
                networkBytes[index] &= mask[index];
            }

            range = new CidrRange(networkBytes, mask, normalizedIp.AddressFamily);
            return true;
        }

        private static byte[] BuildMask(AddressFamily family, int prefixLength)
        {
            var byteLength = family == AddressFamily.InterNetwork ? 4 : 16;
            var mask = new byte[byteLength];
            var bitsRemaining = prefixLength;

            for (var i = 0; i < byteLength; i++)
            {
                if (bitsRemaining >= 8)
                {
                    mask[i] = 0xFF;
                    bitsRemaining -= 8;
                    continue;
                }

                if (bitsRemaining <= 0)
                {
                    mask[i] = 0x00;
                    continue;
                }

                mask[i] = (byte)(0xFF << (8 - bitsRemaining));
                bitsRemaining = 0;
            }

            return mask;
        }
    }
}
