using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Web.Services;

public sealed class AuthSession
{
    public string? AccessToken { get; private set; }
    public DateTime ExpiresUtc { get; private set; }
    public string? RefreshToken { get; private set; }
    public DateTime RefreshTokenExpiresUtc { get; private set; }
    public Guid? UserId { get; private set; }
    public string? Email { get; private set; }
    public UserRole? Role { get; private set; }

    public bool IsAuthenticated => !string.IsNullOrWhiteSpace(AccessToken) && ExpiresUtc > DateTime.UtcNow;

    public bool CanRefresh =>
        !string.IsNullOrWhiteSpace(RefreshToken)
        && RefreshTokenExpiresUtc > DateTime.UtcNow;

    public bool IsAccessTokenExpiringSoon(TimeSpan threshold)
    {
        if (string.IsNullOrWhiteSpace(AccessToken))
        {
            return false;
        }

        return ExpiresUtc <= DateTime.UtcNow.Add(threshold);
    }

    public void Set(AuthTokenResponse token)
    {
        AccessToken = token.AccessToken;
        ExpiresUtc = token.ExpiresUtc;
        RefreshToken = token.RefreshToken;
        RefreshTokenExpiresUtc = token.RefreshTokenExpiresUtc;
        UserId = token.UserId;
        Email = token.Email;
        Role = token.Role;
    }

    public void Clear()
    {
        AccessToken = null;
        ExpiresUtc = default;
        RefreshToken = null;
        RefreshTokenExpiresUtc = default;
        UserId = null;
        Email = null;
        Role = null;
    }
}