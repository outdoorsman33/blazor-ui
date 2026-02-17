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
    public bool KeepSignedIn { get; private set; }

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

    public void Set(AuthTokenResponse token, bool keepSignedIn = false)
    {
        AccessToken = token.AccessToken;
        ExpiresUtc = token.ExpiresUtc;
        RefreshToken = token.RefreshToken;
        RefreshTokenExpiresUtc = token.RefreshTokenExpiresUtc;
        UserId = token.UserId;
        Email = token.Email;
        Role = token.Role;
        KeepSignedIn = keepSignedIn;
    }

    public AuthSessionSnapshot? CreateSnapshot()
    {
        if (string.IsNullOrWhiteSpace(AccessToken)
            || string.IsNullOrWhiteSpace(RefreshToken)
            || UserId is null
            || string.IsNullOrWhiteSpace(Email)
            || Role is null)
        {
            return null;
        }

        return new AuthSessionSnapshot(
            AccessToken,
            ExpiresUtc,
            RefreshToken,
            RefreshTokenExpiresUtc,
            UserId.Value,
            Email!,
            Role.Value,
            KeepSignedIn);
    }

    public bool Restore(AuthSessionSnapshot snapshot)
    {
        if (snapshot is null
            || string.IsNullOrWhiteSpace(snapshot.AccessToken)
            || string.IsNullOrWhiteSpace(snapshot.RefreshToken)
            || snapshot.UserId == Guid.Empty
            || string.IsNullOrWhiteSpace(snapshot.Email))
        {
            return false;
        }

        Set(
            new AuthTokenResponse(
                snapshot.AccessToken,
                snapshot.ExpiresUtc,
                snapshot.RefreshToken,
                snapshot.RefreshTokenExpiresUtc,
                snapshot.UserId,
                snapshot.Email,
                snapshot.Role),
            snapshot.KeepSignedIn);
        return true;
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
        KeepSignedIn = false;
    }
}

public sealed record AuthSessionSnapshot(
    string AccessToken,
    DateTime ExpiresUtc,
    string RefreshToken,
    DateTime RefreshTokenExpiresUtc,
    Guid UserId,
    string Email,
    UserRole Role,
    bool KeepSignedIn);
