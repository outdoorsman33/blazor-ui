using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;

namespace WrestlingPlatform.Api;

internal static class ApiSecurityHelpers
{
    private const int PasswordIterations = 120_000;
    private const int RefreshTokenBytes = 64;
    private const int RefreshTokenPruneRetentionDays = 30;

    internal static bool IsPublicRegistrationRole(UserRole role)
    {
        var normalizedRole = NormalizeRole(role);
        return normalizedRole is UserRole.Athlete
            or UserRole.Coach
            or UserRole.ParentGuardian
            or UserRole.Fan
            or UserRole.MatWorker
            or UserRole.TournamentDirector;
    }

    internal static UserRole NormalizeRole(UserRole role)
    {
        return role switch
        {
            UserRole.Parent => UserRole.ParentGuardian,
            UserRole.EventAdmin => UserRole.TournamentDirector,
            _ => role
        };
    }

    internal static UserRole? ParseRole(string? roleRaw)
    {
        if (string.IsNullOrWhiteSpace(roleRaw))
        {
            return null;
        }

        if (Enum.TryParse<UserRole>(roleRaw.Trim(), ignoreCase: true, out var role))
        {
            return NormalizeRole(role);
        }

        var normalized = roleRaw
            .Trim()
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("/", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .ToLowerInvariant();

        if (normalized.Contains("parent", StringComparison.Ordinal)
            && normalized.Contains("guardian", StringComparison.Ordinal))
        {
            return UserRole.ParentGuardian;
        }

        if (normalized.Contains("mat", StringComparison.Ordinal)
            || normalized.Contains("tableworker", StringComparison.Ordinal))
        {
            return UserRole.MatWorker;
        }

        if (normalized.Contains("tournament", StringComparison.Ordinal)
            && normalized.Contains("director", StringComparison.Ordinal))
        {
            return UserRole.TournamentDirector;
        }

        return null;
    }

    internal static UserRole? GetAuthenticatedRole(ClaimsPrincipal principal)
    {
        var roleRaw = principal.FindFirstValue(ClaimTypes.Role);
        return ParseRole(roleRaw);
    }

    internal static bool IsInRole(ClaimsPrincipal principal, params UserRole[] roles)
    {
        var role = GetAuthenticatedRole(principal);
        if (role is null)
        {
            return false;
        }

        var normalized = NormalizeRole(role.Value);
        foreach (var acceptedRole in roles)
        {
            if (normalized == NormalizeRole(acceptedRole))
            {
                return true;
            }
        }

        return false;
    }

    internal static Guid? GetAuthenticatedUserId(ClaimsPrincipal principal)
    {
        var claimValue = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(claimValue, out var parsed) ? parsed : null;
    }

    internal static bool IsAdminPrincipal(ClaimsPrincipal principal)
    {
        return IsInRole(
            principal,
            UserRole.SystemAdmin,
            UserRole.SchoolAdmin,
            UserRole.ClubAdmin);
    }

    internal static bool IsTournamentDirectorPrincipal(ClaimsPrincipal principal)
    {
        return IsInRole(
            principal,
            UserRole.TournamentDirector,
            UserRole.EventAdmin);
    }

    internal static bool IsEventOperatorPrincipal(ClaimsPrincipal principal)
    {
        return IsInRole(
            principal,
            UserRole.Coach,
            UserRole.MatWorker,
            UserRole.TournamentDirector,
            UserRole.EventAdmin)
            || IsAdminPrincipal(principal);
    }

    internal static bool CanAccessUserResource(HttpContext httpContext, Guid requestedUserId)
    {
        var currentUserId = GetAuthenticatedUserId(httpContext.User);
        return currentUserId is not null
            && (currentUserId.Value == requestedUserId || IsAdminPrincipal(httpContext.User));
    }

    internal static async Task<bool> CanManageCoachProfileAsync(
        WrestlingPlatformDbContext dbContext,
        ClaimsPrincipal principal,
        Guid coachProfileId,
        CancellationToken cancellationToken)
    {
        if (IsAdminPrincipal(principal))
        {
            return true;
        }

        var currentUserId = GetAuthenticatedUserId(principal);
        if (currentUserId is null)
        {
            return false;
        }

        var ownerUserId = await dbContext.CoachProfiles
            .Where(x => x.Id == coachProfileId)
            .Select(x => x.UserAccountId)
            .FirstOrDefaultAsync(cancellationToken);

        return ownerUserId != Guid.Empty && ownerUserId == currentUserId.Value;
    }

    internal static async Task<bool> CanManageAthleteProfileAsync(
        WrestlingPlatformDbContext dbContext,
        ClaimsPrincipal principal,
        Guid athleteProfileId,
        CancellationToken cancellationToken)
    {
        if (IsAdminPrincipal(principal))
        {
            return true;
        }

        var currentUserId = GetAuthenticatedUserId(principal);
        if (currentUserId is null)
        {
            return false;
        }

        var ownerUserId = await dbContext.AthleteProfiles
            .Where(x => x.Id == athleteProfileId)
            .Select(x => x.UserAccountId)
            .FirstOrDefaultAsync(cancellationToken);

        if (ownerUserId == Guid.Empty)
        {
            return false;
        }

        if (ownerUserId == currentUserId.Value)
        {
            return true;
        }

        if (!IsInRole(principal, UserRole.Coach))
        {
            return false;
        }

        var coachProfileId = await dbContext.CoachProfiles
            .Where(x => x.UserAccountId == currentUserId.Value)
            .Select(x => x.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (coachProfileId == Guid.Empty)
        {
            return false;
        }

        return await dbContext.CoachAssociations.AnyAsync(
            x => x.CoachProfileId == coachProfileId
                && x.AthleteProfileId == athleteProfileId
                && x.ApprovedUtc != null,
            cancellationToken);
    }

    internal static async Task<bool> CanManageTournamentOpsAsync(
        WrestlingPlatformDbContext dbContext,
        ClaimsPrincipal principal,
        Guid eventId,
        CancellationToken cancellationToken)
    {
        if (IsAdminPrincipal(principal))
        {
            return true;
        }

        if (!IsTournamentDirectorPrincipal(principal))
        {
            return false;
        }

        var userId = GetAuthenticatedUserId(principal);
        if (userId is null)
        {
            return false;
        }

        var tournamentEvent = await dbContext.TournamentEvents
            .AsNoTracking()
            .Where(x => x.Id == eventId)
            .Select(x => new { x.CreatedByUserAccountId, x.OrganizerType, x.OrganizerId })
            .FirstOrDefaultAsync(cancellationToken);

        if (tournamentEvent is null)
        {
            return false;
        }

        if (tournamentEvent.CreatedByUserAccountId == userId.Value)
        {
            return true;
        }

        if (tournamentEvent.OrganizerType != OrganizerType.Coach)
        {
            return false;
        }

        var organizerCoachOwnerUserId = await dbContext.CoachProfiles
            .AsNoTracking()
            .Where(x => x.Id == tournamentEvent.OrganizerId)
            .Select(x => x.UserAccountId)
            .FirstOrDefaultAsync(cancellationToken);

        return organizerCoachOwnerUserId != Guid.Empty && organizerCoachOwnerUserId == userId.Value;
    }

    internal static async Task<bool> CanScoreEventAsync(
        WrestlingPlatformDbContext dbContext,
        ClaimsPrincipal principal,
        Guid eventId,
        CancellationToken cancellationToken)
    {
        if (await CanManageTournamentOpsAsync(dbContext, principal, eventId, cancellationToken))
        {
            return true;
        }

        if (IsAdminPrincipal(principal))
        {
            return true;
        }

        if (!IsInRole(principal, UserRole.Coach, UserRole.MatWorker))
        {
            return false;
        }

        var userId = GetAuthenticatedUserId(principal);
        if (userId is null)
        {
            return false;
        }

        return await dbContext.TournamentStaffAssignments
            .AsNoTracking()
            .AnyAsync(
                x => x.TournamentEventId == eventId
                     && x.UserAccountId == userId.Value
                     && x.CanScoreMatches,
                cancellationToken);
    }

    internal static async Task<bool> CanScoreMatchAsync(
        WrestlingPlatformDbContext dbContext,
        ClaimsPrincipal principal,
        Guid matchId,
        CancellationToken cancellationToken)
    {
        var eventId = await (
                from match in dbContext.Matches.AsNoTracking()
                join bracket in dbContext.Brackets.AsNoTracking() on match.BracketId equals bracket.Id
                where match.Id == matchId
                select bracket.TournamentEventId)
            .FirstOrDefaultAsync(cancellationToken);

        if (eventId == Guid.Empty)
        {
            return false;
        }

        return await CanScoreEventAsync(dbContext, principal, eventId, cancellationToken);
    }

    internal static async Task<bool> CanManageStreamingDelegationAsync(
        WrestlingPlatformDbContext dbContext,
        ClaimsPrincipal principal,
        Guid eventId,
        CancellationToken cancellationToken)
    {
        if (IsAdminPrincipal(principal))
        {
            return true;
        }

        if (IsInRole(principal, UserRole.ParentGuardian, UserRole.Parent))
        {
            return true;
        }

        var userId = GetAuthenticatedUserId(principal);
        if (userId is null)
        {
            return false;
        }

        return await dbContext.TournamentStaffAssignments
            .AsNoTracking()
            .AnyAsync(
                x => x.TournamentEventId == eventId
                     && x.UserAccountId == userId.Value
                     && x.CanManageStreams,
                cancellationToken);
    }

    internal static async Task<AuthTokenResponse> IssueAuthTokenAsync(
        UserAccount user,
        WrestlingPlatformDbContext dbContext,
        SymmetricSecurityKey signingKey,
        string issuer,
        string audience,
        int accessTokenMinutes,
        int refreshTokenDays,
        CancellationToken cancellationToken)
    {
        var (accessToken, expiresUtc) = CreateAccessToken(user, signingKey, issuer, audience, accessTokenMinutes);

        var refreshToken = GenerateRefreshToken();
        var refreshTokenExpiresUtc = DateTime.UtcNow.AddDays(Math.Max(1, refreshTokenDays));

        var refreshTokenRow = new UserRefreshToken
        {
            UserAccountId = user.Id,
            TokenHash = HashOpaqueToken(refreshToken),
            ExpiresUtc = refreshTokenExpiresUtc
        };

        dbContext.UserRefreshTokens.Add(refreshTokenRow);
        await PruneOldRefreshTokensAsync(dbContext, user.Id, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        return new AuthTokenResponse(
            accessToken,
            expiresUtc,
            refreshToken,
            refreshTokenExpiresUtc,
            user.Id,
            user.Email,
            NormalizeRole(user.Role));
    }

    internal static async Task<AuthTokenResponse?> TryRefreshAuthTokenAsync(
        string refreshToken,
        WrestlingPlatformDbContext dbContext,
        SymmetricSecurityKey signingKey,
        string issuer,
        string audience,
        int accessTokenMinutes,
        int refreshTokenDays,
        CancellationToken cancellationToken)
    {
        var nowUtc = DateTime.UtcNow;
        var tokenHash = HashOpaqueToken(refreshToken);

        var tokenRow = await dbContext.UserRefreshTokens.FirstOrDefaultAsync(x => x.TokenHash == tokenHash, cancellationToken);
        if (tokenRow is null)
        {
            return null;
        }

        var user = await dbContext.UserAccounts.FirstOrDefaultAsync(x => x.Id == tokenRow.UserAccountId, cancellationToken);
        if (user is null || !user.IsActive)
        {
            return null;
        }

        if (tokenRow.ExpiresUtc <= nowUtc)
        {
            tokenRow.RevokedUtc = tokenRow.RevokedUtc ?? nowUtc;
            tokenRow.RevocationReason = tokenRow.RevocationReason ?? "expired";
            await dbContext.SaveChangesAsync(cancellationToken);
            return null;
        }

        if (tokenRow.RevokedUtc is not null)
        {
            if (string.Equals(tokenRow.RevocationReason, "rotated", StringComparison.OrdinalIgnoreCase))
            {
                await RevokeAllRefreshTokensForUserAsync(dbContext, user.Id, "refresh-token-reuse-detected", cancellationToken);
                await dbContext.SaveChangesAsync(cancellationToken);
            }

            return null;
        }

        var nextRefreshToken = GenerateRefreshToken();
        var nextRefreshTokenHash = HashOpaqueToken(nextRefreshToken);
        var nextRefreshTokenExpiresUtc = nowUtc.AddDays(Math.Max(1, refreshTokenDays));

        tokenRow.RevokedUtc = nowUtc;
        tokenRow.RevocationReason = "rotated";
        tokenRow.ReplacedByTokenHash = nextRefreshTokenHash;

        dbContext.UserRefreshTokens.Add(new UserRefreshToken
        {
            UserAccountId = user.Id,
            TokenHash = nextRefreshTokenHash,
            ExpiresUtc = nextRefreshTokenExpiresUtc
        });

        await PruneOldRefreshTokensAsync(dbContext, user.Id, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        var (nextAccessToken, nextAccessExpiresUtc) = CreateAccessToken(user, signingKey, issuer, audience, accessTokenMinutes);

        return new AuthTokenResponse(
            nextAccessToken,
            nextAccessExpiresUtc,
            nextRefreshToken,
            nextRefreshTokenExpiresUtc,
            user.Id,
            user.Email,
            NormalizeRole(user.Role));
    }

    internal static async Task RevokeAllRefreshTokensForUserAsync(
        WrestlingPlatformDbContext dbContext,
        Guid userId,
        string reason,
        CancellationToken cancellationToken)
    {
        var nowUtc = DateTime.UtcNow;

        var activeTokens = await dbContext.UserRefreshTokens
            .Where(x => x.UserAccountId == userId && x.RevokedUtc == null && x.ExpiresUtc > nowUtc)
            .ToListAsync(cancellationToken);

        foreach (var activeToken in activeTokens)
        {
            activeToken.RevokedUtc = nowUtc;
            activeToken.RevocationReason = reason;
        }
    }

    internal static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, PasswordIterations, HashAlgorithmName.SHA256, 32);

        return $"PBKDF2${PasswordIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    internal static bool VerifyPassword(string password, string storedHash)
    {
        if (storedHash.StartsWith("PBKDF2$", StringComparison.Ordinal))
        {
            var parts = storedHash.Split('$', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 4 && int.TryParse(parts[1], out var iterations))
            {
                var salt = Convert.FromBase64String(parts[2]);
                var expectedHash = Convert.FromBase64String(parts[3]);
                var actualHash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expectedHash.Length);
                return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
            }

            return false;
        }

        var legacyBytes = Encoding.UTF8.GetBytes(password);
        var legacyHash = Convert.ToHexString(SHA256.HashData(legacyBytes));
        return string.Equals(legacyHash, storedHash, StringComparison.OrdinalIgnoreCase);
    }

    private static (string AccessToken, DateTime ExpiresUtc) CreateAccessToken(
        UserAccount user,
        SymmetricSecurityKey signingKey,
        string issuer,
        string audience,
        int accessTokenMinutes)
    {
        var expiresUtc = DateTime.UtcNow.AddMinutes(Math.Max(5, accessTokenMinutes));

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Role, NormalizeRole(user.Role).ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
        };

        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: expiresUtc,
            signingCredentials: credentials);

        var accessToken = new JwtSecurityTokenHandler().WriteToken(token);
        return (accessToken, expiresUtc);
    }

    private static string GenerateRefreshToken()
    {
        var tokenBytes = RandomNumberGenerator.GetBytes(RefreshTokenBytes);
        return Convert.ToBase64String(tokenBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    private static string HashOpaqueToken(string token)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    }

    private static async Task PruneOldRefreshTokensAsync(
        WrestlingPlatformDbContext dbContext,
        Guid userId,
        CancellationToken cancellationToken)
    {
        var nowUtc = DateTime.UtcNow;
        var revokedCutoffUtc = nowUtc.AddDays(-RefreshTokenPruneRetentionDays);

        var staleTokens = await dbContext.UserRefreshTokens
            .Where(x => x.UserAccountId == userId
                        && (x.ExpiresUtc <= nowUtc || (x.RevokedUtc != null && x.RevokedUtc <= revokedCutoffUtc)))
            .ToListAsync(cancellationToken);

        if (staleTokens.Count > 0)
        {
            dbContext.UserRefreshTokens.RemoveRange(staleTokens);
        }
    }
}
