using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;

namespace WrestlingPlatform.Api.IntegrationTests;

public sealed class AuthIntegrationTests(WrestlingPlatformApiFactory factory) : IClassFixture<WrestlingPlatformApiFactory>
{
    [Fact]
    public async Task RefreshTokenReuse_RevokesActiveRefreshChain()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();
        var email = $"athlete-{Guid.NewGuid():N}@example.com";
        const string password = "Passw0rd!234";

        var registered = await TestApiHelpers.RegisterUserAsync(client, email, password, UserRole.Athlete);
        var login = await TestApiHelpers.LoginAsync(client, email, password);

        using var rotatedRefreshResponse = await TestApiHelpers.RefreshAsync(client, login.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, rotatedRefreshResponse.StatusCode);
        var rotatedToken = await TestApiHelpers.ReadJsonAsync<AuthTokenResponse>(rotatedRefreshResponse);

        using var reusedOriginalRefreshResponse = await TestApiHelpers.RefreshAsync(client, login.RefreshToken);
        Assert.Equal(HttpStatusCode.Unauthorized, reusedOriginalRefreshResponse.StatusCode);

        using var rotatedTokenRefreshResponse = await TestApiHelpers.RefreshAsync(client, rotatedToken.RefreshToken);
        Assert.Equal(HttpStatusCode.Unauthorized, rotatedTokenRefreshResponse.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();

        var tokenRows = await dbContext.UserRefreshTokens
            .Where(x => x.UserAccountId == registered.Id)
            .ToListAsync();

        Assert.Contains(tokenRows, x => x.RevocationReason == "rotated");
        Assert.Contains(tokenRows, x => x.RevocationReason == "refresh-token-reuse-detected");
        Assert.DoesNotContain(tokenRows, x => x.RevokedUtc is null && x.ExpiresUtc > DateTime.UtcNow);
    }

    [Fact]
    public async Task Logout_RevokesUserRefreshTokens()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();
        var email = $"logout-{Guid.NewGuid():N}@example.com";
        const string password = "Passw0rd!234";

        var registered = await TestApiHelpers.RegisterUserAsync(client, email, password, UserRole.Fan);
        var login = await TestApiHelpers.LoginAsync(client, email, password);

        TestApiHelpers.SetBearerToken(client, login.AccessToken);

        using var logoutResponse = await client.PostAsync("/api/auth/logout", content: null);
        Assert.Equal(HttpStatusCode.OK, logoutResponse.StatusCode);

        using var refreshAfterLogoutResponse = await TestApiHelpers.RefreshAsync(client, login.RefreshToken);
        Assert.Equal(HttpStatusCode.Unauthorized, refreshAfterLogoutResponse.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();

        var activeTokenCount = await dbContext.UserRefreshTokens
            .CountAsync(x => x.UserAccountId == registered.Id && x.RevokedUtc == null && x.ExpiresUtc > DateTime.UtcNow);

        Assert.Equal(0, activeTokenCount);
    }
}
