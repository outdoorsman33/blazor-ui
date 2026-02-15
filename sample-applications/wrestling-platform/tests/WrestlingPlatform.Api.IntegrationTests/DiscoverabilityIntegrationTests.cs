using System.Net;
using WrestlingPlatform.Application.Contracts;

namespace WrestlingPlatform.Api.IntegrationTests;

public sealed class DiscoverabilityIntegrationTests(WrestlingPlatformApiFactory factory) : IClassFixture<WrestlingPlatformApiFactory>
{
    [Fact]
    public async Task GlobalSearch_ReturnsMixedResults()
    {
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/api/search/global?q=columbus&take=10");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var payload = await TestApiHelpers.ReadJsonAsync<GlobalSearchResponse>(response);
        Assert.True(payload.Total > 0);
        Assert.NotEmpty(payload.Results);
    }

    [Fact]
    public async Task ExplorerAndHelpEndpoints_ReturnExpectedPayloads()
    {
        using var client = factory.CreateClient();

        using var explorerResponse = await client.GetAsync("/api/events/explorer?state=OH&daysBack=365&daysAhead=365");
        Assert.Equal(HttpStatusCode.OK, explorerResponse.StatusCode);
        var explorer = await TestApiHelpers.ReadJsonAsync<TournamentExplorerResponse>(explorerResponse);
        Assert.NotNull(explorer.Live);
        Assert.NotNull(explorer.Upcoming);
        Assert.NotNull(explorer.Past);

        using var nilPolicyResponse = await client.GetAsync("/api/nil/policy");
        Assert.Equal(HttpStatusCode.OK, nilPolicyResponse.StatusCode);
        var nilPolicy = await TestApiHelpers.ReadJsonAsync<NilPolicyResponse>(nilPolicyResponse);
        Assert.NotEmpty(nilPolicy.Rules);

        using var faqResponse = await client.GetAsync("/api/help/faqs?q=stream");
        Assert.Equal(HttpStatusCode.OK, faqResponse.StatusCode);
        var faqs = await TestApiHelpers.ReadJsonAsync<List<HelpFaqItem>>(faqResponse);
        Assert.Contains(faqs, x => x.Category.Contains("Streaming", StringComparison.OrdinalIgnoreCase));
    }
}
