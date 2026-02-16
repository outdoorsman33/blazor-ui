using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;

namespace WrestlingPlatform.Api.IntegrationTests;

public sealed class RoleAccessIntegrationTests(WrestlingPlatformApiFactory factory) : IClassFixture<WrestlingPlatformApiFactory>
{
    [Fact]
    public async Task EventControls_AreRestrictedToTournamentDirectorOwner()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();
        const string password = "Passw0rd!234";

        var directorA = await TestApiHelpers.RegisterUserAsync(client, $"director-a-{Guid.NewGuid():N}@example.com", password, UserRole.TournamentDirector);
        var directorB = await TestApiHelpers.RegisterUserAsync(client, $"director-b-{Guid.NewGuid():N}@example.com", password, UserRole.TournamentDirector);

        var directorALogin = await TestApiHelpers.LoginAsync(client, directorA.Email, password);
        TestApiHelpers.SetBearerToken(client, directorALogin.AccessToken);
        var tournamentEvent = await CreateEventAsync(client, "Owner Locked Invitational");

        var updatePayload = new UpdateTournamentControlSettingsRequest(
            TournamentFormat.EliminationBracket,
            BracketReleaseMode.Manual,
            BracketReleaseUtc: null,
            BracketCreationMode.Seeded,
            RegistrationCapEnabled: true,
            RegistrationCap: 64);

        var directorBLogin = await TestApiHelpers.LoginAsync(client, directorB.Email, password);
        TestApiHelpers.SetBearerToken(client, directorBLogin.AccessToken);
        using var forbiddenResponse = await client.PutAsync(
            $"/api/events/{tournamentEvent.Id}/controls",
            TestApiHelpers.JsonContent(updatePayload));

        Assert.Equal(HttpStatusCode.Forbidden, forbiddenResponse.StatusCode);

        TestApiHelpers.SetBearerToken(client, directorALogin.AccessToken);
        using var allowedResponse = await client.PutAsync(
            $"/api/events/{tournamentEvent.Id}/controls",
            TestApiHelpers.JsonContent(updatePayload));

        Assert.Equal(HttpStatusCode.OK, allowedResponse.StatusCode);
    }

    [Fact]
    public async Task MatWorker_ScoringIsScopedToAssignedTournament()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();
        const string password = "Passw0rd!234";

        var director = await TestApiHelpers.RegisterUserAsync(client, $"director-{Guid.NewGuid():N}@example.com", password, UserRole.TournamentDirector);
        var matWorker = await TestApiHelpers.RegisterUserAsync(client, $"matworker-{Guid.NewGuid():N}@example.com", password, UserRole.MatWorker);
        var athleteAUser = await TestApiHelpers.RegisterUserAsync(client, $"athlete-a-{Guid.NewGuid():N}@example.com", password, UserRole.Athlete);
        var athleteBUser = await TestApiHelpers.RegisterUserAsync(client, $"athlete-b-{Guid.NewGuid():N}@example.com", password, UserRole.Athlete);

        var directorLogin = await TestApiHelpers.LoginAsync(client, director.Email, password);
        TestApiHelpers.SetBearerToken(client, directorLogin.AccessToken);
        var eventA = await CreateEventAsync(client, "Assigned Scoring Event");
        var eventB = await CreateEventAsync(client, "Unassigned Scoring Event");

        var athleteALogin = await TestApiHelpers.LoginAsync(client, athleteAUser.Email, password);
        TestApiHelpers.SetBearerToken(client, athleteALogin.AccessToken);
        var athleteAProfile = await CreateAthleteProfileAsync(client, athleteAUser.Id, "Ava", "North", CompetitionLevel.MiddleSchool, 106m);
        await RegisterAthleteAsync(client, eventA.Id, athleteAProfile.Id);
        await RegisterAthleteAsync(client, eventB.Id, athleteAProfile.Id);

        var athleteBLogin = await TestApiHelpers.LoginAsync(client, athleteBUser.Email, password);
        TestApiHelpers.SetBearerToken(client, athleteBLogin.AccessToken);
        var athleteBProfile = await CreateAthleteProfileAsync(client, athleteBUser.Id, "Liam", "South", CompetitionLevel.MiddleSchool, 106m);
        await RegisterAthleteAsync(client, eventA.Id, athleteBProfile.Id);
        await RegisterAthleteAsync(client, eventB.Id, athleteBProfile.Id);

        TestApiHelpers.SetBearerToken(client, directorLogin.AccessToken);
        var eventAMatchId = await PrepareSingleMatchAsync(client, eventA.Id, CompetitionLevel.MiddleSchool, 106m);
        var eventBMatchId = await PrepareSingleMatchAsync(client, eventB.Id, CompetitionLevel.MiddleSchool, 106m);

        using var assignmentResponse = await client.PostAsync(
            $"/api/events/{eventA.Id}/ops/staff-assignments",
            TestApiHelpers.JsonContent(new AssignTournamentStaffRequest(
                matWorker.Id,
                UserRole.MatWorker,
                CanScoreMatches: true,
                CanManageMatches: false,
                CanManageStreams: false)));
        Assert.Equal(HttpStatusCode.OK, assignmentResponse.StatusCode);

        var matWorkerLogin = await TestApiHelpers.LoginAsync(client, matWorker.Email, password);
        TestApiHelpers.SetBearerToken(client, matWorkerLogin.AccessToken);

        var rulesRequest = new ConfigureMatchScoringRequest(
            Style: WrestlingStyle.Folkstyle,
            Level: CompetitionLevel.MiddleSchool);

        using var allowedResponse = await client.PostAsync(
            $"/api/matches/{eventAMatchId}/scoreboard/rules",
            TestApiHelpers.JsonContent(rulesRequest));
        Assert.Equal(HttpStatusCode.OK, allowedResponse.StatusCode);

        using var forbiddenResponse = await client.PostAsync(
            $"/api/matches/{eventBMatchId}/scoreboard/rules",
            TestApiHelpers.JsonContent(rulesRequest));
        Assert.Equal(HttpStatusCode.Forbidden, forbiddenResponse.StatusCode);
    }

    [Fact]
    public async Task EventCancellation_BlockedWhenPaidRegistrationsExist()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();
        const string password = "Passw0rd!234";

        var director = await TestApiHelpers.RegisterUserAsync(client, $"director-cancel-{Guid.NewGuid():N}@example.com", password, UserRole.TournamentDirector);
        var athlete = await TestApiHelpers.RegisterUserAsync(client, $"athlete-cancel-{Guid.NewGuid():N}@example.com", password, UserRole.Athlete);

        var directorLogin = await TestApiHelpers.LoginAsync(client, director.Email, password);
        TestApiHelpers.SetBearerToken(client, directorLogin.AccessToken);
        var tournamentEvent = await CreateEventAsync(client, "Paid Registration Guard", entryFeeCents: 0);

        var athleteLogin = await TestApiHelpers.LoginAsync(client, athlete.Email, password);
        TestApiHelpers.SetBearerToken(client, athleteLogin.AccessToken);
        var athleteProfile = await CreateAthleteProfileAsync(client, athlete.Id, "Noah", "Stone", CompetitionLevel.MiddleSchool, 106m);

        using var registrationResponse = await client.PostAsync(
            $"/api/events/{tournamentEvent.Id}/registrations",
            TestApiHelpers.JsonContent(new RegisterForEventRequest(athleteProfile.Id, TeamId: null, IsFreeAgent: true)));
        Assert.Equal(HttpStatusCode.Created, registrationResponse.StatusCode);

        var registration = await TestApiHelpers.ReadJsonAsync<EventRegistration>(registrationResponse);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();
            var row = await dbContext.EventRegistrations.FirstAsync(x => x.Id == registration.Id);
            row.PaymentStatus = PaymentStatus.Paid;
            row.PaidAmountCents = 2500;
            await dbContext.SaveChangesAsync();
        }

        TestApiHelpers.SetBearerToken(client, directorLogin.AccessToken);
        using var cancelResponse = await client.DeleteAsync($"/api/events/{tournamentEvent.Id}");

        Assert.Equal(HttpStatusCode.Conflict, cancelResponse.StatusCode);
    }

    private static async Task<TournamentEvent> CreateEventAsync(HttpClient client, string name, int entryFeeCents = 0)
    {
        var startUtc = DateTime.UtcNow.Date.AddDays(10);
        var endUtc = startUtc.AddDays(1);

        using var response = await client.PostAsync(
            "/api/events",
            TestApiHelpers.JsonContent(new CreateTournamentEventRequest(
                name,
                OrganizerType.Independent,
                Guid.Empty,
                "OH",
                "Columbus",
                "Metro Sports Center",
                startUtc,
                endUtc,
                entryFeeCents,
                IsPublished: true)));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await TestApiHelpers.ReadJsonAsync<TournamentEvent>(response);
    }

    private static async Task<AthleteProfile> CreateAthleteProfileAsync(
        HttpClient client,
        Guid userId,
        string firstName,
        string lastName,
        CompetitionLevel level,
        decimal weightClass)
    {
        using var response = await client.PostAsync(
            "/api/profiles/athletes",
            TestApiHelpers.JsonContent(new CreateAthleteProfileRequest(
                userId,
                firstName,
                lastName,
                DateTime.UtcNow.Date.AddYears(-14),
                "OH",
                "Columbus",
                "Metro Club",
                8,
                weightClass,
                level)));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await TestApiHelpers.ReadJsonAsync<AthleteProfile>(response);
    }

    private static async Task RegisterAthleteAsync(HttpClient client, Guid eventId, Guid athleteProfileId)
    {
        using var response = await client.PostAsync(
            $"/api/events/{eventId}/registrations",
            TestApiHelpers.JsonContent(new RegisterForEventRequest(athleteProfileId, TeamId: null, IsFreeAgent: true)));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    private static async Task<Guid> PrepareSingleMatchAsync(
        HttpClient client,
        Guid eventId,
        CompetitionLevel level,
        decimal weightClass)
    {
        using var checklistResponse = await client.PutAsync(
            $"/api/events/{eventId}/ops-checklist",
            TestApiHelpers.JsonContent(new UpdateEventOpsChecklistRequest(ScratchListFrozen: true)));
        Assert.Equal(HttpStatusCode.OK, checklistResponse.StatusCode);

        using var generateResponse = await client.PostAsync(
            $"/api/events/{eventId}/brackets/generate",
            TestApiHelpers.JsonContent(new GenerateBracketRequest(level, weightClass, BracketGenerationMode.Seeded, DivisionId: null)));
        Assert.Equal(HttpStatusCode.OK, generateResponse.StatusCode);

        using var matsResponse = await client.GetAsync($"/api/events/{eventId}/mats");
        Assert.Equal(HttpStatusCode.OK, matsResponse.StatusCode);

        var board = await TestApiHelpers.ReadJsonAsync<TableWorkerEventBoard>(matsResponse);
        var firstMatch = board.Mats
            .SelectMany(x => x.Matches)
            .OrderBy(x => x.BoutNumber ?? x.MatchNumber)
            .FirstOrDefault();

        Assert.NotNull(firstMatch);
        return firstMatch!.MatchId;
    }
}
