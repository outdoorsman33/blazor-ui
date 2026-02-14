using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;
using WrestlingPlatform.Infrastructure.Persistence;

namespace WrestlingPlatform.Api.IntegrationTests;

public sealed class OwnershipIntegrationTests(WrestlingPlatformApiFactory factory) : IClassFixture<WrestlingPlatformApiFactory>
{
    [Fact]
    public async Task AthleteProfile_ForDifferentUser_ReturnsForbidAndDoesNotCreateProfile()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();
        const string password = "Passw0rd!234";

        var ownerUser = await TestApiHelpers.RegisterUserAsync(
            client,
            $"owner-{Guid.NewGuid():N}@example.com",
            password,
            UserRole.Athlete);

        var targetUser = await TestApiHelpers.RegisterUserAsync(
            client,
            $"target-{Guid.NewGuid():N}@example.com",
            password,
            UserRole.Athlete);

        var ownerLogin = await TestApiHelpers.LoginAsync(client, ownerUser.Email, password);
        TestApiHelpers.SetBearerToken(client, ownerLogin.AccessToken);

        var request = new CreateAthleteProfileRequest(
            targetUser.Id,
            "Target",
            "Wrestler",
            DateTime.UtcNow.Date.AddYears(-13),
            "OH",
            "Columbus",
            "North Club",
            7,
            92m,
            CompetitionLevel.MiddleSchool);

        using var response = await client.PostAsync("/api/profiles/athletes", TestApiHelpers.JsonContent(request));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();

        var profileExists = await dbContext.AthleteProfiles.AnyAsync(x => x.UserAccountId == targetUser.Id);
        Assert.False(profileExists);
    }

    [Fact]
    public async Task CoachAssociation_ForDifferentCoachProfile_ReturnsForbid()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();
        const string password = "Passw0rd!234";

        var coachA = await TestApiHelpers.RegisterUserAsync(client, $"coach-a-{Guid.NewGuid():N}@example.com", password, UserRole.Coach);
        var coachB = await TestApiHelpers.RegisterUserAsync(client, $"coach-b-{Guid.NewGuid():N}@example.com", password, UserRole.Coach);

        var coachALogin = await TestApiHelpers.LoginAsync(client, coachA.Email, password);
        TestApiHelpers.SetBearerToken(client, coachALogin.AccessToken);
        var coachAProfile = await CreateCoachProfileAsync(client, coachA.Id, "CoachA");

        var coachBLogin = await TestApiHelpers.LoginAsync(client, coachB.Email, password);
        TestApiHelpers.SetBearerToken(client, coachBLogin.AccessToken);
        var coachBProfile = await CreateCoachProfileAsync(client, coachB.Id, "CoachB");

        TestApiHelpers.SetBearerToken(client, coachALogin.AccessToken);
        using var associationResponse = await client.PostAsync(
            $"/api/coaches/{coachBProfile.Id}/associations",
            TestApiHelpers.JsonContent(new CreateCoachAssociationRequest(null, null, "Assistant", true)));

        Assert.Equal(HttpStatusCode.Forbidden, associationResponse.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();
        var associationsForCoachB = await dbContext.CoachAssociations.CountAsync(x => x.CoachProfileId == coachBProfile.Id);

        Assert.Equal(0, associationsForCoachB);
        Assert.NotEqual(coachAProfile.Id, coachBProfile.Id);
    }

    [Fact]
    public async Task TeamScopedRegistration_ByAthleteWithTeamId_ReturnsForbid()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();
        const string password = "Passw0rd!234";

        var coach = await TestApiHelpers.RegisterUserAsync(client, $"coach-{Guid.NewGuid():N}@example.com", password, UserRole.Coach);
        var athlete = await TestApiHelpers.RegisterUserAsync(client, $"athlete-{Guid.NewGuid():N}@example.com", password, UserRole.Athlete);

        var coachLogin = await TestApiHelpers.LoginAsync(client, coach.Email, password);
        TestApiHelpers.SetBearerToken(client, coachLogin.AccessToken);
        var coachProfile = await CreateCoachProfileAsync(client, coach.Id, "CoachTeamOwner");
        var team = await CreateTeamAsync(client, "Central Club", "OH", "Dublin");
        var tournamentEvent = await CreateEventAsync(client, coachProfile.Id, "Central Open", 0);

        var athleteLogin = await TestApiHelpers.LoginAsync(client, athlete.Email, password);
        TestApiHelpers.SetBearerToken(client, athleteLogin.AccessToken);
        var athleteProfile = await CreateAthleteProfileAsync(client, athlete.Id, "Ava", "Carter");

        using var registrationResponse = await client.PostAsync(
            $"/api/events/{tournamentEvent.Id}/registrations",
            TestApiHelpers.JsonContent(new RegisterForEventRequest(athleteProfile.Id, team.Id, IsFreeAgent: false)));

        Assert.Equal(HttpStatusCode.Forbidden, registrationResponse.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<WrestlingPlatformDbContext>();
        var registrationExists = await dbContext.EventRegistrations
            .AnyAsync(x => x.TournamentEventId == tournamentEvent.Id && x.AthleteProfileId == athleteProfile.Id);

        Assert.False(registrationExists);
    }

    [Fact]
    public async Task TeamScopedRegistration_ByAssociatedCoach_CanRegisterAthlete()
    {
        await factory.ResetDatabaseAsync();

        using var client = factory.CreateClient();
        const string password = "Passw0rd!234";

        var coach = await TestApiHelpers.RegisterUserAsync(client, $"coach-ok-{Guid.NewGuid():N}@example.com", password, UserRole.Coach);
        var athlete = await TestApiHelpers.RegisterUserAsync(client, $"athlete-ok-{Guid.NewGuid():N}@example.com", password, UserRole.Athlete);

        var coachLogin = await TestApiHelpers.LoginAsync(client, coach.Email, password);
        TestApiHelpers.SetBearerToken(client, coachLogin.AccessToken);
        var coachProfile = await CreateCoachProfileAsync(client, coach.Id, "CoachOwner");
        var team = await CreateTeamAsync(client, "Northwest Club", "OH", "Toledo");
        var tournamentEvent = await CreateEventAsync(client, coachProfile.Id, "Northwest Invite", 0);

        var athleteLogin = await TestApiHelpers.LoginAsync(client, athlete.Email, password);
        TestApiHelpers.SetBearerToken(client, athleteLogin.AccessToken);
        var athleteProfile = await CreateAthleteProfileAsync(client, athlete.Id, "Liam", "Stone");

        TestApiHelpers.SetBearerToken(client, coachLogin.AccessToken);
        using var associationResponse = await client.PostAsync(
            $"/api/coaches/{coachProfile.Id}/associations",
            TestApiHelpers.JsonContent(new CreateCoachAssociationRequest(athleteProfile.Id, team.Id, "Head Coach", true)));
        Assert.Equal(HttpStatusCode.Created, associationResponse.StatusCode);

        using var registrationResponse = await client.PostAsync(
            $"/api/events/{tournamentEvent.Id}/registrations",
            TestApiHelpers.JsonContent(new RegisterForEventRequest(athleteProfile.Id, team.Id, IsFreeAgent: false)));

        Assert.Equal(HttpStatusCode.Created, registrationResponse.StatusCode);
        var registration = await TestApiHelpers.ReadJsonAsync<EventRegistration>(registrationResponse);

        Assert.Equal(athleteProfile.Id, registration.AthleteProfileId);
        Assert.Equal(team.Id, registration.TeamId);
        Assert.Equal(RegistrationStatus.Confirmed, registration.Status);
    }

    private static async Task<CoachProfile> CreateCoachProfileAsync(HttpClient client, Guid userId, string firstName)
    {
        using var response = await client.PostAsync(
            "/api/profiles/coaches",
            TestApiHelpers.JsonContent(new CreateCoachProfileRequest(
                userId,
                firstName,
                "Johnson",
                "OH",
                "Columbus",
                "Youth wrestling coach")));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await TestApiHelpers.ReadJsonAsync<CoachProfile>(response);
    }

    private static async Task<AthleteProfile> CreateAthleteProfileAsync(
        HttpClient client,
        Guid userId,
        string firstName,
        string lastName)
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
                106m,
                CompetitionLevel.MiddleSchool)));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await TestApiHelpers.ReadJsonAsync<AthleteProfile>(response);
    }

    private static async Task<Team> CreateTeamAsync(HttpClient client, string name, string state, string city)
    {
        using var response = await client.PostAsync(
            "/api/teams",
            TestApiHelpers.JsonContent(new CreateTeamRequest(name, TeamType.Club, state, city)));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await TestApiHelpers.ReadJsonAsync<Team>(response);
    }

    private static async Task<TournamentEvent> CreateEventAsync(HttpClient client, Guid coachProfileId, string name, int entryFeeCents)
    {
        var startUtc = DateTime.UtcNow.Date.AddDays(10);
        var endUtc = startUtc.AddDays(1);

        using var response = await client.PostAsync(
            "/api/events",
            TestApiHelpers.JsonContent(new CreateTournamentEventRequest(
                name,
                OrganizerType.Coach,
                coachProfileId,
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
}
