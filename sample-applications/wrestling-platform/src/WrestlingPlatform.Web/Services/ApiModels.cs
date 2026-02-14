using System.Net;
using WrestlingPlatform.Application.Contracts;
using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Web.Services;

public sealed record ApiResult(bool Success, HttpStatusCode StatusCode, string Message)
{
    public static ApiResult Fail(HttpStatusCode statusCode, string message) => new(false, statusCode, message);

    public static ApiResult Ok(string message = "Success") => new(true, HttpStatusCode.OK, message);
}

public sealed record ApiResult<T>(bool Success, HttpStatusCode StatusCode, string Message, T? Data)
{
    public static ApiResult<T> Fail(HttpStatusCode statusCode, string message) => new(false, statusCode, message, default);

    public static ApiResult<T> Ok(T? data, string message = "Success") => new(true, HttpStatusCode.OK, message, data);
}

public sealed class UserSummary
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public UserRole Role { get; set; }
}

public sealed class GroupedEventsResponse
{
    public string State { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public List<GroupedEventCard> Events { get; set; } = [];
}

public sealed class GroupedEventCard
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public DateTime StartUtc { get; set; }
    public DateTime EndUtc { get; set; }
    public int EntryFeeCents { get; set; }
    public string Venue { get; set; } = string.Empty;
}

public sealed class FreeAgentRegistrationView
{
    public Guid Id { get; set; }
    public Guid AthleteId { get; set; }
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public CompetitionLevel Level { get; set; }
    public decimal WeightClass { get; set; }
    public string State { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public RegistrationStatus Status { get; set; }
}

public sealed class BracketBundle
{
    public Bracket Bracket { get; set; } = new();
    public List<BracketEntry> Entrants { get; set; } = [];
    public List<Match> Matches { get; set; } = [];
}

public sealed class RegistrationSubmissionResponse
{
    public EventRegistration? Registration { get; set; }
    public PaymentIntentResult? PaymentIntent { get; set; }
}
