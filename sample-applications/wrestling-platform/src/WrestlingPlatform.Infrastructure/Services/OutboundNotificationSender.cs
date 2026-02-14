using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using WrestlingPlatform.Application.Services;
using WrestlingPlatform.Domain.Models;

namespace WrestlingPlatform.Infrastructure.Services;

public sealed class NotificationProviderOptions
{
    public string ProviderMode { get; set; } = "Mock";
    public string TwilioAccountSid { get; set; } = string.Empty;
    public string TwilioAuthToken { get; set; } = string.Empty;
    public string TwilioFromNumber { get; set; } = string.Empty;
    public string SendGridApiKey { get; set; } = string.Empty;
    public string SendGridFromEmail { get; set; } = string.Empty;
    public string SendGridFromName { get; set; } = "PinPoint Arena";
}

public sealed class OutboundNotificationSender(IOptions<NotificationProviderOptions> options) : IOutboundNotificationSender
{
    public async Task SendAsync(NotificationChannel channel, string destination, string body, CancellationToken cancellationToken = default)
    {
        if (!string.Equals(options.Value.ProviderMode, "Live", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (channel == NotificationChannel.Sms)
        {
            await SendSmsAsync(destination, body, cancellationToken);
            return;
        }

        await SendEmailAsync(destination, body, cancellationToken);
    }

    private async Task SendSmsAsync(string destination, string body, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(options.Value.TwilioAccountSid)
            || string.IsNullOrWhiteSpace(options.Value.TwilioAuthToken)
            || string.IsNullOrWhiteSpace(options.Value.TwilioFromNumber))
        {
            return;
        }

        using var client = new HttpClient();
        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{options.Value.TwilioAccountSid}:{options.Value.TwilioAuthToken}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var url = $"https://api.twilio.com/2010-04-01/Accounts/{options.Value.TwilioAccountSid}/Messages.json";
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["From"] = options.Value.TwilioFromNumber,
            ["To"] = destination,
            ["Body"] = body
        });

        using var _ = await client.PostAsync(url, content, cancellationToken);
    }

    private async Task SendEmailAsync(string destination, string body, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(options.Value.SendGridApiKey)
            || string.IsNullOrWhiteSpace(options.Value.SendGridFromEmail))
        {
            return;
        }

        using var client = new HttpClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", options.Value.SendGridApiKey);

        var payload = new
        {
            personalizations = new[]
            {
                new
                {
                    to = new[] { new { email = destination } },
                    subject = "Wrestling Match Notification"
                }
            },
            from = new
            {
                email = options.Value.SendGridFromEmail,
                name = options.Value.SendGridFromName
            },
            content = new[]
            {
                new
                {
                    type = "text/plain",
                    value = body
                }
            }
        };

        using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var _ = await client.PostAsync("https://api.sendgrid.com/v3/mail/send", content, cancellationToken);
    }
}
