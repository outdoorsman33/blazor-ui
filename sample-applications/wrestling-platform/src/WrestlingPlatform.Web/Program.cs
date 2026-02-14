using WrestlingPlatform.Web.Components;
using WrestlingPlatform.Web.Services;

namespace WrestlingPlatform.Web;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddRazorComponents()
            .AddInteractiveServerComponents();

        builder.Services.AddScoped<AuthSession>();
        builder.Services.AddHttpClient<PlatformApiClient>(client =>
        {
            client.BaseAddress = ResolveApiBaseUri(builder.Configuration);
        });

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
        app.UseHttpsRedirection();

        app.UseAntiforgery();

        app.MapGet("/healthz", () => Results.Ok(new
        {
            Status = "ok",
            Service = "web",
            Utc = DateTime.UtcNow
        }));

        app.MapStaticAssets();
        app.MapRazorComponents<App>()
            .AddInteractiveServerRenderMode();

        app.Run();
    }

    private static Uri ResolveApiBaseUri(IConfiguration configuration)
    {
        var configuredBaseUrl = configuration["Api:BaseUrl"]?.Trim();
        if (string.IsNullOrWhiteSpace(configuredBaseUrl))
        {
            return new Uri("http://127.0.0.1:5099");
        }

        if (Uri.TryCreate(configuredBaseUrl, UriKind.Absolute, out var absoluteUri)
            && (string.Equals(absoluteUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                || string.Equals(absoluteUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            return absoluteUri;
        }

        // Render `fromService.hostport` values are host:port without a scheme.
        if (Uri.TryCreate($"http://{configuredBaseUrl}", UriKind.Absolute, out var hostPortUri))
        {
            return hostPortUri;
        }

        throw new InvalidOperationException($"Api:BaseUrl is invalid: '{configuredBaseUrl}'.");
    }
}

