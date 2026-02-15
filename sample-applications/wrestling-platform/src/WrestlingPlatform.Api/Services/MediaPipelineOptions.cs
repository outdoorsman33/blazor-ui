namespace WrestlingPlatform.Api.Services;

public sealed class MediaPipelineOptions
{
    public string StorageMode { get; set; } = "Local";

    public string WorkingDirectory { get; set; } = "App_Data/media-pipeline";

    public string PublicBaseUrl { get; set; } = "https://media.pinpointarena.local";

    public int RetentionDays { get; set; } = 120;

    public string? S3Bucket { get; set; }

    public string? S3Region { get; set; }

    public string? S3ServiceUrl { get; set; }

    public bool S3ForcePathStyle { get; set; } = true;

    public string? S3AccessKeyId { get; set; }

    public string? S3SecretAccessKey { get; set; }

    public string AiProvider { get; set; } = "RuleBased";

    public string? OpenAiApiKey { get; set; }

    public string OpenAiModel { get; set; } = "gpt-4.1-mini";
}

