using System.Collections.Concurrent;
using WrestlingPlatform.Application.Contracts;

namespace WrestlingPlatform.Api.Services;

public interface IMediaPipelineService
{
    VideoAssetRecord CreateVideoAsset(CreateVideoAssetRequest request);

    IReadOnlyList<VideoAssetRecord> GetAthleteVideos(Guid athleteProfileId);

    VideoAssetRecord? GetVideo(Guid videoId);

    AiHighlightJobSnapshot QueueAiHighlights(QueueAiHighlightsRequest request);

    IReadOnlyList<AiHighlightJobSnapshot> GetAiJobs(Guid athleteProfileId);

    void ProcessTick();
}

public sealed class MediaPipelineService : IMediaPipelineService
{
    private readonly ConcurrentDictionary<Guid, VideoAssetState> _videoById = new();
    private readonly ConcurrentDictionary<Guid, AiJobState> _aiJobById = new();

    public VideoAssetRecord CreateVideoAsset(CreateVideoAssetRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.SourceUrl))
        {
            throw new ArgumentException("Source URL is required.", nameof(request.SourceUrl));
        }

        var now = DateTime.UtcNow;
        var videoId = Guid.NewGuid();
        var state = new VideoAssetState
        {
            VideoId = videoId,
            AthleteProfileId = request.AthleteProfileId,
            MatchId = request.MatchId,
            StreamId = request.StreamId,
            SourceUrl = request.SourceUrl.Trim(),
            PlaybackUrl = request.SourceUrl.Trim(),
            State = request.QueueTranscode ? VideoPipelineState.QueuedForTranscode : VideoPipelineState.Ready,
            CreatedUtc = now,
            ReadyUtc = request.QueueTranscode ? null : now,
            LastUpdatedUtc = now
        };

        _videoById[videoId] = state;
        return state.ToRecord();
    }

    public IReadOnlyList<VideoAssetRecord> GetAthleteVideos(Guid athleteProfileId)
    {
        return _videoById.Values
            .Where(x => x.AthleteProfileId == athleteProfileId)
            .OrderByDescending(x => x.CreatedUtc)
            .Select(x => x.ToRecord())
            .ToList();
    }

    public VideoAssetRecord? GetVideo(Guid videoId)
    {
        return _videoById.TryGetValue(videoId, out var state) ? state.ToRecord() : null;
    }

    public AiHighlightJobSnapshot QueueAiHighlights(QueueAiHighlightsRequest request)
    {
        var now = DateTime.UtcNow;
        var state = new AiJobState
        {
            JobId = Guid.NewGuid(),
            AthleteProfileId = request.AthleteProfileId,
            EventId = request.EventId,
            Status = "Queued",
            QueuedUtc = now,
            LastUpdatedUtc = now,
            MaxMatches = Math.Clamp(request.MaxMatches, 1, 50),
            ClipsProduced = 0
        };

        _aiJobById[state.JobId] = state;
        return state.ToSnapshot();
    }

    public IReadOnlyList<AiHighlightJobSnapshot> GetAiJobs(Guid athleteProfileId)
    {
        return _aiJobById.Values
            .Where(x => x.AthleteProfileId == athleteProfileId)
            .OrderByDescending(x => x.QueuedUtc)
            .Select(x => x.ToSnapshot())
            .ToList();
    }

    public void ProcessTick()
    {
        var now = DateTime.UtcNow;

        foreach (var video in _videoById.Values)
        {
            if (video.State == VideoPipelineState.QueuedForTranscode && now - video.LastUpdatedUtc >= TimeSpan.FromSeconds(4))
            {
                video.State = VideoPipelineState.Processing;
                video.LastUpdatedUtc = now;
                continue;
            }

            if (video.State == VideoPipelineState.Processing && now - video.LastUpdatedUtc >= TimeSpan.FromSeconds(5))
            {
                video.State = VideoPipelineState.Ready;
                video.ReadyUtc = now;
                video.LastUpdatedUtc = now;
                video.PlaybackUrl = BuildPlaybackUrl(video);
            }
        }

        foreach (var aiJob in _aiJobById.Values)
        {
            if (aiJob.Status == "Queued" && now - aiJob.LastUpdatedUtc >= TimeSpan.FromSeconds(3))
            {
                aiJob.Status = "Running";
                aiJob.StartedUtc = now;
                aiJob.LastUpdatedUtc = now;
                continue;
            }

            if (aiJob.Status == "Running" && now - aiJob.LastUpdatedUtc >= TimeSpan.FromSeconds(6))
            {
                aiJob.Status = "Completed";
                aiJob.CompletedUtc = now;
                aiJob.ClipsProduced = Math.Clamp(Random.Shared.Next(2, 8), 1, aiJob.MaxMatches);
                aiJob.Details = "AI highlight extraction completed from timeline + stream metadata.";
                aiJob.LastUpdatedUtc = now;
            }
        }
    }

    private static string BuildPlaybackUrl(VideoAssetState state)
    {
        var athleteSegment = state.AthleteProfileId.ToString("N")[..8];
        return $"https://media.pinpointarena.local/athletes/{athleteSegment}/videos/{state.VideoId:N}/master.m3u8";
    }

    private sealed class VideoAssetState
    {
        public Guid VideoId { get; init; }
        public Guid AthleteProfileId { get; init; }
        public Guid MatchId { get; init; }
        public Guid? StreamId { get; init; }
        public string SourceUrl { get; set; } = string.Empty;
        public string PlaybackUrl { get; set; } = string.Empty;
        public VideoPipelineState State { get; set; }
        public DateTime CreatedUtc { get; init; }
        public DateTime LastUpdatedUtc { get; set; }
        public DateTime? ReadyUtc { get; set; }
        public string? FailureReason { get; set; }

        public VideoAssetRecord ToRecord()
        {
            return new VideoAssetRecord(
                VideoId,
                AthleteProfileId,
                MatchId,
                StreamId,
                SourceUrl,
                PlaybackUrl,
                State,
                CreatedUtc,
                ReadyUtc,
                FailureReason);
        }
    }

    private sealed class AiJobState
    {
        public Guid JobId { get; init; }
        public Guid AthleteProfileId { get; init; }
        public Guid? EventId { get; init; }
        public DateTime QueuedUtc { get; init; }
        public DateTime? StartedUtc { get; set; }
        public DateTime? CompletedUtc { get; set; }
        public string Status { get; set; } = "Queued";
        public int ClipsProduced { get; set; }
        public string? Details { get; set; }
        public int MaxMatches { get; init; }
        public DateTime LastUpdatedUtc { get; set; }

        public AiHighlightJobSnapshot ToSnapshot()
        {
            return new AiHighlightJobSnapshot(
                JobId,
                AthleteProfileId,
                EventId,
                QueuedUtc,
                StartedUtc,
                CompletedUtc,
                Status,
                ClipsProduced,
                Details);
        }
    }
}

public sealed class MediaPipelineWorker(IMediaPipelineService mediaPipelineService, ILogger<MediaPipelineWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                mediaPipelineService.ProcessTick();
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Media pipeline tick failed.");
            }
        }
    }
}
