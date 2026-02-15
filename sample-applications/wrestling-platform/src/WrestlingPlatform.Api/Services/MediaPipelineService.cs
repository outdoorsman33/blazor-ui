using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;
using WrestlingPlatform.Application.Contracts;

namespace WrestlingPlatform.Api.Services;

public interface IMediaPipelineService
{
    VideoAssetRecord CreateVideoAsset(CreateVideoAssetRequest request);

    IReadOnlyList<VideoAssetRecord> GetAthleteVideos(Guid athleteProfileId);

    VideoAssetRecord? GetVideo(Guid videoId);

    AiHighlightJobSnapshot QueueAiHighlights(QueueAiHighlightsRequest request);

    IReadOnlyList<AiHighlightJobSnapshot> GetAiJobs(Guid athleteProfileId);

    IReadOnlyList<AthleteHighlightClip> GetGeneratedHighlights(Guid athleteProfileId);

    Task ProcessTickAsync(CancellationToken cancellationToken = default);
}

public sealed class MediaPipelineService : IMediaPipelineService
{
    private readonly ConcurrentDictionary<Guid, VideoAssetState> _videoById = new();
    private readonly ConcurrentDictionary<Guid, AiJobState> _aiJobById = new();
    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<Guid, AthleteHighlightClip>> _clipsByAthleteId = new();
    private readonly IMediaObjectStorage _storage;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<MediaPipelineService> _logger;
    private readonly MediaPipelineOptions _options;
    private readonly SemaphoreSlim _tickLock = new(1, 1);
    private readonly object _stateLock = new();
    private readonly string _workingRoot;
    private readonly string _stateFilePath;
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private DateTime _lastRetentionSweepUtc = DateTime.MinValue;

    public MediaPipelineService(
        IMediaObjectStorage storage,
        IHttpClientFactory httpClientFactory,
        IOptions<MediaPipelineOptions> options,
        IWebHostEnvironment environment,
        ILogger<MediaPipelineService> logger)
    {
        _storage = storage;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _options = options.Value;
        _workingRoot = ResolveWorkingRoot(environment.ContentRootPath, _options.WorkingDirectory);
        _stateFilePath = Path.Combine(_workingRoot, "state", "media-pipeline-state.json");

        Directory.CreateDirectory(_workingRoot);
        LoadState();
    }

    public VideoAssetRecord CreateVideoAsset(CreateVideoAssetRequest request)
    {
        if (request.AthleteProfileId == Guid.Empty)
        {
            throw new ArgumentException("Athlete profile id is required.", nameof(request.AthleteProfileId));
        }

        if (request.MatchId == Guid.Empty)
        {
            throw new ArgumentException("Match id is required.", nameof(request.MatchId));
        }

        if (string.IsNullOrWhiteSpace(request.SourceUrl))
        {
            throw new ArgumentException("Source URL is required.", nameof(request.SourceUrl));
        }

        var now = DateTime.UtcNow;
        var videoId = Guid.NewGuid();
        var normalizedSource = request.SourceUrl.Trim();
        var sourceExtension = ResolveExtensionFromSource(normalizedSource);
        var storagePrefix = $"athletes/{request.AthleteProfileId:N}/videos/{videoId:N}";
        var sourceObjectKey = $"{storagePrefix}/source{sourceExtension}";
        var state = new VideoAssetState
        {
            VideoId = videoId,
            AthleteProfileId = request.AthleteProfileId,
            MatchId = request.MatchId,
            StreamId = request.StreamId,
            SourceUrl = normalizedSource,
            PlaybackUrl = normalizedSource,
            State = request.QueueTranscode ? VideoPipelineState.QueuedForTranscode : VideoPipelineState.Ready,
            CreatedUtc = now,
            LastUpdatedUtc = now,
            ReadyUtc = request.QueueTranscode ? null : now,
            StoragePrefix = storagePrefix,
            SourceObjectKey = sourceObjectKey,
            PlaybackObjectKey = request.QueueTranscode ? $"{storagePrefix}/master.m3u8" : sourceObjectKey
        };

        _videoById[state.VideoId] = state;
        PersistState();
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
        if (request.AthleteProfileId == Guid.Empty)
        {
            throw new ArgumentException("Athlete profile id is required.", nameof(request.AthleteProfileId));
        }

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
            ClipsProduced = 0,
            Provider = ResolveAiProvider()
        };

        _aiJobById[state.JobId] = state;
        PersistState();
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

    public IReadOnlyList<AthleteHighlightClip> GetGeneratedHighlights(Guid athleteProfileId)
    {
        if (!_clipsByAthleteId.TryGetValue(athleteProfileId, out var clips))
        {
            return [];
        }

        return clips.Values
            .OrderByDescending(x => x.ClipEndUtc)
            .Take(150)
            .ToList();
    }

    public async Task ProcessTickAsync(CancellationToken cancellationToken = default)
    {
        if (!await _tickLock.WaitAsync(0, cancellationToken))
        {
            return;
        }

        try
        {
            await ProcessNextVideoAsync(cancellationToken);
            await ProcessNextAiJobAsync(cancellationToken);
            await SweepRetentionAsync(cancellationToken);
        }
        finally
        {
            _tickLock.Release();
        }
    }

    private async Task ProcessNextVideoAsync(CancellationToken cancellationToken)
    {
        var queuedVideo = _videoById.Values
            .Where(x => x.State == VideoPipelineState.QueuedForTranscode)
            .OrderBy(x => x.CreatedUtc)
            .FirstOrDefault();

        if (queuedVideo is null)
        {
            return;
        }

        queuedVideo.State = VideoPipelineState.Processing;
        queuedVideo.LastUpdatedUtc = DateTime.UtcNow;
        queuedVideo.FailureReason = null;
        PersistState();

        try
        {
            var playback = await ProcessVideoAssetAsync(queuedVideo, cancellationToken);
            queuedVideo.PlaybackUrl = playback;
            queuedVideo.State = VideoPipelineState.Ready;
            queuedVideo.ReadyUtc = DateTime.UtcNow;
            queuedVideo.LastUpdatedUtc = queuedVideo.ReadyUtc.Value;
            queuedVideo.FailureReason = null;
        }
        catch (Exception ex)
        {
            queuedVideo.State = VideoPipelineState.Failed;
            queuedVideo.ReadyUtc = null;
            queuedVideo.LastUpdatedUtc = DateTime.UtcNow;
            queuedVideo.FailureReason = ex.Message.Length > 320 ? ex.Message[..320] : ex.Message;
            _logger.LogWarning(ex, "Media transcode failed for video {VideoId}", queuedVideo.VideoId);
        }
        finally
        {
            PersistState();
        }
    }

    private async Task<string> ProcessVideoAssetAsync(VideoAssetState video, CancellationToken cancellationToken)
    {
        var stagingRoot = Path.Combine(_workingRoot, "staging", video.VideoId.ToString("N"));
        Directory.CreateDirectory(stagingRoot);

        var downloadedSource = await MaterializeSourceAsync(video.SourceUrl, stagingRoot, cancellationToken);
        var extension = Path.GetExtension(downloadedSource.LocalPath).ToLowerInvariant();
        var shouldTranscode = extension is ".mp4" or ".mov" or ".mkv" or ".webm" or ".ts";

        if (shouldTranscode && await TryRunFfmpegAsync(downloadedSource.LocalPath, stagingRoot, cancellationToken))
        {
            var generatedFiles = Directory.GetFiles(stagingRoot, "*", SearchOption.TopDirectoryOnly);
            if (generatedFiles.Length > 0)
            {
                foreach (var filePath in generatedFiles)
                {
                    var fileName = Path.GetFileName(filePath);
                    var objectKey = $"{video.StoragePrefix}/{fileName}";
                    await _storage.UploadFileAsync(filePath, objectKey, cancellationToken);
                }

                video.PlaybackObjectKey = $"{video.StoragePrefix}/master.m3u8";
                return _storage.BuildPublicUrl(video.PlaybackObjectKey);
            }
        }

        if (downloadedSource.FromRemoteM3u8)
        {
            video.PlaybackObjectKey = null;
            return video.SourceUrl;
        }

        var sourceObjectKey = string.IsNullOrWhiteSpace(video.SourceObjectKey)
            ? $"{video.StoragePrefix}/source{ResolveExtensionFromSource(downloadedSource.LocalPath)}"
            : video.SourceObjectKey;

        await _storage.UploadFileAsync(downloadedSource.LocalPath, sourceObjectKey, cancellationToken);
        video.SourceObjectKey = sourceObjectKey;
        video.PlaybackObjectKey = sourceObjectKey;
        return _storage.BuildPublicUrl(sourceObjectKey);
    }

    private async Task<MaterializedSource> MaterializeSourceAsync(string sourceUrl, string stagingRoot, CancellationToken cancellationToken)
    {
        if (Uri.TryCreate(sourceUrl, UriKind.Absolute, out var sourceUri))
        {
            if (sourceUri.Scheme is "http" or "https")
            {
                if (sourceUri.AbsolutePath.EndsWith(".m3u8", StringComparison.OrdinalIgnoreCase))
                {
                    return new MaterializedSource(sourceUrl, FromRemoteM3u8: true);
                }

                var extension = Path.GetExtension(sourceUri.AbsolutePath);
                var localPath = Path.Combine(stagingRoot, $"source{(string.IsNullOrWhiteSpace(extension) ? ".mp4" : extension)}");
                using var client = _httpClientFactory.CreateClient("media-pipeline");
                using var response = await client.GetAsync(sourceUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                response.EnsureSuccessStatusCode();
                await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
                await using var output = File.Create(localPath);
                await input.CopyToAsync(output, cancellationToken);
                return new MaterializedSource(localPath, FromRemoteM3u8: false);
            }

            if (sourceUri.Scheme.Equals("file", StringComparison.OrdinalIgnoreCase))
            {
                var localPath = sourceUri.LocalPath;
                if (!File.Exists(localPath))
                {
                    throw new FileNotFoundException("Video source file was not found.", localPath);
                }

                var copiedPath = Path.Combine(stagingRoot, $"source{ResolveExtensionFromSource(localPath)}");
                File.Copy(localPath, copiedPath, overwrite: true);
                return new MaterializedSource(copiedPath, FromRemoteM3u8: false);
            }
        }

        if (!File.Exists(sourceUrl))
        {
            throw new InvalidOperationException("Source URL/path is invalid or unreachable for media processing.");
        }

        var copied = Path.Combine(stagingRoot, $"source{ResolveExtensionFromSource(sourceUrl)}");
        File.Copy(sourceUrl, copied, overwrite: true);
        return new MaterializedSource(copied, FromRemoteM3u8: false);
    }

    private async Task<bool> TryRunFfmpegAsync(string sourceFilePath, string outputDirectory, CancellationToken cancellationToken)
    {
        var manifestPath = Path.Combine(outputDirectory, "master.m3u8");
        var segmentPattern = Path.Combine(outputDirectory, "segment_%03d.ts");
        var args =
            $"-y -i \"{sourceFilePath}\" -c:v libx264 -preset veryfast -c:a aac -f hls -hls_time 4 -hls_playlist_type vod -hls_segment_filename \"{segmentPattern}\" \"{manifestPath}\"";

        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "ffmpeg",
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            await process.WaitForExitAsync(cancellationToken);
            if (process.ExitCode != 0 || !File.Exists(manifestPath))
            {
                var stderr = await process.StandardError.ReadToEndAsync(cancellationToken);
                _logger.LogInformation("ffmpeg fallback triggered. ExitCode={ExitCode}, detail={Detail}", process.ExitCode, Truncate(stderr, 180));
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogInformation(ex, "ffmpeg unavailable or failed. Falling back to source passthrough.");
            return false;
        }
    }

    private async Task ProcessNextAiJobAsync(CancellationToken cancellationToken)
    {
        var queued = _aiJobById.Values
            .Where(x => x.Status == "Queued")
            .OrderBy(x => x.QueuedUtc)
            .FirstOrDefault();

        if (queued is null)
        {
            return;
        }

        queued.Status = "Running";
        queued.StartedUtc = DateTime.UtcNow;
        queued.LastUpdatedUtc = queued.StartedUtc.Value;
        queued.Details = $"Analyzing media timeline with provider: {queued.Provider}.";
        PersistState();

        try
        {
            var clips = await GenerateHighlightClipsAsync(queued, cancellationToken);
            queued.ClipsProduced = clips.Count;
            queued.Status = "Completed";
            queued.CompletedUtc = DateTime.UtcNow;
            queued.LastUpdatedUtc = queued.CompletedUtc.Value;
            queued.Details = $"Generated {clips.Count} AI clips using {queued.Provider}.";
        }
        catch (Exception ex)
        {
            queued.Status = "Failed";
            queued.LastUpdatedUtc = DateTime.UtcNow;
            queued.Details = $"AI generation failed: {Truncate(ex.Message, 220)}";
            _logger.LogWarning(ex, "AI highlight generation failed for job {JobId}", queued.JobId);
        }
        finally
        {
            PersistState();
        }
    }

    private async Task<List<AthleteHighlightClip>> GenerateHighlightClipsAsync(AiJobState job, CancellationToken cancellationToken)
    {
        var readyVideos = _videoById.Values
            .Where(x => x.AthleteProfileId == job.AthleteProfileId && x.State == VideoPipelineState.Ready)
            .OrderByDescending(x => x.ReadyUtc ?? x.CreatedUtc)
            .Take(job.MaxMatches)
            .ToList();

        if (readyVideos.Count == 0)
        {
            return [];
        }

        var producedClips = new List<AthleteHighlightClip>();
        foreach (var video in readyVideos)
        {
            var endUtc = video.ReadyUtc ?? DateTime.UtcNow;
            var startUtc = endUtc.AddSeconds(-45);
            var impactScore = BuildImpactScore(video.MatchId, video.CreatedUtc);
            var summary = await BuildAiSummaryAsync(video, impactScore, cancellationToken);
            var title = impactScore >= 88 ? "Elite Sequence" : impactScore >= 78 ? "Momentum Shift" : "Key Exchange";

            var clip = new AthleteHighlightClip(
                Guid.NewGuid(),
                job.AthleteProfileId,
                video.MatchId,
                video.StreamId,
                title,
                summary,
                video.PlaybackUrl,
                startUtc,
                endUtc,
                impactScore,
                AiGenerated: true);

            AddGeneratedClip(clip);
            producedClips.Add(clip);
        }

        return producedClips;
    }

    private async Task<string> BuildAiSummaryAsync(VideoAssetState video, int impactScore, CancellationToken cancellationToken)
    {
        if (!ResolveAiProvider().Equals("OpenAI", StringComparison.OrdinalIgnoreCase))
        {
            return BuildRuleSummary(video, impactScore);
        }

        if (string.IsNullOrWhiteSpace(_options.OpenAiApiKey))
        {
            return BuildRuleSummary(video, impactScore);
        }

        try
        {
            using var client = _httpClientFactory.CreateClient("media-ai");
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.openai.com/v1/responses");
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _options.OpenAiApiKey.Trim());
            request.Content = JsonContent.Create(new
            {
                model = string.IsNullOrWhiteSpace(_options.OpenAiModel) ? "gpt-4.1-mini" : _options.OpenAiModel.Trim(),
                input = $"Create a concise wrestling highlight caption (max 20 words). MatchId: {video.MatchId}. Impact score: {impactScore}.",
                max_output_tokens = 80
            });

            using var response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return BuildRuleSummary(video, impactScore);
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            if (TryReadOutputText(document.RootElement, out var outputText))
            {
                return outputText;
            }
        }
        catch (Exception ex)
        {
            _logger.LogInformation(ex, "OpenAI highlight summary fallback used.");
        }

        return BuildRuleSummary(video, impactScore);
    }

    private async Task SweepRetentionAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        if (now - _lastRetentionSweepUtc < TimeSpan.FromMinutes(20))
        {
            return;
        }

        _lastRetentionSweepUtc = now;
        var retentionDays = Math.Clamp(_options.RetentionDays, 7, 730);
        var cutoffUtc = now.AddDays(-retentionDays);

        var expired = _videoById.Values
            .Where(x => x.CreatedUtc < cutoffUtc && x.State is VideoPipelineState.Ready or VideoPipelineState.Failed)
            .ToList();

        if (expired.Count == 0)
        {
            return;
        }

        foreach (var video in expired)
        {
            try
            {
                await _storage.DeletePrefixAsync(video.StoragePrefix, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to delete media prefix {Prefix}", video.StoragePrefix);
            }

            _videoById.TryRemove(video.VideoId, out _);
        }

        PersistState();
    }

    private void AddGeneratedClip(AthleteHighlightClip clip)
    {
        var clips = _clipsByAthleteId.GetOrAdd(clip.AthleteProfileId, _ => new ConcurrentDictionary<Guid, AthleteHighlightClip>());
        clips[clip.ClipId] = clip;

        const int maxClipsPerAthlete = 300;
        if (clips.Count <= maxClipsPerAthlete)
        {
            return;
        }

        var toRemove = clips.Values
            .OrderBy(x => x.ClipEndUtc)
            .Take(clips.Count - maxClipsPerAthlete)
            .Select(x => x.ClipId)
            .ToList();

        foreach (var clipId in toRemove)
        {
            clips.TryRemove(clipId, out _);
        }
    }

    private void LoadState()
    {
        try
        {
            if (!File.Exists(_stateFilePath))
            {
                return;
            }

            var json = File.ReadAllText(_stateFilePath);
            if (string.IsNullOrWhiteSpace(json))
            {
                return;
            }

            var state = JsonSerializer.Deserialize<PersistedMediaState>(json, _jsonOptions);
            if (state is null)
            {
                return;
            }

            foreach (var video in state.Videos)
            {
                _videoById[video.VideoId] = video;
            }

            foreach (var job in state.AiJobs)
            {
                _aiJobById[job.JobId] = job;
            }

            foreach (var clip in state.Clips)
            {
                AddGeneratedClip(clip);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load media pipeline state.");
        }
    }

    private void PersistState()
    {
        try
        {
            lock (_stateLock)
            {
                var snapshot = new PersistedMediaState
                {
                    Videos = _videoById.Values.OrderByDescending(x => x.CreatedUtc).Take(2500).ToList(),
                    AiJobs = _aiJobById.Values.OrderByDescending(x => x.QueuedUtc).Take(1500).ToList(),
                    Clips = _clipsByAthleteId.Values.SelectMany(x => x.Values).OrderByDescending(x => x.ClipEndUtc).Take(5000).ToList()
                };

                var directory = Path.GetDirectoryName(_stateFilePath);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var tempPath = _stateFilePath + ".tmp";
                File.WriteAllText(tempPath, JsonSerializer.Serialize(snapshot, _jsonOptions));
                File.Move(tempPath, _stateFilePath, overwrite: true);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist media pipeline state.");
        }
    }

    private int BuildImpactScore(Guid matchId, DateTime referenceUtc)
    {
        var hash = Math.Abs(HashCode.Combine(matchId, referenceUtc.Ticks));
        return 62 + (hash % 36);
    }

    private string ResolveAiProvider()
    {
        return string.IsNullOrWhiteSpace(_options.AiProvider) ? "RuleBased" : _options.AiProvider.Trim();
    }

    private static bool TryReadOutputText(JsonElement root, out string outputText)
    {
        outputText = string.Empty;

        if (root.TryGetProperty("output_text", out var directText)
            && directText.ValueKind == JsonValueKind.String)
        {
            var value = directText.GetString()?.Trim();
            if (!string.IsNullOrWhiteSpace(value))
            {
                outputText = value;
                return true;
            }
        }

        if (!root.TryGetProperty("output", out var outputNode) || outputNode.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var outputItem in outputNode.EnumerateArray())
        {
            if (!outputItem.TryGetProperty("content", out var contentNode) || contentNode.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var contentItem in contentNode.EnumerateArray())
            {
                if (contentItem.TryGetProperty("text", out var textNode) && textNode.ValueKind == JsonValueKind.String)
                {
                    var value = textNode.GetString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        outputText = value;
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private static string BuildRuleSummary(VideoAssetState video, int impactScore)
    {
        var intensityBand = impactScore switch
        {
            >= 90 => "explosive",
            >= 80 => "high-control",
            >= 70 => "momentum-building",
            _ => "technical"
        };

        return $"{intensityBand} sequence from match {video.MatchId.ToString("N")[..8]} with finish-ready pressure.";
    }

    private static string ResolveWorkingRoot(string contentRoot, string configured)
    {
        var root = string.IsNullOrWhiteSpace(configured) ? "App_Data/media-pipeline" : configured.Trim();
        return Path.IsPathRooted(root) ? root : Path.Combine(contentRoot, root);
    }

    private static string ResolveExtensionFromSource(string source)
    {
        var extension = Path.GetExtension(source).ToLowerInvariant();
        return string.IsNullOrWhiteSpace(extension) ? ".mp4" : extension;
    }

    private static string Truncate(string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private sealed class PersistedMediaState
    {
        public List<VideoAssetState> Videos { get; set; } = [];

        public List<AiJobState> AiJobs { get; set; } = [];

        public List<AthleteHighlightClip> Clips { get; set; } = [];
    }

    private sealed class VideoAssetState
    {
        public Guid VideoId { get; set; }
        public Guid AthleteProfileId { get; set; }
        public Guid MatchId { get; set; }
        public Guid? StreamId { get; set; }
        public string SourceUrl { get; set; } = string.Empty;
        public string PlaybackUrl { get; set; } = string.Empty;
        public VideoPipelineState State { get; set; }
        public DateTime CreatedUtc { get; set; }
        public DateTime LastUpdatedUtc { get; set; }
        public DateTime? ReadyUtc { get; set; }
        public string? FailureReason { get; set; }
        public string StoragePrefix { get; set; } = string.Empty;
        public string? SourceObjectKey { get; set; }
        public string? PlaybackObjectKey { get; set; }

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
        public Guid JobId { get; set; }
        public Guid AthleteProfileId { get; set; }
        public Guid? EventId { get; set; }
        public DateTime QueuedUtc { get; set; }
        public DateTime? StartedUtc { get; set; }
        public DateTime? CompletedUtc { get; set; }
        public string Status { get; set; } = "Queued";
        public int ClipsProduced { get; set; }
        public string? Details { get; set; }
        public int MaxMatches { get; set; }
        public DateTime LastUpdatedUtc { get; set; }
        public string Provider { get; set; } = "RuleBased";

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

    private sealed record MaterializedSource(string LocalPath, bool FromRemoteM3u8);
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
                await mediaPipelineService.ProcessTickAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Media pipeline tick failed.");
            }
        }
    }
}

