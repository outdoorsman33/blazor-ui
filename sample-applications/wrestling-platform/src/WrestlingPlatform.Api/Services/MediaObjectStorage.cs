using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Options;

namespace WrestlingPlatform.Api.Services;

public interface IMediaObjectStorage
{
    string Mode { get; }

    bool IsExternalStorageEnabled { get; }

    Task UploadFileAsync(string localFilePath, string objectKey, CancellationToken cancellationToken);

    Task DeletePrefixAsync(string prefix, CancellationToken cancellationToken);

    string BuildPublicUrl(string objectKey);
}

public sealed class MediaObjectStorage : IMediaObjectStorage
{
    private readonly ILogger<MediaObjectStorage> _logger;
    private readonly MediaPipelineOptions _options;
    private readonly string _localRoot;
    private readonly IAmazonS3? _s3Client;
    private readonly string? _bucket;
    private bool _isS3Mode;

    public MediaObjectStorage(
        IWebHostEnvironment environment,
        IOptions<MediaPipelineOptions> options,
        ILogger<MediaObjectStorage> logger)
    {
        _logger = logger;
        _options = options.Value;
        _localRoot = ResolveLocalRoot(environment.ContentRootPath, _options.WorkingDirectory);
        Directory.CreateDirectory(_localRoot);

        var storageMode = (_options.StorageMode ?? "Local").Trim();
        _isS3Mode = storageMode.Equals("S3", StringComparison.OrdinalIgnoreCase)
                    || storageMode.Equals("R2", StringComparison.OrdinalIgnoreCase);

        if (!_isS3Mode)
        {
            Mode = "Local";
            return;
        }

        if (string.IsNullOrWhiteSpace(_options.S3Bucket))
        {
            Mode = "Local";
            _isS3Mode = false;
            _logger.LogWarning("Media storage mode is S3/R2 but S3 bucket is not configured. Falling back to local storage.");
            return;
        }

        var config = new AmazonS3Config
        {
            ForcePathStyle = _options.S3ForcePathStyle
        };

        if (!string.IsNullOrWhiteSpace(_options.S3ServiceUrl))
        {
            config.ServiceURL = _options.S3ServiceUrl.Trim();
            config.AuthenticationRegion = string.IsNullOrWhiteSpace(_options.S3Region)
                ? "auto"
                : _options.S3Region.Trim();
        }
        else if (!string.IsNullOrWhiteSpace(_options.S3Region))
        {
            config.RegionEndpoint = RegionEndpoint.GetBySystemName(_options.S3Region.Trim());
        }

        var hasStaticCredentials = !string.IsNullOrWhiteSpace(_options.S3AccessKeyId)
                                   && !string.IsNullOrWhiteSpace(_options.S3SecretAccessKey);
        if (hasStaticCredentials)
        {
            var credentials = new BasicAWSCredentials(_options.S3AccessKeyId!.Trim(), _options.S3SecretAccessKey!.Trim());
            _s3Client = new AmazonS3Client(credentials, config);
        }
        else
        {
            _s3Client = new AmazonS3Client(config);
        }

        _bucket = _options.S3Bucket.Trim();
        Mode = "S3";
    }

    public string Mode { get; private set; } = "Local";

    public bool IsExternalStorageEnabled => _isS3Mode && _s3Client is not null && !string.IsNullOrWhiteSpace(_bucket);

    public async Task UploadFileAsync(string localFilePath, string objectKey, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(localFilePath))
        {
            throw new ArgumentException("Local file path is required.", nameof(localFilePath));
        }

        if (string.IsNullOrWhiteSpace(objectKey))
        {
            throw new ArgumentException("Object key is required.", nameof(objectKey));
        }

        if (!File.Exists(localFilePath))
        {
            throw new FileNotFoundException("Local file does not exist.", localFilePath);
        }

        if (IsExternalStorageEnabled)
        {
            var request = new PutObjectRequest
            {
                BucketName = _bucket,
                Key = NormalizeObjectKey(objectKey),
                FilePath = localFilePath,
                ContentType = ResolveContentType(localFilePath)
            };

            await _s3Client!.PutObjectAsync(request, cancellationToken);
            return;
        }

        var destinationPath = GetLocalObjectPath(objectKey);
        var destinationDirectory = Path.GetDirectoryName(destinationPath);
        if (!string.IsNullOrWhiteSpace(destinationDirectory))
        {
            Directory.CreateDirectory(destinationDirectory);
        }

        File.Copy(localFilePath, destinationPath, overwrite: true);
    }

    public async Task DeletePrefixAsync(string prefix, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(prefix))
        {
            return;
        }

        if (IsExternalStorageEnabled)
        {
            var continuationToken = default(string);
            var normalizedPrefix = NormalizeObjectKey(prefix).TrimEnd('/') + "/";
            do
            {
                var list = await _s3Client!.ListObjectsV2Async(new ListObjectsV2Request
                {
                    BucketName = _bucket,
                    Prefix = normalizedPrefix,
                    ContinuationToken = continuationToken
                }, cancellationToken);

                continuationToken = list.IsTruncated ? list.NextContinuationToken : null;
                if (list.S3Objects.Count == 0)
                {
                    continue;
                }

                var delete = new DeleteObjectsRequest
                {
                    BucketName = _bucket,
                    Objects = list.S3Objects.Select(x => new KeyVersion { Key = x.Key }).ToList()
                };

                await _s3Client.DeleteObjectsAsync(delete, cancellationToken);
            }
            while (!string.IsNullOrWhiteSpace(continuationToken));

            return;
        }

        var directoryPath = GetLocalObjectPath(prefix);
        if (Directory.Exists(directoryPath))
        {
            Directory.Delete(directoryPath, recursive: true);
        }
    }

    public string BuildPublicUrl(string objectKey)
    {
        var normalizedKey = NormalizeObjectKey(objectKey);
        var escapedKey = EscapePathSegments(normalizedKey);

        if (!string.IsNullOrWhiteSpace(_options.PublicBaseUrl))
        {
            var baseUrl = _options.PublicBaseUrl.TrimEnd('/');
            return $"{baseUrl}/{escapedKey}";
        }

        if (IsExternalStorageEnabled && !string.IsNullOrWhiteSpace(_options.S3ServiceUrl))
        {
            var serviceUrl = _options.S3ServiceUrl!.TrimEnd('/');
            return _options.S3ForcePathStyle
                ? $"{serviceUrl}/{_bucket}/{escapedKey}"
                : $"{serviceUrl}/{escapedKey}";
        }

        var localPath = GetLocalObjectPath(normalizedKey).Replace('\\', '/');
        return $"file:///{localPath.TrimStart('/')}";
    }

    private string GetLocalObjectPath(string objectKey)
    {
        var normalized = NormalizeObjectKey(objectKey);
        var parts = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return parts.Aggregate(_localRoot, Path.Combine);
    }

    private static string ResolveLocalRoot(string contentRoot, string workingDirectory)
    {
        var root = string.IsNullOrWhiteSpace(workingDirectory)
            ? "App_Data/media-pipeline"
            : workingDirectory.Trim();

        return Path.IsPathRooted(root) ? root : Path.Combine(contentRoot, root, "objects");
    }

    private static string NormalizeObjectKey(string objectKey)
    {
        var normalized = objectKey.Replace('\\', '/').Trim('/');
        return string.Join('/',
            normalized
                .Split('/', StringSplitOptions.RemoveEmptyEntries)
                .Where(segment => segment != "." && segment != ".."));
    }

    private static string EscapePathSegments(string key)
    {
        return string.Join('/',
            key.Split('/', StringSplitOptions.RemoveEmptyEntries)
                .Select(Uri.EscapeDataString));
    }

    private static string ResolveContentType(string filePath)
    {
        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        return extension switch
        {
            ".m3u8" => "application/vnd.apple.mpegurl",
            ".ts" => "video/mp2t",
            ".mp4" => "video/mp4",
            ".webm" => "video/webm",
            ".mov" => "video/quicktime",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            _ => "application/octet-stream"
        };
    }
}
