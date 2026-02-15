using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WrestlingPlatform.Application.Contracts;

namespace WrestlingPlatform.Api.Services;

public interface IMfaService
{
    MfaEnrollmentResponse Enroll(Guid userId, string email);

    MfaVerifyResponse Verify(VerifyMfaCodeRequest request);

    bool IsEnabled(Guid userId);
}

public sealed class MfaService : IMfaService
{
    private readonly ConcurrentDictionary<Guid, MfaUserState> _stateByUserId = new();
    private readonly object _persistenceLock = new();
    private readonly ILogger<MfaService> _logger;
    private readonly string _storePath;
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public MfaService(IWebHostEnvironment environment, IConfiguration configuration, ILogger<MfaService> logger)
    {
        _logger = logger;
        _storePath = ResolveStorePath(environment.ContentRootPath, configuration["Security:Mfa:StoreFilePath"]);
        LoadStore();
    }

    public MfaEnrollmentResponse Enroll(Guid userId, string email)
    {
        var now = DateTime.UtcNow;
        var state = _stateByUserId.GetOrAdd(userId, _ => new MfaUserState
        {
            SharedSecret = GenerateBase32Secret(20),
            FailedAttempts = 0,
            LastVerifiedTimeStep = null,
            LockoutUntilUtc = null,
            UpdatedUtc = now
        });

        state.UpdatedUtc = now;

        var safeEmail = string.IsNullOrWhiteSpace(email) ? userId.ToString("N") : email.Trim();
        var encodedIssuer = Uri.EscapeDataString("PinPoint Arena");
        var encodedAccount = Uri.EscapeDataString(safeEmail);
        var provisioningUri = $"otpauth://totp/{encodedIssuer}:{encodedAccount}?secret={state.SharedSecret}&issuer={encodedIssuer}&algorithm=SHA1&digits=6&period=30";

        PersistStore();
        return new MfaEnrollmentResponse(userId, state.SharedSecret, provisioningUri, Enabled: true);
    }

    public MfaVerifyResponse Verify(VerifyMfaCodeRequest request)
    {
        if (!_stateByUserId.TryGetValue(request.UserId, out var state))
        {
            return new MfaVerifyResponse(request.UserId, false, DateTime.MinValue);
        }

        var now = DateTime.UtcNow;
        if (state.LockoutUntilUtc is not null && state.LockoutUntilUtc > now)
        {
            return new MfaVerifyResponse(request.UserId, false, DateTime.MinValue);
        }

        var normalizedCode = NormalizeCode(request.Code);
        if (normalizedCode is null)
        {
            RegisterFailedAttempt(state, now);
            return new MfaVerifyResponse(request.UserId, false, DateTime.MinValue);
        }

        var currentTimeStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var acceptedStep = VerifyWithTimeSkew(state.SharedSecret, normalizedCode, currentTimeStep);
        if (acceptedStep is null)
        {
            RegisterFailedAttempt(state, now);
            return new MfaVerifyResponse(request.UserId, false, DateTime.MinValue);
        }

        // Reject replays within the same or previous verified time step.
        if (state.LastVerifiedTimeStep is not null && acceptedStep <= state.LastVerifiedTimeStep.Value)
        {
            RegisterFailedAttempt(state, now);
            return new MfaVerifyResponse(request.UserId, false, DateTime.MinValue);
        }

        state.FailedAttempts = 0;
        state.LockoutUntilUtc = null;
        state.LastVerifiedTimeStep = acceptedStep;
        state.UpdatedUtc = now;
        PersistStore();

        return new MfaVerifyResponse(request.UserId, true, now);
    }

    public bool IsEnabled(Guid userId)
    {
        return _stateByUserId.ContainsKey(userId);
    }

    private void RegisterFailedAttempt(MfaUserState state, DateTime now)
    {
        state.FailedAttempts++;
        state.UpdatedUtc = now;

        if (state.FailedAttempts >= 5)
        {
            state.LockoutUntilUtc = now.AddMinutes(2);
        }

        PersistStore();
    }

    private static long? VerifyWithTimeSkew(string base32Secret, string code, long currentStep)
    {
        var candidateSteps = new[] { currentStep - 1, currentStep, currentStep + 1 };
        foreach (var step in candidateSteps)
        {
            if (VerifyAgainstTimeStep(base32Secret, code, step))
            {
                return step;
            }
        }

        return null;
    }

    private static string GenerateBase32Secret(int byteLength)
    {
        var bytes = RandomNumberGenerator.GetBytes(byteLength);
        return Base32Encode(bytes);
    }

    private static string? NormalizeCode(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return null;
        }

        var digits = new string(input.Where(char.IsDigit).ToArray());
        return digits.Length == 6 ? digits : null;
    }

    private static bool VerifyAgainstTimeStep(string base32Secret, string code, long timestep)
    {
        var secret = Base32Decode(base32Secret);
        var counter = BitConverter.GetBytes(timestep);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(counter);
        }

        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(counter);
        var offset = hash[^1] & 0x0F;
        var binary =
            ((hash[offset] & 0x7F) << 24)
            | (hash[offset + 1] << 16)
            | (hash[offset + 2] << 8)
            | hash[offset + 3];

        var otp = (binary % 1_000_000).ToString("D6");
        return FixedTimeEquals(otp, code);
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(left),
            Encoding.UTF8.GetBytes(right));
    }

    private void LoadStore()
    {
        try
        {
            if (!File.Exists(_storePath))
            {
                return;
            }

            var json = File.ReadAllText(_storePath);
            if (string.IsNullOrWhiteSpace(json))
            {
                return;
            }

            var store = JsonSerializer.Deserialize<MfaStore>(json, _jsonOptions);
            if (store is null)
            {
                return;
            }

            foreach (var row in store.Users)
            {
                _stateByUserId[row.UserId] = new MfaUserState
                {
                    SharedSecret = row.SharedSecret,
                    FailedAttempts = row.FailedAttempts,
                    LastVerifiedTimeStep = row.LastVerifiedTimeStep,
                    LockoutUntilUtc = row.LockoutUntilUtc,
                    UpdatedUtc = row.UpdatedUtc
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load MFA store.");
        }
    }

    private void PersistStore()
    {
        try
        {
            lock (_persistenceLock)
            {
                var store = new MfaStore
                {
                    Users = _stateByUserId
                        .Select(x => new MfaStoreUser
                        {
                            UserId = x.Key,
                            SharedSecret = x.Value.SharedSecret,
                            FailedAttempts = x.Value.FailedAttempts,
                            LastVerifiedTimeStep = x.Value.LastVerifiedTimeStep,
                            LockoutUntilUtc = x.Value.LockoutUntilUtc,
                            UpdatedUtc = x.Value.UpdatedUtc
                        })
                        .OrderBy(x => x.UserId)
                        .ToList()
                };

                var directory = Path.GetDirectoryName(_storePath);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var tempPath = _storePath + ".tmp";
                File.WriteAllText(tempPath, JsonSerializer.Serialize(store, _jsonOptions));
                File.Move(tempPath, _storePath, overwrite: true);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist MFA store.");
        }
    }

    private static string ResolveStorePath(string contentRoot, string? configuredPath)
    {
        var path = string.IsNullOrWhiteSpace(configuredPath)
            ? "App_Data/security/mfa-store.json"
            : configuredPath.Trim();

        return Path.IsPathRooted(path) ? path : Path.Combine(contentRoot, path);
    }

    private static string Base32Encode(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new StringBuilder((int)Math.Ceiling(data.Length * 8 / 5d));
        var buffer = (int)data[0];
        var next = 1;
        var bitsLeft = 8;

        while (bitsLeft > 0 || next < data.Length)
        {
            if (bitsLeft < 5)
            {
                if (next < data.Length)
                {
                    buffer <<= 8;
                    buffer |= data[next++] & 0xFF;
                    bitsLeft += 8;
                }
                else
                {
                    var pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }

            var index = (buffer >> (bitsLeft - 5)) & 0x1F;
            bitsLeft -= 5;
            output.Append(alphabet[index]);
        }

        return output.ToString();
    }

    private static byte[] Base32Decode(string value)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var cleaned = value.Trim().TrimEnd('=').ToUpperInvariant();
        if (cleaned.Length == 0)
        {
            return [];
        }

        var bytes = new List<byte>();
        var buffer = 0;
        var bitsLeft = 0;

        foreach (var c in cleaned)
        {
            var index = alphabet.IndexOf(c);
            if (index < 0)
            {
                continue;
            }

            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft < 8)
            {
                continue;
            }

            bytes.Add((byte)((buffer >> (bitsLeft - 8)) & 0xFF));
            bitsLeft -= 8;
        }

        return bytes.ToArray();
    }

    private sealed class MfaUserState
    {
        public string SharedSecret { get; set; } = string.Empty;
        public int FailedAttempts { get; set; }
        public long? LastVerifiedTimeStep { get; set; }
        public DateTime? LockoutUntilUtc { get; set; }
        public DateTime UpdatedUtc { get; set; }
    }

    private sealed class MfaStore
    {
        public List<MfaStoreUser> Users { get; set; } = [];
    }

    private sealed class MfaStoreUser
    {
        public Guid UserId { get; set; }
        public string SharedSecret { get; set; } = string.Empty;
        public int FailedAttempts { get; set; }
        public long? LastVerifiedTimeStep { get; set; }
        public DateTime? LockoutUntilUtc { get; set; }
        public DateTime UpdatedUtc { get; set; }
    }
}
