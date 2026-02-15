using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
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
    private readonly ConcurrentDictionary<Guid, string> _secretByUserId = new();
    private readonly ConcurrentDictionary<Guid, DateTime> _lastVerifiedUtcByUserId = new();

    public MfaEnrollmentResponse Enroll(Guid userId, string email)
    {
        var secret = _secretByUserId.GetOrAdd(userId, _ => GenerateBase32Secret(20));
        var safeEmail = string.IsNullOrWhiteSpace(email) ? userId.ToString("N") : email.Trim();
        var encodedIssuer = Uri.EscapeDataString("PinPoint Arena");
        var encodedAccount = Uri.EscapeDataString(safeEmail);
        var provisioningUri = $"otpauth://totp/{encodedIssuer}:{encodedAccount}?secret={secret}&issuer={encodedIssuer}&algorithm=SHA1&digits=6&period=30";

        return new MfaEnrollmentResponse(userId, secret, provisioningUri, Enabled: true);
    }

    public MfaVerifyResponse Verify(VerifyMfaCodeRequest request)
    {
        if (!_secretByUserId.TryGetValue(request.UserId, out var secret))
        {
            return new MfaVerifyResponse(request.UserId, false, DateTime.MinValue);
        }

        var normalizedCode = NormalizeCode(request.Code);
        if (normalizedCode is null)
        {
            return new MfaVerifyResponse(request.UserId, false, DateTime.MinValue);
        }

        var now = DateTime.UtcNow;
        var unixWindow = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var verified = VerifyAgainstTimeStep(secret, normalizedCode, unixWindow - 1)
                       || VerifyAgainstTimeStep(secret, normalizedCode, unixWindow)
                       || VerifyAgainstTimeStep(secret, normalizedCode, unixWindow + 1);

        if (verified)
        {
            _lastVerifiedUtcByUserId[request.UserId] = now;
            return new MfaVerifyResponse(request.UserId, true, now);
        }

        return new MfaVerifyResponse(request.UserId, false, DateTime.MinValue);
    }

    public bool IsEnabled(Guid userId)
    {
        return _secretByUserId.ContainsKey(userId);
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
}
