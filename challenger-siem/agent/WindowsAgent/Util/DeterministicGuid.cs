using System.Security.Cryptography;
using System.Text;

namespace Challenger.Siem.WindowsAgent.Util;

public static class DeterministicGuid
{
    public static Guid Create(params string[] parts)
    {
        var canonical = string.Join('\u001f', parts);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(canonical), hash);

        Span<byte> guidBytes = stackalloc byte[16];
        hash[..16].CopyTo(guidBytes);

        guidBytes[7] = (byte)((guidBytes[7] & 0x0F) | 0x50); // version 5-shaped deterministic GUID
        guidBytes[8] = (byte)((guidBytes[8] & 0x3F) | 0x80); // RFC 4122 variant

        return new Guid(guidBytes);
    }
}
