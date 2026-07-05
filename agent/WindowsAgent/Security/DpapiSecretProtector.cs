using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Challenger.Siem.WindowsAgent.Security;

public interface ISecretProtector
{
    string Protect(string plaintext);

    string Unprotect(string protectedValue);
}

public sealed class DpapiSecretProtector : ISecretProtector
{
    private const int CryptProtectLocalMachine = 0x4;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("ChallengerSIEM.WindowsAgent.v1");

    public string Protect(string plaintext)
    {
        if (string.IsNullOrEmpty(plaintext))
        {
            return string.Empty;
        }

        var protectedBytes = ProtectBytes(Encoding.UTF8.GetBytes(plaintext));
        return "dpapi:" + Convert.ToBase64String(protectedBytes);
    }

    public string Unprotect(string protectedValue)
    {
        if (string.IsNullOrWhiteSpace(protectedValue))
        {
            return string.Empty;
        }

        var value = protectedValue.StartsWith("dpapi:", StringComparison.OrdinalIgnoreCase)
            ? protectedValue[6..]
            : protectedValue;
        var plaintextBytes = UnprotectBytes(Convert.FromBase64String(value));
        return Encoding.UTF8.GetString(plaintextBytes);
    }

    private static byte[] ProtectBytes(byte[] plaintext)
    {
        var input = DataBlob.FromBytes(plaintext);
        var entropy = DataBlob.FromBytes(Entropy);
        try
        {
            if (!CryptProtectData(ref input, "Challenger SIEM agent token", ref entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectLocalMachine, out var output))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "DPAPI CryptProtectData failed.");
            }

            return output.ToArrayAndFree();
        }
        finally
        {
            input.Free();
            entropy.Free();
        }
    }

    private static byte[] UnprotectBytes(byte[] protectedValue)
    {
        var input = DataBlob.FromBytes(protectedValue);
        var entropy = DataBlob.FromBytes(Entropy);
        try
        {
            if (!CryptUnprotectData(ref input, out _, ref entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectLocalMachine, out var output))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "DPAPI CryptUnprotectData failed.");
            }

            return output.ToArrayAndFree();
        }
        finally
        {
            input.Free();
            entropy.Free();
        }
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DataBlob dataIn,
        string? dataDescription,
        ref DataBlob optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        int flags,
        out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(
        ref DataBlob dataIn,
        out IntPtr dataDescription,
        ref DataBlob optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        int flags,
        out DataBlob dataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Count;
        public IntPtr Data;

        public static DataBlob FromBytes(byte[] bytes)
        {
            var blob = new DataBlob
            {
                Count = bytes.Length,
                Data = Marshal.AllocHGlobal(bytes.Length)
            };
            Marshal.Copy(bytes, 0, blob.Data, bytes.Length);
            return blob;
        }

        public readonly byte[] ToArrayAndFree()
        {
            try
            {
                var bytes = new byte[Count];
                Marshal.Copy(Data, bytes, 0, Count);
                return bytes;
            }
            finally
            {
                if (Data != IntPtr.Zero)
                {
                    _ = LocalFree(Data);
                }
            }
        }

        public void Free()
        {
            if (Data != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Data);
                Data = IntPtr.Zero;
                Count = 0;
            }
        }
    }
}
