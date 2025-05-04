using System.Text;

namespace PkarrSharp;

public static class ZBase32
{
    private const string Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";

    public static string Encode(byte[] data)
    {
        if (data == null || data.Length == 0)
            return string.Empty;

        var result = new StringBuilder();
        var bitIndex = 0;
        var buffer = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitIndex += 8;

            while (bitIndex >= 5)
            {
                bitIndex -= 5;
                var index = (buffer >> bitIndex) & 31;
                result.Append(Alphabet[index]);
            }
        }

        // Handle remaining bits if any
        if (bitIndex > 0)
        {
            var index = (buffer << (5 - bitIndex)) & 31;
            result.Append(Alphabet[index]);
        }

        return result.ToString();
    }

    public static byte[] Decode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            return Array.Empty<byte>();

        // Create a lookup table for faster character to value conversion
        var lookup = new int[128];
        for (var i = 0; i < lookup.Length; i++)
            lookup[i] = -1;

        for (var i = 0; i < Alphabet.Length; i++)
            lookup[Alphabet[i]] = i;

        // Calculate output length (approximately)
        var result = new byte[encoded.Length * 5 / 8 + 1];
        var bitIndex = 0;
        var buffer = 0;
        var resultIndex = 0;

        foreach (var c in encoded)
        {
            var value = c < lookup.Length ? lookup[c] : -1;
            if (value == -1)
                throw new ArgumentException($"Invalid zbase32 character: {c}");

            buffer = (buffer << 5) | value;
            bitIndex += 5;

            if (bitIndex >= 8)
            {
                bitIndex -= 8;
                result[resultIndex++] = (byte)(buffer >> bitIndex);
            }
        }

        // Resize the array to the actual length
        Array.Resize(ref result, resultIndex);
        return result;
    }
}