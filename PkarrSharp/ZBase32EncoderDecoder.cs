using System.Buffers;
using System.Runtime.CompilerServices;
 
namespace PkarrSharp;

public static class ZBase32
{
    private const string Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";

    // Pre-calculated lookup table for decoding
    private static readonly int[] LookupTable = CreateLookupTable();

    private static int[] CreateLookupTable()
    {
        var lookup = new int[128];
        Array.Fill(lookup, -1);

        for (var i = 0; i < Alphabet.Length; i++)
            lookup[Alphabet[i]] = i;

        return lookup;
    }

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return string.Empty;

        // Calculate output length: each 5 bits becomes one character
        // 8 bits per byte * data.Length bits total / 5 bits per output char, rounded up
        var outputLength = (data.Length * 8 + 4) / 5;

        // Rent a char array for the result to avoid allocating a new one
        var rentedArray = ArrayPool<char>.Shared.Rent(outputLength);
        var result = rentedArray.AsSpan(0, outputLength);

        int bitIndex = 0;
        ulong buffer = 0;
        int resultIndex = 0;

        foreach (var b in data)
        {
            // Add 8 more bits to the buffer
            buffer = (buffer << 8) | b;
            bitIndex += 8;

            // Extract as many 5-bit chunks as possible
            while (bitIndex >= 5)
            {
                bitIndex -= 5;
                int index = (int)((buffer >> bitIndex) & 0x1F);
                result[resultIndex++] = Alphabet[index];
            }
        }

        // Handle remaining bits if any
        if (bitIndex > 0)
        {
            int index = (int)((buffer << (5 - bitIndex)) & 0x1F);
            result[resultIndex++] = Alphabet[index];
        }

        // Create string from the filled portion of the array
        var encodedString = new string(result.Slice(0, resultIndex));

        // Return the array to the pool
        ArrayPool<char>.Shared.Return(rentedArray);

        return encodedString;
    }

    // public static string Encode(ReadOnlySpan<byte> data)
    // {
    //     if (data.IsEmpty)
    //         return string.Empty;
    //
    //     // Calculate output length: each 5 bits becomes one character
    //     // 8 bits per byte * data.Length bits total / 5 bits per output char, rounded up
    //     var outputLength = (data.Length * 8 + 4) / 5;
    //
    //     // Rent a char array for the result to avoid allocating a new one
    //     var rentedArray = ArrayPool<char>.Shared.Rent(outputLength);
    //     var result = rentedArray.AsSpan(0, outputLength);
    //
    //     var bitIndex = 0;
    //     var buffer = 0;
    //     var resultIndex = 0;
    //
    //     foreach (var b in data)
    //     {
    //         buffer = (buffer << 8) | b;
    //         bitIndex += 8;
    //
    //         while (bitIndex >= 5)
    //         {
    //             bitIndex -= 5;
    //             var index = (buffer >> bitIndex) & 31;
    //             result[resultIndex++] = Alphabet[index];
    //         }
    //     }
    //
    //     // Handle remaining bits if any
    //     if (bitIndex > 0)
    //     {
    //         var index = (buffer << (5 - bitIndex)) & 31;
    //         result[resultIndex++] = Alphabet[index];
    //     }
    //
    //     // Create string from the filled portion of the array
    //     var encodedString = new string(result.Slice(0, resultIndex));
    //
    //     // Return the array to the pool
    //     ArrayPool<char>.Shared.Return(rentedArray);
    //
    //     return encodedString;
    // }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string Encode(byte[] data)
    {
        return Encode(data.AsSpan());
    }

    public static byte[] Decode(ReadOnlySpan<char> encoded)
    {
        if (encoded.IsEmpty)
            return Array.Empty<byte>();

        // Calculate max output size (approximately)
        var maxOutputSize = encoded.Length * 5 / 8 + 1;

        // Rent a byte array for the result to avoid allocating a new one
        var rentedArray = ArrayPool<byte>.Shared.Rent(maxOutputSize);
        var result = rentedArray.AsSpan(0, maxOutputSize);

        var bitIndex = 0;
        var buffer = 0;
        var resultIndex = 0;

        foreach (var c in encoded)
        {
            // Validate the character and get its value
            if (c >= 128 || LookupTable[c] == -1)
                throw new ArgumentException($"Invalid zbase32 character: {c}");

            var value = LookupTable[c];
            buffer = (buffer << 5) | value;
            bitIndex += 5;

            if (bitIndex >= 8)
            {
                bitIndex -= 8;
                result[resultIndex++] = (byte)(buffer >> bitIndex);
            }
        }

        // Copy only the used portion of the result
        var finalResult = result.Slice(0, resultIndex).ToArray();

        // Return the array to the pool
        ArrayPool<byte>.Shared.Return(rentedArray);

        return finalResult;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] Decode(string encoded)
    {
        return Decode(encoded.AsSpan());
    }
}

