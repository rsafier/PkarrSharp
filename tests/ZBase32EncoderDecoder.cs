using System;
using System.Text;

public static class ZBase32
{
    private const string Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";
    
    public static string Encode(byte[] data)
    {
        if (data == null || data.Length == 0)
            return string.Empty;
            
        StringBuilder result = new StringBuilder();
        int bitIndex = 0;
        int buffer = 0;
        
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bitIndex += 8;
            
            while (bitIndex >= 5)
            {
                bitIndex -= 5;
                int index = (buffer >> bitIndex) & 31;
                result.Append(Alphabet[index]);
            }
        }
        
        // Handle remaining bits if any
        if (bitIndex > 0)
        {
            int index = (buffer << (5 - bitIndex)) & 31;
            result.Append(Alphabet[index]);
        }
        
        return result.ToString();
    }
    
    public static byte[] Decode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            return Array.Empty<byte>();
            
        // Create a lookup table for faster character to value conversion
        int[] lookup = new int[128];
        for (int i = 0; i < lookup.Length; i++)
            lookup[i] = -1;
            
        for (int i = 0; i < Alphabet.Length; i++)
            lookup[Alphabet[i]] = i;
            
        // Calculate output length (approximately)
        byte[] result = new byte[(encoded.Length * 5 / 8) + 1];
        int bitIndex = 0;
        int buffer = 0;
        int resultIndex = 0;
        
        foreach (char c in encoded)
        {
            int value = c < lookup.Length ? lookup[c] : -1;
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