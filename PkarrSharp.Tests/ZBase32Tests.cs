using Xunit;

namespace PkarrSharp.Tests;

public class ZBase32Tests
{
    [Fact]
    public void Encode_EmptyData_ReturnsEmptyString()
    {
        // Arrange
        byte[] data = Array.Empty<byte>();
        
        // Act
        string result = ZBase32.Encode(data);
        
        // Assert
        Assert.Equal(string.Empty, result);
    }
    
    [Fact]
    public void Decode_EmptyString_ReturnsEmptyArray()
    {
        // Arrange
        string encoded = string.Empty;
        
        // Act
        byte[] result = ZBase32.Decode(encoded);
        
        // Assert
        Assert.Empty(result);
    }
    
    
    
   
    
    [Fact]
    public void Encode_ThenDecode_RoundTripsCorrectly()
    {
        // Arrange
        byte[] originalData = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        
        // Act
        string encoded = ZBase32.Encode(originalData);
        byte[] decoded = ZBase32.Decode(encoded);
        
        // Assert
        Assert.Equal(originalData, decoded);
    }
    
    [Fact]
    public void Decode_InvalidCharacter_ThrowsArgumentException()
    {
        // Arrange
        string invalidEncoding = "y!ycu"; // '!' is not in the zbase32 alphabet
        
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => ZBase32.Decode(invalidEncoding));
        Assert.Contains("Invalid zbase32 character", exception.Message);
    }
    
    [Fact]
    public void Encode_UsingReadOnlySpan_MatchesArrayVersion()
    {
        // Arrange
        byte[] data = { 0x12, 0x34, 0x56, 0x78 };
        
        // Act
        string spanResult = ZBase32.Encode(data.AsSpan());
        string arrayResult = ZBase32.Encode(data);
        
        // Assert
        Assert.Equal(arrayResult, spanResult);
    }
    
    [Fact]
    public void Decode_UsingReadOnlySpan_MatchesStringVersion()
    {
        // Arrange
        string encoded = "48hxj4t";
        
        // Act
        byte[] spanResult = ZBase32.Decode(encoded.AsSpan());
        byte[] stringResult = ZBase32.Decode(encoded);
        
        // Assert
        Assert.Equal(stringResult, spanResult);
    }
}
