using Xunit;

namespace PkarrSharp.Tests;

public class DnsPacketDecoderTests
{
    [Fact]
    public void DecodeTyped_ValidDnsPacket_DecodesCorrectly()
    {
        // Arrange
        // This is a simplified DNS packet with:
        // - Header (12 bytes)
        // - 1 Question for "example.com" type A (IN)
        // - 1 Answer with an A record pointing to 93.184.216.34
        byte[] packetData = {
            // Header
            0x12, 0x34,             // ID: 0x1234
            0x81, 0x80,             // Flags: 0x8180 (Standard response)
            0x00, 0x01,             // Questions: 1
            0x00, 0x01,             // Answer RRs: 1
            0x00, 0x00,             // Authority RRs: 0
            0x00, 0x00,             // Additional RRs: 0
            
            // Question
            0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', // "example"
            0x03, (byte)'c', (byte)'o', (byte)'m', // "com"
            0x00,                   // Null terminator
            0x00, 0x01,             // Type: A
            0x00, 0x01,             // Class: IN
            
            // Answer
            0xC0, 0x0C,             // Compressed name pointer to offset 12
            0x00, 0x01,             // Type: A
            0x00, 0x01,             // Class: IN
            0x00, 0x00, 0x0E, 0x10, // TTL: 3600 seconds
            0x00, 0x04,             // Data length: 4 bytes
            0x5D, 0xB8, 0xD8, 0x22  // IP: 93.184.216.34
        };

        // Act
        DnsPacket result = DnsPacketDecoder.DecodeTyped(packetData);

        // Assert
        Assert.NotNull(result);
        
        // Header checks
        Assert.Equal(0x1234, result.Header.Id);
        Assert.Equal(0x8180, result.Header.Flags);
        Assert.True(result.Header.IsResponse);
        Assert.Equal(1, result.Header.QuestionCount);
        Assert.Equal(1, result.Header.AnswerCount);
        
        // Question checks
        Assert.Single(result.Questions);
        Assert.Equal("example.com", result.Questions[0].Name);
        Assert.Equal(1, result.Questions[0].Type);  // A record
        Assert.Equal(1, result.Questions[0].Class); // IN class
        
        // Answer checks
        Assert.Single(result.Answers);
        Assert.Equal("example.com", result.Answers[0].Name);
        Assert.Equal(1, result.Answers[0].Type);  // A record
        Assert.Equal(1, result.Answers[0].Class); // IN class
        Assert.Equal(3600u, result.Answers[0].TTL);
        Assert.Equal(4, result.Answers[0].DataLength);
        
        // Check that we got the correct record type
        Assert.IsType<DnsARecord>(result.Answers[0]);
        var aRecord = (DnsARecord)result.Answers[0];
        Assert.NotNull(aRecord.Address);
        Assert.Equal("93.184.216.34", aRecord.Address.ToString());
    }
    
    [Fact]
    public void DecodeTyped_TxtRecord_DecodesCorrectly()
    {
        // Arrange
        // This is a simplified DNS packet with:
        // - Header (12 bytes)
        // - 1 Question for "example.com" type TXT
        // - 1 Answer with a TXT record containing "Hello, world!"
        byte[] packetData = {
            // Header
            0x12, 0x34,             // ID: 0x1234
            0x81, 0x80,             // Flags: 0x8180 (Standard response)
            0x00, 0x01,             // Questions: 1
            0x00, 0x01,             // Answer RRs: 1
            0x00, 0x00,             // Authority RRs: 0
            0x00, 0x00,             // Additional RRs: 0
            
            // Question
            0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', // "example"
            0x03, (byte)'c', (byte)'o', (byte)'m', // "com"
            0x00,                   // Null terminator
            0x00, 0x10,             // Type: TXT (16)
            0x00, 0x01,             // Class: IN
            
            // Answer
            0xC0, 0x0C,             // Compressed name pointer to offset 12
            0x00, 0x10,             // Type: TXT (16)
            0x00, 0x01,             // Class: IN
            0x00, 0x00, 0x0E, 0x10, // TTL: 3600 seconds
            0x00, 0x0E,             // Data length: 14 bytes
            0x0D,                   // Text length: 13 bytes
            (byte)'H', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)',', (byte)' ',
            (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!'
        };

        // Act
        DnsPacket result = DnsPacketDecoder.DecodeTyped(packetData);

        // Assert
        Assert.NotNull(result);
        
        // Question checks
        Assert.Single(result.Questions);
        Assert.Equal("example.com", result.Questions[0].Name);
        Assert.Equal(16, result.Questions[0].Type);  // TXT record
        
        // Answer checks
        Assert.Single(result.Answers);
        Assert.IsType<DnsTxtRecord>(result.Answers[0]);
        var txtRecord = (DnsTxtRecord)result.Answers[0];
        Assert.Equal("example.com", txtRecord.Name);
        Assert.Equal(16, txtRecord.Type);  // TXT record
        Assert.Single(txtRecord.TextValues);
        Assert.Equal("Hello, world!", txtRecord.TextValues[0]);
    }
    
   
    [Fact]
    public void DecodeTyped_InvalidPacket_HandlesTruncatedData()
    {
        // Arrange - Header with counts but not enough data
        byte[] truncatedData = {
            0x12, 0x34,             // ID: 0x1234
            0x81, 0x80,             // Flags: 0x8180
            0x00, 0x01,             // Questions: 1
            0x00, 0x01,             // Answer RRs: 1
            0x00, 0x00,             // Authority RRs: 0
            0x00, 0x00              // Additional RRs: 0
            // Missing all the actual data
        };
        
        // Act & Assert
        Assert.Throws<IndexOutOfRangeException>(() => DnsPacketDecoder.DecodeTyped(truncatedData));
    }
}
