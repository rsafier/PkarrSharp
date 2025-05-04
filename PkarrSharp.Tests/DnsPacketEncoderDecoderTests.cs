using Xunit;

namespace PkarrSharp.Tests;

public class DnsPacketEncoderDecoderTests
{
    [Fact]
    public void EncodeThenDecode_SingleTxtRecord_RoundTripsCorrectly()
    {
        // Arrange
        string domainName = "test.example.com";
        string textValue = "Hello, Pkarr!";
        uint ttl = 60;

        // Act
        // Encode a DNS packet with a TXT record
        byte[] encodedPacket = DnsPacketEncoder.CreateTxtRecordPacket(domainName, textValue, ttl);
        
        // Then decode it
        DnsPacket decodedPacket = DnsPacketDecoder.DecodeTyped(encodedPacket);

        // Assert
        // Header checks
        Assert.NotNull(decodedPacket);
        Assert.Equal(0x0000, decodedPacket.Header.Id); // ID should be 0 in generated packet
        Assert.True(decodedPacket.Header.IsResponse);
        Assert.Equal(0, decodedPacket.Header.QuestionCount);
        Assert.Equal(1, decodedPacket.Header.AnswerCount);
        
        // Answer checks
        Assert.Single(decodedPacket.Answers);
        Assert.IsType<DnsTxtRecord>(decodedPacket.Answers[0]);
        
        var txtRecord = (DnsTxtRecord)decodedPacket.Answers[0];
        Assert.Equal(domainName, txtRecord.Name);
        Assert.Equal(16, txtRecord.Type); // TXT record
        Assert.Equal(ttl, txtRecord.TTL);
        Assert.Single(txtRecord.TextValues);
        Assert.Equal(textValue, txtRecord.TextValues[0]);
    }
    
    [Fact]
    public void EncodeThenDecode_MultipleTextRecords_RoundTripsCorrectly()
    {
        // Arrange
        var records = new Dictionary<string, string>
        {
            { "record1.example.com", "First record value" },
            { "record2.example.com", "Second record value" },
            { "record3.example.com", "Third record value" }
        };
        uint ttl = 300;

        // Act
        // Encode a DNS packet with multiple TXT records
        byte[] encodedPacket = DnsPacketEncoder.CreateMultiTxtRecordPacket(records, ttl);
        
        // Then decode it
        DnsPacket decodedPacket = DnsPacketDecoder.DecodeTyped(encodedPacket);

        // Assert
        Assert.NotNull(decodedPacket);
        Assert.Equal(0, decodedPacket.Header.QuestionCount);
        Assert.Equal(records.Count, decodedPacket.Header.AnswerCount);
        Assert.Equal(records.Count, decodedPacket.Answers.Count);
        
        // Check each record
        foreach (var answer in decodedPacket.Answers)
        {
            Assert.IsType<DnsTxtRecord>(answer);
            var txtRecord = (DnsTxtRecord)answer;
            
            // Verify the record exists in our original dictionary
            Assert.True(records.ContainsKey(txtRecord.Name));
            
            // Verify the value matches
            Assert.Single(txtRecord.TextValues);
            Assert.Equal(records[txtRecord.Name], txtRecord.TextValues[0]);
            
            // Verify TTL
            Assert.Equal(ttl, txtRecord.TTL);
        }
    }
    
    [Fact]
    public void EncodeThenDecode_EmptyTextValue_RoundTripsCorrectly()
    {
        // Arrange
        string domainName = "empty.example.com";
        string textValue = ""; // Empty value
        uint ttl = 30;

        // Act
        byte[] encodedPacket = DnsPacketEncoder.CreateTxtRecordPacket(domainName, textValue, ttl);
        DnsPacket decodedPacket = DnsPacketDecoder.DecodeTyped(encodedPacket);

        // Assert
        Assert.NotNull(decodedPacket);
        Assert.Single(decodedPacket.Answers);
        Assert.IsType<DnsTxtRecord>(decodedPacket.Answers[0]);
        
        var txtRecord = (DnsTxtRecord)decodedPacket.Answers[0];
        Assert.Equal(domainName, txtRecord.Name);
        Assert.Single(txtRecord.TextValues);
        Assert.Equal(textValue, txtRecord.TextValues[0]);
    }
    
    [Fact]
    public void EncodeThenDecode_LongTextValue_RoundTripsCorrectly()
    {
        // Arrange
        string domainName = "long.example.com";
        string textValue = new string('A', 200); // 200 'A' characters
        uint ttl = 30;

        // Act
        byte[] encodedPacket = DnsPacketEncoder.CreateTxtRecordPacket(domainName, textValue, ttl);
        DnsPacket decodedPacket = DnsPacketDecoder.DecodeTyped(encodedPacket);

        // Assert
        Assert.NotNull(decodedPacket);
        Assert.Single(decodedPacket.Answers);
        Assert.IsType<DnsTxtRecord>(decodedPacket.Answers[0]);
        
        var txtRecord = (DnsTxtRecord)decodedPacket.Answers[0];
        Assert.Equal(domainName, txtRecord.Name);
        Assert.Single(txtRecord.TextValues);
        Assert.Equal(textValue, txtRecord.TextValues[0]);
    }
    
    [Fact]
    public void EncodeThenDecode_SpecialCharacters_RoundTripsCorrectly()
    {
        // Arrange
        string domainName = "special.example.com";
        string textValue = "Special chars: !@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`"; // Various special characters
        uint ttl = 30;

        // Act
        byte[] encodedPacket = DnsPacketEncoder.CreateTxtRecordPacket(domainName, textValue, ttl);
        DnsPacket decodedPacket = DnsPacketDecoder.DecodeTyped(encodedPacket);

        // Assert
        Assert.NotNull(decodedPacket);
        Assert.Single(decodedPacket.Answers);
        Assert.IsType<DnsTxtRecord>(decodedPacket.Answers[0]);
        
        var txtRecord = (DnsTxtRecord)decodedPacket.Answers[0];
        Assert.Equal(domainName, txtRecord.Name);
        Assert.Single(txtRecord.TextValues);
        Assert.Equal(textValue, txtRecord.TextValues[0]);
    }
    
    [Fact]
    public void EncodeThenDecode_Unicode_RoundTripsCorrectly()
    {
        // Arrange
        string domainName = "unicode.example.com";
        string textValue = "Unicode symbols: €£¥©®™½±°—–…µ"; // Unicode characters
        uint ttl = 30;
    
        // Act
        byte[] encodedPacket = DnsPacketEncoder.CreateTxtRecordPacket(domainName, textValue, ttl);
        DnsPacket decodedPacket = DnsPacketDecoder.DecodeTyped(encodedPacket);
    
        // Assert
        Assert.NotNull(decodedPacket);
        Assert.Single(decodedPacket.Answers);
        Assert.IsType<DnsTxtRecord>(decodedPacket.Answers[0]);
        
        var txtRecord = (DnsTxtRecord)decodedPacket.Answers[0];
        Assert.Equal(domainName, txtRecord.Name);
        Assert.Single(txtRecord.TextValues);
        Assert.Equal(textValue, txtRecord.TextValues[0]);
    }
    
    [Fact]
    public void CreateQueryPacket_ReturnsValidDNSQuery()
    {
        // Arrange
        string domainName = "query.example.com";
        ushort recordType = 16; // TXT
        
        // Act
        byte[] queryPacket = DnsPacketEncoder.CreateQueryPacket(domainName, recordType);
        
        // Parse the query using the decoder
        DnsPacket decodedPacket = DnsPacketDecoder.DecodeTyped(queryPacket);
        
        // Assert
        Assert.NotNull(decodedPacket);
        Assert.Equal(1, decodedPacket.Header.QuestionCount);
        Assert.Equal(0, decodedPacket.Header.AnswerCount);
        Assert.False(decodedPacket.Header.IsResponse);
        
        // Question should contain our domain name and query type
        Assert.Single(decodedPacket.Questions);
        Assert.Equal(domainName, decodedPacket.Questions[0].Name);
        Assert.Equal(recordType, decodedPacket.Questions[0].Type);
        Assert.Equal(1, decodedPacket.Questions[0].Class); // IN class
    }
    
    [Fact]
    public void EncodeThenDecode_MultilevelDomainName_RoundTripsCorrectly()
    {
        // Arrange
        string domainName = "sub.multi.level.example.com";
        string textValue = "Value for multi-level domain";
        uint ttl = 30;

        // Act
        byte[] encodedPacket = DnsPacketEncoder.CreateTxtRecordPacket(domainName, textValue, ttl);
        DnsPacket decodedPacket = DnsPacketDecoder.DecodeTyped(encodedPacket);

        // Assert
        Assert.NotNull(decodedPacket);
        Assert.Single(decodedPacket.Answers);
        Assert.IsType<DnsTxtRecord>(decodedPacket.Answers[0]);
        
        var txtRecord = (DnsTxtRecord)decodedPacket.Answers[0];
        Assert.Equal(domainName, txtRecord.Name);
        Assert.Single(txtRecord.TextValues);
        Assert.Equal(textValue, txtRecord.TextValues[0]);
    }
}
