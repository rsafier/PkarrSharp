using System.Buffers.Binary;
using System.Text;

namespace PkarrSharp;

/// <summary>
/// Provides methods for encoding DNS packets to be used with Pkarr
/// </summary>
public static class DnsPacketEncoder
{
    // DNS packet constants
    private const ushort QueryTypeA = 1;     // A Record
    private const ushort QueryTypeTXT = 16;  // TXT Record
    private const ushort QueryClassIN = 1;   // Internet class
    
    /// <summary>
    /// Encodes a DnsPacket object into a byte array.
    /// </summary>
    /// <param name="packet">The DnsPacket to encode</param>
    /// <returns>A byte array containing the encoded DNS packet</returns>
    public static byte[] Encode(DnsPacket packet)
    {
        using var memoryStream = new MemoryStream();
        using var writer = new BinaryWriter(memoryStream);
        
        // Write DNS header
        writer.Write(BinaryPrimitives.ReverseEndianness(packet.Header.Id));
        writer.Write(BinaryPrimitives.ReverseEndianness(packet.Header.Flags));
        writer.Write(BinaryPrimitives.ReverseEndianness(packet.Header.QuestionCount));
        writer.Write(BinaryPrimitives.ReverseEndianness(packet.Header.AnswerCount));
        writer.Write(BinaryPrimitives.ReverseEndianness(packet.Header.AuthorityCount));
        writer.Write(BinaryPrimitives.ReverseEndianness(packet.Header.AdditionalCount));
        
        // Write Questions section
        foreach (var question in packet.Questions)
        {
            WriteDomainName(writer, question.Name);
            writer.Write(BinaryPrimitives.ReverseEndianness(question.Type));
            writer.Write(BinaryPrimitives.ReverseEndianness(question.Class));
        }
        
        // Write Answer records
        WriteResourceRecords(writer, packet.Answers);
        
        // Write Authority records
        WriteResourceRecords(writer, packet.Authority);
        
        // Write Additional records
        WriteResourceRecords(writer, packet.Additional);
        
        return memoryStream.ToArray();
    }
    
    private static void WriteResourceRecords(BinaryWriter writer, List<DnsResourceRecord> records)
    {
        foreach (var record in records)
        {
            // Write the name
            WriteDomainName(writer, record.Name);
            
            // Write record type
            writer.Write(BinaryPrimitives.ReverseEndianness(record.Type));
            
            // Write record class
            writer.Write(BinaryPrimitives.ReverseEndianness(record.Class));
            
            // Write TTL
            writer.Write(BinaryPrimitives.ReverseEndianness(record.TTL));
            
            // Special handling for TXT records
            if (record is DnsTxtRecord txtRecord)
            {
                // Calculate total length of all text strings with their length bytes
                int totalLength = 0;
                foreach (var text in txtRecord.TextValues)
                {
                    var textBytes = Encoding.UTF8.GetBytes(text);
                    totalLength += textBytes.Length + 1; // +1 for the length byte
                }
                
                // Write data length
                writer.Write(BinaryPrimitives.ReverseEndianness((ushort)totalLength));
                
                // Write each text string in [length][data] format
                foreach (var text in txtRecord.TextValues)
                {
                    var textBytes = Encoding.UTF8.GetBytes(text);
                    writer.Write((byte)textBytes.Length);
                    writer.Write(textBytes);
                }
            }
            else
            {
                // For all other record types, just write the data length and raw data
                writer.Write(BinaryPrimitives.ReverseEndianness(record.DataLength));
                writer.Write(record.Data);
            }
        }
    }

    /// <summary>
    /// Creates a DNS packet with a TXT record.
    /// </summary>
    /// <param name="name">The domain name for the TXT record (e.g., "_foo.example.com")</param>
    /// <param name="value">The value for the TXT record</param>
    /// <param name="ttl">Time to live in seconds</param>
    /// <returns>A byte array containing the encoded DNS packet</returns>
    public static byte[] CreateTxtRecordPacket(string name, string value, uint ttl = 30)
    {
        using var memoryStream = new MemoryStream();
        using var writer = new BinaryWriter(memoryStream);

        // Transaction ID (2 bytes) - using 0 for simplicity
        writer.Write((ushort)0);

        // Flags (2 bytes) - Set as a response, authoritative answer
        ushort flags = 0x8400; // Standard response, authoritative answer
        writer.Write(BinaryPrimitives.ReverseEndianness(flags));

        // Questions count (2 bytes) - 0 questions as this is a response
        writer.Write((ushort)0);

        // Answer count (2 bytes) - 1 answer record
        writer.Write(BinaryPrimitives.ReverseEndianness((ushort)1));

        // Authority count (2 bytes) - 0 authority records
        writer.Write((ushort)0);

        // Additional count (2 bytes) - 0 additional records
        writer.Write((ushort)0);

        // Answer section
        // Write the domain name
        WriteDomainName(writer, name);

        // Write record type (TXT) - in network byte order (big endian)
        writer.Write(BinaryPrimitives.ReverseEndianness(QueryTypeTXT));

        // Write record class (IN) - in network byte order (big endian)
        writer.Write(BinaryPrimitives.ReverseEndianness(QueryClassIN));

        // Write TTL (4 bytes) - in network byte order (big endian)
        writer.Write(BinaryPrimitives.ReverseEndianness(ttl));

        // For TXT records, we need to encode the text as [length][data] format
        byte[] textBytes = Encoding.UTF8.GetBytes(value);
        
        // Calculate RDATA length (length of all text strings including their length bytes)
        ushort rdataLength = (ushort)(textBytes.Length + 1); // +1 for the length byte
        
        // Write RDATA length - in network byte order (big endian)
        writer.Write(BinaryPrimitives.ReverseEndianness(rdataLength));
        
        // Write text length byte followed by the text data
        writer.Write((byte)textBytes.Length);
        writer.Write(textBytes);

        return memoryStream.ToArray();
    }

    /// <summary>
    /// Creates a DNS packet with multiple TXT records.
    /// </summary>
    /// <param name="records">Dictionary of record names to values</param>
    /// <param name="ttl">Time to live in seconds</param>
    /// <returns>A byte array containing the encoded DNS packet</returns>
    public static byte[] CreateMultiTxtRecordPacket(Dictionary<string, string> records, uint ttl = 30)
    {
        using var memoryStream = new MemoryStream();
        using var writer = new BinaryWriter(memoryStream);

        // Transaction ID (2 bytes) - using 0 for simplicity
        writer.Write((ushort)0);

        // Flags (2 bytes) - Set as a response, authoritative answer
        ushort flags = 0x8400; // Standard response, authoritative answer
        writer.Write(BinaryPrimitives.ReverseEndianness(flags));

        // Questions count (2 bytes) - 0 questions as this is a response
        writer.Write((ushort)0);

        // Answer count (2 bytes) - number of answer records - in network byte order (big endian)
        writer.Write(BinaryPrimitives.ReverseEndianness((ushort)records.Count));

        // Authority count (2 bytes) - 0 authority records
        writer.Write((ushort)0);

        // Additional count (2 bytes) - 0 additional records
        writer.Write((ushort)0);

        // Answer section - for each record
        foreach (var record in records)
        {
            // Write the domain name
            WriteDomainName(writer, record.Key);

            // Write record type (TXT) - in network byte order (big endian)
            writer.Write(BinaryPrimitives.ReverseEndianness(QueryTypeTXT));

            // Write record class (IN) - in network byte order (big endian)
            writer.Write(BinaryPrimitives.ReverseEndianness(QueryClassIN));

            // Write TTL (4 bytes) - in network byte order (big endian)
            writer.Write(BinaryPrimitives.ReverseEndianness(ttl));

            // Calculate RDATA length for this record
            byte[] textBytes = Encoding.UTF8.GetBytes(record.Value);
            ushort rdataLength = (ushort)(textBytes.Length + 1); // +1 for the length byte
            
            // Write RDATA length - in network byte order (big endian)
            writer.Write(BinaryPrimitives.ReverseEndianness(rdataLength));
            
            // Write text length byte followed by the text data
            writer.Write((byte)textBytes.Length);
            writer.Write(textBytes);
        }

        return memoryStream.ToArray();
    }

    /// <summary>
    /// Writes a domain name in DNS packet format.
    /// Used both for creating new packets and encoding existing DnsPacket objects.
    /// </summary>
    /// <param name="writer">The binary writer to write to</param>
    /// <param name="domainName">The domain name to write</param>
    private static void WriteDomainName(BinaryWriter writer, string domainName)
    {
        // Handle empty domain name
        if (string.IsNullOrEmpty(domainName))
        {
            writer.Write((byte)0); // Root domain
            return;
        }
        
        string[] labels = domainName.Split('.');
        foreach (string label in labels)
        {
            // Skip empty labels
            if (string.IsNullOrEmpty(label))
                continue;
                
            byte[] labelBytes = Encoding.ASCII.GetBytes(label);
            
            // DNS labels have a max length of 63 bytes
            if (labelBytes.Length > 63)
                throw new ArgumentException($"Domain name label '{label}' exceeds the maximum length of 63 bytes");
                
            writer.Write((byte)labelBytes.Length);
            writer.Write(labelBytes);
        }
        
        // Terminate with a zero length label
        writer.Write((byte)0);
    }
    
    /// <summary>
    /// Creates a DNS packet with a question section.
    /// </summary>
    /// <param name="name">The domain name to query (e.g., "example.com")</param>
    /// <param name="recordType">The record type to query (e.g., 16 for TXT)</param>
    /// <param name="recordClass">The class (e.g., 1 for IN)</param>
    /// <returns>A byte array containing the encoded DNS packet</returns>
    public static byte[] CreateQueryPacket(string name, ushort recordType = QueryTypeTXT, ushort recordClass = QueryClassIN)
    {
        using var memoryStream = new MemoryStream();
        using var writer = new BinaryWriter(memoryStream);
        
        // Generate a random transaction ID
        ushort transactionId = (ushort)new Random().Next(0, 65535);
        writer.Write(BinaryPrimitives.ReverseEndianness(transactionId));
        
        // Flags (2 bytes) - Standard query with recursion desired
        ushort flags = 0x0100; // Recursion desired
        writer.Write(BinaryPrimitives.ReverseEndianness(flags));
        
        // Questions count (2 bytes) - 1 question
        writer.Write(BinaryPrimitives.ReverseEndianness((ushort)1));
        
        // Answer, Authority, Additional counts - all 0
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        
        // Question section
        WriteDomainName(writer, name);
        
        // Record type (e.g., TXT)
        writer.Write(BinaryPrimitives.ReverseEndianness(recordType));
        
        // Record class (e.g., IN)
        writer.Write(BinaryPrimitives.ReverseEndianness(recordClass));
        
        return memoryStream.ToArray();
    }
}
