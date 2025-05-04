using System.Net;
using System.Text;

namespace PkarrSharp;

// Structured DNS packet representation
public class DnsPacket
{
    public DnsHeader Header { get; set; }
    public List<DnsQuestion> Questions { get; set; } = new();
    public List<DnsResourceRecord> Answers { get; set; } = new();
    public List<DnsResourceRecord> Authority { get; set; } = new();
    public List<DnsResourceRecord> Additional { get; set; } = new();
}

// DNS header structure
public class DnsHeader
{
    public ushort Id { get; set; }
    public ushort Flags { get; set; }
    public bool IsResponse => (Flags & 0x8000) != 0;
    public byte Opcode => (byte)((Flags >> 11) & 0x0F);
    public bool AuthoritativeAnswer => (Flags & 0x0400) != 0;
    public bool Truncation => (Flags & 0x0200) != 0;
    public bool RecursionDesired => (Flags & 0x0100) != 0;
    public bool RecursionAvailable => (Flags & 0x0080) != 0;
    public byte ResponseCode => (byte)(Flags & 0x000F);
    public ushort QuestionCount { get; set; }
    public ushort AnswerCount { get; set; }
    public ushort AuthorityCount { get; set; }
    public ushort AdditionalCount { get; set; }
}

// DNS question structure
public class DnsQuestion
{
    public string Name { get; set; }
    public ushort Type { get; set; }
    public ushort Class { get; set; }
}

// Base DNS resource record
public class DnsResourceRecord
{
    public string Name { get; set; }
    public ushort Type { get; set; }
    public ushort Class { get; set; }
    public uint TTL { get; set; }
    public ushort DataLength { get; set; }
    public byte[] Data { get; set; }

    // Factory method to create typed record based on record type
    public static DnsResourceRecord CreateTyped(string name, ushort type, ushort @class, uint ttl, byte[] data)
    {
        return type switch
        {
            1 => new DnsARecord(name, @class, ttl, data),
            2 => new DnsNSRecord(name, @class, ttl, data),
            5 => new DnsCnameRecord(name, @class, ttl, data),
            16 => new DnsTxtRecord(name, @class, ttl, data),
            28 => new DnsAaaaRecord(name, @class, ttl, data),
            65 => new DnsHttpsRecord(name, @class, ttl, data),
            _ => new DnsResourceRecord
                { Name = name, Type = type, Class = @class, TTL = ttl, DataLength = (ushort)data.Length, Data = data }
        };
    }
}

// A Record (IPv4 address)
public class DnsARecord : DnsResourceRecord
{
    public DnsARecord(string name, ushort @class, uint ttl, byte[] data)
    {
        Name = name;
        Type = 1;
        Class = @class;
        TTL = ttl;
        DataLength = (ushort)data.Length;
        Data = data;

        if (data.Length == 4) Address = new IPAddress(data);
    }

    public IPAddress Address { get; set; }
}

// NS Record (Name Server)
public class DnsNSRecord : DnsResourceRecord
{
    public DnsNSRecord(string name, ushort @class, uint ttl, byte[] data)
    {
        Name = name;
        Type = 2;
        Class = @class;
        TTL = ttl;
        DataLength = (ushort)data.Length;
        Data = data;

        // NS record contains a domain name that should be decoded
        // For simplicity in this implementation, we'll leave it as null
        // The actual implementation would need to decode the domain name from data
    }

    public string NameServer { get; set; }
}

// CNAME Record (Canonical name)
public class DnsCnameRecord : DnsResourceRecord
{
    public DnsCnameRecord(string name, ushort @class, uint ttl, byte[] data)
    {
        Name = name;
        Type = 5;
        Class = @class;
        TTL = ttl;
        DataLength = (ushort)data.Length;
        Data = data;

        // CNAME record contains a domain name that should be decoded
        // For simplicity in this implementation, we'll leave it as null
        // The actual implementation would need to decode the domain name from data
    }

    public string CanonicalName { get; set; }
}

// TXT Record (Text)
public class DnsTxtRecord : DnsResourceRecord
{
    public DnsTxtRecord(string name, ushort @class, uint ttl, byte[] data)
    {
        Name = name;
        Type = 16;
        Class = @class;
        TTL = ttl;
        DataLength = (ushort)data.Length;
        Data = data;

        try
        {
            var txtOffset = 0;
            while (txtOffset < data.Length)
            {
                var txtLen = data[txtOffset++];
                if (txtOffset + txtLen > data.Length) break;
                TextValues.Add(Encoding.UTF8.GetString(data, txtOffset, txtLen));
                txtOffset += txtLen;
            }
        }
        catch
        {
            // Handle error silently - the raw data is still available
        }
    }

    public List<string> TextValues { get; set; } = new();
}

// AAAA Record (IPv6 address)
public class DnsAaaaRecord : DnsResourceRecord
{
    public DnsAaaaRecord(string name, ushort @class, uint ttl, byte[] data)
    {
        Name = name;
        Type = 28;
        Class = @class;
        TTL = ttl;
        DataLength = (ushort)data.Length;
        Data = data;

        if (data.Length == 16) Address = new IPAddress(data);
    }

    public IPAddress Address { get; set; }
}

// HTTPS/SVCB Record (Type 65)
public class DnsHttpsRecord : DnsResourceRecord
{
    public DnsHttpsRecord(string name, ushort @class, uint ttl, byte[] data)
    {
        Name = name;
        Type = 65;
        Class = @class;
        TTL = ttl;
        DataLength = (ushort)data.Length;
        Data = data;

        try
        {
            if (data.Length >= 2)
            {
                Priority = (ushort)((data[0] << 8) | data[1]);

                var targetNameStartOffset = 2;
                // This is a simplification - actual implementation should properly decode the domain name
                if (targetNameStartOffset < data.Length)
                    TargetName =
                        DnsPacketDecoder.DecodeDomainNameSequenceForObject(data, ref targetNameStartOffset,
                            data.Length);
            }
        }
        catch
        {
            // Handle error silently - the raw data is still available
        }
    }

    public ushort Priority { get; set; }
    public string TargetName { get; set; }
}

public class DnsPacketDecoder
{
    // public static void Decode(byte[] data)
    // {
    //     int offset = 0;
    //
    //     // DNS Header
    //     ushort id = ReadUInt16(data, ref offset);
    //     ushort flags = ReadUInt16(data, ref offset);
    //     ushort qdCount = ReadUInt16(data, ref offset);
    //     ushort anCount = ReadUInt16(data, ref offset);
    //     ushort nsCount = ReadUInt16(data, ref offset);
    //     ushort arCount = ReadUInt16(data, ref offset);
    //
    //     Console.WriteLine($"ID: {id}, Flags: 0x{flags:X4}");
    //     Console.WriteLine($"Questions: {qdCount}, Answers: {anCount}, Authority: {nsCount}, Additional: {arCount}");
    //     Console.WriteLine(); // Add a blank line for clarity
    //
    //     // Questions
    //     for (int i = 0; i < qdCount; i++)
    //     {
    //          Console.WriteLine($"--- Question {i + 1} ---");
    //         string qName = ReadDomainName(data, ref offset);
    //         ushort qType = ReadUInt16(data, ref offset);
    //         ushort qClass = ReadUInt16(data, ref offset);
    //
    //         Console.WriteLine($"  Name: {qName}");
    //         Console.WriteLine($"  Type: {qType}");
    //         Console.WriteLine($"  Class: {qClass}");
    //         Console.WriteLine();
    //     }
    //
    //     // Answers
    //     for (int i = 0; i < anCount; i++)
    //     {
    //          Console.WriteLine($"--- Answer {i + 1} ---");
    //         string rrName = ReadDomainName(data, ref offset);
    //         ushort rrType = ReadUInt16(data, ref offset);
    //         ushort rrClass = ReadUInt16(data, ref offset);
    //         uint rrTTL = ReadUInt32(data, ref offset); // Use new ReadUInt32 helper
    //         ushort rdLength = ReadUInt16(data, ref offset);
    //
    //         Console.WriteLine($"  Name: {rrName}");
    //         Console.WriteLine($"  Type: {rrType}");
    //         Console.WriteLine($"  Class: {rrClass}");
    //         Console.WriteLine($"  TTL: {rrTTL}");
    //         Console.WriteLine($"  RDLENGTH: {rdLength}");
    //
    //         // Ensure we don't read past the end of the data FOR RDATA
    //         int rdataStartOffset = offset;
    //         if (rdataStartOffset + rdLength > data.Length)
    //         {
    //             Console.WriteLine($"  [Error: RDATA length {rdLength} exceeds packet boundary at offset {rdataStartOffset}]");
    //             offset = data.Length; // Move offset to end to stop further parsing
    //             break;
    //         }
    //
    //         byte[] rdata = new byte[rdLength];
    //         Buffer.BlockCopy(data, rdataStartOffset, rdata, 0, rdLength);
    //         offset += rdLength; // Advance main offset past RDATA
    //
    //         // Basic RDATA display (Hex)
    //          Console.WriteLine($"  RDATA (Hex): {BitConverter.ToString(rdata).Replace("-", "")}");
    //
    //         // Decode specific types
    //         if (rrType == 16 && rdLength > 0) // TXT Record
    //         {
    //             try
    //             {
    //                 int txtOffset = 0;
    //                 var txtParts = new List<string>();
    //                 while (txtOffset < rdLength)
    //                 {
    //                     byte txtLen = rdata[txtOffset++];
    //                     if (txtOffset + txtLen > rdLength)
    //                     {
    //                          Console.WriteLine("    [Malformed TXT RDATA: length byte exceeds RDLENGTH]");
    //                         break;
    //                     }
    //                     // Using UTF8, though ASCII is common too. Adjust if needed.
    //                     txtParts.Add(Encoding.UTF8.GetString(rdata, txtOffset, txtLen));
    //                     txtOffset += txtLen;
    //                 }
    //                  Console.WriteLine($"  RDATA (Decoded TXT): {string.Join("; ", txtParts)}");
    //             }
    //             catch (Exception ex)
    //             {
    //                  Console.WriteLine($"    [Error decoding TXT RDATA: {ex.Message}]");
    //             }
    //         }
    //          else if (rrType == 65 && rdLength >= 2) // HTTPS/SVCB Record (Type 65) - Basic assumption
    //          {
    //              try
    //              {
    //                  int currentRdataOffset = 0; // Use offset relative to rdata buffer
    //                  // Read 2-byte priority (Big Endian)
    //                  ushort priority = (ushort)((rdata[currentRdataOffset] << 8) | rdata[currentRdataOffset + 1]);
    //                  currentRdataOffset += 2;
    //
    //                  // Decode the rest as a domain name sequence
    //                  // Adjust offset within rdata buffer BEFORE calling
    //                  int targetNameStartOffset = currentRdataOffset;
    //                  string targetName = DecodeDomainNameSequence(rdata, ref targetNameStartOffset, rdLength); // Pass rdata buffer and its length
    //
    //                  Console.WriteLine($"  RDATA (Decoded Type 65): Priority={priority}, Target={targetName}");
    //                  // Note: We don't update the main offset here, as it was already advanced past the full RDATA block earlier.
    //              }
    //              catch (Exception ex)
    //              {
    //                   Console.WriteLine($"    [Error decoding Type 65 RDATA: {ex.Message}]");
    //              }
    //          }
    //         // Add more handlers for other rrTypes (A, AAAA, CNAME, etc.) if needed
    //
    //         Console.WriteLine(); // Add a blank line between answers
    //     }
    //
    //     // TODO: Add loops for Authority (nsCount) and Additional (arCount) records if needed
    //     // These follow the same format as Answer records.
    // }

    private static ushort ReadUInt16(byte[] data, ref int offset)
    {
        if (offset + 2 > data.Length) throw new IndexOutOfRangeException("Attempted to read UInt16 past end of data.");
        var val = (ushort)((data[offset] << 8) | data[offset + 1]);
        offset += 2;
        return val;
    }

    private static uint ReadUInt32(byte[] data, ref int offset)
    {
        if (offset + 4 > data.Length) throw new IndexOutOfRangeException("Attempted to read UInt32 past end of data.");
        var val = ((uint)data[offset] << 24) |
                  ((uint)data[offset + 1] << 16) |
                  ((uint)data[offset + 2] << 8) |
                  data[offset + 3];
        offset += 4;
        return val;
    }

    // // Decodes a domain name sequence (labels prefixed by length bytes)
    // // Used for Type 65 RDATA target names. Does not handle compression or add dots.
    // // Modified to take the starting offset within the buffer and the total length of the sequence section.
    // private static string DecodeDomainNameSequence(byte[] buffer, ref int offsetInRdata, int rdataTotalLength)
    // {
    //     StringBuilder name = new StringBuilder();
    //     int endOfRdataInBuffer = rdataTotalLength; // Calculate the end index within the rdata buffer
    //
    //     // Stop when offset reaches the end of the rdata buffer portion OR we hit a null terminator
    //     while (offsetInRdata < endOfRdataInBuffer)
    //     {
    //          // Ensure we don't read len byte past the designated rdata section
    //          if (offsetInRdata >= buffer.Length) throw new IndexOutOfRangeException("RDATA sequence read out of bounds (len byte).");
    //
    //         byte len = buffer[offsetInRdata++]; // Read length byte and advance offset
    //
    //         if (len == 0) break; // Null terminator, end of sequence
    //
    //         // Check if the label length extends beyond the rdata section
    //         if (offsetInRdata + len > endOfRdataInBuffer)
    //             throw new IndexOutOfRangeException($"RDATA label length ({len}) exceeds RDATA boundary at offset {offsetInRdata}.");
    //         // Also check against underlying data array just in case (should be redundant if rdataTotalLength is correct)
    //          if (offsetInRdata + len > buffer.Length)
    //             throw new IndexOutOfRangeException($"RDATA label length ({len}) exceeds main data boundary at offset {offsetInRdata}.");
    //
    //
    //         // Use ASCII, common for domain names. Might need adjustment.
    //         name.Append(Encoding.ASCII.GetString(buffer, offsetInRdata, len));
    //         offsetInRdata += len; // Advance offset past the label content
    //     }
    //     return name.ToString();
    // }

    // Public version for use by record objects
    public static string DecodeDomainNameSequenceForObject(byte[] buffer, ref int offsetInRdata, int rdataTotalLength)
    {
        var name = new StringBuilder();
        var endOfRdataInBuffer = rdataTotalLength; // Calculate the end index within the rdata buffer

        // Stop when offset reaches the end of the rdata buffer portion OR we hit a null terminator
        while (offsetInRdata < endOfRdataInBuffer)
        {
            // Ensure we don't read len byte past the designated rdata section
            if (offsetInRdata >= buffer.Length)
                throw new IndexOutOfRangeException("RDATA sequence read out of bounds (len byte).");

            var len = buffer[offsetInRdata++]; // Read length byte and advance offset

            if (len == 0) break; // Null terminator, end of sequence

            // Check if the label length extends beyond the rdata section
            if (offsetInRdata + len > endOfRdataInBuffer)
                throw new IndexOutOfRangeException(
                    $"RDATA label length ({len}) exceeds RDATA boundary at offset {offsetInRdata}.");
            // Also check against underlying data array just in case (should be redundant if rdataTotalLength is correct)
            if (offsetInRdata + len > buffer.Length)
                throw new IndexOutOfRangeException(
                    $"RDATA label length ({len}) exceeds main data boundary at offset {offsetInRdata}.");

            // Add dot if not the first label
            if (name.Length > 0) name.Append('.');

            // Use ASCII, common for domain names. Might need adjustment.
            name.Append(Encoding.ASCII.GetString(buffer, offsetInRdata, len));
            offsetInRdata += len; // Advance offset past the label content
        }

        return name.ToString();
    }


    // Main function to read domain names, handling compression and adding dots
    private static string ReadDomainName(byte[] data, ref int offset)
    {
        var name = new StringBuilder();
        var initialOffset = offset;
        var recursionDepth = 0;
        const int maxRecursionDepth = 10;

        // Use a separate variable to track position *during* the reading of the current name
        // The main 'offset' should only be advanced *after* a full name segment (or pointer) is read.
        var currentReadOffset = offset;

        while (true)
        {
            if (currentReadOffset >= data.Length) throw new IndexOutOfRangeException("DNS name read out of bounds.");

            var len = data[currentReadOffset];

            if ((len & 0xC0) == 0xC0) // Pointer
            {
                if (currentReadOffset + 1 >= data.Length)
                    throw new IndexOutOfRangeException("DNS compression pointer offset out of bounds.");

                var pointer = ((len & 0x3F) << 8) | data[currentReadOffset + 1];

                if (pointer >= initialOffset) // Basic loop/forward check
                    throw new InvalidDataException("Invalid DNS compression pointer (points forward or loops).");

                if (++recursionDepth > maxRecursionDepth)
                    throw new InvalidDataException("Maximum DNS pointer recursion depth exceeded.");

                // **MODIFIED:** Add dot BEFORE appending the pointed-to name if name isn't empty
                if (name.Length > 0) name.Append(".");

                // If this pointer is the *first* thing we read for this name, advance the main offset past the 2 pointer bytes.
                // Otherwise, the main offset was already advanced by the preceding label read.
                if (currentReadOffset == offset) offset += 2;

                var jumpOffset = pointer; // Start recursive read from the pointer location
                var pointedName = ReadDomainNameRecursive(data, ref jumpOffset, initialOffset, recursionDepth);
                name.Append(pointedName);
                break; // Pointer always terminates the current sequence
            }

            if (len == 0) // Null terminator
            {
                currentReadOffset++; // Move past the null byte
                // Advance the main offset to the position after the null byte
                offset = currentReadOffset;
                break; // End of name
            }

            // Label segment
            // Append dot *before* reading the next label if name isn't empty
            if (name.Length > 0) name.Append(".");

            currentReadOffset++; // Move past the length byte
            if (currentReadOffset + len > data.Length)
                throw new IndexOutOfRangeException("DNS label length exceeds packet boundary.");

            name.Append(Encoding.ASCII.GetString(data, currentReadOffset, len));
            currentReadOffset += len; // Move past the label content

            // Advance the main offset to the position after this label
            offset = currentReadOffset;
        }

        return name.ToString();
    }

    /// <summary>
    ///     Decodes a DNS packet and returns a structured DnsPacket object
    /// </summary>
    /// <param name="data">Raw DNS packet data</param>
    /// <returns>Structured DnsPacket object with full type information</returns>
    public static DnsPacket DecodeTyped(byte[] data)
    {
        var packet = new DnsPacket();
        var offset = 0;

        // DNS Header
        packet.Header = new DnsHeader
        {
            Id = ReadUInt16(data, ref offset),
            Flags = ReadUInt16(data, ref offset),
            QuestionCount = ReadUInt16(data, ref offset),
            AnswerCount = ReadUInt16(data, ref offset),
            AuthorityCount = ReadUInt16(data, ref offset),
            AdditionalCount = ReadUInt16(data, ref offset)
        };

        // Questions
        for (var i = 0; i < packet.Header.QuestionCount; i++)
        {
            var question = new DnsQuestion
            {
                Name = ReadDomainName(data, ref offset),
                Type = ReadUInt16(data, ref offset),
                Class = ReadUInt16(data, ref offset)
            };
            packet.Questions.Add(question);
        }

        // Process Answer Records
        packet.Answers = ProcessResourceRecords(data, ref offset, packet.Header.AnswerCount);

        // Process Authority Records
        packet.Authority = ProcessResourceRecords(data, ref offset, packet.Header.AuthorityCount);

        // Process Additional Records
        packet.Additional = ProcessResourceRecords(data, ref offset, packet.Header.AdditionalCount);

        return packet;
    }

    private static List<DnsResourceRecord> ProcessResourceRecords(byte[] data, ref int offset, ushort count)
    {
        var records = new List<DnsResourceRecord>();

        for (var i = 0; i < count; i++)
        {
            var rrName = ReadDomainName(data, ref offset);
            var rrType = ReadUInt16(data, ref offset);
            var rrClass = ReadUInt16(data, ref offset);
            var rrTTL = ReadUInt32(data, ref offset);
            var rdLength = ReadUInt16(data, ref offset);

            // Ensure we don't read past the end of the data for RDATA
            var rdataStartOffset = offset;
            if (rdataStartOffset + rdLength > data.Length)
            {
                offset = data.Length; // Move offset to end to stop further parsing
                break;
            }

            var rdata = new byte[rdLength];
            Buffer.BlockCopy(data, rdataStartOffset, rdata, 0, rdLength);
            offset += rdLength; // Advance main offset past RDATA

            // Create the appropriate typed record
            var record = DnsResourceRecord.CreateTyped(rrName, rrType, rrClass, rrTTL, rdata);
            records.Add(record);
        }

        return records;
    }

    // Recursive helper for pointers, ensures correct offset management and depth checking
    private static string ReadDomainNameRecursive(byte[] data, ref int currentOffset, int initialOffset,
        int recursionDepth)
    {
        var name = new StringBuilder();
        // This helper function reads from a given 'currentOffset' but does NOT advance the caller's offset.
        // It constructs the name part found at that location.

        while (true)
        {
            if (currentOffset >= data.Length)
                throw new IndexOutOfRangeException("DNS name read out of bounds (recursive).");

            var len = data[currentOffset];

            if ((len & 0xC0) == 0xC0) // Pointer
            {
                if (currentOffset + 1 >= data.Length)
                    throw new IndexOutOfRangeException("DNS compression pointer offset out of bounds (recursive).");
                var pointer = ((len & 0x3F) << 8) | data[currentOffset + 1];

                if (pointer >= initialOffset)
                    throw new InvalidDataException(
                        "Invalid DNS compression pointer (points forward or loops in recursive call).");

                if (++recursionDepth > 10)
                    throw new InvalidDataException("Maximum DNS pointer recursion depth exceeded (recursive).");

                // **MODIFIED:** Add dot BEFORE appending the pointed-to name if name isn't empty
                if (name.Length > 0) name.Append(".");

                var jumpOffset = pointer; // Prepare to jump
                // Recursively call to get the name at the pointer location
                var pointedName = ReadDomainNameRecursive(data, ref jumpOffset, initialOffset, recursionDepth);
                name.Append(pointedName);
                // The offset advancement happens *outside* the recursive call (in ReadDomainName)
                // We just read the name found at the pointer.
                break; // Pointer terminates this sequence
            }

            if (len == 0) // End of name segment
            {
                currentOffset++; // Consume the null terminator for the next read in this loop if any, although break happens next.
                break;
            }

            // Label
            // Append dot *before* reading the next label if name isn't empty
            if (name.Length > 0) name.Append(".");

            currentOffset++; // Move past length byte
            if (currentOffset + len > data.Length)
                throw new IndexOutOfRangeException("DNS label length exceeds packet boundary (recursive).");

            name.Append(Encoding.ASCII.GetString(data, currentOffset, len));
            currentOffset += len; // Move past label content for the next read in this loop
        }

        return name.ToString();
    }
}