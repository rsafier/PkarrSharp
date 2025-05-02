using System.Text;
using System.Collections.Generic; // Needed for List

namespace PkarrTests;

public class DnsPacketDecoder
{
    public static void Decode(byte[] data)
    {
        int offset = 0;

        // DNS Header
        ushort id = ReadUInt16(data, ref offset);
        ushort flags = ReadUInt16(data, ref offset);
        ushort qdCount = ReadUInt16(data, ref offset);
        ushort anCount = ReadUInt16(data, ref offset);
        ushort nsCount = ReadUInt16(data, ref offset);
        ushort arCount = ReadUInt16(data, ref offset);

        Console.WriteLine($"ID: {id}, Flags: 0x{flags:X4}");
        Console.WriteLine($"Questions: {qdCount}, Answers: {anCount}, Authority: {nsCount}, Additional: {arCount}");
        Console.WriteLine(); // Add a blank line for clarity

        // Questions
        for (int i = 0; i < qdCount; i++)
        {
             Console.WriteLine($"--- Question {i + 1} ---");
            string qName = ReadDomainName(data, ref offset);
            ushort qType = ReadUInt16(data, ref offset);
            ushort qClass = ReadUInt16(data, ref offset);

            Console.WriteLine($"  Name: {qName}");
            Console.WriteLine($"  Type: {qType}");
            Console.WriteLine($"  Class: {qClass}");
            Console.WriteLine();
        }

        // Answers
        for (int i = 0; i < anCount; i++)
        {
             Console.WriteLine($"--- Answer {i + 1} ---");
            string rrName = ReadDomainName(data, ref offset);
            ushort rrType = ReadUInt16(data, ref offset);
            ushort rrClass = ReadUInt16(data, ref offset);
            uint rrTTL = ReadUInt32(data, ref offset); // Use new ReadUInt32 helper
            ushort rdLength = ReadUInt16(data, ref offset);

            Console.WriteLine($"  Name: {rrName}");
            Console.WriteLine($"  Type: {rrType}");
            Console.WriteLine($"  Class: {rrClass}");
            Console.WriteLine($"  TTL: {rrTTL}");
            Console.WriteLine($"  RDLENGTH: {rdLength}");

            // Ensure we don't read past the end of the data FOR RDATA
            int rdataStartOffset = offset;
            if (rdataStartOffset + rdLength > data.Length)
            {
                Console.WriteLine($"  [Error: RDATA length {rdLength} exceeds packet boundary at offset {rdataStartOffset}]");
                offset = data.Length; // Move offset to end to stop further parsing
                break;
            }

            byte[] rdata = new byte[rdLength];
            Buffer.BlockCopy(data, rdataStartOffset, rdata, 0, rdLength);
            offset += rdLength; // Advance main offset past RDATA

            // Basic RDATA display (Hex)
             Console.WriteLine($"  RDATA (Hex): {BitConverter.ToString(rdata).Replace("-", "")}");

            // Decode specific types
            if (rrType == 16 && rdLength > 0) // TXT Record
            {
                try
                {
                    int txtOffset = 0;
                    var txtParts = new List<string>();
                    while (txtOffset < rdLength)
                    {
                        byte txtLen = rdata[txtOffset++];
                        if (txtOffset + txtLen > rdLength)
                        {
                             Console.WriteLine("    [Malformed TXT RDATA: length byte exceeds RDLENGTH]");
                            break;
                        }
                        // Using UTF8, though ASCII is common too. Adjust if needed.
                        txtParts.Add(Encoding.UTF8.GetString(rdata, txtOffset, txtLen));
                        txtOffset += txtLen;
                    }
                     Console.WriteLine($"  RDATA (Decoded TXT): {string.Join("; ", txtParts)}");
                }
                catch (Exception ex)
                {
                     Console.WriteLine($"    [Error decoding TXT RDATA: {ex.Message}]");
                }
            }
             else if (rrType == 65 && rdLength >= 2) // HTTPS/SVCB Record (Type 65) - Basic assumption
             {
                 try
                 {
                     int currentRdataOffset = 0; // Use offset relative to rdata buffer
                     // Read 2-byte priority (Big Endian)
                     ushort priority = (ushort)((rdata[currentRdataOffset] << 8) | rdata[currentRdataOffset + 1]);
                     currentRdataOffset += 2;

                     // Decode the rest as a domain name sequence
                     // Adjust offset within rdata buffer BEFORE calling
                     int targetNameStartOffset = currentRdataOffset;
                     string targetName = DecodeDomainNameSequence(rdata, ref targetNameStartOffset, rdLength); // Pass rdata buffer and its length

                     Console.WriteLine($"  RDATA (Decoded Type 65): Priority={priority}, Target={targetName}");
                     // Note: We don't update the main offset here, as it was already advanced past the full RDATA block earlier.
                 }
                 catch (Exception ex)
                 {
                      Console.WriteLine($"    [Error decoding Type 65 RDATA: {ex.Message}]");
                 }
             }
            // Add more handlers for other rrTypes (A, AAAA, CNAME, etc.) if needed

            Console.WriteLine(); // Add a blank line between answers
        }

        // TODO: Add loops for Authority (nsCount) and Additional (arCount) records if needed
        // These follow the same format as Answer records.
    }

    private static ushort ReadUInt16(byte[] data, ref int offset)
    {
        if (offset + 2 > data.Length) throw new IndexOutOfRangeException("Attempted to read UInt16 past end of data.");
        ushort val = (ushort)((data[offset] << 8) | data[offset + 1]);
        offset += 2;
        return val;
    }

    private static uint ReadUInt32(byte[] data, ref int offset)
    {
        if (offset + 4 > data.Length) throw new IndexOutOfRangeException("Attempted to read UInt32 past end of data.");
        uint val = ((uint)data[offset] << 24) |
                   ((uint)data[offset + 1] << 16) |
                   ((uint)data[offset + 2] << 8) |
                   data[offset + 3];
        offset += 4;
        return val;
    }

    // Decodes a domain name sequence (labels prefixed by length bytes)
    // Used for Type 65 RDATA target names. Does not handle compression or add dots.
    // Modified to take the starting offset within the buffer and the total length of the sequence section.
    private static string DecodeDomainNameSequence(byte[] buffer, ref int offsetInRdata, int rdataTotalLength)
    {
        StringBuilder name = new StringBuilder();
        int endOfRdataInBuffer = rdataTotalLength; // Calculate the end index within the rdata buffer

        // Stop when offset reaches the end of the rdata buffer portion OR we hit a null terminator
        while (offsetInRdata < endOfRdataInBuffer)
        {
             // Ensure we don't read len byte past the designated rdata section
             if (offsetInRdata >= buffer.Length) throw new IndexOutOfRangeException("RDATA sequence read out of bounds (len byte).");

            byte len = buffer[offsetInRdata++]; // Read length byte and advance offset

            if (len == 0) break; // Null terminator, end of sequence

            // Check if the label length extends beyond the rdata section
            if (offsetInRdata + len > endOfRdataInBuffer)
                throw new IndexOutOfRangeException($"RDATA label length ({len}) exceeds RDATA boundary at offset {offsetInRdata}.");
            // Also check against underlying data array just in case (should be redundant if rdataTotalLength is correct)
             if (offsetInRdata + len > buffer.Length)
                throw new IndexOutOfRangeException($"RDATA label length ({len}) exceeds main data boundary at offset {offsetInRdata}.");


            // Use ASCII, common for domain names. Might need adjustment.
            name.Append(Encoding.ASCII.GetString(buffer, offsetInRdata, len));
            offsetInRdata += len; // Advance offset past the label content
        }
        return name.ToString();
    }


    // Main function to read domain names, handling compression and adding dots
    private static string ReadDomainName(byte[] data, ref int offset)
    {
        StringBuilder name = new StringBuilder();
        int initialOffset = offset;
        int recursionDepth = 0;
        const int maxRecursionDepth = 10;

        // Use a separate variable to track position *during* the reading of the current name
        // The main 'offset' should only be advanced *after* a full name segment (or pointer) is read.
        int currentReadOffset = offset;

        while (true)
        {
            if (currentReadOffset >= data.Length) throw new IndexOutOfRangeException("DNS name read out of bounds.");

            byte len = data[currentReadOffset];

            if ((len & 0xC0) == 0xC0) // Pointer
            {
                if (currentReadOffset + 1 >= data.Length) throw new IndexOutOfRangeException("DNS compression pointer offset out of bounds.");

                int pointer = ((len & 0x3F) << 8) | data[currentReadOffset + 1];

                if (pointer >= initialOffset) // Basic loop/forward check
                    throw new InvalidDataException("Invalid DNS compression pointer (points forward or loops).");

                if (++recursionDepth > maxRecursionDepth)
                    throw new InvalidDataException("Maximum DNS pointer recursion depth exceeded.");

                 // **MODIFIED:** Add dot BEFORE appending the pointed-to name if name isn't empty
                 if (name.Length > 0)
                 {
                     name.Append(".");
                 }

                // If this pointer is the *first* thing we read for this name, advance the main offset past the 2 pointer bytes.
                // Otherwise, the main offset was already advanced by the preceding label read.
                if (currentReadOffset == offset)
                {
                    offset += 2;
                }

                int jumpOffset = pointer; // Start recursive read from the pointer location
                string pointedName = ReadDomainNameRecursive(data, ref jumpOffset, initialOffset, recursionDepth);
                name.Append(pointedName);
                break; // Pointer always terminates the current sequence
            }
            else if (len == 0) // Null terminator
            {
                currentReadOffset++; // Move past the null byte
                // Advance the main offset to the position after the null byte
                offset = currentReadOffset;
                break; // End of name
            }
            else // Label segment
            {
                 // Append dot *before* reading the next label if name isn't empty
                 if (name.Length > 0)
                 {
                     name.Append(".");
                 }

                currentReadOffset++; // Move past the length byte
                if (currentReadOffset + len > data.Length) throw new IndexOutOfRangeException("DNS label length exceeds packet boundary.");

                name.Append(Encoding.ASCII.GetString(data, currentReadOffset, len));
                currentReadOffset += len; // Move past the label content

                // Advance the main offset to the position after this label
                offset = currentReadOffset;
            }
        }
        return name.ToString();
    }

    // Recursive helper for pointers, ensures correct offset management and depth checking
    private static string ReadDomainNameRecursive(byte[] data, ref int currentOffset, int initialOffset, int recursionDepth)
    {
        StringBuilder name = new StringBuilder();
        // This helper function reads from a given 'currentOffset' but does NOT advance the caller's offset.
        // It constructs the name part found at that location.

        while (true)
        {
             if (currentOffset >= data.Length) throw new IndexOutOfRangeException("DNS name read out of bounds (recursive).");

             byte len = data[currentOffset];

             if ((len & 0xC0) == 0xC0) // Pointer
             {
                 if (currentOffset + 1 >= data.Length) throw new IndexOutOfRangeException("DNS compression pointer offset out of bounds (recursive).");
                 int pointer = ((len & 0x3F) << 8) | data[currentOffset + 1];

                 if (pointer >= initialOffset)
                     throw new InvalidDataException("Invalid DNS compression pointer (points forward or loops in recursive call).");

                 if (++recursionDepth > 10)
                      throw new InvalidDataException("Maximum DNS pointer recursion depth exceeded (recursive).");

                 // **MODIFIED:** Add dot BEFORE appending the pointed-to name if name isn't empty
                 if (name.Length > 0)
                 {
                     name.Append(".");
                 }

                 int jumpOffset = pointer; // Prepare to jump
                 // Recursively call to get the name at the pointer location
                 string pointedName = ReadDomainNameRecursive(data, ref jumpOffset, initialOffset, recursionDepth);
                 name.Append(pointedName);
                 // The offset advancement happens *outside* the recursive call (in ReadDomainName)
                 // We just read the name found at the pointer.
                 break; // Pointer terminates this sequence
             }
             else if (len == 0) // End of name segment
             {
                 currentOffset++; // Consume the null terminator for the next read in this loop if any, although break happens next.
                 break;
             }
             else // Label
             {
                 // Append dot *before* reading the next label if name isn't empty
                 if (name.Length > 0)
                 {
                     name.Append(".");
                 }

                 currentOffset++; // Move past length byte
                 if (currentOffset + len > data.Length) throw new IndexOutOfRangeException("DNS label length exceeds packet boundary (recursive).");

                 name.Append(Encoding.ASCII.GetString(data, currentOffset, len));
                 currentOffset += len; // Move past label content for the next read in this loop
             }
         }
         return name.ToString();
    }
}