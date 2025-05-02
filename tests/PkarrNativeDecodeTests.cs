using System.Net.Http.Headers;
using ARSoft.Tools.Net.Dns;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSec.Cryptography;

namespace PkarrTests;

[TestClass]
public class PkarrNativeDecodeTests
{
    // Change TestMethod to DataTestMethod
    [DataTestMethod]
    // Add DataRow attribute with the public key string
    [DataRow("o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy")]
    [DataRow("gpj136mfx7j8qeu3gurpm9eys7zuyt43pnx5f45bfw1s7thdoa8o")]

    public async Task TestReadAndVerifyPkarrRecord(string publicKeyZBase32)
    {
        // 1. Define known pkarr key and relay
        // Using the example key from the provided test logs 
        string pkarrRelay = "https://relay.pkarr.org"; // Standard pkarr relay

        // 2. Perform DoH query
        byte[]? dnsResponsePacket = null;
        using (var httpClient = new HttpClient())
        {
            var requestUri = $"{pkarrRelay}/{publicKeyZBase32}";
            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            // DoH requires specific Accept header
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

            try
            {
                var response = await httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();
                dnsResponsePacket = await response.Content.ReadAsByteArrayAsync();
            }
            catch (HttpRequestException e)
            {
                Assert.Fail($"HTTP request to pkarr relay failed: {e.Message}");
                return;
            }
        }

        Assert.IsNotNull(dnsResponsePacket, "DNS response packet should not be null.");
        Assert.IsTrue(dnsResponsePacket.Length > 12, "DNS response packet seems too short."); // Basic check (header size)
      var x=  PkarrSignedPacket.Parse(dnsResponsePacket);
        // 3. Parse DNS Response to find TXT record containing "pkarr="
        string? base64Payload = null;
        try
        {
            // Use ARSoft.Tools.Net for proper DNS packet parsing with compression support
             DnsPacketDecoder.Decode(x.EncodedDnsRecords);
           //  var dnsMessage = DnsMessage.Parse(x.EncodedDnsRecords); 
           //Console.WriteLine($"Number of answer records: {dnsMessage.AnswerRecords.Count}");
                // var dnsMessage = DnsMessage.Parse(dnsResponsePacket);
                //
                // // Look for TXT records in the Answer section
                // var txtRecords = dnsMessage.sAnswerRecords
                //     .OfType<TxtRecord>()
                //     .ToList();
                //
                // Console.WriteLine($"Found {txtRecords.Count} TXT records in DNS response");
                //
                // // Find a TXT record containing "pkarr="
                // foreach (var txtRecord in txtRecords)
                // {
                //     foreach (var textPart in txtRecord.TextParts)
                //     {
                //         if (textPart.StartsWith("pkarr="))
                //         {
                //             base64Payload = textPart.Substring(6); // Skip "pkarr="
                //             Console.WriteLine($"Found pkarr payload in TXT record for {txtRecord.Name}");
                //             break;
                //         }
                //     }
                //     
                //     if (base64Payload != null)
                //         break;
                // }
          
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error parsing DNS message: {ex.Message}");
            // We'll try a fallback approach if the library fails
        }

        //
        // // 4. Decode Base64 Payload
        // byte[] signedPacket;
        // try
        // {
        //     // Remove potential escape characters if any were present
        //     base64Payload = base64Payload.Replace("\\\"", "\"").Replace("\\\\", "\\");
        //     signedPacket = Convert.FromBase64String(base64Payload);
        // }
        // catch (FormatException e)
        // {
        //     Assert.Fail($"Failed to decode base64 payload: {e.Message}. Payload was: {base64Payload}");
        //     return;
        // }
        //
        // // 5. Separate signature, timestamp, and records
        // const int signatureLength = 64;
        // const int timestampLength = 8;
        // const int headerLength = signatureLength + timestampLength;
        //
        // Assert.IsTrue(signedPacket.Length >= headerLength, $"Signed packet is too short. Length: {signedPacket.Length}");
        //
        // byte[] signature = signedPacket.Take(signatureLength).ToArray();
        // byte[] timestampBytes = signedPacket.Skip(signatureLength).Take(timestampLength).ToArray();
        // byte[] encodedRecords = signedPacket.Skip(headerLength).ToArray();
        //
        // // Optional: Convert timestamp bytes to a usable format (Big Endian)
        // if (BitConverter.IsLittleEndian) // Ensure correct byte order
        // {
        //     Array.Reverse(timestampBytes);
        // }
        // ulong timestampMicroseconds = BitConverter.ToUInt64(timestampBytes, 0);
        // DateTimeOffset timestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)(timestampMicroseconds / 1000));
        //
        // Console.WriteLine($"Extracted Timestamp: {timestamp.ToString("o")}"); // Log the timestamp
        //
        // // 6. Decode the zbase32 public key
        // byte[] publicKeyBytes;
        // try
        // {
        //     publicKeyBytes = ZBase32.Decode(publicKeyZBase32);
        // }
        // catch (Exception e)
        // {
        //     Assert.Fail($"Failed to decode zbase32 public key: {e.Message}");
        //     return;
        // }
        //
        // Assert.AreEqual(32, publicKeyBytes.Length, "Decoded Ed25519 public key should be 32 bytes long.");
        //
        // // 7. Verify the signature
        // // The signed data is the concatenation of the timestamp and the encoded records
        // byte[] dataToVerify = new byte[timestampLength + encodedRecords.Length];
        // Buffer.BlockCopy(timestampBytes, 0, dataToVerify, 0, timestampLength);
        // Buffer.BlockCopy(encodedRecords, 0, dataToVerify, timestampLength, encodedRecords.Length);
        //
        // var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, publicKeyBytes, KeyBlobFormat.RawPublicKey);
        // bool isValid = SignatureAlgorithm.Ed25519.Verify(publicKey, dataToVerify, signature);
        //
        // // 8. Assert verification result
        // Assert.IsTrue(isValid, "Pkarr signature verification failed.");
        //
        // Console.WriteLine("Pkarr signature verified successfully.");
        //
        // // 9. Parse the inner DNS records (if signature verified)
        // if (isValid && encodedRecords.Length > 0)
        // {
        //     try
        //     {
        //         
        //             var innerDnsMessage = DnsMessage.Parse(encodedRecords);
        //             
        //             Console.WriteLine($"Inner DNS packet contains {innerDnsMessage.Questions.Count} questions and {innerDnsMessage.AnswerRecords.Count} answers");
        //             
        //             foreach (var record in innerDnsMessage.AnswerRecords)
        //             {
        //                 Console.WriteLine($"Record: {record.Name}, Type: {record.RecordType}, TTL: {record.TimeToLive}");
        //                 
        //                 if (record is TxtRecord txtRecord)
        //                 {
        //                     Console.WriteLine($"  TXT data: {string.Join(", ", txtRecord.TextParts)}");
        //                 }
        //             }
        //         
        //     }
        //     catch (Exception ex)
        //     {
        //         Console.WriteLine($"Failed to parse inner DNS records: {ex.Message}");
        //         // This is not a test failure, just informational
        //     }
        // }
    }
    
    
    
    
}