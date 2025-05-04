using System.Net.Http.Headers;

namespace PkarrSharp;

public class PkarrClientSettings
{
    public string PkarrRelay { get; set; } = "https://relay.pkarr.org";
}

public class PkarrRelayClient : IDisposable
{
    private readonly PkarrClientSettings _clientSettings;

    private readonly HttpClient _httpClient;

    public PkarrRelayClient(PkarrClientSettings clientSettings)
    {
        _httpClient = new HttpClient();
        _clientSettings = clientSettings;
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }


    public async Task<(PkarrSignedPacket SignedPacket, DnsPacket DnsPacket)> GetPkarrDns(string publicKeyZBase32)
    {
        if (string.IsNullOrEmpty(publicKeyZBase32))
            throw new ArgumentNullException(nameof(publicKeyZBase32), "Public key string cannot be null or empty.");

        // Remove PK: prefix if present
        if (publicKeyZBase32[..3] == "PK:")
            publicKeyZBase32 = publicKeyZBase32[3..];


        // 2. Perform DoH query
        byte[]? dnsResponsePacket = null;
        using (var httpClient = new HttpClient())
        {
            var requestUri = $"{_clientSettings.PkarrRelay}/{publicKeyZBase32}";
            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            // DoH requires specific Accept header
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

            var response = await httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            dnsResponsePacket = await response.Content.ReadAsByteArrayAsync();
        }

        if (dnsResponsePacket == null) throw new Exception("DNS response packet is null.");
        if (dnsResponsePacket.Length < 12) throw new Exception("DNS response packet seems too short.");

        // This will throw if sig-check fails
        var pkarrSignedPacket =
            PkarrSignedPacket.ParseRelayResponse(dnsResponsePacket, ZBase32.Decode(publicKeyZBase32));
        var dnsPacket = DnsPacketDecoder.DecodeTyped(pkarrSignedPacket.EncodedDnsRecords);

        return (pkarrSignedPacket, dnsPacket);
    }
    
    /// <summary>
    /// Publishes a signed DNS packet to the Pkarr relay
    /// </summary>
    /// <param name="publicKeyZBase32">The public key in ZBase32 format</param>
    /// <param name="signedPacket">The signed packet to publish</param>
    /// <returns>True if the packet was successfully published, false otherwise</returns>
    public async Task<bool> PutPkarrDns(string publicKeyZBase32, byte[] signedPacket)
    {
        if (string.IsNullOrEmpty(publicKeyZBase32))
            throw new ArgumentNullException(nameof(publicKeyZBase32), "Public key string cannot be null or empty.");
        
        if (signedPacket == null || signedPacket.Length == 0)
            throw new ArgumentNullException(nameof(signedPacket), "Signed packet cannot be null or empty.");
    
        // Remove PK: prefix if present
        if (publicKeyZBase32[..3] == "PK:")
            publicKeyZBase32 = publicKeyZBase32[3..];
    
        try
        {
            var requestUri = $"{_clientSettings.PkarrRelay}/{publicKeyZBase32}";
            var request = new HttpRequestMessage(HttpMethod.Put, requestUri);
            
            // Set the content type to application/dns-message as specified in the relay design
            var content = new ByteArrayContent(signedPacket);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
            request.Content = content;
    
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            // Consider logging the exception details
            Console.WriteLine($"Error publishing packet: {ex.Message}");
            return false;
        }
    }
    
    /// <summary>
    /// Creates and publishes a TXT record to the Pkarr relay
    /// </summary>
    /// <param name="publicKeyZBase32">The public key in ZBase32 format</param>
    /// <param name="privateKey">The private key as a byte array</param>
    /// <param name="recordName">The name of the TXT record (e.g., "_foo")</param>
    /// <param name="recordValue">The value for the TXT record</param>
    /// <param name="ttl">Time to live in seconds</param>
    /// <returns>True if the record was successfully published, false otherwise</returns>
    public async Task<bool> PutTxtRecord(string publicKeyZBase32, byte[] privateKey, string recordName, string recordValue, uint ttl = 30)
    {
        // Create signed TXT record
        byte[] signedPacket = PkarrSignedPacket.CreateSignedTxtRecord(
            publicKeyZBase32, 
            privateKey, 
            recordName, 
            recordValue,
            ttl);
    
        // Send to relay
        return await PutPkarrDns(publicKeyZBase32, signedPacket);
    }
    
    /// <summary>
    /// Creates and publishes multiple TXT records to the Pkarr relay
    /// </summary>
    /// <param name="publicKeyZBase32">The public key in ZBase32 format</param>
    /// <param name="privateKey">The private key as a byte array</param>
    /// <param name="records">Dictionary of record names to values</param>
    /// <param name="ttl">Time to live in seconds</param>
    /// <returns>True if the records were successfully published, false otherwise</returns>
    public async Task<bool> PutMultipleTxtRecords(string publicKeyZBase32, byte[] privateKey, Dictionary<string, string> records, uint ttl = 30)
    {
        // Create signed packet with multiple TXT records
        byte[] signedPacket = PkarrSignedPacket.CreateSignedMultiTxtRecords(
            publicKeyZBase32,
            privateKey,
            records,
            ttl);
    
        // Send to relay
        return await PutPkarrDns(publicKeyZBase32, signedPacket);
    }
}