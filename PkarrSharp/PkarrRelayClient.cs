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
}