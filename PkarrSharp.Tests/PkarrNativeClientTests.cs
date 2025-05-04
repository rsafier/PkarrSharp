using System.Net; 
using PkarrSharp;
using ServiceStack.Text; 
using Xunit;
using Assert = Xunit.Assert;

namespace PkarrSharp.Tests;
 
public class PkarrNativeClientTests
{
    [Theory]
    [InlineData("o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy",
        "_matrix.o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy")]
    [InlineData("gpj136mfx7j8qeu3gurpm9eys7zuyt43pnx5f45bfw1s7thdoa8o", "_foo")]
    [InlineData("PK:ufibwbmed6jeq9k4p583go95wofakh9fwpp4k734trq79pd9u1uy",
        "ufibwbmed6jeq9k4p583go95wofakh9fwpp4k734trq79pd9u1uy")]
    public async Task TestClient(string publicKeyZBase32, string expectedName)
    {
        // Specifically for IPAddress type
        JsConfig<IPAddress>.SerializeFn = ipAddress => ipAddress.ToString();

        var client = new PkarrRelayClient(new PkarrClientSettings());
        var result = await client.GetPkarrDns(publicKeyZBase32);

        Assert.True(result.DnsPacket.Answers.Any(x => x.Name.StartsWith(expectedName)));
        Assert.True(result.SignedPacket.SignatureValidated);
        result.DnsPacket.PrintDump();
        result.SignedPacket.PrintDump();
        await Task.Delay(500); //slow it down a little so we don't rate limit ourselves
    }
}