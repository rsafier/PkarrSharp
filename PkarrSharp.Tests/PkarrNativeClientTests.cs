using System.Buffers.Binary;
using System.Net;
using System.Text;
using NSec.Cryptography;
using PkarrSharp;
using ServiceStack.Text; 
// using Xunit;
// using Assert = NUnit.Assert;
using NUnit;
using NUnit.Framework;
using Xunit;
using Assert = NUnit.Framework.Assert;

namespace PkarrSharp.Tests;
 
public class PkarrNativeClientTests
{
    // [Theory]
    // [InlineData("o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy",
    //     "_matrix.o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy")]
    // [InlineData("gpj136mfx7j8qeu3gurpm9eys7zuyt43pnx5f45bfw1s7thdoa8o", "_foo")]
    // [InlineData("PK:ufibwbmed6jeq9k4p583go95wofakh9fwpp4k734trq79pd9u1uy",
    //     "ufibwbmed6jeq9k4p583go95wofakh9fwpp4k734trq79pd9u1uy")]
    [TestCase("o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy",
        "_matrix.o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy")]
    [TestCase("gpj136mfx7j8qeu3gurpm9eys7zuyt43pnx5f45bfw1s7thdoa8o", "_foo")]
    [TestCase("PK:ufibwbmed6jeq9k4p583go95wofakh9fwpp4k734trq79pd9u1uy",
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
         
        await Task.Delay(1000); //slow it down a little so we don't rate limit ourselves
    }

    [Test]
    public async Task TestPkarrPut()
    {
        var keys = GenerateRandomEd25519KeyPair();
        
        var publicKeyBytes = ZBase32.Decode(keys.publicKeyZBase32);
        var privateKeyBytes = Convert.FromHexString(keys.privateKeyHex);

        // Arrange
        string domainName = $"test.{keys.publicKeyZBase32}";
        string textValue = "Hello, Pkarr!";
        uint ttl = 60;

        // Act
        
        // Encode a DNS packet with a TXT record
        var record = new DnsPacket();
        record.Header = new DnsHeader { Flags = 0x8400 }; // Standard query response, no error
        record.AddTxtRecord(domainName,textValue,ttl); 
        
        var encodedDnsPacket = DnsPacketEncoder.Encode(record);
        
        // byte[] encodedDnsPacket = DnsPacketEncoder.CreateTxtRecordPacket(domainName, textValue, ttl);
        // var dnsPacket = DnsPacketDecoder.DecodeTyped(encodedDnsPacket);
        // dnsPacket.PrintDump();

        byte[] encodePkarrPacket =
            PkarrSignedPacket.CreateSignedPacket(encodedDnsPacket, privateKeyBytes, publicKeyBytes);
        var decodedPecket = PkarrSignedPacket.ParseRelayResponse(encodePkarrPacket, publicKeyBytes);
        decodedPecket.PrintDump();
        
        var pkarrClient = new PkarrRelayClient(new PkarrClientSettings());
        var response = await pkarrClient.PutPkarrDns(keys.publicKeyZBase32, encodePkarrPacket);
        response.PrintDump();
    }

    [Test]
    public async Task TestPkarrPutMulti()
    {
        var keys = GenerateRandomEd25519KeyPair();
        
        var publicKeyBytes = ZBase32.Decode(keys.publicKeyZBase32);
        var privateKeyBytes = Convert.FromHexString(keys.privateKeyHex);
        var pkarrClient = new PkarrRelayClient(new PkarrClientSettings());
        var response = await pkarrClient.PutMultipleTxtRecords(keys.publicKeyZBase32,privateKeyBytes,new Dictionary<string,string> {{"pkarr","test"},{"foo","bar"}});
        keys.publicKeyZBase32.PrintDump();
        Assert.IsTrue(response);
    }
    
    [Test]
    public async Task TestDnsGen()
    {
        var keys = GenerateRandomEd25519KeyPair();
        // Arrange
        string domainName = $"test.{keys.publicKeyZBase32}";
        string textValue = "Hello, Pkarr!";
        uint ttl = 60;

        // Act
        // Encode a DNS packet with a TXT record
        var record = new DnsPacket();
        record.Header = new DnsHeader { Flags = 0x8400 }; // Standard query response, no error
        record.AddTxtRecord(domainName,textValue,ttl); 
        
        var encoded = DnsPacketEncoder.Encode(record);
        
        byte[] encodedDnsPacket = DnsPacketEncoder.CreateTxtRecordPacket(domainName, textValue, ttl);
        var dnsPacket = DnsPacketDecoder.DecodeTyped(encodedDnsPacket);
        dnsPacket.PrintDump();

        var publicKeyBytes = ZBase32.Decode(keys.publicKeyZBase32);
        var privateKeyBytes = Convert.FromHexString(keys.privateKeyHex);
        byte[] encodePkarrPacket =
            PkarrSignedPacket.CreateSignedPacket(encodedDnsPacket, privateKeyBytes, publicKeyBytes);
        var decodedPecket = PkarrSignedPacket.ParseRelayResponse(encodePkarrPacket, publicKeyBytes);
        decodedPecket.PrintDump();
        var dnsPacket3 = DnsPacketDecoder.DecodeTyped(decodedPecket.EncodedDnsRecords); 
        var e = DnsPacketEncoder.Encode(dnsPacket3);
        Assert.AreEqual(e,decodedPecket.EncodedDnsRecords);
        Assert.AreEqual(encoded,encodedDnsPacket);
    }
     
    
    // Create a new random Ed25519 key pair
    public (string publicKeyZBase32, string privateKeyHex) GenerateRandomEd25519KeyPair()
    {
        // Specify the signature algorithm
        var algorithm = SignatureAlgorithm.Ed25519;

        // Generate a new random key pair
        using var key = Key.Create(algorithm,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        // Export the private key in raw format
        var privateKeyBytes = key.Export(KeyBlobFormat.RawPrivateKey);

        // Export the public key in raw format
        var publicKeyBytes = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        // Convert the private key to hex string
        var privateKeyHex = Convert.ToHexString(privateKeyBytes).ToLower();

        // Encode the public key using ZBase32
        var publicKeyZBase32 = ZBase32.Encode(publicKeyBytes);

        return (publicKeyZBase32, privateKeyHex);
    }
}