using System.Buffers.Binary;
using System.Text;
using NSec.Cryptography;

namespace PkarrSharp; 

/// <summary>
///     Represents the decoded content of a pkarr HTTP response
/// </summary>
public class PkarrSignedPacket
{
    private const int SignatureLength = 64;
    private const int TimestampLength = 8;
    private const int HeaderLength = SignatureLength + TimestampLength;

    // Private constructor to ensure usage via the Parse factory method
    private PkarrSignedPacket(byte[] signature, ulong timestampMicroseconds, byte[] encodedDnsRecords,
        bool signatureValidated, byte[]? nodePublicKey = null)
    {
        Signature = signature ?? throw new ArgumentNullException(nameof(signature));
        TimestampMicroseconds = timestampMicroseconds;
        // Convert microseconds to milliseconds for DateTimeOffset
        Timestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)(timestampMicroseconds / 1000));
        EncodedDnsRecords = encodedDnsRecords ?? throw new ArgumentNullException(nameof(encodedDnsRecords));
        SignatureValidated = signatureValidated;
        NodePublicKey = nodePublicKey;
    }

    public byte[]? NodePublicKey { get; private set; }

    /// <summary>
    ///     The Ed25519 signature (64 bytes).
    /// </summary>
    public byte[] Signature { get; private set; }

    /// <summary>
    ///     Indicates whether the signature of the packet has been successfully validated.
    /// </summary>
    public bool SignatureValidated { get; private set; }

    /// <summary>
    ///     Timestamp in microseconds since the Unix epoch (1970-01-01T00:00:00Z).
    /// </summary>
    public ulong TimestampMicroseconds { get; private set; }

    /// <summary>
    ///     The timestamp converted to a DateTimeOffset.
    /// </summary>
    public DateTimeOffset Timestamp { get; private set; }

    /// <summary>
    ///     The raw bytes of the inner, encoded DNS message.
    /// </summary>
    public byte[] EncodedDnsRecords { get; private set; }

    /// <summary>
    ///     Generates the bencode format of the data according to BEP-0044 specification
    ///     signable = prefix dns-packet
    ///     prefix = "3:seqi" timestamp "e1:v" dns-packet-length ":"
    /// </summary>
    /// <returns>The bencoded data that should be signed/verified</returns>
    private static byte[] GetBencodedSignableData(ulong timestampMicroseconds, byte[] encodedDnsRecords)
    {
        var timestampStr = timestampMicroseconds.ToString();
        var dnsPacketLengthStr = encodedDnsRecords.Length.ToString();

        // Construct the bencode prefix: "3:seqi{timestamp}e1:v{length}:"
        var prefix = $"3:seqi{timestampStr}e1:v{dnsPacketLengthStr}:";

        // Convert the prefix to bytes
        var prefixBytes = Encoding.ASCII.GetBytes(prefix);

        // Combine prefix bytes with DNS record bytes to get the complete signable data
        var signableData = new byte[prefixBytes.Length + encodedDnsRecords.Length];
        Buffer.BlockCopy(prefixBytes, 0, signableData, 0, prefixBytes.Length);
        Buffer.BlockCopy(encodedDnsRecords, 0, signableData, prefixBytes.Length, encodedDnsRecords.Length);

        return signableData;
    }

    /// <summary>
    ///     Parses a Relay response from the signed packet bytes and optionally verifies the signature.
    /// </summary>
    /// <param name="signedPacketBytes">The byte array containing the signed DNS packet to be parsed.</param>
    /// <param name="nodePublicKey">
    ///     The public key of the node used to verify the packet's signature.
    ///     If null, signature validation will be skipped.
    /// </param>
    /// <returns>
    ///     An instance of <see cref="PkarrSignedPacket" /> representing the parsed signed packet
    /// </returns>
    /// <exception cref="Exception">
    ///     Thrown if the signature is invalid and a public key is provided,
    ///     or if any other parsing error occurs.
    /// </exception>
    public static PkarrSignedPacket ParseRelayResponse(byte[] signedPacketBytes, byte[]? nodePublicKey = null)
    {
        // 1. Extract Signature
        var signature = signedPacketBytes.Take(SignatureLength).ToArray();

        // 2. Extract Timestamp (Big Endian)
        var timestampBytes = signedPacketBytes.Skip(SignatureLength).Take(TimestampLength).ToArray();
        if (BitConverter.IsLittleEndian)
            // Reverse bytes if the system architecture is little-endian
            // because the timestamp is specified as Big Endian (Network Byte Order).
            Array.Reverse(timestampBytes);
        var timestampMicroseconds = BitConverter.ToUInt64(timestampBytes, 0);

        // 3. Extract Encoded DNS Records
        var encodedRecords = signedPacketBytes.Skip(HeaderLength).ToArray();

        // Create initial packet without signature validation
        var packet = new PkarrSignedPacket(signature, timestampMicroseconds, encodedRecords, false, nodePublicKey);
        // Get the bencoded signable data as per BEP-0044
        var bencodedData = GetBencodedSignableData(timestampMicroseconds, encodedRecords);
        // Verify signature if public key is provided, will throw if doesn't match
        if (nodePublicKey != null)
            try
            {
                // Verify using NSec
                var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, nodePublicKey, KeyBlobFormat.RawPublicKey);
                packet.SignatureValidated = SignatureAlgorithm.Ed25519.Verify(publicKey, bencodedData, signature);
            }
            catch (Exception ex)
            {
                throw new Exception(
                    $"Error verifying signature of Pkarr signed packet for {ZBase32.Encode(nodePublicKey)}", ex);
            }

        return packet;
    }

    /// <summary>
    /// Creates a signed Pkarr packet ready for publishing to a relay
    /// </summary>
    /// <param name="dnsPacket">The DNS packet to include in the signed packet</param>
    /// <param name="privateKey">The Ed25519 private key in raw format</param>
    /// <param name="publicKey">The corresponding Ed25519 public key in raw format</param>
    /// <returns>The complete signed packet bytes ready for transmission</returns>
    public static byte[] CreateSignedPacket(byte[] dnsPacket, byte[] privateKey, byte[] publicKey)
    {
        if (dnsPacket == null || dnsPacket.Length == 0)
            throw new ArgumentNullException(nameof(dnsPacket), "DNS packet cannot be null or empty");
        
        if (privateKey == null || privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes", nameof(privateKey));
        
        if (publicKey == null || publicKey.Length != 32)
            throw new ArgumentException("Public key must be 32 bytes", nameof(publicKey));

        // Generate current timestamp in microseconds
        ulong timestampMicros = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000;
        
        // Prepare the bencoded data to sign
        byte[] bencodedData = GetBencodedSignableData(timestampMicros, dnsPacket);
        
        try
        {
            // Import the private key
            var keypair = Key.Import(SignatureAlgorithm.Ed25519, privateKey, KeyBlobFormat.RawPrivateKey);
            
            // Sign the bencoded data
            byte[] signature = SignatureAlgorithm.Ed25519.Sign(keypair, bencodedData);
            
            // Create the complete packet: signature + timestamp + dns packet
            using var memoryStream = new MemoryStream(signature.Length + 8 + dnsPacket.Length);
            
            // Write signature (64 bytes)
            memoryStream.Write(signature, 0, signature.Length);
            
            // Write timestamp (8 bytes) in big-endian order
            byte[] timestampBytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(timestampBytes, timestampMicros);
            memoryStream.Write(timestampBytes, 0, timestampBytes.Length);
            
            // Write DNS packet
            memoryStream.Write(dnsPacket, 0, dnsPacket.Length);
            
            return memoryStream.ToArray();
        }
        catch (Exception ex)
        {
            throw new Exception("Failed to create signed packet", ex);
        }
    }

    /// <summary>
    /// Creates a signed TXT record packet for Pkarr
    /// </summary>
    /// <param name="publicKeyZBase32">The public key in ZBase32 format</param>
    /// <param name="privateKey">The private key in raw binary format</param>
    /// <param name="recordName">The name of the TXT record (e.g., "_foo")</param>
    /// <param name="recordValue">The value of the TXT record</param>
    /// <param name="ttl">Time to live in seconds</param>
    /// <returns>The complete signed packet bytes ready for transmission</returns>
    public static byte[] CreateSignedTxtRecord(string publicKeyZBase32, byte[] privateKey, string recordName, string recordValue, uint ttl = 30)
    {
        // Decode the public key from ZBase32
        byte[] publicKey = ZBase32.Decode(publicKeyZBase32);
        
        // Ensure the record name doesn't have a trailing dot
        recordName = recordName.TrimEnd('.');
        
        // Construct the full domain name
        string fullDomain = $"{recordName}.{publicKeyZBase32}";
        
        // Create the DNS packet with the TXT record
        byte[] dnsPacket = DnsPacketEncoder.CreateTxtRecordPacket(fullDomain, recordValue, ttl);
        
        // Sign the packet
        return CreateSignedPacket(dnsPacket, privateKey, publicKey);
    }
    
    /// <summary>
    /// Creates a signed packet with multiple TXT records
    /// </summary>
    /// <param name="publicKeyZBase32">The public key in ZBase32 format</param>
    /// <param name="privateKey">The private key in raw binary format</param>
    /// <param name="records">Dictionary of record names to values</param>
    /// <param name="ttl">Time to live in seconds</param>
    /// <returns>The complete signed packet bytes ready for transmission</returns>
    public static byte[] CreateSignedMultiTxtRecords(string publicKeyZBase32, byte[] privateKey, Dictionary<string, string> records, uint ttl = 30)
    {
        if (records == null || records.Count == 0)
            throw new ArgumentException("Records dictionary cannot be null or empty", nameof(records));
            
        // Decode the public key from ZBase32
        byte[] publicKey = ZBase32.Decode(publicKeyZBase32);
        
        // Process records to include the domain
        var processedRecords = new Dictionary<string, string>();
        foreach (var record in records)
        {
            string recordName = record.Key.TrimEnd('.');
            string fullDomain = $"{recordName}.{publicKeyZBase32}";
            processedRecords[fullDomain] = record.Value;
        }
        
        // Create the DNS packet with multiple TXT records
        byte[] dnsPacket = DnsPacketEncoder.CreateMultiTxtRecordPacket(processedRecords, ttl);
        
        // Sign the packet
        return CreateSignedPacket(dnsPacket, privateKey, publicKey);
    }
    
    /// <summary>
    /// Checks if the public key in a response packet matches the expected public key
    /// </summary>
    /// <param name="packet">The parsed signed packet</param>
    /// <param name="expectedPublicKey">The expected public key in raw binary format</param>
    /// <returns>True if the keys match, false otherwise</returns>
    public static bool VerifyPublicKey(PkarrSignedPacket packet, byte[] expectedPublicKey)
    {
        if (packet == null)
            throw new ArgumentNullException(nameof(packet));
            
        if (expectedPublicKey == null || expectedPublicKey.Length != 32)
            throw new ArgumentException("Expected public key must be 32 bytes", nameof(expectedPublicKey));
            
        if (packet.NodePublicKey == null)
            return false;
            
        return expectedPublicKey.SequenceEqual(packet.NodePublicKey);
    }
}