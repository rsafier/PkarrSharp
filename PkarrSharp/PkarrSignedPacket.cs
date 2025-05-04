using System.Text;
using NSec.Cryptography;

namespace PkarrSharp; // Or your preferred namespace

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
    ///     Parses the Base64 encoded payload from a pkarr TXT record.
    /// </summary>
    /// <param name="base64Payload">The Base64 encoded string (the value after "pkarr=").</param>
    /// <returns>A PkarrSignedPacket instance containing the parsed data.</returns>
    /// <exception cref="ArgumentNullException">Thrown if base64Payload is null or empty.</exception>
    /// <exception cref="ArgumentException">Thrown if the payload is invalid Base64 or too short.</exception>
    public static PkarrSignedPacket Parse(byte[] signedPacketBytes, byte[]? nodePublicKey = null)
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
        // Verify signature if public key is provided
        if (nodePublicKey != null)
            try
            {
                // Verify using NSec
                var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, nodePublicKey, KeyBlobFormat.RawPublicKey);
                packet.SignatureValidated = SignatureAlgorithm.Ed25519.Verify(publicKey, bencodedData, signature);
            }
            catch (Exception ex)
            {
                // Log verification error
                Console.WriteLine($"Signature verification error: {ex.Message}");
                packet.SignatureValidated = false;
            }

        return packet;
    }
}