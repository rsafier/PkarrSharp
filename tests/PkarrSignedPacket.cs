using System;
using System.Linq;
using Org.BouncyCastle.Utilities;

namespace PkarrTests // Or your preferred namespace
{
    /// <summary>
    /// Represents the decoded content of a pkarr HTTP response
    /// </summary>
    public class PkarrSignedPacket
    {
        /// <summary>
        /// The Ed25519 signature (64 bytes).
        /// </summary>
        public byte[] Signature { get; private set; }

        /// <summary>
        /// Timestamp in microseconds since the Unix epoch (1970-01-01T00:00:00Z).
        /// </summary>
        public ulong TimestampMicroseconds { get; private set; }

        /// <summary>
        /// The timestamp converted to a DateTimeOffset.
        /// </summary>
        public DateTimeOffset Timestamp { get; private set; }

        /// <summary>
        /// The raw bytes of the inner, encoded DNS message.
        /// </summary>
        public byte[] EncodedDnsRecords { get; private set; }

        private const int SignatureLength = 64;
        private const int TimestampLength = 8;
        private const int HeaderLength = SignatureLength + TimestampLength;

        // Private constructor to ensure usage via the Parse factory method
        private PkarrSignedPacket(byte[] signature, ulong timestampMicroseconds, byte[] encodedDnsRecords)
        {
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            TimestampMicroseconds = timestampMicroseconds;
            // Convert microseconds to milliseconds for DateTimeOffset
            Timestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)(timestampMicroseconds / 1000));
            EncodedDnsRecords = encodedDnsRecords ?? throw new ArgumentNullException(nameof(encodedDnsRecords));
        }

        /// <summary>
        /// Parses the Base64 encoded payload from a pkarr TXT record.
        /// </summary>
        /// <param name="base64Payload">The Base64 encoded string (the value after "pkarr=").</param>
        /// <returns>A PkarrSignedPacket instance containing the parsed data.</returns>
        /// <exception cref="ArgumentNullException">Thrown if base64Payload is null or empty.</exception>
        /// <exception cref="ArgumentException">Thrown if the payload is invalid Base64 or too short.</exception>
        public static PkarrSignedPacket Parse(byte[] signedPacketBytes)
        {
             
           
            // 1. Extract Signature
            byte[] signature = signedPacketBytes.Take(SignatureLength).ToArray();

            // 2. Extract Timestamp (Big Endian)
            byte[] timestampBytes = signedPacketBytes.Skip(SignatureLength).Take(TimestampLength).ToArray();
            if (BitConverter.IsLittleEndian)
            {
                // Reverse bytes if the system architecture is little-endian
                // because the timestamp is specified as Big Endian (Network Byte Order).
                Array.Reverse(timestampBytes);
            }
            ulong timestampMicroseconds = BitConverter.ToUInt64(timestampBytes, 0);

            // 3. Extract Encoded DNS Records
            byte[] encodedRecords = signedPacketBytes.Skip(HeaderLength).ToArray();

            return new PkarrSignedPacket(signature, timestampMicroseconds, encodedRecords);
        }
    }
}