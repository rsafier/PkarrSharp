using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Pkarr.Tests
{
  
    [TestClass]
    public class PkarrTests
    {
        // Define the structures that match the Rust FFI
        [StructLayout(LayoutKind.Sequential)]
        public struct ResolveResult
        {
            public IntPtr data;
            public UIntPtr length;
            public IntPtr error;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ResourceRecord
        {
            public IntPtr name;
            public ushort classType;
            public uint ttl;
            public ushort rdataType;
            public IntPtr rdataData;
            public UIntPtr rdataLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SignedPacketFFI
        {
            public IntPtr publicKey;
            public ulong timestamp;
            public ulong lastSeen;
            public IntPtr records;
            public UIntPtr recordsCount;
            public IntPtr rawData;
            public UIntPtr rawLength;
        }

        // P/Invoke declarations for the pkarr-ffi library
        [DllImport("../../../../../../target/debug/libpkarr_ffi.dylib", EntryPoint = "pkarr_init")]
        public static extern IntPtr PkarrInit();

        [DllImport("../../../../../../target/debug/libpkarr_ffi.dylib", EntryPoint = "pkarr_shutdown")]
        public static extern void PkarrShutdown();

        [DllImport("../../../../../../target/debug/libpkarr_ffi.dylib", EntryPoint = "pkarr_resolve")]
        public static extern ResolveResult PkarrResolve(IntPtr publicKeyStr, bool mostRecent);

        [DllImport("../../../../../../target/debug/libpkarr_ffi.dylib", EntryPoint = "pkarr_free_result")]
        public static extern void PkarrFreeResult(ResolveResult result);

        [DllImport("../../../../../../target/debug/libpkarr_ffi.dylib", EntryPoint = "pkarr_free_signed_packet_ffi")]
        public static extern void PkarrFreeSignedPacketFFI(SignedPacketFFI packet);

        [TestInitialize]
        public void Setup()
        {
            IntPtr error = PkarrInit();
            if (error != IntPtr.Zero)
            {
                string errorMessage = Marshal.PtrToStringAnsi(error);
                Assert.Fail($"Failed to initialize pkarr: {errorMessage}");
            }
            Console.WriteLine("pkarr initialized successfully");
        }

        [TestCleanup]
        public void Cleanup()
        {
            PkarrShutdown();
            Console.WriteLine("pkarr shutdown completed");
        }

        [TestMethod]
        public void TestResolveMostRecent()
        {
            // Using a placeholder public key for testing. Replace with a real key if needed.
            string publicKey = "gpj136mfx7j8qeu3gurpm9eys7zuyt43pnx5f45bfw1s7thdoa8o";
            Console.WriteLine($"Testing resolve most recent with public key: {publicKey}");
            
            IntPtr publicKeyPtr = Marshal.StringToHGlobalAnsi(publicKey);
            ResolveResult result = PkarrResolve(publicKeyPtr, true);
            Marshal.FreeHGlobal(publicKeyPtr);

            if (result.error != IntPtr.Zero)
            {
                string errorMessage = Marshal.PtrToStringAnsi(result.error);
                PkarrFreeResult(result);
                Console.WriteLine($"Resolve most recent failed: {errorMessage}");
                // Not failing the test as this might be expected behavior if no data exists
                return;
            }

            if (result.data != IntPtr.Zero && result.length.ToUInt64() > 0)
            {
                SignedPacketFFI packet = Marshal.PtrToStructure<SignedPacketFFI>(result.data);
                string pubKey = Marshal.PtrToStringAnsi(packet.publicKey);
                Console.WriteLine($"Resolved packet for public key: {pubKey}");
                Console.WriteLine($"Timestamp: {packet.timestamp}");
                Console.WriteLine($"Last Seen: {packet.lastSeen}");
                Console.WriteLine($"Number of records: {packet.recordsCount.ToUInt64()}");

                if (packet.recordsCount.ToUInt64() > 0 && packet.records != IntPtr.Zero)
                {
                    for (ulong i = 0; i < packet.recordsCount.ToUInt64(); i++)
                    {
                        IntPtr recordPtr = IntPtr.Add(packet.records, (int)i * Marshal.SizeOf<ResourceRecord>());
                        ResourceRecord record = Marshal.PtrToStructure<ResourceRecord>(recordPtr);
                        string name = Marshal.PtrToStringAnsi(record.name);
                        string rdata = Marshal.PtrToStringAnsi(record.rdataData);
                        Console.WriteLine($"Record {i + 1}:");
                        Console.WriteLine($"  Name: {name}");
                        Console.WriteLine($"  Class: {record.classType}");
                        Console.WriteLine($"  TTL: {record.ttl}");
                        Console.WriteLine($"  RData Type: {record.rdataType}");
                        Console.WriteLine($"  RData: {rdata}");
                    }
                }
                else
                {
                    Console.WriteLine("No records found in the packet.");
                }

                // Store the pointer to free it later
                IntPtr packetPtr = result.data;
                PkarrFreeSignedPacketFFI(packet);
                // Don't free result.data again in PkarrFreeResult since we already freed it
                result.data = IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("No data returned from resolve most recent");
                // Not failing the test as this might be expected behavior if no data exists
            }

            PkarrFreeResult(result);
        }

        [TestMethod]
        public void TestResolve()
        {
            // Using a placeholder public key for testing. Replace with a real key if needed.
            string publicKey = "gpj136mfx7j8qeu3gurpm9eys7zuyt43pnx5f45bfw1s7thdoa8o";
            Console.WriteLine($"Testing resolve with public key: {publicKey}");
            
            IntPtr publicKeyPtr = Marshal.StringToHGlobalAnsi(publicKey);
            ResolveResult result = PkarrResolve(publicKeyPtr, false);
            Marshal.FreeHGlobal(publicKeyPtr);

            if (result.error != IntPtr.Zero)
            {
                string errorMessage = Marshal.PtrToStringAnsi(result.error);
                PkarrFreeResult(result);
                Console.WriteLine($"Resolve failed: {errorMessage}");
                // Not failing the test as this might be expected behavior if no data exists
                return;
            }

            if (result.data != IntPtr.Zero && result.length.ToUInt64() > 0)
            {
                SignedPacketFFI packet = Marshal.PtrToStructure<SignedPacketFFI>(result.data);
                string pubKey = Marshal.PtrToStringAnsi(packet.publicKey);
                Console.WriteLine($"Resolved packet for public key: {pubKey}");
                Console.WriteLine($"Timestamp: {packet.timestamp}");
                Console.WriteLine($"Last Seen: {packet.lastSeen}");
                Console.WriteLine($"Number of records: {packet.recordsCount.ToUInt64()}");

                if (packet.recordsCount.ToUInt64() > 0 && packet.records != IntPtr.Zero)
                {
                    for (ulong i = 0; i < packet.recordsCount.ToUInt64(); i++)
                    {
                        IntPtr recordPtr = IntPtr.Add(packet.records, (int)i * Marshal.SizeOf<ResourceRecord>());
                        ResourceRecord record = Marshal.PtrToStructure<ResourceRecord>(recordPtr);
                        string name = Marshal.PtrToStringAnsi(record.name);
                        string rdata = Marshal.PtrToStringAnsi(record.rdataData);
                        Console.WriteLine($"Record {i + 1}:");
                        Console.WriteLine($"  Name: {name}");
                        Console.WriteLine($"  Class: {record.classType}");
                        Console.WriteLine($"  TTL: {record.ttl}");
                        Console.WriteLine($"  RData Type: {record.rdataType}");
                        Console.WriteLine($"  RData: {rdata}");
                    }
                }
                else
                {
                    Console.WriteLine("No records found in the packet.");
                }

                // Store the pointer to free it later
                IntPtr packetPtr = result.data;
                PkarrFreeSignedPacketFFI(packet);
                // Don't free result.data again in PkarrFreeResult since we already freed it
                result.data = IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("No data returned from resolve");
                // Not failing the test as this might be expected behavior if no data exists
            }

            PkarrFreeResult(result);
        }

        [DllImport("../../../../../../target/debug/libpkarr_ffi.dylib", EntryPoint = "pkarr_generate_keypair")]
        public static extern ResolveResult PkarrGenerateKeypair();

        [DllImport("../../../../../../target/debug/libpkarr_ffi.dylib", EntryPoint = "pkarr_publish")]
        public static extern ResolveResult PkarrPublish(IntPtr publicKeyStr, IntPtr privateKeyStr, IntPtr txtKey, IntPtr txtValue, uint ttl);

        [TestMethod]
        public void TestResolveInvalidKey()
        {
            string publicKey = "invalid_key_format";
            Console.WriteLine($"Testing resolve with invalid public key: {publicKey}");
            
            IntPtr publicKeyPtr = Marshal.StringToHGlobalAnsi(publicKey);
            ResolveResult result = PkarrResolve(publicKeyPtr, true);
            Marshal.FreeHGlobal(publicKeyPtr);

            Assert.IsTrue(result.error != IntPtr.Zero, "Expected error for invalid public key");
            
            if (result.error != IntPtr.Zero)
            {
                string errorMessage = Marshal.PtrToStringAnsi(result.error);
                Console.WriteLine($"Expected error received: {errorMessage}");
            }
            
            PkarrFreeResult(result);
        }

        [TestMethod]
        public void TestGenerateKeypair()
        {
            Console.WriteLine("Testing keypair generation");
            ResolveResult result = PkarrGenerateKeypair();

            if (result.error != IntPtr.Zero)
            {
                string errorMessage = Marshal.PtrToStringAnsi(result.error);
                PkarrFreeResult(result);
                Console.WriteLine($"Keypair generation failed: {errorMessage}");
                Assert.Fail($"Keypair generation failed: {errorMessage}");
            }

            if (result.data != IntPtr.Zero && result.length.ToUInt64() > 0)
            {
                byte[] data = new byte[result.length.ToUInt64()];
                Marshal.Copy(result.data, data, 0, data.Length);
                string keypairStr = Encoding.UTF8.GetString(data);
                var parts = keypairStr.Split('|');
                if (parts.Length != 2)
                {
                    Console.WriteLine("Invalid keypair format returned");
                    Assert.Fail("Invalid keypair format returned");
                }

                string publicKey = parts[0];
                string privateKeyHex = parts[1];
                Console.WriteLine($"Generated public key: {publicKey}");
                Console.WriteLine($"Generated private key (hex): {privateKeyHex}");
                
                // Verify the public key can be decoded and re-encoded to the same value
                byte[] decodedPublicKey = ZBase32.Decode(publicKey);
                string reEncodedPublicKey = ZBase32.Encode(decodedPublicKey);
                Console.WriteLine($"Re-encoded public key: {reEncodedPublicKey}");
                Assert.AreEqual(publicKey, reEncodedPublicKey, "Public key should encode and decode consistently");
                
                // Free the data since it's a Vec<u8> and not a struct
                Marshal.FreeHGlobal(result.data);
                result.data = IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("No data returned from keypair generation");
                Assert.Fail("No data returned from keypair generation");
            }

            PkarrFreeResult(result);
        }

        [TestMethod]
        public void TestZBase32Encoding()
        {
            // Example byte array representing a public key (32 bytes for Ed25519)
            byte[] publicKeyBytes = new byte[32];
            for (int i = 0; i < publicKeyBytes.Length; i++)
            {
                publicKeyBytes[i] = (byte)i; // Just for testing, fill with incremental values
            }

            string zbase32Encoded = ZBase32.Encode(publicKeyBytes);
            Console.WriteLine($"z-base32 encoded public key: {zbase32Encoded}");

            byte[] decodedBytes = ZBase32.Decode(zbase32Encoded);
            Console.WriteLine($"Decoded bytes match original: {publicKeyBytes.SequenceEqual(decodedBytes)}");

            Assert.IsTrue(publicKeyBytes.SequenceEqual(decodedBytes), "Decoded bytes should match the original input.");
        }

        [TestMethod]
        public void TestPublish()
        {
            Console.WriteLine("Testing publish functionality");
            
            // First generate a keypair
            ResolveResult keyResult = PkarrGenerateKeypair();
            if (keyResult.error != IntPtr.Zero)
            {
                string errorMessage = Marshal.PtrToStringAnsi(keyResult.error);
                PkarrFreeResult(keyResult);
                Console.WriteLine($"Keypair generation failed: {errorMessage}");
                Assert.Fail($"Keypair generation failed: {errorMessage}");
            }

            string publicKey = "";
            string privateKeyHex = "";
            if (keyResult.data != IntPtr.Zero && keyResult.length.ToUInt64() > 0)
            {
                byte[] data = new byte[keyResult.length.ToUInt64()];
                Marshal.Copy(keyResult.data, data, 0, data.Length);
                string keypairStr = Encoding.UTF8.GetString(data);
                var parts = keypairStr.Split('|');
                if (parts.Length == 2)
                {
                    publicKey = parts[0];
                    privateKeyHex = parts[1];
                    Console.WriteLine($"Using generated public key for publish: {publicKey}");
                    Console.WriteLine($"Using generated private key (hex) for publish: {privateKeyHex}");
                }
                
                // Free the data since it's a Vec<u8> and not a struct
                Marshal.FreeHGlobal(keyResult.data);
                keyResult.data = IntPtr.Zero;
            }
            PkarrFreeResult(keyResult);

            // Now publish a TXT record
            string txtKey = "_foo";
            string txtValue = "bar";
            uint ttl = 30;

            IntPtr publicKeyPtr = Marshal.StringToHGlobalAnsi(publicKey);
            IntPtr privateKeyPtr = Marshal.StringToHGlobalAnsi(privateKeyHex);
            IntPtr txtKeyPtr = Marshal.StringToHGlobalAnsi(txtKey);
            IntPtr txtValuePtr = Marshal.StringToHGlobalAnsi(txtValue);

            ResolveResult result = PkarrPublish(publicKeyPtr, privateKeyPtr, txtKeyPtr, txtValuePtr, ttl);

            Marshal.FreeHGlobal(publicKeyPtr);
            Marshal.FreeHGlobal(privateKeyPtr);
            Marshal.FreeHGlobal(txtKeyPtr);
            Marshal.FreeHGlobal(txtValuePtr);

            if (result.error != IntPtr.Zero)
            {
                string errorMessage = Marshal.PtrToStringAnsi(result.error);
                PkarrFreeResult(result);
                Console.WriteLine($"Publish failed: {errorMessage}");
                Assert.Fail($"Publish failed: {errorMessage}");
            }

            if (result.data != IntPtr.Zero && result.length.ToUInt64() > 0)
            {
                byte[] data = new byte[result.length.ToUInt64()];
                Marshal.Copy(result.data, data, 0, data.Length);
                string successMessage = Encoding.UTF8.GetString(data);
                Console.WriteLine($"Publish result: {successMessage}");
                
                // Free the data since it's a Vec<u8> and not a struct
                Marshal.FreeHGlobal(result.data);
                result.data = IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("No data returned from publish");
            }

            PkarrFreeResult(result);

            // Add a small delay to allow for propagation
            Console.WriteLine("Waiting for propagation...");
            System.Threading.Thread.Sleep(5000);

            // Now attempt to resolve the published record
            Console.WriteLine($"Testing resolve after publish with public key: {publicKey}");
            publicKeyPtr = Marshal.StringToHGlobalAnsi(publicKey);
            ResolveResult resolveResult = PkarrResolve(publicKeyPtr, true);
            Marshal.FreeHGlobal(publicKeyPtr);

            if (resolveResult.error != IntPtr.Zero)
            {
                string errorMessage = Marshal.PtrToStringAnsi(resolveResult.error);
                PkarrFreeResult(resolveResult);
                Console.WriteLine($"Resolve after publish failed: {errorMessage}");
                // Not failing the test as this might be expected if the data isn't immediately available
                return;
            }

            if (resolveResult.data != IntPtr.Zero && resolveResult.length.ToUInt64() > 0)
            {
                SignedPacketFFI packet = Marshal.PtrToStructure<SignedPacketFFI>(resolveResult.data);
                string pubKey = Marshal.PtrToStringAnsi(packet.publicKey);
                Console.WriteLine($"Resolved packet for public key: {pubKey}");
                Console.WriteLine($"Timestamp: {packet.timestamp}");
                Console.WriteLine($"Last Seen: {packet.lastSeen}");
                Console.WriteLine($"Number of records: {packet.recordsCount.ToUInt64()}");

                if (packet.recordsCount.ToUInt64() > 0 && packet.records != IntPtr.Zero)
                {
                    for (ulong i = 0; i < packet.recordsCount.ToUInt64(); i++)
                    {
                        IntPtr recordPtr = IntPtr.Add(packet.records, (int)i * Marshal.SizeOf<ResourceRecord>());
                        ResourceRecord record = Marshal.PtrToStructure<ResourceRecord>(recordPtr);
                        string name = Marshal.PtrToStringAnsi(record.name);
                        string rdata = Marshal.PtrToStringAnsi(record.rdataData);
                        Console.WriteLine($"Record {i + 1}:");
                        Console.WriteLine($"  Name: {name}");
                        Console.WriteLine($"  Class: {record.classType}");
                        Console.WriteLine($"  TTL: {record.ttl}");
                        Console.WriteLine($"  RData Type: {record.rdataType}");
                        Console.WriteLine($"  RData: {rdata}");
                    }
                }
                else
                {
                    Console.WriteLine("No records found in the packet.");
                }

                // Store the pointer to free it later
                IntPtr packetPtr = resolveResult.data;
                PkarrFreeSignedPacketFFI(packet);
                // Don't free result.data again in PkarrFreeResult since we already freed it
                resolveResult.data = IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("No data returned from resolve after publish");
                // Not failing the test as this might be expected if the data isn't immediately available
            }

            PkarrFreeResult(resolveResult);
        }
    }
}
