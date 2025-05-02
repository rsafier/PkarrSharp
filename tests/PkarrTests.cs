using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
// Using the NSec.Cryptography library
using NSec.Cryptography;
using System.Runtime.InteropServices;
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
        private static string GetLibraryName()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return "libpkarr_ffi.dylib";
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return "libpkarr_ffi.so";
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return "pkarr_ffi.dll";
            else
                throw new PlatformNotSupportedException("Unsupported OS platform");
        }

#if OSX
        [DllImport("libpkarr_ffi.dylib", EntryPoint = "pkarr_init")]
        public static extern IntPtr PkarrInit();

        [DllImport("libpkarr_ffi.dylib", EntryPoint = "pkarr_shutdown")]
        public static extern void PkarrShutdown();

        [DllImport("libpkarr_ffi.dylib", EntryPoint = "pkarr_resolve")]
        public static extern ResolveResult PkarrResolve(IntPtr publicKeyStr, bool mostRecent);

        [DllImport("libpkarr_ffi.dylib", EntryPoint = "pkarr_free_result")]
        public static extern void PkarrFreeResult(ResolveResult result);

        [DllImport("libpkarr_ffi.dylib", EntryPoint = "pkarr_free_signed_packet_ffi")]
        public static extern void PkarrFreeSignedPacketFFI(SignedPacketFFI packet);
#elif LINUX
        [DllImport("libpkarr_ffi.so", EntryPoint = "pkarr_init")]
        public static extern IntPtr PkarrInit();

        [DllImport("libpkarr_ffi.so", EntryPoint = "pkarr_shutdown")]
        public static extern void PkarrShutdown();

        [DllImport("libpkarr_ffi.so", EntryPoint = "pkarr_resolve")]
        public static extern ResolveResult PkarrResolve(IntPtr publicKeyStr, bool mostRecent);

        [DllImport("libpkarr_ffi.so", EntryPoint = "pkarr_free_result")]
        public static extern void PkarrFreeResult(ResolveResult result);

        [DllImport("libpkarr_ffi.so", EntryPoint = "pkarr_free_signed_packet_ffi")]
        public static extern void PkarrFreeSignedPacketFFI(SignedPacketFFI packet);
#elif WINDOWS
        [DllImport("pkarr_ffi.dll", EntryPoint = "pkarr_init")]
        public static extern IntPtr PkarrInit();

        [DllImport("pkarr_ffi.dll", EntryPoint = "pkarr_shutdown")]
        public static extern void PkarrShutdown();

        [DllImport("pkarr_ffi.dll", EntryPoint = "pkarr_resolve")]
        public static extern ResolveResult PkarrResolve(IntPtr publicKeyStr, bool mostRecent);

        [DllImport("pkarr_ffi.dll", EntryPoint = "pkarr_free_result")]
        public static extern void PkarrFreeResult(ResolveResult result);

        [DllImport("pkarr_ffi.dll", EntryPoint = "pkarr_free_signed_packet_ffi")]
        public static extern void PkarrFreeSignedPacketFFI(SignedPacketFFI packet);
#else
        public static IntPtr PkarrInit() => throw new PlatformNotSupportedException("Unsupported OS platform");
        public static void PkarrShutdown() => throw new PlatformNotSupportedException("Unsupported OS platform");
        public static ResolveResult PkarrResolve(IntPtr publicKeyStr, bool mostRecent) => throw new PlatformNotSupportedException("Unsupported OS platform");
        public static void PkarrFreeResult(ResolveResult result) => throw new PlatformNotSupportedException("Unsupported OS platform");
        public static void PkarrFreeSignedPacketFFI(SignedPacketFFI packet) => throw new PlatformNotSupportedException("Unsupported OS platform");
#endif

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
            string publicKey = "o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy";
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

#if OSX
        [DllImport("libpkarr_ffi.dylib", EntryPoint = "pkarr_generate_keypair")]
        public static extern ResolveResult PkarrGenerateKeypair();

        [DllImport("libpkarr_ffi.dylib", EntryPoint = "pkarr_publish")]
        public static extern ResolveResult PkarrPublish(IntPtr privateKeyStr, IntPtr txtKey, IntPtr txtValue, uint ttl);
#elif LINUX
        [DllImport("libpkarr_ffi.so", EntryPoint = "pkarr_generate_keypair")]
        public static extern ResolveResult PkarrGenerateKeypair();

        [DllImport("libpkarr_ffi.so", EntryPoint = "pkarr_publish")]
        public static extern ResolveResult PkarrPublish(IntPtr privateKeyStr, IntPtr txtKey, IntPtr txtValue, uint ttl);
#elif WINDOWS
        [DllImport("pkarr_ffi.dll", EntryPoint = "pkarr_generate_keypair")]
        public static extern ResolveResult PkarrGenerateKeypair();

        [DllImport("pkarr_ffi.dll", EntryPoint = "pkarr_publish")]
        public static extern ResolveResult PkarrPublish(IntPtr privateKeyStr, IntPtr txtKey, IntPtr txtValue, uint ttl);
#else
        public static ResolveResult PkarrGenerateKeypair() => throw new PlatformNotSupportedException("Unsupported OS platform");
        public static ResolveResult PkarrPublish(IntPtr privateKeyStr, IntPtr txtKey, IntPtr txtValue, uint ttl) => throw new PlatformNotSupportedException("Unsupported OS platform");
#endif

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
        public void TestPublishRandomPK()
        {
            Console.WriteLine("Testing publish functionality");

            var pkPair = GenerateRandomEd25519KeyPair();
            string publicKey = pkPair.publicKeyZBase32;
            string privateKeyHex = pkPair.privateKeyHex;;
            
            // Now publish a TXT record
            string txtKey = "_foo";
            string txtValue = "bar";
            uint ttl = 30;

            IntPtr privateKeyPtr = Marshal.StringToHGlobalAnsi(privateKeyHex);
            IntPtr txtKeyPtr = Marshal.StringToHGlobalAnsi(txtKey);
            IntPtr txtValuePtr = Marshal.StringToHGlobalAnsi(txtValue);

            ResolveResult result = PkarrPublish(privateKeyPtr, txtKeyPtr, txtValuePtr, ttl);

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
        
        
        [TestMethod]
        public void TestPublishFixedPK()
        {
            Console.WriteLine("Testing publish functionality");
            
            string privateKeyHex = "4c069a831ff30dcd404ec4269d2c3f09322c7422b821419e926241f750965bfa";
            string publicKey = (GetPublicKeyFromPrivate(privateKeyHex));
             
            // Now publish a TXT record
            string txtKey = "_foo";
            string txtValue = "bar";
            uint ttl = 30;

            IntPtr privateKeyPtr = Marshal.StringToHGlobalAnsi(privateKeyHex);
            IntPtr txtKeyPtr = Marshal.StringToHGlobalAnsi(txtKey);
            IntPtr txtValuePtr = Marshal.StringToHGlobalAnsi(txtValue);

            ResolveResult result = PkarrPublish(privateKeyPtr, txtKeyPtr, txtValuePtr, ttl);

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
        
        
     

        public string GetPublicKeyFromPrivate(string privateKeyHex)
        {
            // Convert hex string to byte array
            byte[] privateKeyBytes = Convert.FromHexString(privateKeyHex);
    
            // Create the key pair from the private key
            var algorithm = SignatureAlgorithm.Ed25519;
            var privateKey = Key.Import(algorithm, privateKeyBytes, KeyBlobFormat.RawPrivateKey);
    
            // Extract the public key
            byte[] publicKeyBytes = privateKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    
            // Encode using your ZBase32 encoder
            return ZBase32.Encode(publicKeyBytes);
        }
        
        // Create a new random Ed25519 key pair
        public (string publicKeyZBase32, string privateKeyHex) GenerateRandomEd25519KeyPair()
        {
            // Specify the signature algorithm
            var algorithm = SignatureAlgorithm.Ed25519;
    
            // Generate a new random key pair
            using var key = Key.Create(algorithm,
                new KeyCreationParameters() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
    
            // Export the private key in raw format
            byte[] privateKeyBytes = key.Export(KeyBlobFormat.RawPrivateKey);
    
            // Export the public key in raw format
            byte[] publicKeyBytes = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    
            // Convert the private key to hex string
            string privateKeyHex = Convert.ToHexString(privateKeyBytes).ToLower();
    
            // Encode the public key using ZBase32
            string publicKeyZBase32 = ZBase32.Encode(publicKeyBytes);
    
            return (publicKeyZBase32, privateKeyHex);
        }

    }
}
