# Pkarr FFI Library - warning this is still mostly AI generated slop but works.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Overview

Pkarr is a Foreign Function Interface (FFI) library that provides a Rust-based backend for resolving and publishing DNS records using the Pkarr protocol. This library is designed to be used in conjunction with other languages (such as C#) by exposing a C-compatible interface. It supports keypair generation, DNS record resolution, and publishing signed DNS packets.

## Features

- **Initialization and Shutdown**: Initialize the library runtime with `pkarr_init()` and clean up resources with `pkarr_shutdown()`.
- **DNS Resolution**: Resolve DNS records for a given public key with `pkarr_resolve()`, supporting options for fetching the most recent records.
- **Keypair Generation**: Generate a public/private keypair for use in signing DNS records with `pkarr_generate_keypair()`.
- **Publishing DNS Records**: Publish signed DNS TXT records using `pkarr_publish()` with a provided public/private keypair.
- **Memory Management**: Provides utility functions like `pkarr_free_result()` and `pkarr_free_signed_packet_ffi()` to manage memory allocation across FFI boundaries.

## Building the Library

This project uses Cargo, the Rust package manager, to build the library. A build script is provided to automate the process of building the Rust library and copying it to the C# test project.

```bash
./build.sh
```

The compiled library will be available in the `target/release/` directory as `libpkarr_ffi.dylib` (on macOS), `libpkarr_ffi.so` (on Linux), or `pkarr_ffi.dll` (on Windows), and will be copied to the `tests` directory for use in the C# project.

## Usage

### Prerequisites

- Rust and Cargo must be installed on your system to build the library.
- A compatible runtime environment for linking the library in your target language (e.g., C# with P/Invoke).

### Integration

The library exposes a C-compatible API that can be called from other languages. Below is an example of how to integrate with C# using P/Invoke:

```csharp
[DllImport("libpkarr_ffi.dylib", EntryPoint = "pkarr_init")]
public static extern IntPtr PkarrInit();

[DllImport("libpkarr_ffi.dylib", EntryPoint = "pkarr_shutdown")]
public static extern void PkarrShutdown();

[DllImport("libpkarr_ffi.dylib", EntryPoint = "pkarr_resolve")]
public static extern ResolveResult PkarrResolve(IntPtr publicKeyStr, bool mostRecent);

// Additional P/Invoke declarations as needed
```

### API Documentation

- `pkarr_init()`: Initializes the library runtime. Must be called before any other functions. Returns an error message if initialization fails.
- `pkarr_shutdown()`: Shuts down the library runtime and cleans up resources.
- `pkarr_resolve(public_key_str, most_recent)`: Resolves DNS records for the given public key. If `most_recent` is true, it fetches the latest records.
- `pkarr_generate_keypair()`: Generates a new public/private keypair for signing DNS records.
- `pkarr_publish(public_key_str, private_key_str, txt_key, txt_value)`: Publishes a signed DNS TXT record for the given keypair.
- Memory management functions to free allocated resources after use.

## Testing

The repository includes a test suite written in C# to validate the functionality of the library. To run the tests:

1. Build the library and copy it to the test directory using `./build.sh`.
2. Run the tests from the root directory with `dotnet test tests/PkarrTests.csproj`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an issue for any bugs or feature requests.
