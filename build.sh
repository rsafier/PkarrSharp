#!/bin/bash
set -e

# Build the Rust library
cargo build --release

# Determine the platform and set the library name accordingly
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_NAME="libpkarr_ffi.dylib"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_NAME="libpkarr_ffi.so"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
    LIB_NAME="pkarr_ffi.dll"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

# Copy the library to the tests directory
cp "target/release/$LIB_NAME" "tests/$LIB_NAME"

echo "Build and copy completed successfully."
