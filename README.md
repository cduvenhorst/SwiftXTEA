# SwiftXTEA

A small, dependency-free Swift implementation of the XTEA block cipher.

## Features

- XTEA with 32 rounds
- 64-bit block size and 128-bit key
- Big-endian byte representation
- Single-block encryption and decryption
- Input-length validation

## Usage

```swift
import SwiftXTEA
import Foundation

let key = Data(repeating: 0, count: 16)
let plaintext = Data(repeating: 0, count: 8)

let xtea = try XTEA(key: key)
let ciphertext = try xtea.encrypt(block: plaintext)
let decrypted = try xtea.decrypt(block: ciphertext)
```

## Testing

Run the test suite with:

```sh
swift test
```

The tests include known-answer vectors, a round-trip test, and invalid-length checks.

## Security note

XTEA is a legacy, unauthenticated block cipher with a 64-bit block size. This package provides the primitive only; it does not provide a secure mode of operation, padding, or authentication. Do not use it for new security-sensitive systems. Prefer authenticated encryption such as AES-GCM or ChaCha20-Poly1305.

## License

MIT
