import Foundation

/// XTEA (eXtended Tiny Encryption Algorithm).
///
/// XTEA operates on 64-bit blocks with a 128-bit key and 32 rounds.
/// It is a legacy block cipher; new systems should generally use an
/// authenticated encryption algorithm such as AES-GCM or ChaCha20-Poly1305.
public struct XTEA: Sendable {
    public enum Error: Swift.Error, Equatable {
        case invalidKeyLength
        case invalidBlockLength
    }

    private static let delta: UInt32 = 0x9E3779B9
    private let key: [UInt32]

    /// Creates an XTEA instance using a 16-byte key.
    /// Key words are interpreted in big-endian byte order.
    public init(key: Data) throws {
        guard key.count == 16 else {
            throw Error.invalidKeyLength
        }

        let bytes = Array(key)
        self.key = stride(from: 0, to: 16, by: 4).map { offset in
            (UInt32(bytes[offset]) << 24)
                | (UInt32(bytes[offset + 1]) << 16)
                | (UInt32(bytes[offset + 2]) << 8)
                | UInt32(bytes[offset + 3])
        }
    }

    /// Encrypts one 8-byte block. The result uses big-endian byte order.
    public func encrypt(block: Data) throws -> Data {
        try transform(block: block, decrypt: false)
    }

    /// Decrypts one 8-byte block. The input uses big-endian byte order.
    public func decrypt(block: Data) throws -> Data {
        try transform(block: block, decrypt: true)
    }

    private func transform(block: Data, decrypt: Bool) throws -> Data {
        guard block.count == 8 else {
            throw Error.invalidBlockLength
        }

        let bytes = Array(block)
        var v0 = readWord(bytes, at: 0)
        var v1 = readWord(bytes, at: 4)

        if decrypt {
            var sum = Self.delta &* 32
            for _ in 0..<32 {
                v1 = v1 &- ((((v0 << 4) ^ (v0 >> 5)) &+ v0) ^ (sum &+ key[Int((sum >> 11) & 3)]))
                sum = sum &- Self.delta
                v0 = v0 &- ((((v1 << 4) ^ (v1 >> 5)) &+ v1) ^ (sum &+ key[Int(sum & 3)]))
            }
        } else {
            var sum: UInt32 = 0
            for _ in 0..<32 {
                v0 = v0 &+ ((((v1 << 4) ^ (v1 >> 5)) &+ v1) ^ (sum &+ key[Int(sum & 3)]))
                sum = sum &+ Self.delta
                v1 = v1 &+ ((((v0 << 4) ^ (v0 >> 5)) &+ v0) ^ (sum &+ key[Int((sum >> 11) & 3)]))
            }
        }

        return Data([
            UInt8(truncatingIfNeeded: v0 >> 24),
            UInt8(truncatingIfNeeded: v0 >> 16),
            UInt8(truncatingIfNeeded: v0 >> 8),
            UInt8(truncatingIfNeeded: v0),
            UInt8(truncatingIfNeeded: v1 >> 24),
            UInt8(truncatingIfNeeded: v1 >> 16),
            UInt8(truncatingIfNeeded: v1 >> 8),
            UInt8(truncatingIfNeeded: v1)
        ])
    }

    private func readWord(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
    }
}
