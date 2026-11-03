import Foundation
import XCTest
@testable import SwiftXTEA

final class XTEATests: XCTestCase {
    func testEncryptsZeroBlockWithZeroKey() throws {
        let cipher = try XTEA(key: Data(repeating: 0, count: 16))
        let encrypted = try cipher.encrypt(block: Data(repeating: 0, count: 8))

        XCTAssertEqual(encrypted.hex, "dee9d4d8f7131ed9")
    }

    func testDecryptsZeroVector() throws {
        let cipher = try XTEA(key: Data(repeating: 0, count: 16))
        let plaintext = try cipher.decrypt(block: Data(hex: "dee9d4d8f7131ed9"))

        XCTAssertEqual(plaintext, Data(repeating: 0, count: 8))
    }

    func testKnownAnswerVector() throws {
        let cipher = try XTEA(key: Data(hex: "000102030405060708090a0b0c0d0e0f"))
        let encrypted = try cipher.encrypt(block: Data("ABCDEFGH".utf8))

        XCTAssertEqual(encrypted.hex, "497df3d072612cb5")
    }

    func testEncryptsAllOnesVector() throws {
        let cipher = try XTEA(key: Data(repeating: 0xff, count: 16))
        let encrypted = try cipher.encrypt(block: Data(repeating: 0xff, count: 8))

        XCTAssertEqual(encrypted.hex, "28fc2891e623566a")
    }

    func testDecryptsAllOnesVector() throws {
        let cipher = try XTEA(key: Data(repeating: 0xff, count: 16))
        let plaintext = try cipher.decrypt(block: Data(hex: "28fc2891e623566a"))

        XCTAssertEqual(plaintext, Data(repeating: 0xff, count: 8))
    }

    func testWordAPIEncryptMatchesDataAPI() throws {
        let key = Data(hex: "000102030405060708090a0b0c0d0e0f")
        let cipher = try XTEA(key: key)
        let words: [UInt32] = [0x41424344, 0x45464748]
        let result = try XTEA.encrypt(v0: words[0], v1: words[1], key: [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f])
        let bytes = try cipher.encrypt(block: Data("ABCDEFGH".utf8))
        let expectedV0 = bytes.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let expectedV1 = bytes.suffix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        XCTAssertEqual(result.v0, expectedV0)
        XCTAssertEqual(result.v1, expectedV1)
        // Independent expected result from the original Python XTEA snippet.
        XCTAssertEqual(result.v0, 0x497df3d0)
        XCTAssertEqual(result.v1, 0x72612cb5)
    }

    func testWordAPIEncryptDecryptRoundTrip() throws {
        let key: [UInt32] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff]
        let encrypted = try XTEA.encrypt(v0: 0x31323334, v1: 0x35363738, key: key)
        let decrypted = try XTEA.decrypt(v0: encrypted.v0, v1: encrypted.v1, key: key)
        XCTAssertEqual(decrypted.v0, 0x31323334)
        XCTAssertEqual(decrypted.v1, 0x35363738)
    }

    func testWordAPIRejectsInvalidKeyAndRounds() {
        XCTAssertThrowsError(try XTEA.encrypt(v0: 0, v1: 0, key: [0, 1, 2])) { error in
            XCTAssertEqual(error as? XTEA.Error, .invalidKeyWordCount)
        }
        XCTAssertThrowsError(try XTEA.encrypt(v0: 0, v1: 0, key: [0, 1, 2, 3], rounds: -1)) { error in
            XCTAssertEqual(error as? XTEA.Error, .invalidRoundCount)
        }
    }

    func testRoundTrip() throws {
        let key = Data(hex: "00112233445566778899aabbccddeeff")
        let block = Data("12345678".utf8)
        let cipher = try XTEA(key: key)

        XCTAssertEqual(try cipher.decrypt(block: cipher.encrypt(block: block)), block)
    }

    func testRejectsInvalidKeyLength() {
        XCTAssertThrowsError(try XTEA(key: Data(repeating: 0, count: 15))) { error in
            XCTAssertEqual(error as? XTEA.Error, .invalidKeyLength)
        }
    }

    func testRejectsInvalidBlockLength() throws {
        let cipher = try XTEA(key: Data(repeating: 0, count: 16))

        XCTAssertThrowsError(try cipher.encrypt(block: Data(repeating: 0, count: 7))) { error in
            XCTAssertEqual(error as? XTEA.Error, .invalidBlockLength)
        }
        XCTAssertThrowsError(try cipher.decrypt(block: Data(repeating: 0, count: 9))) { error in
            XCTAssertEqual(error as? XTEA.Error, .invalidBlockLength)
        }
    }
}

private extension Data {
    init(hex: String) {
        self.init(stride(from: 0, to: hex.count, by: 2).map { index in
            let start = hex.index(hex.startIndex, offsetBy: index)
            let end = hex.index(start, offsetBy: 2)
            return UInt8(hex[start..<end], radix: 16)!
        })
    }

    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
