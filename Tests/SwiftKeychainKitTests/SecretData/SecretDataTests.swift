@testable import SwiftKeychainKit
import Foundation
import Testing

@Suite("SecretData Tests")
struct SecretDataTests {
    // MARK: - makeByCopying Tests

    @Test("makeByCopying copies bytes from buffer pointer")
    func makeByCopyingCopiesBytes() throws {
        let originalData = "test password".data(using: .utf8)!
        
        try originalData.withUnsafeBytes { buffer in
            let secret = try SecretData.makeByCopying(from: buffer)

            let retrievedData = secret.withUnsafeBytes { buffer in
                Data(bytes: buffer.baseAddress!, count: buffer.count)
            }
            
            #expect(retrievedData == originalData)
        }
    }

    @Test("makeByCopying throws emptyBuffer for empty buffer")
    func makeByCopyingThrowsEmptyBuffer() {
        let emptyBuffer = UnsafeRawBufferPointer(start: nil, count: 0)

        #expect(throws: SecretDataError.emptyBuffer) {
            _ = try SecretData.makeByCopying(from: emptyBuffer)
        }
    }

    // MARK: - init(count:initializer:) Tests

    @Test("init(count:initializer:) initializes buffer with closure")
    func initCountInitializerInitializesBuffer() throws {
        let testBytes: [UInt8] = [1, 2, 3, 4, 5]
        let secret = try SecretData(count: testBytes.count) { buffer in
            for (index, byte) in testBytes.enumerated() {
                buffer[index] = byte
            }
        }

        let retrievedBytes = secret.withUnsafeBytes { buffer in
            Array(buffer)
        }

        #expect(retrievedBytes == testBytes)
    }

    @Test("init(count:initializer:) throws emptyBuffer for zero count")
    func initCountInitializerThrowsEmptyBuffer() {
        #expect(throws: SecretDataError.emptyBuffer) {
            _ = try SecretData(count: 0) { _ in }
        }
    }

    @Test("init(count:initializer:) rethrows initializer errors")
    func initCountInitializerRethrowsErrors() {
        struct TestError: Error, Equatable {}

        #expect(throws: TestError()) {
            _ = try SecretData(count: 10) { _ in
                throw TestError()
            }
        }
    }

    @Test("init(count:initializer:) pre-zeros buffer")
    func initCountInitializerPreZerosBuffer() throws {
        let secret = try SecretData(count: 10) { buffer in
            // Don't initialize - verify buffer is pre-zeroed
        }

        let bytes = secret.withUnsafeBytes { buffer in
            Array(buffer)
        }

        #expect(bytes.allSatisfy { $0 == 0 })
    }

    // MARK: - init(copyingAndWiping:) Tests

    @Test("makeByCopyingAndWiping copies and wipes source")
    func makeByCopyingAndWipingCopiesAndWipes() throws {
        let originalBytes: [UInt8] = [1, 2, 3, 4, 5]
        let mutableData = NSMutableData(bytes: originalBytes, length: originalBytes.count)

        let secret = try SecretData.makeByCopyingAndWiping(unsafeData: mutableData)

        // Verify data was copied correctly
        let retrievedBytes = secret.withUnsafeBytes { buffer in
            Array(buffer)
        }
        #expect(retrievedBytes == originalBytes)

        // Verify source was wiped
        let wipedBytes = Array(UnsafeBufferPointer(
            start: mutableData.bytes.assumingMemoryBound(to: UInt8.self),
            count: mutableData.length
        ))
        #expect(wipedBytes.allSatisfy { $0 == 0 })
    }

    @Test("makeByCopyingAndWiping throws emptyBuffer for empty data")
    func initCopyingAndWipingThrowsEmptyBuffer() {
        let emptyData = NSMutableData()

        #expect(throws: SecretDataError.emptyBuffer) {
            _ = try SecretData.makeByCopyingAndWiping(unsafeData: emptyData)
        }
    }

    // MARK: - withUnsafeBytes Tests

    @Test("withUnsafeBytes rethrows errors")
    func withUnsafeBytesRethrowsErrors() throws {
        struct TestError: Error, Equatable {}
        let secret = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")

        #expect(throws: TestError()) {
            try secret.withUnsafeBytes { _ in
                throw TestError()
            }
        }
    }

    // MARK: - makeUnsafeData Tests

    @Test("makeUnsafeData returns Data with same bytes")
    func makeUnsafeDataReturnsSameBytes() throws {
        let originalBytes: [UInt8] = [1, 2, 3, 4, 5]
        let secret = try SecretData(count: originalBytes.count) { buffer in
            for (index, byte) in originalBytes.enumerated() {
                buffer[index] = byte
            }
        }

        let data = secret.makeUnsafeData()

        #expect(Array(data) == originalBytes)
    }

    @Test("makeUnsafeData with UTF-8 string")
    func makeUnsafeDataWithUTF8String() throws {
        let testString = "test password"
        let secret = try SecretData.makeByCopyingUTF8(fromUnsafeString: testString)

        let data = secret.makeUnsafeData()

        #expect(data == testString.data(using: .utf8)!)
    }

    // MARK: - makeUnsafeUTF8String Tests

    @Test("makeUnsafeUTF8String returns string for valid UTF-8")
    func makeUnsafeUTF8StringReturnsValidString() throws {
        let testString = "test password"
        let secret = try SecretData.makeByCopyingUTF8(fromUnsafeString: testString)

        let string = secret.makeUnsafeUTF8String()

        #expect(string == testString)
    }

    @Test("makeUnsafeUTF8String returns nil for invalid UTF-8")
    func makeUnsafeUTF8StringReturnsNilForInvalidUTF8() throws {
        // Invalid UTF-8 sequence
        let invalidBytes: [UInt8] = [0xFF, 0xFE, 0xFD]
        let secret = try SecretData(count: invalidBytes.count) { buffer in
            for (index, byte) in invalidBytes.enumerated() {
                buffer[index] = byte
            }
        }

        let string = secret.makeUnsafeUTF8String()

        #expect(string == nil)
    }

    @Test("makeUnsafeUTF8String with special characters")
    func makeUnsafeUTF8StringWithSpecialCharacters() throws {
        let testString = "test 🔐 password 日本語"
        let secret = try SecretData.makeByCopyingUTF8(fromUnsafeString: testString)

        let string = secret.makeUnsafeUTF8String()

        #expect(string == testString)
    }
}
