@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("KeyClass Tests")
struct KeyClassTests {
    // MARK: - make(for: CFString) Tests

    @Test(
        "make(for:CFString) returns expected result",
        arguments: [
            CFStringTestCase("public key", kSecAttrKeyClassPublic, expected: .publicKey),
            CFStringTestCase("private key", kSecAttrKeyClassPrivate, expected: .privateKey),
            CFStringTestCase("symmetric key", kSecAttrKeyClassSymmetric, expected: .symmetric),
            CFStringTestCase("unknown value", "unknown-key-class" as CFString, expected: nil),
        ]
    )
    func makeForCFStringReturnsExpectedResult(testCase: CFStringTestCase) {
        let keyClass = Keychain.Keys.KeyClass.make(for: testCase.keychainValue)
        #expect(keyClass == testCase.expected)
    }

    // MARK: - make(for: NSNumber) Tests

    @Test(
        "make(for:NSNumber) returns expected result",
        arguments: [
            NSNumberTestCase("public key", NSNumber(value: 0), expected: .publicKey),
            NSNumberTestCase("private key", NSNumber(value: 1), expected: .privateKey),
            NSNumberTestCase("symmetric key", NSNumber(value: 2), expected: .symmetric),
            NSNumberTestCase("unknown numeric value", NSNumber(value: 999), expected: nil),
        ]
    )
    func makeForNSNumberReturnsExpectedResult(testCase: NSNumberTestCase) {
        let keyClass = Keychain.Keys.KeyClass.make(for: testCase.keychainValue)
        #expect(keyClass == testCase.expected)
    }

    // MARK: - get(from:) Tests

    @Test(
        "get(from:) with NSNumber value returns expected result",
        arguments: [
            DictionaryTestCase(
                "public key as NSNumber",
                [kSecAttrKeyClass as String: NSNumber(value: 0)],
                expected: .publicKey
            ),
            DictionaryTestCase(
                "private key as NSNumber",
                [kSecAttrKeyClass as String: NSNumber(value: 1)],
                expected: .privateKey
            ),
            DictionaryTestCase(
                "symmetric key as NSNumber",
                [kSecAttrKeyClass as String: NSNumber(value: 2)],
                expected: .symmetric
            ),
        ]
    )
    func getFromDictionaryWithNSNumberReturnsExpectedResult(testCase: DictionaryTestCase) {
        let keyClass = Keychain.Keys.KeyClass.get(from: testCase.dictionary)
        #expect(keyClass == testCase.expected)
    }

    @Test(
        "get(from:) with String value returns expected result",
        arguments: [
            DictionaryTestCase(
                "public key as String",
                [kSecAttrKeyClass as String: kSecAttrKeyClassPublic as String],
                expected: .publicKey
            ),
            DictionaryTestCase(
                "private key as String",
                [kSecAttrKeyClass as String: kSecAttrKeyClassPrivate as String],
                expected: .privateKey
            ),
            DictionaryTestCase(
                "symmetric key as String",
                [kSecAttrKeyClass as String: kSecAttrKeyClassSymmetric as String],
                expected: .symmetric
            ),
        ]
    )
    func getFromDictionaryWithStringReturnsExpectedResult(testCase: DictionaryTestCase) {
        let keyClass = Keychain.Keys.KeyClass.get(from: testCase.dictionary)
        #expect(keyClass == testCase.expected)
    }

    @Test(
        "get(from:) returns nil for invalid inputs",
        arguments: [
            DictionaryTestCase("missing key", [:], expected: nil),
            DictionaryTestCase(
                "wrong type",
                [kSecAttrKeyClass as String: [1, 2, 3]],
                expected: nil
            ),
            DictionaryTestCase(
                "unknown NSNumber",
                [kSecAttrKeyClass as String: NSNumber(value: 999)],
                expected: nil
            ),
            DictionaryTestCase(
                "unknown String",
                [kSecAttrKeyClass as String: "unknown-key-class"],
                expected: nil
            ),
        ]
    )
    func getFromDictionaryReturnsNilForInvalidInputs(testCase: DictionaryTestCase) {
        let keyClass = Keychain.Keys.KeyClass.get(from: testCase.dictionary)
        #expect(keyClass == testCase.expected)
    }
}

extension KeyClassTests {
    // Unchecked Sendable is okay since CFString is immutable and thread-safe
    struct CFStringTestCase: @unchecked Sendable {
        let name: String
        let keychainValue: CFString
        let expected: Keychain.Keys.KeyClass?

        init(
            _ name: String,
            _ keychainValue: CFString,
            expected: Keychain.Keys.KeyClass?
        ) {
            self.name = name
            self.keychainValue = keychainValue
            self.expected = expected
        }
    }

    struct NSNumberTestCase: Sendable {
        let name: String
        let keychainValue: NSNumber
        let expected: Keychain.Keys.KeyClass?

        init(
            _ name: String,
            _ keychainValue: NSNumber,
            expected: Keychain.Keys.KeyClass?
        ) {
            self.name = name
            self.keychainValue = keychainValue
            self.expected = expected
        }
    }

    // Unchecked Sendable is okay since we know what kind of values we put into the dictionary and they all conform to Sendable
    struct DictionaryTestCase: @unchecked Sendable {
        let name: String
        let dictionary: [String: Any]
        let expected: Keychain.Keys.KeyClass?

        init(
            _ name: String,
            _ dictionary: [String: Any],
            expected: Keychain.Keys.KeyClass?
        ) {
            self.name = name
            self.dictionary = dictionary
            self.expected = expected
        }
    }
}
