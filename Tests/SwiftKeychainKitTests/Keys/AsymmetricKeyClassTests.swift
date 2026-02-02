@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("AsymmetricKeyClass Tests")
struct AsymmetricKeyClassTests {
    // MARK: - make(for: CFString) Tests

    @Test(
        "make(for:CFString) returns expected result",
        arguments: [
            CFStringTestCase(
                "public key",
                keychainValue: kSecAttrKeyClassPublic,
                expected: .publicKey
            ),
            CFStringTestCase(
                "private key",
                keychainValue: kSecAttrKeyClassPrivate,
                expected: .privateKey
            ),
            CFStringTestCase(
                "unknown value",
                keychainValue: "unknown-key-class" as CFString,
                expected: nil
            ),
            CFStringTestCase(
                "symmetric key class",
                keychainValue: kSecAttrKeyClassSymmetric,
                expected: nil
            ),
        ]
    )
    func makeForCFStringReturnsExpectedResult(testCase: CFStringTestCase) {
        let keyClass = AsymmetricKeyClass.make(for: testCase.keychainValue)
        #expect(keyClass == testCase.expected)
    }

    // MARK: - make(for: String) Tests

    @Test(
        "make(for:String) creates correct instance",
        arguments: [
            StringTestCase(
                "public key",
                keychainValue: kSecAttrKeyClassPublic,
                expected: .publicKey
            ),
            StringTestCase(
                "private key",
                keychainValue: kSecAttrKeyClassPrivate,
                expected: .privateKey
            ),
        ]
    )
    func makeForStringCreatesCorrectInstance(testCase: StringTestCase) {
        let keyClass = AsymmetricKeyClass.make(for: testCase.keychainValue)
        #expect(keyClass == testCase.expected)
    }

    // MARK: - make(for: NSNumber) Tests

    @Test(
        "make(for:NSNumber) returns expected result",
        arguments: [
            NSNumberTestCase(
                "public key",
                keychainValue: NSNumber(value: 0),
                expected: .publicKey
            ),
            NSNumberTestCase(
                "private key",
                keychainValue: NSNumber(value: 1),
                expected: .privateKey
            ),
            NSNumberTestCase(
                "unknown numeric value",
                keychainValue: NSNumber(value: 999),
                expected: nil
            ),
        ]
    )
    func makeForNSNumberReturnsExpectedResult(testCase: NSNumberTestCase) {
        let keyClass = AsymmetricKeyClass.make(for: testCase.keychainValue)
        #expect(keyClass == testCase.expected)
    }
}

extension AsymmetricKeyClassTests {
    struct CFStringTestCase: Sendable {
        let name: String
        private let _keychainValue: String
        let expected: AsymmetricKeyClass?

        var keychainValue: CFString {
            _keychainValue as CFString
        }

        init(
            _ name: String,
            keychainValue: CFString,
            expected: AsymmetricKeyClass?
        ) {
            self.name = name
            _keychainValue = keychainValue as String
            self.expected = expected
        }
    }

    struct StringTestCase: Sendable {
        let name: String
        let keychainValue: String
        let expected: AsymmetricKeyClass

        init(
            _ name: String,
            keychainValue: CFString,
            expected: AsymmetricKeyClass
        ) {
            self.name = name
            self.keychainValue = keychainValue as String
            self.expected = expected
        }
    }

    struct NSNumberTestCase: Sendable {
        let name: String
        let keychainValue: NSNumber
        let expected: AsymmetricKeyClass?

        init(
            _ name: String,
            keychainValue: NSNumber,
            expected: AsymmetricKeyClass?
        ) {
            self.name = name
            self.keychainValue = keychainValue
            self.expected = expected
        }
    }
}
