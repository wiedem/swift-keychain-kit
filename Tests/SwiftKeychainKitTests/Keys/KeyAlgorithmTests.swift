@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("KeyAlgorithm Tests")
struct KeyAlgorithmTests {
    // MARK: - make(for: NSNumber) Tests

    @Test(
        "make(for:NSNumber) returns expected result for common algorithms",
        arguments: [
            NSNumberTestCase(
                "RSA",
                NSNumber(value: 42),
                expected: .rsa
            ),
            NSNumberTestCase(
                "Elliptic Curve",
                NSNumber(value: 73),
                expected: .ellipticCurve
            ),
            NSNumberTestCase(
                "unknown numeric value",
                NSNumber(value: 999),
                expected: nil
            ),
        ]
    )
    func makeForNSNumberReturnsExpectedResult(testCase: NSNumberTestCase) {
        let algorithm = Keychain.Keys.KeyAlgorithm.make(for: testCase.keychainValue)
        #expect(algorithm == testCase.expected)
    }

    #if os(macOS)
    @Test(
        "make(for:NSNumber) returns expected result for macOS-only algorithms",
        arguments: [
            NSNumberTestCase(
                "DES",
                NSNumber(value: 14),
                expected: .des
            ),
            NSNumberTestCase(
                "Triple DES",
                NSNumber(value: 17),
                expected: .tripleDES
            ),
            NSNumberTestCase(
                "RC4",
                NSNumber(value: 25),
                expected: .rc4
            ),
            NSNumberTestCase(
                "RC2",
                NSNumber(value: 23),
                expected: .rc2
            ),
            NSNumberTestCase(
                "CAST",
                NSNumber(value: 56),
                expected: .cast
            ),
            NSNumberTestCase(
                "DSA",
                NSNumber(value: 43),
                expected: .dsa
            ),
        ]
    )
    func makeForNSNumberReturnsExpectedResultMacOSOnly(testCase: NSNumberTestCase) {
        let algorithm = Keychain.Keys.KeyAlgorithm.make(for: testCase.keychainValue)
        #expect(algorithm == testCase.expected)
    }
    #endif

    // MARK: - get(from:) Tests

    @Test(
        "get(from:) with NSNumber value returns expected result for common algorithms",
        arguments: [
            DictionaryTestCase(
                "RSA as NSNumber",
                [kSecAttrKeyType as String: NSNumber(value: 42)],
                expected: .rsa
            ),
            DictionaryTestCase(
                "Elliptic Curve as NSNumber",
                [kSecAttrKeyType as String: NSNumber(value: 73)],
                expected: .ellipticCurve
            ),
        ]
    )
    func getFromDictionaryWithNSNumberReturnsExpectedResult(testCase: DictionaryTestCase) {
        let algorithm = Keychain.Keys.KeyAlgorithm.get(from: testCase.dictionary)
        #expect(algorithm == testCase.expected)
    }

    #if os(macOS)
    @Test(
        "get(from:) with NSNumber value returns expected result for macOS-only algorithms",
        arguments: [
            DictionaryTestCase(
                "DES as NSNumber",
                [kSecAttrKeyType as String: NSNumber(value: 14)],
                expected: .des
            ),
        ]
    )
    func getFromDictionaryWithNSNumberReturnsExpectedResultMacOSOnly(testCase: DictionaryTestCase) {
        let algorithm = Keychain.Keys.KeyAlgorithm.get(from: testCase.dictionary)
        #expect(algorithm == testCase.expected)
    }
    #endif

    @Test(
        "get(from:) with String value returns expected result for common algorithms",
        arguments: [
            DictionaryTestCase(
                "RSA as String",
                [kSecAttrKeyType as String: kSecAttrKeyTypeRSA as String],
                expected: .rsa
            ),
            DictionaryTestCase(
                "Elliptic Curve as String (ECSECPrimeRandom)",
                [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom as String],
                expected: .ellipticCurve
            ),
            DictionaryTestCase(
                "Elliptic Curve as String (EC)",
                [kSecAttrKeyType as String: kSecAttrKeyTypeEC as String],
                expected: .ellipticCurve
            ),
        ]
    )
    func getFromDictionaryWithStringReturnsExpectedResult(testCase: DictionaryTestCase) {
        let algorithm = Keychain.Keys.KeyAlgorithm.get(from: testCase.dictionary)
        #expect(algorithm == testCase.expected)
    }

    #if os(macOS)
    @Test(
        "get(from:) with String value returns expected result for macOS-only algorithms",
        arguments: [
            DictionaryTestCase(
                "DES as String",
                [kSecAttrKeyType as String: kSecAttrKeyTypeDES as String],
                expected: .des
            ),
            DictionaryTestCase(
                "Triple DES as String",
                [kSecAttrKeyType as String: kSecAttrKeyType3DES as String],
                expected: .tripleDES
            ),
            DictionaryTestCase(
                "RC4 as String",
                [kSecAttrKeyType as String: kSecAttrKeyTypeRC4 as String],
                expected: .rc4
            ),
            DictionaryTestCase(
                "RC2 as String",
                [kSecAttrKeyType as String: kSecAttrKeyTypeRC2 as String],
                expected: .rc2
            ),
            DictionaryTestCase(
                "CAST as String",
                [kSecAttrKeyType as String: kSecAttrKeyTypeCAST as String],
                expected: .cast
            ),
            DictionaryTestCase(
                "DSA as String",
                [kSecAttrKeyType as String: kSecAttrKeyTypeDSA as String],
                expected: .dsa
            ),
        ]
    )
    func getFromDictionaryWithStringReturnsExpectedResultMacOSOnly(testCase: DictionaryTestCase) {
        let algorithm = Keychain.Keys.KeyAlgorithm.get(from: testCase.dictionary)
        #expect(algorithm == testCase.expected)
    }
    #endif

    @Test(
        "get(from:) returns nil for invalid inputs",
        arguments: [
            DictionaryTestCase("missing key", [:], expected: nil),
            DictionaryTestCase(
                "wrong type",
                [kSecAttrKeyType as String: true],
                expected: nil
            ),
            DictionaryTestCase(
                "unknown NSNumber",
                [kSecAttrKeyType as String: NSNumber(value: 999)],
                expected: nil
            ),
            DictionaryTestCase(
                "unknown String",
                [kSecAttrKeyType as String: "unknown-key-type"],
                expected: nil
            ),
        ]
    )
    func getFromDictionaryReturnsNilForInvalidInputs(testCase: DictionaryTestCase) {
        let algorithm = Keychain.Keys.KeyAlgorithm.get(from: testCase.dictionary)
        #expect(algorithm == testCase.expected)
    }
}

extension KeyAlgorithmTests {
    struct NSNumberTestCase: Sendable {
        let name: String
        let keychainValue: NSNumber
        let expected: Keychain.Keys.KeyAlgorithm?

        init(
            _ name: String,
            _ keychainValue: NSNumber,
            expected: Keychain.Keys.KeyAlgorithm?
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
        let expected: Keychain.Keys.KeyAlgorithm?

        init(
            _ name: String,
            _ dictionary: [String: Any],
            expected: Keychain.Keys.KeyAlgorithm?
        ) {
            self.name = name
            self.dictionary = dictionary
            self.expected = expected
        }
    }
}
