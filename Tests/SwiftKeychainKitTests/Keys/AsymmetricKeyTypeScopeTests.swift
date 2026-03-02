@testable import SwiftKeychainKit
import CryptoKit
import Foundation
import Security
import Testing

@Suite("AsymmetricKeyTypeScope Tests")
struct AsymmetricKeyTypeScopeTests {
    // MARK: - keyTypeKeychainValue Tests

    @Test(
        "keyTypeKeychainValue returns expected CFString",
        arguments: [
            KeyTypeTestCase("RSA", scope: .rsa(), expected: kSecAttrKeyTypeRSA),
            KeyTypeTestCase(
                "RSA with public key",
                scope: .rsa(.publicKey),
                expected: kSecAttrKeyTypeRSA
            ),
            KeyTypeTestCase(
                "Elliptic Curve",
                scope: .ellipticCurve(),
                expected: kSecAttrKeyTypeECSECPrimeRandom
            ),
            KeyTypeTestCase(
                "Elliptic Curve with private key",
                scope: .ellipticCurve(.privateKey),
                expected: kSecAttrKeyTypeECSECPrimeRandom
            ),
        ]
    )
    func keyTypeKeychainValueReturnsExpectedCFString(testCase: KeyTypeTestCase) {
        let value = testCase.scope.keyTypeKeychainValue
        #expect(value == testCase.expected)
    }

    // MARK: - keyClassKeychainValue Tests

    @Test(
        "keyClassKeychainValue returns expected CFString",
        arguments: [
            KeyClassValueTestCase(
                "RSA with public key",
                scope: .rsa(.publicKey),
                expected: kSecAttrKeyClassPublic
            ),
            KeyClassValueTestCase(
                "RSA with private key",
                scope: .rsa(.privateKey),
                expected: kSecAttrKeyClassPrivate
            ),
            KeyClassValueTestCase(
                "RSA with any",
                scope: .rsa(.any),
                expected: nil
            ),
            KeyClassValueTestCase(
                "Elliptic Curve with public key",
                scope: .ellipticCurve(.publicKey),
                expected: kSecAttrKeyClassPublic
            ),
            KeyClassValueTestCase(
                "Elliptic Curve with private key",
                scope: .ellipticCurve(.privateKey),
                expected: kSecAttrKeyClassPrivate
            ),
            KeyClassValueTestCase(
                "Elliptic Curve with any",
                scope: .ellipticCurve(.any),
                expected: nil
            ),
        ]
    )
    func keyClassKeychainValueReturnsExpectedCFString(testCase: KeyClassValueTestCase) {
        let value = testCase.scope.keyClassKeychainValue
        if let expected = testCase.expected {
            #expect(value == expected)
        } else {
            #expect(value == nil)
        }
    }

    // MARK: - apply(to:) Tests

    @Test("apply with RSA and publicKey sets both attributes")
    func applyWithRSAAndPublicKeySetsAttributes() {
        var query: [String: Any] = [:]
        Keychain.AsymmetricKeyTypeScope.rsa(.publicKey).apply(to: &query)

        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeRSA)
        #expect(query[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPublic)
        #expect(query.count == 2)
    }

    @Test("apply with RSA and any sets only key type")
    func applyWithRSAAndAnySetsOnlyKeyType() {
        var query: [String: Any] = [:]
        Keychain.AsymmetricKeyTypeScope.rsa(.any).apply(to: &query)

        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeRSA)
        #expect(query[kSecAttrKeyClass as String] == nil)
        #expect(query.count == 1)
    }

    @Test("apply with Elliptic Curve and privateKey sets both attributes")
    func applyWithEllipticCurveAndPrivateKeySetsAttributes() {
        var query: [String: Any] = [:]
        Keychain.AsymmetricKeyTypeScope.ellipticCurve(.privateKey).apply(to: &query)

        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeECSECPrimeRandom)
        #expect(query[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(query.count == 2)
    }

    @Test("apply with Elliptic Curve and any sets only key type")
    func applyWithEllipticCurveAndAnySetsOnlyKeyType() {
        var query: [String: Any] = [:]
        Keychain.AsymmetricKeyTypeScope.ellipticCurve(.any).apply(to: &query)

        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeECSECPrimeRandom)
        #expect(query[kSecAttrKeyClass as String] == nil)
        #expect(query.count == 1)
    }

    // MARK: - keyType(_: AsymmetricKeyType) Factory Tests

    @Test(
        "keyType factory creates matching scope from AsymmetricKeyType",
        arguments: [
            KeyTypeFactoryTestCase(
                "RSA public key",
                input: .rsa(.publicKey),
                expected: .rsa(.publicKey)
            ),
            KeyTypeFactoryTestCase(
                "RSA private key",
                input: .rsa(.privateKey),
                expected: .rsa(.privateKey)
            ),
            KeyTypeFactoryTestCase(
                "Elliptic Curve public key",
                input: .ellipticCurve(.publicKey),
                expected: .ellipticCurve(.publicKey)
            ),
            KeyTypeFactoryTestCase(
                "Elliptic Curve private key",
                input: .ellipticCurve(.privateKey),
                expected: .ellipticCurve(.privateKey)
            ),
        ]
    )
    func keyTypeFactoryCreatesMatchingScope(testCase: KeyTypeFactoryTestCase) {
        let scope = Keychain.AsymmetricKeyTypeScope.keyType(testCase.input)
        #expect(scope == testCase.expected)
    }

    // MARK: - keyType(_: AsymmetricKeyTypeProviding.Type) Factory Tests

    @Test("keyType factory creates scope from AsymmetricKeyTypeProviding metatype")
    func keyTypeFactoryCreatesMatchingScopeFromProvidingType() {
        let scope = Keychain.AsymmetricKeyTypeScope.keyType(P256.Signing.PrivateKey.self)
        #expect(scope == .ellipticCurve(.privateKey))
    }
}

extension AsymmetricKeyTypeScopeTests {
    struct KeyTypeTestCase: Sendable {
        let name: String
        let scope: Keychain.AsymmetricKeyTypeScope
        private let _expected: String

        var expected: CFString {
            _expected as CFString
        }

        init(
            _ name: String,
            scope: Keychain.AsymmetricKeyTypeScope,
            expected: CFString
        ) {
            self.name = name
            self.scope = scope
            _expected = expected as String
        }
    }

    struct KeyTypeFactoryTestCase: Sendable, CustomTestStringConvertible {
        let name: String
        let input: AsymmetricKeyType
        let expected: Keychain.AsymmetricKeyTypeScope

        var testDescription: String {
            name
        }

        init(
            _ name: String,
            input: AsymmetricKeyType,
            expected: Keychain.AsymmetricKeyTypeScope
        ) {
            self.name = name
            self.input = input
            self.expected = expected
        }
    }

    struct KeyClassValueTestCase: Sendable {
        let name: String
        let scope: Keychain.AsymmetricKeyTypeScope
        private let _expected: String?

        var expected: CFString? {
            _expected as CFString?
        }

        init(
            _ name: String,
            scope: Keychain.AsymmetricKeyTypeScope,
            expected: CFString?
        ) {
            self.name = name
            self.scope = scope
            _expected = expected as String?
        }
    }
}
