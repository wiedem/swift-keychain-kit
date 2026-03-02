@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("AsymmetricKeyClassScope Tests")
struct AsymmetricKeyClassScopeTests {
    // MARK: - keychainValue Tests

    @Test(
        "keychainValue returns expected CFString",
        arguments: [
            KeychainValueTestCase(
                "public key",
                scope: .publicKey,
                expected: kSecAttrKeyClassPublic
            ),
            KeychainValueTestCase(
                "private key",
                scope: .privateKey,
                expected: kSecAttrKeyClassPrivate
            ),
            KeychainValueTestCase(
                "any",
                scope: .any,
                expected: nil
            ),
        ]
    )
    func keychainValueReturnsExpectedCFString(testCase: KeychainValueTestCase) {
        let value = testCase.scope.keychainValue
        if let expected = testCase.expected {
            #expect(value == expected)
        } else {
            #expect(value == nil)
        }
    }

    // MARK: - apply(to:) Tests

    @Test("apply with publicKey scope sets kSecAttrKeyClass")
    func applyWithPublicKeySetsAttribute() {
        var query: [String: Any] = [:]
        Keychain.AsymmetricKeyClassScope.publicKey.apply(to: &query)

        #expect(query[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPublic)
        #expect(query.count == 1)
    }

    @Test("apply with privateKey scope sets kSecAttrKeyClass")
    func applyWithPrivateKeySetsAttribute() {
        var query: [String: Any] = [:]
        Keychain.AsymmetricKeyClassScope.privateKey.apply(to: &query)

        #expect(query[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(query.count == 1)
    }

    @Test("apply with any scope removes kSecAttrKeyClass")
    func applyWithAnyScopeRemovesAttribute() {
        var query: [String: Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        Keychain.AsymmetricKeyClassScope.any.apply(to: &query)

        #expect(query[kSecAttrKeyClass as String] == nil)
        #expect(query.count == 0)
    }

    @Test("apply with any scope on empty query does nothing")
    func applyWithAnyScopeOnEmptyQuery() {
        var query: [String: Any] = [:]
        Keychain.AsymmetricKeyClassScope.any.apply(to: &query)

        #expect(query.count == 0)
    }
}

extension AsymmetricKeyClassScopeTests {
    struct KeychainValueTestCase: Sendable {
        let name: String
        let scope: Keychain.AsymmetricKeyClassScope
        private let _expected: String?

        var expected: CFString? {
            _expected as CFString?
        }

        init(
            _ name: String,
            scope: Keychain.AsymmetricKeyClassScope,
            expected: CFString?
        ) {
            self.name = name
            self.scope = scope
            _expected = expected as String?
        }
    }
}
