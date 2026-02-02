@testable import SwiftKeychainKit
import Testing

@Suite("AsymmetricKeyType Tests")
struct AsymmetricKeyTypeTests {
    // MARK: - keychainQueryScope Tests

    @Test(
        "keychainQueryScope returns expected scope",
        arguments: [
            TestCase(
                "RSA public key",
                input: .rsa(.publicKey),
                expected: .rsa(.publicKey)
            ),
            TestCase(
                "RSA private key",
                input: .rsa(.privateKey),
                expected: .rsa(.privateKey)
            ),
            TestCase(
                "Elliptic Curve public key",
                input: .ellipticCurve(.publicKey),
                expected: .ellipticCurve(.publicKey)
            ),
            TestCase(
                "Elliptic Curve private key",
                input: .ellipticCurve(.privateKey),
                expected: .ellipticCurve(.privateKey)
            ),
        ]
    )
    func keychainQueryScopeReturnsExpectedScope(testCase: TestCase) {
        let scope = testCase.input.keychainQueryScope
        #expect(scope == testCase.expected)
    }
}

extension AsymmetricKeyTypeTests {
    struct TestCase: Sendable {
        let name: String
        let input: AsymmetricKeyType
        let expected: Keychain.AsymmetricKeyTypeScope

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
}
