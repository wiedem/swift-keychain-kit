import Foundation
import LocalAuthentication
import Security
import SwiftKeychainKit
import Testing

@Suite(
    "Keys with Application Password Constraint Tests",
    .tags(.userInteractive),
    .serialized
)
final class KeysApplicationPasswordTests {
    private let keychainApplicationTag = "ApplicationPassword-applicationTag-\(UUID().uuidString)".data(using: .utf8)!

    deinit {
        cleanup()
    }

    @Test("Private key with application password constraint shows password prompt on add and query")
    func addPrivateKeyWithApplicationPasswordCausesPrompts() async throws {
        let (_, privateKey) = try Self.makeKeyPair()

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            )
        )

        let queriedKey = try await Keychain.Keys.query(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag),
            limit: .count(2)
        )
        #expect(queriedKey.count == 1)

        let deleted = try await Keychain.Keys.delete(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(deleted)
    }
}

// MARK: - Cleanup

private extension KeysApplicationPasswordTests {
    enum TestError: Error, Sendable {
        case keyCreationFailure
    }

    static func makeKeyPair() throws -> (publicKey: SecKey, privateKey: SecKey) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            Issue.record("Failed to create test key pair: \(error!)")
            throw TestError.keyCreationFailure
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            Issue.record("Failed to get public key")
            throw TestError.keyCreationFailure
        }

        return (publicKey, privateKey)
    }

    func cleanup() {
        do {
            try Keychain.Keys.delete(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(keychainApplicationTag),
                accessGroup: .any
            )
        } catch {
            print("Error cleaning up: \(error)")
        }
    }
}
