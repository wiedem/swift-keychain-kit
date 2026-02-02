import Foundation
import LocalAuthentication
import Security
import SwiftKeychainKit
import Testing

@Suite(
    "SecureEnclaveKeys with Constraints Requiring UI Tests",
    .enabled(if: Keychain.SecureEnclaveKeys.isAvailable, "Requires real device with Secure Enclave"),
    .tags(.userInteractive),
    .serialized
)
final class KeysWithUIConstraintsTests {
    private let keychainApplicationTag = "ConstraintsUI-applicationTag-\(UUID().uuidString)".data(using: .utf8)!

    deinit {
        cleanup()
    }

    @Test("Key with application password constraint shows password prompt on generate, use and deletion")
    func keyOperationsWithApplicationPasswordConstraint() async throws {
        let (_, privateKey) = try Self.makeKeyPair()

        // Add key with application password constraint
        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            )
        )

        // Query does not show application password prompt
        let queriedKeys = try await Keychain.Keys.query(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(queriedKeys.count == 1)

        // Deletion triggers application password prompt but any password will perform the deletion
        let deleted = try await Keychain.Keys.delete(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(deleted)
    }

    @Test("Key with user presence constraint shows prompt on generate, use and deletion")
    func keyOperationsWithUserPresenceConstraint() async throws {
        let (_, privateKey) = try Self.makeKeyPair()

        // Add key with application password constraint
        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .userPresence
            )
        )

        // Query does not show credential prompt
        let queriedKeys = try await Keychain.Keys.query(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(queriedKeys.count == 1)

        // Deletion triggers credential prompt but any password will perform the deletion
        let deleted = try await Keychain.Keys.delete(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(deleted)
    }
}

// MARK: - Cleanup

private extension KeysWithUIConstraintsTests {
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
            print("Failed to clean up key after test: \(error)")
        }
    }
}
