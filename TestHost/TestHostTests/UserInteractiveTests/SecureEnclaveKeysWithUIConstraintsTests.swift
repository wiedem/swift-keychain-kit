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
final class SecureEnclaveKeysWithUIConstraintsTests {
    private let keychainApplicationTag = "ConstraintsUI-applicationTag-\(UUID().uuidString)".data(using: .utf8)!

    deinit {
        cleanup()
    }

    @Test("Secure Enclave key with application password constraint shows password prompt on generate, use and deletion")
    func generateWithApplicationPasswordCausesPrompts() async throws {
        // Generate key with application password constraint
        _ = try await Keychain.SecureEnclaveKeys.generate(
            applicationTag: keychainApplicationTag,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            )
        )

        // Query does not show application password prompt
        let queriedKeys = try await Keychain.SecureEnclaveKeys.query(
            applicationTag: .specific(keychainApplicationTag)
        )
        let privateKey = try #require(queriedKeys.first)

        // Key usage triggers application password prompt
        try await Self.useKey(privateKey)

        // Deletion triggers application password prompt but any password will perform the deletion
        let deleted = try await Keychain.SecureEnclaveKeys.delete(
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(deleted)
    }

    @Test("Secure Enclave key with user presence constraint shows prompt on generate, use and deletion")
    func keyOperationsWithUserPresenceConstraint() async throws {
        // Generate key with application password constraint
        _ = try await Keychain.SecureEnclaveKeys.generate(
            applicationTag: keychainApplicationTag,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .userPresence
            )
        )

        // Query does not show credential prompt
        let queriedKeys = try await Keychain.SecureEnclaveKeys.query(
            applicationTag: .specific(keychainApplicationTag)
        )
        let privateKey = try #require(queriedKeys.first)

        // Key usage triggers credential prompt
        try await Self.useKey(privateKey)

        // Deletion triggers credential prompt but any password will perform the deletion
        let deleted = try await Keychain.SecureEnclaveKeys.delete(
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(deleted)
    }
}

// MARK: - Cleanup

private extension SecureEnclaveKeysWithUIConstraintsTests {
    static func useKey(_ privateKey: SecKey) async throws {
        // Sign data
        let dataToSign = "Test data".data(using: .utf8)!
        var error: Unmanaged<CFError>?

        _ = try #require(SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            dataToSign as CFData,
            &error
        ) as Data?, "Could not create signature")
    }

    func cleanup() {
        do {
            let context = LAContext()
            // Set any credential to prevent a UI prompt for application password protected items
            context.setCredential(" ".data(using: .utf8)!, type: .applicationPassword)

            try Keychain.SecureEnclaveKeys.delete(
                applicationTag: .specific(keychainApplicationTag),
                accessGroup: .any,
                authenticationContext: context
            )
        } catch {
            print("Error cleaning up: \(error)")
        }
    }
}
