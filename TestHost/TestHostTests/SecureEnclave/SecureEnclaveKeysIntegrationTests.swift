import Foundation
import Security
import SwiftKeychainKit
import Testing

// The test suite is only enabled when the Secure Enclave is available.
@Suite(
    "Secure Enclave Keys Integration Tests",
    .enabled(if: Keychain.SecureEnclaveKeys.isAvailable, "Requires real device with Secure Enclave"),
    .tags(.secureEnclave)
)
final class SecureEnclaveKeysIntegrationTests {
    private let keychainApplicationTag = "SecureEnclaveKeysIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!

    deinit {
        cleanup()
    }

    // MARK: - Generate Tests

    @Test("Generate creates key in Secure Enclave")
    func generateCreatesKey() async throws {
        _ = try await Keychain.SecureEnclaveKeys.generate(
            applicationTag: keychainApplicationTag,
            accessControl: .whenUnlockedThisDeviceOnly
        )

        // Verify we can retrieve the key
        let retrieved = try await Keychain.SecureEnclaveKeys.query(
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(retrieved.count == 1)
    }

    @Test("Generate with custom label")
    func generateWithCustomLabel() async throws {
        let label = "Test Key \(UUID().uuidString)"

        _ = try await Keychain.SecureEnclaveKeys.generate(
            applicationTag: keychainApplicationTag,
            label: label,
            accessControl: .whenUnlockedThisDeviceOnly
        )

        // Verify label in attributes
        let attributes = try await requireUnwrapped(
            Keychain.SecureEnclaveKeys.queryAttributes(
                applicationTag: .specific(keychainApplicationTag)
            ).first
        )
        #expect(attributes.label == label)
    }

    @Test("Generate throws duplicateItem for existing key")
    func generateDuplicateThrows() async throws {
        // The application label is a primary key so make sure we use a unique one for the both operations.
        let applicationLabel = "application-label-\(UUID().uuidString)".data(using: .utf8)!

        _ = try await Keychain.SecureEnclaveKeys.generate(
            applicationTag: keychainApplicationTag,
            applicationLabel: .data(applicationLabel),
            accessControl: .whenUnlockedThisDeviceOnly
        )

        await #expect(throws: KeychainError.duplicateItem) {
            try await Keychain.SecureEnclaveKeys.generate(
                applicationTag: keychainApplicationTag,
                applicationLabel: .data(applicationLabel),
                accessControl: .whenUnlockedThisDeviceOnly
            )
        }
    }

    // MARK: - Query Tests

    @Test("Query returns empty array for non-existent key")
    func queryNonExistent() async throws {
        let tag = "test-nonexistent-\(UUID().uuidString)".data(using: .utf8)!

        let result = try await Keychain.SecureEnclaveKeys.query(
            applicationTag: .specific(tag)
        )
        #expect(result.isEmpty == true)
    }

    @Test("Get returns nil for non-existent key")
    func getNonExistent() async throws {
        let tag = "test-nonexistent-\(UUID().uuidString)".data(using: .utf8)!

        let result = try await Keychain.SecureEnclaveKeys.query(
            applicationTag: .specific(tag)
        )
        #expect(result.isEmpty == true)
    }

    @Test("Query finds generated key")
    func queryFindsKey() async throws {
        _ = try await Keychain.SecureEnclaveKeys.generate(
            applicationTag: keychainApplicationTag,
            accessControl: .whenUnlockedThisDeviceOnly
        )

        let keys = try await Keychain.SecureEnclaveKeys.query(
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(keys.count == 1)
    }

    // MARK: - Delete Tests

    @Test("Delete returns false for non-existent key")
    func deleteNonExistent() async throws {
        let tag = "test-nonexistent-\(UUID().uuidString)".data(using: .utf8)!

        let result = try await Keychain.SecureEnclaveKeys.delete(
            applicationTag: .specific(tag)
        )
        #expect(!result)
    }

    @Test("Delete removes generated key")
    func deleteRemovesKey() async throws {
        _ = try await Keychain.SecureEnclaveKeys.generate(
            applicationTag: keychainApplicationTag,
            accessControl: .whenUnlockedThisDeviceOnly
        )

        let deleted = try await Keychain.SecureEnclaveKeys.delete(
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(deleted)

        let result = try await Keychain.SecureEnclaveKeys.query(
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(result.isEmpty == true)
    }

    // MARK: - Attributes Tests

    @Test("Query attributes returns key metadata")
    func queryAttributesReturnsMetadata() async throws {
        let label = "Test Key \(UUID().uuidString)"

        _ = try await Keychain.SecureEnclaveKeys.generate(
            applicationTag: keychainApplicationTag,
            label: label,
            accessControl: .whenUnlockedThisDeviceOnly
        )

        let attributes = try await requireUnwrapped(
            Keychain.SecureEnclaveKeys.queryAttributes(
                applicationTag: .specific(keychainApplicationTag)
            ).first
        )

        #expect(attributes.applicationTag == keychainApplicationTag)
        #expect(attributes.label == label)
    }

    // MARK: - Cryptographic Operations Tests

    @Test("Generated key can sign data")
    func generatedKeyCanSign() async throws {
        let privateKey = try await Keychain.SecureEnclaveKeys.generate(
            applicationTag: keychainApplicationTag,
            accessControl: .whenUnlockedThisDeviceOnly
        )

        // Get public key for verification
        let publicKey = try requireUnwrapped(SecKeyCopyPublicKey(privateKey), "Could not get public key")

        // Sign data
        let dataToSign = "Test data".data(using: .utf8)!
        var error: Unmanaged<CFError>?

        let signature = try requireUnwrapped(SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            dataToSign as CFData,
            &error
        ) as Data?, "Could not create signature")

        // Verify signature
        let verified = SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureMessageX962SHA256,
            dataToSign as CFData,
            signature as CFData,
            &error
        )

        #expect(verified)
    }
}

// MARK: - Cleanup

private extension SecureEnclaveKeysIntegrationTests {
    func cleanup() {
        do {
            try Keychain.SecureEnclaveKeys.delete(
                applicationTag: .specific(keychainApplicationTag),
                accessGroup: .any
            )
        } catch {
            print("Failed to clean up secure enclave key after test: \(error)")
        }
    }
}
