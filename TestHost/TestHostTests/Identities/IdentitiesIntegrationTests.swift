import Foundation
@preconcurrency import Security
import SwiftKeychainKit
import Testing

@Suite("Identities Integration Tests")
final class IdentitiesIntegrationTests {
    private let keychainLabel = "IdentitiesIntegrationTests-label-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    // MARK: - Add Tests

    @Test("Add and retrieve identity")
    func addAndRetrieve() async throws {
        let identity = try TestCertificateGenerator.generateSecIdentity(
            commonName: "Test-Add-\(UUID().uuidString)"
        )

        try await Keychain.Identities.add(
            identity,
            label: .custom(keychainLabel)
        )

        let retrieved = try await Keychain.Identities.query(
            label: .specific(keychainLabel),
            limit: .count(2)
        )
        #expect(retrieved.count == 1)
    }

    @Test("Add duplicate throws duplicateItem error")
    func addDuplicateThrows() async throws {
        let identity = try TestCertificateGenerator.generateSecIdentity(
            commonName: "Test-Duplicate-\(UUID().uuidString)"
        )

        try await Keychain.Identities.add(
            identity,
            label: .custom(keychainLabel)
        )

        await #expect(throws: KeychainError.duplicateItem) {
            try await Keychain.Identities.add(
                identity,
                label: .custom(keychainLabel)
            )
        }
    }

    // MARK: - Get Tests

    @Test("Get returns nil for non-existent identity")
    func getNonExistent() async throws {
        let result = try await Keychain.Identities.query(label: .specific(keychainLabel))
        #expect(result.isEmpty == true)
    }

    // MARK: - Query Tests

    @Test("Query finds identities by label")
    func queryFindsByLabel() async throws {
        let identity = try TestCertificateGenerator.generateSecIdentity(
            commonName: "Test-Query-\(UUID().uuidString)"
        )

        try await Keychain.Identities.add(
            identity,
            label: .custom(keychainLabel)
        )

        let results = try await Keychain.Identities.query(
            label: .specific(keychainLabel),
            limit: .count(2)
        )
        #expect(results.count == 1)

        // Verify the returned identity matches the stored one
        let retrievedIdentity = try requireUnwrapped(results.first)

        var originalCertificate: SecCertificate?
        let certStatus = SecIdentityCopyCertificate(identity, &originalCertificate)
        #expect(certStatus == errSecSuccess)
        let originalCert = try requireUnwrapped(originalCertificate)

        var retrievedCertificate: SecCertificate?
        let retrievedCertStatus = SecIdentityCopyCertificate(retrievedIdentity, &retrievedCertificate)
        #expect(retrievedCertStatus == errSecSuccess)
        let retrievedCert = try requireUnwrapped(retrievedCertificate)

        // Compare certificates by their data
        let originalData = SecCertificateCopyData(originalCert) as Data
        let retrievedData = SecCertificateCopyData(retrievedCert) as Data
        #expect(originalData == retrievedData)
    }

    @Test("Query returns empty array when no identities exist")
    func queryReturnsEmptyArrayWhenNoIdentities() async throws {
        let results = try await Keychain.Identities.query(label: .specific(keychainLabel))
        #expect(results.isEmpty == true)
    }

    // MARK: - Delete Tests

    @Test("Delete removes identity")
    func deleteRemovesIdentity() async throws {
        let identity = try TestCertificateGenerator.generateSecIdentity(
            commonName: "Test-Delete-\(UUID().uuidString)"
        )

        try await Keychain.Identities.add(
            identity,
            label: .custom(keychainLabel)
        )

        let deleted = try await Keychain.Identities.delete(label: .specific(keychainLabel))
        #expect(deleted == true)

        let retrieved = try await Keychain.Identities.query(label: .specific(keychainLabel))
        #expect(retrieved.isEmpty == true)
    }

    @Test("Delete returns false for non-existent identity")
    func deleteReturnsFalseForNonExistent() async throws {
        let deleted = try await Keychain.Identities.delete(label: .specific(keychainLabel))
        #expect(deleted == false)
    }

    @Test("Delete with synchronized scope removes only synchronized identity")
    func deleteSynchronizedRemovesOnlySynchronizedIdentity() async throws {
        let testLabel = "test-sync-identity-\(UUID().uuidString)"
        let identity = try TestCertificateGenerator.generateSecIdentity(
            commonName: "Test-Sync-\(UUID().uuidString)"
        )

        defer {
            _ = try? Keychain.Identities.delete(
                label: .specific(testLabel),
                synchronizable: .any
            )
        }

        // Add non-synchronized identity
        try await Keychain.Identities.add(
            identity,
            label: .custom(testLabel),
            synchronizable: false
        )

        // Add synchronized identity (same identity)
        try await Keychain.Identities.add(
            identity,
            label: .custom(testLabel),
            synchronizable: true
        )

        // Delete only synchronized identity
        let deleted = try await Keychain.Identities.delete(
            label: .specific(testLabel),
            synchronizable: .synchronized
        )
        #expect(deleted == true)

        // Verify non-synchronized identity still exists
        let remaining = try await Keychain.Identities.query(
            label: .specific(testLabel),
            synchronizable: .notSynchronized,
            limit: .count(2)
        )
        #expect(remaining.count == 1)
    }

    @Test("Delete with not synchronized scope removes only non-synchronized identity")
    func deleteNotSynchronizedRemovesOnlyNonSynchronizedIdentity() async throws {
        let testLabel = "test-nonsync-identity-\(UUID().uuidString)"
        let identity = try TestCertificateGenerator.generateSecIdentity(
            commonName: "Test-NonSync-\(UUID().uuidString)"
        )

        defer {
            _ = try? Keychain.Identities.delete(
                label: .specific(testLabel),
                synchronizable: .any
            )
        }

        // Add non-synchronized identity
        try await Keychain.Identities.add(
            identity,
            label: .custom(testLabel),
            synchronizable: false
        )

        // Add synchronized identity (same identity)
        try await Keychain.Identities.add(
            identity,
            label: .custom(testLabel),
            synchronizable: true
        )

        // Delete only non-synchronized identity
        let deleted = try await Keychain.Identities.delete(
            label: .specific(testLabel),
            synchronizable: .notSynchronized
        )
        #expect(deleted == true)

        // Verify synchronized identity still exists
        let remaining = try await Keychain.Identities.queryAttributes(
            label: .specific(testLabel),
            synchronizable: .synchronized,
            limit: .count(2)
        )
        #expect(remaining.count == 1)
    }

    @Test("Delete with any scope removes both synchronized and non-synchronized identities")
    func deleteAnyRemovesBothIdentities() async throws {
        let testLabel = "test-any-identity-\(UUID().uuidString)"
        let identity = try TestCertificateGenerator.generateSecIdentity(
            commonName: "Test-Any-\(UUID().uuidString)"
        )

        defer {
            _ = try? Keychain.Identities.delete(
                label: .specific(testLabel),
                synchronizable: .any
            )
        }

        // Add non-synchronized identity
        try await Keychain.Identities.add(
            identity,
            label: .custom(testLabel),
            synchronizable: false
        )

        // Add synchronized identity (same identity)
        try await Keychain.Identities.add(
            identity,
            label: .custom(testLabel),
            synchronizable: true
        )

        // Delete both identities
        let deleted = try await Keychain.Identities.delete(
            label: .specific(testLabel),
            synchronizable: .any
        )
        #expect(deleted == true)

        // Verify no identities remain
        let remainingNonSync = try await Keychain.Identities.query(
            label: .specific(testLabel),
            synchronizable: .notSynchronized
        )
        #expect(remainingNonSync.isEmpty == true)

        let remainingSync = try await Keychain.Identities.query(
            label: .specific(testLabel),
            synchronizable: .synchronized
        )
        #expect(remainingSync.isEmpty == true)
    }
}

// MARK: - Private Helpers

private extension IdentitiesIntegrationTests {
    func cleanup() {
        do {
            try Keychain.Identities.delete(
                label: .specific(keychainLabel)
            )
        } catch {
            print("Failed to clean up identity after test: \(error)")
        }
    }
}
