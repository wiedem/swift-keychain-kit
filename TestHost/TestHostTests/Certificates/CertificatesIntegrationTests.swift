import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("Certificates Integration Tests")
final class CertificatesIntegrationTests {
    private let keychainLabel = "CertificatesIntegrationTests-label-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    // MARK: - Add Tests

    @Test("Add and retrieve certificate")
    func addAndRetrieve() async throws {
        let commonName = "Test-Add-\(UUID().uuidString)"
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: commonName
        )

        try await Keychain.Certificates.add(
            certificate,
            label: .custom(keychainLabel)
        )

        let retrieved = try await Keychain.Certificates.query(
            label: .specific(keychainLabel),
            limit: .count(2)
        )
        #expect(retrieved.count == 1)
    }

    @Test("Add duplicate throws duplicateItem error")
    func addDuplicateThrows() async throws {
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: "Test-Duplicate-\(UUID().uuidString)"
        )

        try await Keychain.Certificates.add(
            certificate,
            label: .custom(keychainLabel)
        )

        await #expect(throws: KeychainError.duplicateItem) {
            try await Keychain.Certificates.add(
                certificate,
                label: .custom(keychainLabel)
            )
        }
    }

    // MARK: - Get Tests

    @Test("Get returns nil for non-existent certificate")
    func getNonExistent() async throws {
        let result = try await Keychain.Certificates.query(label: .specific(keychainLabel))
        #expect(result.isEmpty == true)
    }

    // MARK: - Query Tests

    @Test("Query finds certificates by label")
    func queryFindsByLabel() async throws {
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: "Test-Query-\(UUID().uuidString)"
        )

        try await Keychain.Certificates.add(
            certificate,
            label: .custom(keychainLabel)
        )

        let results = try await Keychain.Certificates.query(
            label: .specific(keychainLabel),
            limit: .count(2)
        )
        #expect(results.count == 1)
    }

    @Test("Query returns empty array when no matches")
    func queryReturnsEmptyArrayWhenNoMatches() async throws {
        let results = try await Keychain.Certificates.query(label: .specific(keychainLabel))
        #expect(results.isEmpty == true)
    }

    // MARK: - Delete Tests

    @Test("Delete removes certificate")
    func deleteRemovesCertificate() async throws {
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: "Test-Delete-\(UUID().uuidString)"
        )

        try await Keychain.Certificates.add(
            certificate,
            label: .custom(keychainLabel)
        )

        let deleted = try await Keychain.Certificates.delete(label: .specific(keychainLabel))
        #expect(deleted == true)

        let retrieved = try await Keychain.Certificates.query(label: .specific(keychainLabel))
        #expect(retrieved.isEmpty == true)
    }

    @Test("Delete returns false for non-existent certificate")
    func deleteReturnsFalseForNonExistent() async throws {
        let deleted = try await Keychain.Certificates.delete(label: .specific(keychainLabel))
        #expect(deleted == false)
    }

    @Test("Delete with synchronized scope removes only synchronized certificate")
    func deleteSynchronizedRemovesOnlySynchronizedCertificate() async throws {
        let testLabel = "test-sync-cert-\(UUID().uuidString)"
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: "Test-Sync-\(UUID().uuidString)"
        )

        defer {
            _ = try? Keychain.Certificates.delete(
                label: .specific(testLabel),
                synchronizable: .any
            )
        }

        // Add non-synchronized certificate
        try await Keychain.Certificates.add(
            certificate,
            label: .custom(testLabel),
            synchronizable: false
        )

        // Add synchronized certificate (same certificate)
        try await Keychain.Certificates.add(
            certificate,
            label: .custom(testLabel),
            synchronizable: true
        )

        // Delete only synchronized certificate
        let deleted = try await Keychain.Certificates.delete(
            label: .specific(testLabel),
            synchronizable: .synchronized
        )
        #expect(deleted == true)

        // Verify non-synchronized certificate still exists
        let remaining = try await Keychain.Certificates.query(
            label: .specific(testLabel),
            synchronizable: .notSynchronized,
            limit: .count(2)
        )
        #expect(remaining.count == 1)
    }

    @Test("Delete with not synchronized scope removes only non-synchronized certificate")
    func deleteNotSynchronizedRemovesOnlyNonSynchronizedCertificate() async throws {
        let testLabel = "test-nonsync-cert-\(UUID().uuidString)"
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: "Test-NonSync-\(UUID().uuidString)"
        )

        defer {
            _ = try? Keychain.Certificates.delete(
                label: .specific(testLabel),
                synchronizable: .any
            )
        }

        // Add non-synchronized certificate
        try await Keychain.Certificates.add(
            certificate,
            label: .custom(testLabel),
            synchronizable: false
        )

        // Add synchronized certificate (same certificate)
        try await Keychain.Certificates.add(
            certificate,
            label: .custom(testLabel),
            synchronizable: true
        )

        // Delete only non-synchronized certificate
        let deleted = try await Keychain.Certificates.delete(
            label: .specific(testLabel),
            synchronizable: .notSynchronized
        )
        #expect(deleted == true)

        // Verify synchronized certificate still exists
        let remaining = try await Keychain.Certificates.query(
            label: .specific(testLabel),
            synchronizable: .synchronized,
            limit: .count(2)
        )
        #expect(remaining.count == 1)
    }

    @Test("Delete with any scope removes both synchronized and non-synchronized certificates")
    func deleteAnyRemovesBothCertificates() async throws {
        let testLabel = "test-any-cert-\(UUID().uuidString)"
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: "Test-Any-\(UUID().uuidString)"
        )

        defer {
            _ = try? Keychain.Certificates.delete(
                label: .specific(testLabel),
                synchronizable: .any
            )
        }

        // Add non-synchronized certificate
        try await Keychain.Certificates.add(
            certificate,
            label: .custom(testLabel),
            synchronizable: false
        )

        // Add synchronized certificate (same certificate)
        try await Keychain.Certificates.add(
            certificate,
            label: .custom(testLabel),
            synchronizable: true
        )

        // Delete both certificates
        let deleted = try await Keychain.Certificates.delete(
            label: .specific(testLabel),
            synchronizable: .any
        )
        #expect(deleted == true)

        // Verify no certificates remain
        let remainingNonSync = try await Keychain.Certificates.query(
            label: .specific(testLabel),
            synchronizable: .notSynchronized
        )
        #expect(remainingNonSync.isEmpty == true)

        let remainingSync = try await Keychain.Certificates.query(
            label: .specific(testLabel),
            synchronizable: .synchronized
        )
        #expect(remainingSync.isEmpty == true)
    }
}

// MARK: - Private Helpers

private extension CertificatesIntegrationTests {
    func cleanup() {
        do {
            try Keychain.Certificates.delete(
                label: .specific(keychainLabel)
            )
        } catch {
            print("Failed to clean up certificate after test: \(error)")
        }
    }
}
