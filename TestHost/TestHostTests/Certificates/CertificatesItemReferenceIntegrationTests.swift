import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("Certificates ItemReference Integration Tests")
final class CertificatesItemReferenceIntegrationTests {
    private let keychainLabel = "CertificatesItemReferenceIntegrationTests-label-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("ItemReference lifecycle: add, get, attributes, delete")
    func itemReferenceLifecycle() async throws {
        let commonName = "Test-ItemRef-\(UUID().uuidString)"
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: commonName
        )

        // Add
        let itemReference = try await Keychain.Certificates.add(
            certificate,
            label: .custom(keychainLabel)
        )

        // Get by reference
        let retrieved = try await requireUnwrapped(
            Keychain.Certificates.get(itemReference: itemReference)
        )
        #expect(retrieved == certificate)

        // Attributes by reference
        let attributes = try await Keychain.Certificates.attributes(itemReference: itemReference)
        let attributeValues = try requireUnwrapped(attributes)
        #expect(attributeValues.label == keychainLabel)

        // Delete by reference
        let deleted = try await Keychain.Certificates.delete(itemReference: itemReference)
        #expect(deleted == true)

        // Verify deletion
        let afterDelete = try await Keychain.Certificates.get(itemReference: itemReference)
        #expect(afterDelete == nil)
    }

    @Test("Operations with stale ItemReference return nil or false")
    func staleItemReference() async throws {
        let commonName = "Test-Stale-\(UUID().uuidString)"
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: commonName
        )

        let itemReference = try await Keychain.Certificates.add(
            certificate,
            label: .custom(keychainLabel)
        )

        // Delete via normal API to make the reference stale
        try await Keychain.Certificates.delete(
            label: .specific(keychainLabel)
        )

        let retrieved = try await Keychain.Certificates.get(itemReference: itemReference)
        #expect(retrieved == nil)

        let attributes = try await Keychain.Certificates.attributes(itemReference: itemReference)
        #expect(attributes == nil)

        let deleted = try await Keychain.Certificates.delete(itemReference: itemReference)
        #expect(deleted == false)
    }
}

// MARK: - Private Helpers

private extension CertificatesItemReferenceIntegrationTests {
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
