import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("Identities ItemReference Integration Tests")
final class IdentitiesItemReferenceIntegrationTests {
    private let keychainLabel = "IdentitiesItemReferenceIntegrationTests-label-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("ItemReference lifecycle: add, get, attributes, delete")
    func itemReferenceLifecycle() async throws {
        let identity = try TestCertificateGenerator.generateSecIdentity(
            commonName: "Test-ItemRef-\(UUID().uuidString)"
        )

        // Add
        let itemReference = try await Keychain.Identities.add(
            identity,
            label: .custom(keychainLabel)
        )

        // Get by reference
        let retrieved = try await requireUnwrapped(
            Keychain.Identities.get(itemReference: itemReference)
        )
        #expect(retrieved == identity)

        // Attributes by reference
        let attributes = try await Keychain.Identities.attributes(itemReference: itemReference)
        let attributeValues = try requireUnwrapped(attributes)
        #expect(attributeValues.label == keychainLabel)

        // Delete by reference
        let deleted = try await Keychain.Identities.delete(itemReference: itemReference)
        #expect(deleted == true)

        // Verify deletion
        let afterDelete = try await Keychain.Identities.get(itemReference: itemReference)
        #expect(afterDelete == nil)
    }

    @Test("Operations with stale ItemReference return nil or false")
    func staleItemReference() async throws {
        let identity = try TestCertificateGenerator.generateSecIdentity(
            commonName: "Test-Stale-\(UUID().uuidString)"
        )

        let itemReference = try await Keychain.Identities.add(
            identity,
            label: .custom(keychainLabel)
        )

        // Delete via normal API to make the reference stale
        try await Keychain.Identities.delete(
            label: .specific(keychainLabel)
        )

        let retrieved = try await Keychain.Identities.get(itemReference: itemReference)
        #expect(retrieved == nil)

        let attributes = try await Keychain.Identities.attributes(itemReference: itemReference)
        #expect(attributes == nil)

        let deleted = try await Keychain.Identities.delete(itemReference: itemReference)
        #expect(deleted == false)
    }
}

// MARK: - Private Helpers

private extension IdentitiesItemReferenceIntegrationTests {
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
