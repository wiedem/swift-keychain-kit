import BasicContainers
import Foundation
import SwiftKeychainKit
import Testing

@Suite("GenericPassword ItemReference Integration Tests")
final class GenericPasswordItemReferenceIntegrationTests {
    private let keychainServiceName = "GenericPasswordItemReferenceIntegrationTests-service-\(UUID().uuidString)"
    private let keychainAccountName = "GenericPasswordItemReferenceIntegrationTests-account-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("ItemReference lifecycle: add, get, attributes, update, delete")
    func itemReferenceLifecycle() async throws {
        // Add
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret123")
        let expectedPassword = try password.duplicate()
        let itemReference = try await Keychain.GenericPassword.add(
            password,
            account: keychainAccountName,
            service: keychainServiceName
        )

        // Get by reference
        let retrieved = try await requireUnwrapped(
            Keychain.GenericPassword.get(itemReference: itemReference)
        )
        #expect((retrieved == expectedPassword) == true)

        // Attributes by reference
        let attributes = try await Keychain.GenericPassword.attributes(itemReference: itemReference)
        let attributeValues = try requireUnwrapped(attributes)
        #expect(attributeValues.account == keychainAccountName)
        #expect(attributeValues.service == keychainServiceName)

        // Update by reference
        let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "updated456")
        let expectedUpdated = try newPassword.duplicate()
        try await Keychain.GenericPassword.update(itemReference: itemReference, to: newPassword)

        let updatedRetrieved = try await requireUnwrapped(
            Keychain.GenericPassword.get(itemReference: itemReference)
        )
        #expect((updatedRetrieved == expectedUpdated) == true)

        // Delete by reference
        let deleted = try await Keychain.GenericPassword.delete(itemReference: itemReference)
        #expect(deleted == true)

        // Verify deletion
        let afterDelete = try await Keychain.GenericPassword.get(itemReference: itemReference)
        #expect((afterDelete == nil) == true)
    }

    @Test("Operations with stale ItemReference return nil, false, or throw")
    func staleItemReference() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "temporary")
        let itemReference = try await Keychain.GenericPassword.add(
            password,
            account: keychainAccountName,
            service: keychainServiceName
        )

        // Delete via normal API to make the reference stale
        try await Keychain.GenericPassword.delete(
            account: .specific(keychainAccountName),
            service: .specific(keychainServiceName),
            accessGroup: .default
        )

        let retrieved = try await Keychain.GenericPassword.get(itemReference: itemReference)
        #expect((retrieved == nil) == true)

        let attributes = try await Keychain.GenericPassword.attributes(itemReference: itemReference)
        #expect(attributes == nil)

        let deleted = try await Keychain.GenericPassword.delete(itemReference: itemReference)
        #expect(deleted == false)

        await #expect(throws: KeychainError.itemNotFound) {
            let updateData = try SecretData.makeByCopyingUTF8(fromUnsafeString: "update")
            try await Keychain.GenericPassword.update(
                itemReference: itemReference,
                to: updateData
            )
        }
    }
}

// MARK: - Private Helpers

private extension GenericPasswordItemReferenceIntegrationTests {
    func cleanup() {
        do {
            try Keychain.GenericPassword.delete(
                account: .specific(keychainAccountName),
                service: .specific(keychainServiceName),
                accessGroup: .default
            )
        } catch {
            print("Failed to clean up generic password after test: \(error)")
        }
    }
}
