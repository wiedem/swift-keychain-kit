import BasicContainers
import Foundation
import SwiftKeychainKit
import Testing

@Suite("InternetPassword ItemReference Integration Tests")
final class InternetPasswordItemReferenceIntegrationTests {
    private let keychainAccountName = "InternetPasswordItemReferenceIntegrationTests-account-\(UUID().uuidString)"
    private let keychainServerName = "InternetPasswordItemReferenceIntegrationTests-server-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("ItemReference lifecycle: add, get, attributes, update, delete")
    func itemReferenceLifecycle() async throws {
        // Add
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret123")
        let expectedPassword = try password.duplicate()
        let itemReference = try await Keychain.InternetPassword.add(
            password,
            account: keychainAccountName,
            server: keychainServerName
        )

        // Get by reference
        let retrieved = try await requireUnwrapped(
            Keychain.InternetPassword.get(itemReference: itemReference)
        )
        #expect((retrieved == expectedPassword) == true)

        // Attributes by reference
        let attributes = try await Keychain.InternetPassword.attributes(itemReference: itemReference)
        let attributeValues = try requireUnwrapped(attributes)
        #expect(attributeValues.account == keychainAccountName)
        #expect(attributeValues.server == keychainServerName)

        // Update by reference
        let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "updated456")
        let expectedUpdated = try newPassword.duplicate()
        try await Keychain.InternetPassword.update(itemReference: itemReference, to: newPassword)

        let updatedRetrieved = try await requireUnwrapped(
            Keychain.InternetPassword.get(itemReference: itemReference)
        )
        #expect((updatedRetrieved == expectedUpdated) == true)

        // Delete by reference
        let deleted = try await Keychain.InternetPassword.delete(itemReference: itemReference)
        #expect(deleted == true)

        // Verify deletion
        let afterDelete = try await Keychain.InternetPassword.get(itemReference: itemReference)
        #expect((afterDelete == nil) == true)
    }

    @Test("Operations with stale ItemReference return nil, false, or throw")
    func staleItemReference() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "temporary")
        let itemReference = try await Keychain.InternetPassword.add(
            password,
            account: keychainAccountName,
            server: keychainServerName
        )

        // Delete via normal API to make the reference stale
        try await Keychain.InternetPassword.delete(
            account: .specific(keychainAccountName),
            server: .specific(keychainServerName),
            accessGroup: .default
        )

        let retrieved = try await Keychain.InternetPassword.get(itemReference: itemReference)
        #expect((retrieved == nil) == true)

        let attributes = try await Keychain.InternetPassword.attributes(itemReference: itemReference)
        #expect(attributes == nil)

        let deleted = try await Keychain.InternetPassword.delete(itemReference: itemReference)
        #expect(deleted == false)

        await #expect(throws: KeychainError.itemNotFound) {
            let updateData = try SecretData.makeByCopyingUTF8(fromUnsafeString: "update")
            try await Keychain.InternetPassword.update(
                itemReference: itemReference,
                to: updateData
            )
        }
    }
}

// MARK: - Private Helpers

private extension InternetPasswordItemReferenceIntegrationTests {
    func cleanup() {
        do {
            try Keychain.InternetPassword.delete(
                account: .specific(keychainAccountName),
                server: .specific(keychainServerName),
                accessGroup: .default
            )
        } catch {
            print("Failed to clean up internet password after test: \(error)")
        }
    }
}
