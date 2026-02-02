import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("GenericPassword Update Integration Tests")
final class GenericPasswordUpdateIntegrationTests {
    private let keychainServiceName = "GenericPasswordUpdateIntegrationTests-service-\(UUID().uuidString)"
    private let keychainAccountName = "GenericPasswordUpdateIntegrationTests-account-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test(
        "Update changes password data",
        .enabled(
            if: AppEntitlementsAccessGroupProvider.isDefaultAccessGroupAvailable,
            "Default keychain access group could not be determined"
        )
    )
    func updateChangesPassword() async throws {
        let originalPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "original")
        let updatedPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "updated")
        let updatedPasswordExpected = try updatedPassword.duplicate()

        try await Keychain.GenericPassword.add(
            originalPassword,
            account: keychainAccountName,
            service: keychainServiceName
        )

        try await Keychain.GenericPassword.update(
            account: keychainAccountName,
            service: keychainServiceName,
            accessGroup: .default,
            to: updatedPassword
        )

        var items = try await Keychain.GenericPassword.query(
            account: .specific(keychainAccountName),
            service: .specific(keychainServiceName)
        )
        let retrieved = items.remove(at: 0)
        #expect((retrieved == updatedPasswordExpected) == true)
    }

    @Test(
        "Update non-existent item throws itemNotFound",
        .enabled(
            if: AppEntitlementsAccessGroupProvider.isDefaultAccessGroupAvailable,
            "Default keychain access group could not be determined"
        )
    )
    func updateNonExistentThrows() async throws {
        await #expect(throws: KeychainError.itemNotFound) {
            let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password")
            try await Keychain.GenericPassword.update(
                account: keychainAccountName,
                service: keychainServiceName,
                accessGroup: .default,
                to: password
            )
        }
    }

    @Test(
        "Update only updates the exact matching entry",
        .enabled(
            if: AppEntitlementsAccessGroupProvider.isDefaultAccessGroupAvailable,
            "Default keychain access group could not be determined"
        )
    )
    func updateOnlyUpdatesExactMatch() async throws {
        // Create two entries: one synchronized, one not
        let syncAccount = "sync-\(UUID().uuidString)"
        let nonSyncAccount = "nonsync-\(UUID().uuidString)"
        let service = keychainServiceName

        defer {
            _ = try? Keychain.GenericPassword.delete(
                service: .specific(service),
                accessGroup: .any,
                synchronizable: .any
            )
        }

        try await Keychain.GenericPassword.add(
            SecretData.makeByCopyingUTF8(fromUnsafeString: "sync-password"),
            account: syncAccount,
            service: service,
            synchronizable: true
        )

        try await Keychain.GenericPassword.add(
            SecretData.makeByCopyingUTF8(fromUnsafeString: "nonsync-password"),
            account: nonSyncAccount,
            service: service,
            synchronizable: false
        )

        // Update only the non-synchronized entry
        let updatedPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "updated-nonsync")
        let updatedPasswordExpected = try updatedPassword.duplicate()
        try await Keychain.GenericPassword.update(
            account: nonSyncAccount,
            service: service,
            accessGroup: .default,
            synchronizable: false,
            to: updatedPassword
        )

        // Verify only the non-synchronized entry was updated
        var nonSyncRetrieved = try await Keychain.GenericPassword.query(
            account: .specific(nonSyncAccount),
            service: .specific(service),
            synchronizable: .notSynchronized,
            limit: .count(2)
        )
        #expect(nonSyncRetrieved.count == 1)
        let nonSyncRetrievedItem = nonSyncRetrieved.remove(at: 0)
        #expect((nonSyncRetrievedItem == updatedPasswordExpected) == true)

        // Verify synchronized entry was not modified
        let syncPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "sync-password")
        var syncRetrieved = try await Keychain.GenericPassword.query(
            account: .specific(syncAccount),
            service: .specific(service),
            synchronizable: .synchronized,
            limit: .count(2)
        )
        #expect(syncRetrieved.count == 1)
        let syncRetrievedItem = syncRetrieved.remove(at: 0)
        #expect((syncRetrievedItem == syncPassword) == true)
    }
}

// MARK: - Private Helpers

private extension GenericPasswordUpdateIntegrationTests {
    func cleanup() {
        do {
            try Keychain.GenericPassword.delete(
                account: .specific(keychainAccountName),
                service: .specific(keychainServiceName),
                accessGroup: .any,
                synchronizable: .any
            )
        } catch {
            print("Failed to clean up generic password after test: \(error)")
        }
    }
}
