import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("GenericPassword Delete Integration Tests")
final class GenericPasswordDeleteIntegrationTests {
    private let keychainServiceName = "GenericPasswordDeleteIntegrationTests-service-\(UUID().uuidString)"
    private let keychainAccountName = "GenericPasswordDeleteIntegrationTests-account-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Delete removes item")
    func deleteRemovesItem() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "toDelete")

        try await Keychain.GenericPassword.add(
            password,
            account: keychainAccountName,
            service: keychainServiceName
        )

        let deleted = try await Keychain.GenericPassword.delete(
            account: .specific(keychainAccountName),
            service: .specific(keychainServiceName),
            accessGroup: .any
        )
        #expect(deleted == true)

        let retrieved = try await Keychain.GenericPassword.query(
            account: .specific(keychainAccountName),
            service: .specific(keychainServiceName)
        )
        #expect(retrieved.isEmpty == true)
    }

    @Test("Delete returns false for non-existent item")
    func deleteReturnsFalseForNonExistent() async throws {
        let deleted = try await Keychain.GenericPassword.delete(
            account: .specific(UUID().uuidString),
            service: .specific(keychainServiceName),
            accessGroup: .any
        )
        #expect(deleted == false)
    }

    @Test("Delete with synchronized scope removes only synchronized item")
    func deleteSynchronizedRemovesOnlySynchronizedItem() async throws {
        let testAccount = "test-sync-account-\(UUID().uuidString)"
        let testService = "test-sync-service-\(UUID().uuidString)"
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password")
        let passwordCopy = try password.duplicate()

        defer {
            _ = try? Keychain.GenericPassword.delete(
                account: .specific(testAccount),
                service: .specific(testService),
                accessGroup: .any,
                synchronizable: .any
            )
        }

        // Add non-synchronized item
        try await Keychain.GenericPassword.add(
            password,
            account: testAccount,
            service: testService,
            synchronizable: false
        )

        // Add synchronized item (same account + service)
        try await Keychain.GenericPassword.add(
            passwordCopy,
            account: testAccount,
            service: testService,
            synchronizable: true
        )

        // Delete only synchronized item
        let deleted = try await Keychain.GenericPassword.delete(
            account: .specific(testAccount),
            service: .specific(testService),
            accessGroup: .any,
            synchronizable: .synchronized
        )
        #expect(deleted == true)

        // Verify non-synchronized item still exists
        let remaining = try await Keychain.GenericPassword.query(
            account: .specific(testAccount),
            service: .specific(testService),
            synchronizable: .notSynchronized,
            limit: .count(2)
        )
        #expect(remaining.count == 1)
    }

    @Test("Delete with not synchronized scope removes only non-synchronized item")
    func deleteNotSynchronizedRemovesOnlyNonSynchronizedItem() async throws {
        let testAccount = "test-nonsync-account-\(UUID().uuidString)"
        let testService = "test-nonsync-service-\(UUID().uuidString)"
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password")
        let passwordCopy = try password.duplicate()

        defer {
            _ = try? Keychain.GenericPassword.delete(
                account: .specific(testAccount),
                service: .specific(testService),
                accessGroup: .any,
                synchronizable: .any
            )
        }

        // Add non-synchronized item
        try await Keychain.GenericPassword.add(
            password,
            account: testAccount,
            service: testService,
            synchronizable: false
        )

        // Add synchronized item (same account + service)
        try await Keychain.GenericPassword.add(
            passwordCopy,
            account: testAccount,
            service: testService,
            synchronizable: true
        )

        // Delete only non-synchronized item
        let deleted = try await Keychain.GenericPassword.delete(
            account: .specific(testAccount),
            service: .specific(testService),
            accessGroup: .any,
            synchronizable: .notSynchronized
        )
        #expect(deleted == true)

        // Verify synchronized item still exists
        let remaining = try await Keychain.GenericPassword.query(
            account: .specific(testAccount),
            service: .specific(testService),
            synchronizable: .synchronized,
            limit: .count(2)
        )
        #expect(remaining.count == 1)
    }

    @Test("Delete with any scope removes both synchronized and non-synchronized items")
    func deleteAnyRemovesBothItems() async throws {
        let testAccount = "test-any-account-\(UUID().uuidString)"
        let testService = "test-any-service-\(UUID().uuidString)"
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password")
        let passwordCopy = try password.duplicate()

        defer {
            _ = try? Keychain.GenericPassword.delete(
                account: .specific(testAccount),
                service: .specific(testService),
                accessGroup: .any,
                synchronizable: .any
            )
        }

        // Add non-synchronized item
        try await Keychain.GenericPassword.add(
            password,
            account: testAccount,
            service: testService,
            synchronizable: false
        )

        // Add synchronized item (same account + service)
        try await Keychain.GenericPassword.add(
            passwordCopy,
            account: testAccount,
            service: testService,
            synchronizable: true
        )

        // Delete both items
        let deleted = try await Keychain.GenericPassword.delete(
            account: .specific(testAccount),
            service: .specific(testService),
            accessGroup: .any,
            synchronizable: .any
        )
        #expect(deleted == true)

        // Verify no items remain
        let remainingNonSync = try await Keychain.GenericPassword.query(
            account: .specific(testAccount),
            service: .specific(testService),
            synchronizable: .notSynchronized
        )
        #expect(remainingNonSync.isEmpty == true)

        let remainingSync = try await Keychain.GenericPassword.query(
            account: .specific(testAccount),
            service: .specific(testService),
            synchronizable: .synchronized
        )
        #expect(remainingSync.isEmpty == true)
    }
}

// MARK: - Private Helpers

private extension GenericPasswordDeleteIntegrationTests {
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
