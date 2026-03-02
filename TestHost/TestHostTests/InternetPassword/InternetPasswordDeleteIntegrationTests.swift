import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("InternetPassword Delete Integration Tests")
final class InternetPasswordDeleteIntegrationTests {
    private let keychainAccountName = "InternetPasswordDeleteIntegrationTests-account-\(UUID().uuidString)"
    private let keychainServer = "InternetPasswordDeleteIntegrationTests-server-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Delete removes item")
    func deleteRemovesItem() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "toDelete")

        try await Keychain.InternetPassword.add(
            password,
            account: keychainAccountName,
            server: keychainServer
        )

        let deleted = try await Keychain.InternetPassword.delete(
            account: .specific(keychainAccountName),
            server: .specific(keychainServer),
            accessGroup: .default
        )
        #expect(deleted == true)

        let retrieved = try await Keychain.InternetPassword.queryOne(
            account: keychainAccountName,
            server: keychainServer
        )
        #expect((retrieved == nil) == true)
    }

    @Test("Delete returns false for non-existent item")
    func deleteReturnsFalseForNonExistent() async throws {
        let deleted = try await Keychain.InternetPassword.delete(
            account: .specific(keychainAccountName),
            server: .specific(keychainServer),
            accessGroup: .default
        )
        #expect(deleted == false)
    }

    @Test("Delete with synchronized scope removes only synchronized item")
    func deleteSynchronizedRemovesOnlySynchronizedItem() async throws {
        let testAccount = "test-sync-account-\(UUID().uuidString)"
        let testServer = "test-sync-server-\(UUID().uuidString)"
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password")
        let password2 = try password.duplicate()

        defer {
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(testAccount),
                server: .specific(testServer),
                accessGroup: .default,
                synchronizable: .any
            )
        }

        // Add non-synchronized item
        try await Keychain.InternetPassword.add(
            password,
            account: testAccount,
            server: testServer,
            synchronizable: false
        )

        // Add synchronized item (same account + server)
        try await Keychain.InternetPassword.add(
            password2,
            account: testAccount,
            server: testServer,
            synchronizable: true
        )

        // Delete only synchronized item
        let deleted = try await Keychain.InternetPassword.delete(
            account: .specific(testAccount),
            server: .specific(testServer),
            accessGroup: .default,
            synchronizable: .synchronized
        )
        #expect(deleted == true)

        // Verify non-synchronized item still exists
        let remaining = try await Keychain.InternetPassword.queryOne(
            account: testAccount,
            server: testServer,
            synchronizable: false
        )
        #expect((remaining != nil) == true)
    }

    @Test("Delete with not synchronized scope removes only non-synchronized item")
    func deleteNotSynchronizedRemovesOnlyNonSynchronizedItem() async throws {
        let testAccount = "test-nonsync-account-\(UUID().uuidString)"
        let testServer = "test-nonsync-server-\(UUID().uuidString)"
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password")
        let password2 = try password.duplicate()

        defer {
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(testAccount),
                server: .specific(testServer),
                accessGroup: .default,
                synchronizable: .any
            )
        }

        // Add non-synchronized item
        try await Keychain.InternetPassword.add(
            password,
            account: testAccount,
            server: testServer,
            synchronizable: false
        )

        // Add synchronized item (same account + server)
        try await Keychain.InternetPassword.add(
            password2,
            account: testAccount,
            server: testServer,
            synchronizable: true
        )

        // Delete only non-synchronized item
        let deleted = try await Keychain.InternetPassword.delete(
            account: .specific(testAccount),
            server: .specific(testServer),
            accessGroup: .default,
            synchronizable: .notSynchronized
        )
        #expect(deleted == true)

        // Verify synchronized item still exists
        let remaining = try await Keychain.InternetPassword.queryOne(
            account: testAccount,
            server: testServer,
            synchronizable: true
        )
        #expect((remaining != nil) == true)
    }

    @Test("Delete with any scope removes both synchronized and non-synchronized items")
    func deleteAnyRemovesBothItems() async throws {
        let testAccount = "test-any-account-\(UUID().uuidString)"
        let testServer = "test-any-server-\(UUID().uuidString)"
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password")
        let password2 = try password.duplicate()

        defer {
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(testAccount),
                server: .specific(testServer),
                accessGroup: .default,
                synchronizable: .any
            )
        }

        // Add non-synchronized item
        try await Keychain.InternetPassword.add(
            password,
            account: testAccount,
            server: testServer,
            synchronizable: false
        )

        // Add synchronized item (same account + server)
        try await Keychain.InternetPassword.add(
            password2,
            account: testAccount,
            server: testServer,
            synchronizable: true
        )

        // Delete both items
        let deleted = try await Keychain.InternetPassword.delete(
            account: .specific(testAccount),
            server: .specific(testServer),
            accessGroup: .default,
            synchronizable: .any
        )
        #expect(deleted == true)

        // Verify no items remain
        let remainingNonSync = try await Keychain.InternetPassword.queryOne(
            account: testAccount,
            server: testServer,
            synchronizable: false
        )
        #expect((remainingNonSync == nil) == true)

        let remainingSync = try await Keychain.InternetPassword.queryOne(
            account: testAccount,
            server: testServer,
            synchronizable: true
        )
        #expect((remainingSync == nil) == true)
    }
}

// MARK: - Private Helpers

private extension InternetPasswordDeleteIntegrationTests {
    func cleanup() {
        do {
            try Keychain.InternetPassword.delete(
                account: .specific(keychainAccountName),
                server: .specific(keychainServer),
                accessGroup: .default
            )
        } catch {
            print("Failed to clean up internet password after test: \(error)")
        }
    }
}
