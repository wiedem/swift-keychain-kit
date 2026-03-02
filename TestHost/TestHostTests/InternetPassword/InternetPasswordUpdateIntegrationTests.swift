import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("InternetPassword Update Integration Tests")
final class InternetPasswordUpdateIntegrationTests {
    private let keychainAccountName = "InternetPasswordUpdateIntegrationTests-account-\(UUID().uuidString)"
    private let keychainServer = "InternetPasswordUpdateIntegrationTests-server-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("UpdateMatching changes password data")
    func updateMatchingChangesPassword() async throws {
        let originalPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "original")
        let updatedPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "updated")
        let updatedPasswordExpected = try updatedPassword.duplicate()

        try await Keychain.InternetPassword.add(
            originalPassword,
            account: keychainAccountName,
            server: keychainServer
        )

        try await Keychain.InternetPassword.updateMatching(
            account: keychainAccountName,
            server: keychainServer,
            to: updatedPassword
        )

        let retrieved = try await requireUnwrapped(
            Keychain.InternetPassword.queryOne(
                account: keychainAccountName,
                server: keychainServer
            )
        )
        #expect((retrieved == updatedPasswordExpected) == true)
    }

    @Test("UpdateMatching with specific port only updates that port")
    func updateMatchingWithSpecificPortOnlyUpdatesThatPort() async throws {
        let account = "port-update-\(UUID().uuidString)"
        let server = "example.com"
        let password8080 = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password-8080")
        let password443 = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password-443")
        let password443Expected = try password443.duplicate()
        let updatedPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "updated")
        let updatedPasswordExpected = try updatedPassword.duplicate()

        defer {
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(account),
                server: .specific(server),
                port: 8080,
                accessGroup: .default
            )
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(account),
                server: .specific(server),
                port: 443,
                accessGroup: .default
            )
        }

        // Add two entries with different ports
        try await Keychain.InternetPassword.add(
            password8080,
            account: account,
            server: server,
            port: 8080
        )
        try await Keychain.InternetPassword.add(
            password443,
            account: account,
            server: server,
            port: 443
        )

        // Update only port 8080
        try await Keychain.InternetPassword.updateMatching(
            account: account,
            server: server,
            port: .specific(8080),
            to: updatedPassword
        )

        // Check port 8080 was updated
        let retrieved8080 = try await requireUnwrapped(
            Keychain.InternetPassword.queryOne(
                account: account,
                server: server,
                port: .specific(8080)
            )
        )
        #expect((retrieved8080 == updatedPasswordExpected) == true)

        // Check port 443 was NOT updated
        let retrieved443 = try await requireUnwrapped(
            Keychain.InternetPassword.queryOne(
                account: account,
                server: server,
                port: .specific(443)
            )
        )
        #expect((retrieved443 == password443Expected) == true)
    }

    @Test("UpdateMatching with .any scope updates all matching entries")
    func updateMatchingWithAnyScopeUpdatesAllEntries() async throws {
        let account = "any-update-\(UUID().uuidString)"
        let server = "example.com"
        let password8080 = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password-8080")
        let password443 = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password-443")
        let updatedPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "updated-all")
        let updatedPasswordExpected = try updatedPassword.duplicate()

        defer {
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(account),
                server: .specific(server),
                accessGroup: .default
            )
        }

        // Add two entries with different ports
        try await Keychain.InternetPassword.add(
            password8080,
            account: account,
            server: server,
            port: 8080
        )
        try await Keychain.InternetPassword.add(
            password443,
            account: account,
            server: server,
            port: 443
        )

        // Update all entries (port = .any)
        try await Keychain.InternetPassword.updateMatching(
            account: account,
            server: server,
            port: .any,
            to: updatedPassword
        )

        // Check both were updated
        let retrieved8080 = try await requireUnwrapped(
            Keychain.InternetPassword.queryOne(
                account: account,
                server: server,
                port: .specific(8080)
            )
        )
        #expect((retrieved8080 == updatedPasswordExpected) == true)

        let retrieved443 = try await requireUnwrapped(
            Keychain.InternetPassword.queryOne(
                account: account,
                server: server,
                port: .specific(443)
            )
        )
        #expect((retrieved443 == updatedPasswordExpected) == true)
    }

    @Test("UpdateMatching non-existent item throws itemNotFound")
    func updateMatchingNonExistentThrows() async throws {
        await #expect(throws: KeychainError.itemNotFound) {
            let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password")
            try await Keychain.InternetPassword.updateMatching(
                account: keychainAccountName,
                server: keychainServer,
                to: password
            )
        }
    }
}

// MARK: - Private Helpers

private extension InternetPasswordUpdateIntegrationTests {
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
