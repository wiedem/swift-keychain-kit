import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("InternetPassword Query Integration Tests")
final class InternetPasswordQueryIntegrationTests {
    private let keychainAccountName = "InternetPasswordQueryIntegrationTests-account-\(UUID().uuidString)"
    private let keychainServer = "InternetPasswordQueryIntegrationTests-server-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Query returns empty array for non-existent item")
    func queryNonExistent() async throws {
        let result = try await Keychain.InternetPassword.query(
            account: .specific(UUID().uuidString),
            server: .specific(keychainServer)
        )
        #expect(result.isEmpty == true)
    }

    @Test("Query with server filter returns matching items")
    func queryWithServerFilter() async throws {
        let accounts = (0..<2).map { "test-query-\($0)-\(UUID().uuidString)" }

        defer {
            for account in accounts {
                _ = try? Keychain.InternetPassword.delete(
                    account: .specific(account),
                    server: .specific(keychainServer),
                    accessGroup: .any
                )
            }
        }

        for account in accounts {
            try await Keychain.InternetPassword.add(
                SecretData.makeByCopyingUTF8(fromUnsafeString: "password"),
                account: account,
                server: keychainServer
            )
        }

        let results = try await Keychain.InternetPassword.query(
            server: .specific(keychainServer),
            limit: .unlimited
        )
        #expect(results.count >= 2)
    }

    @Test("Query returns empty array when no matches")
    func queryReturnsEmptyArrayWhenNoMatches() async throws {
        let results = try await Keychain.InternetPassword.query(
            server: .specific(UUID().uuidString)
        )
        #expect(results.isEmpty == true)
    }
}

// MARK: - Private Helpers

private extension InternetPasswordQueryIntegrationTests {
    func cleanup() {
        do {
            try Keychain.InternetPassword.delete(
                account: .specific(keychainAccountName),
                server: .specific(keychainServer),
                accessGroup: .any
            )
        } catch {
            print("Failed to clean up internet password after test: \(error)")
        }
    }
}
