import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("GenericPassword Query Integration Tests")
final class GenericPasswordQueryIntegrationTests {
    private let keychainServiceName = "GenericPasswordQueryIntegrationTests-service-\(UUID().uuidString)"
    private let keychainAccountName = "GenericPasswordQueryIntegrationTests-account-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Query returns multiple items")
    func queryReturnsMultipleItems() async throws {
        let accounts = (0..<3).map { "test-query-\($0)-\(UUID().uuidString)" }

        defer {
            for account in accounts {
                _ = try? Keychain.GenericPassword.delete(
                    account: .specific(account),
                    service: .specific(keychainServiceName),
                    accessGroup: .any
                )
            }
        }

        for (index, account) in accounts.enumerated() {
            let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password-\(index)")
            try await Keychain.GenericPassword.add(
                password,
                account: account,
                service: keychainServiceName
            )
        }

        let results = try await Keychain.GenericPassword.query(
            service: .specific(keychainServiceName),
            limit: .unlimited
        )
        #expect(results.count >= 3)
    }

    @Test("Query with limit returns limited results")
    func queryWithLimit() async throws {
        let accounts = (0..<3).map { "test-query-limit-\($0)-\(UUID().uuidString)" }

        defer {
            for account in accounts {
                _ = try? Keychain.GenericPassword.delete(
                    account: .specific(account),
                    service: .specific(keychainServiceName),
                    accessGroup: .any
                )
            }
        }

        for account in accounts {
            let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password")
            try await Keychain.GenericPassword.add(
                password,
                account: account,
                service: keychainServiceName
            )
        }

        let results = try await Keychain.GenericPassword.query(
            service: .specific(keychainServiceName),
            limit: .count(2)
        )
        #expect(results.count <= 2)
    }

    @Test("Query returns empty array when no matches")
    func queryReturnsEmptyArrayWhenNoMatches() async throws {
        let results = try await Keychain.GenericPassword.query(
            service: .specific(UUID().uuidString)
        )
        #expect(results.isEmpty == true)
    }

    @Test("Query generic type returns UniqueArray with converted items")
    func queryGenericTypeReturnsUniqueArray() async throws {
        let accountsAndPasswords = [
            ("account-\(UUID().uuidString)", "password-1"),
            ("account-\(UUID().uuidString)", "password-2"),
            ("account-\(UUID().uuidString)", "password-3"),
        ]

        defer {
            for (account, _) in accountsAndPasswords {
                _ = try? Keychain.GenericPassword.delete(
                    account: .specific(account),
                    service: .specific(keychainServiceName),
                    accessGroup: .any
                )
            }
        }

        for (account, password) in accountsAndPasswords {
            let secretData = try SecretData.makeByCopyingUTF8(fromUnsafeString: password)

            try await Keychain.GenericPassword.add(
                secretData,
                account: account,
                service: keychainServiceName
            )
        }

        var results = try await Keychain.GenericPassword.query(
            TestPassword.self,
            service: .specific(keychainServiceName),
            limit: .unlimited
        )

        #expect(results.count == 3)

        var passwords = Set<String>()
        while let passwordData = results.popLast() {
            let password = try #require(String(data: passwordData.value, encoding: .utf8))
            passwords.insert(password)
        }
        #expect(passwords == Set(accountsAndPasswords.map(\.1)))
    }
}

// MARK: - Private Helpers

private extension GenericPasswordQueryIntegrationTests {
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

// MARK: - Test Types

private extension GenericPasswordQueryIntegrationTests {
    struct TestPassword: Keychain.GenericPasswordInitializable & Copyable {
        let value: Data

        init(genericPasswordRepresentation data: consuming some SecretDataProtocol & ~Copyable) throws {
            value = data.withUnsafeBytes { buffer in
                Data(bytes: buffer.baseAddress!, count: buffer.count)
            }
        }
    }
}
