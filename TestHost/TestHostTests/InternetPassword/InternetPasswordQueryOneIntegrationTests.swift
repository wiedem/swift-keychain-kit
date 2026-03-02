import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("InternetPassword QueryOne Integration Tests")
final class InternetPasswordQueryOneIntegrationTests {
    private let testAccount = "queryOne-test-\(UUID().uuidString)"
    private let testServer = "queryOne-server-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    // MARK: - Basic queryOne Tests

    @Test("queryOne returns single item")
    func queryOneReturnsSingleItem() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret123")
        let passwordCopy = try password.duplicate()

        try await Keychain.InternetPassword.add(
            password,
            account: testAccount,
            server: testServer
        )

        let result = try await Keychain.InternetPassword.queryOne(
            account: testAccount,
            server: testServer
        )

        let retrieved = try requireUnwrapped(result)
        #expect((retrieved == passwordCopy) == true)
    }

    @Test("queryOne returns nil for non-existent item")
    func queryOneReturnsNilForNonExistent() async throws {
        let result = try await Keychain.InternetPassword.queryOne(
            account: UUID().uuidString,
            server: testServer
        )

        #expect((result == nil) == true)
    }

    @Test("queryOne throws multipleItemsFound when multiple items match")
    func queryOneThrowsMultipleItemsFound() async throws {
        let account = "multi-\(UUID().uuidString)"
        let server = "example.com"
        let password1 = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password1")
        let password2 = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password2")

        defer {
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(account),
                server: .specific(server),
                port: .any,
                accessGroup: .default
            )
        }

        // Add two entries with same account + server but different ports
        try await Keychain.InternetPassword.add(
            password1,
            account: account,
            server: server,
            port: 8080
        )
        try await Keychain.InternetPassword.add(
            password2,
            account: account,
            server: server,
            port: 443
        )

        // queryOne should throw because multiple items match
        await #expect(throws: KeychainError.multipleItemsFound) {
            _ = try await Keychain.InternetPassword.queryOne(
                account: account,
                server: server
            )
        }
    }

    // MARK: - queryOne with Optional Parameters

    @Test("queryOne with all specific parameters")
    func queryOneWithAllSpecificParameters() async throws {
        let account = "specific-\(UUID().uuidString)"
        let server = "api.example.com"
        let targetPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "target-pass")
        let targetPassword2 = try targetPassword.duplicate()
        let otherPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "other-pass")

        defer {
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(account),
                server: .specific(server),
                protocol: .any,
                authenticationType: .any,
                port: .any,
                path: .any,
                securityDomain: .any,
                accessGroup: .default
            )
        }

        // Add target entry with all attributes
        try await Keychain.InternetPassword.add(
            targetPassword,
            account: account,
            server: server,
            protocol: .https,
            authenticationType: .httpBasic,
            port: 443,
            path: "/api/v1",
            securityDomain: "domain1"
        )

        // Add another entry with different port
        try await Keychain.InternetPassword.add(
            otherPassword,
            account: account,
            server: server,
            protocol: .https,
            authenticationType: .httpBasic,
            port: 8443,
            path: "/api/v1",
            securityDomain: "domain1"
        )

        // Query with all filters to get specific entry
        let result = try await Keychain.InternetPassword.queryOne(
            account: account,
            server: server,
            protocol: .specific(.https),
            authenticationType: .specific(.httpBasic),
            port: .specific(443),
            path: .specific("/api/v1"),
            securityDomain: .specific("domain1")
        )

        let retrieved = try requireUnwrapped(result)
        #expect((retrieved == targetPassword2) == true)
    }

    @Test("queryOne with .any parameters")
    func queryOneWithAnyParameters() async throws {
        let account = "any-\(UUID().uuidString)"
        let server = "example.com"
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password")
        let passwordCopy = try password.duplicate()

        defer {
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(account),
                server: .specific(server),
                accessGroup: .default
            )
        }

        try await Keychain.InternetPassword.add(
            password,
            account: account,
            server: server,
            protocol: .https,
            port: 443
        )

        // Query with .any for optional parameters
        let result = try await Keychain.InternetPassword.queryOne(
            account: account,
            server: server,
            protocol: .any,
            authenticationType: .any,
            port: .any,
            path: .any,
            securityDomain: .any
        )

        let retrieved = try requireUnwrapped(result)
        #expect((retrieved == passwordCopy) == true)
    }
}

// MARK: - Private Helpers

private extension InternetPasswordQueryOneIntegrationTests {
    func cleanup() {
        do {
            try Keychain.InternetPassword.delete(
                account: .specific(testAccount),
                server: .specific(testServer),
                accessGroup: .default
            )
        } catch {
            print("Failed to clean up internet password after test: \(error)")
        }
    }
}
