import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("InternetPassword Add Integration Tests")
final class InternetPasswordAddIntegrationTests {
    private let keychainAccountName = "InternetPasswordAddIntegrationTests-account-\(UUID().uuidString)"
    private let keychainServer = "InternetPasswordAddIntegrationTests-server-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Add and retrieve password")
    func addAndRetrieve() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "internetSecret123")
        let password2 = try password.duplicate()

        try await Keychain.InternetPassword.add(
            password,
            account: keychainAccountName,
            server: keychainServer
        )

        let retrieved = try await requireUnwrapped(
            Keychain.InternetPassword.queryOne(
                account: keychainAccountName,
                server: keychainServer
            )
        )
        #expect((retrieved == password2) == true)
    }

    @Test("Add with protocol and port")
    func addWithProtocolAndPort() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
        let passwordExpected = try password.duplicate()

        try await Keychain.InternetPassword.add(
            password,
            account: keychainAccountName,
            server: keychainServer,
            protocol: .https,
            port: 443
        )

        let retrieved = try await requireUnwrapped(
            Keychain.InternetPassword.queryOne(
                account: keychainAccountName,
                server: keychainServer,
                protocol: .specific(.https),
                port: .specific(443)
            )
        )
        #expect((retrieved == passwordExpected) == true)
    }

    @Test("Add with path")
    func addWithPath() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "pathSecret")
        let passwordExpected = try password.duplicate()
        let path = "/api/v1/auth"

        try await Keychain.InternetPassword.add(
            password,
            account: keychainAccountName,
            server: keychainServer,
            path: path
        )

        let retrieved = try await requireUnwrapped(
            Keychain.InternetPassword.queryOne(
                account: keychainAccountName,
                server: keychainServer,
                path: .specific(path)
            )
        )
        #expect((retrieved == passwordExpected) == true)
    }

    @Test("Add with all optional parameters")
    func addWithAllOptionalParameters() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "fullSecret")
        let passwordExpected = try password.duplicate()
        let path = "/secure"

        try await Keychain.InternetPassword.add(
            password,
            account: keychainAccountName,
            server: keychainServer,
            protocol: .https,
            authenticationType: .httpBasic,
            port: 8443,
            path: path,
            label: "Test Internet Password"
        )

        let retrieved = try await requireUnwrapped(
            Keychain.InternetPassword.queryOne(
                account: keychainAccountName,
                server: keychainServer,
                protocol: .specific(.https),
                authenticationType: .specific(.httpBasic),
                port: .specific(8443),
                path: .specific(path)
            )
        )
        #expect((retrieved == passwordExpected) == true)
    }

    @Test("Add duplicate throws duplicateItem error")
    func addDuplicateThrows() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")

        try await Keychain.InternetPassword.add(
            password,
            account: keychainAccountName,
            server: keychainServer
        )

        await #expect(throws: KeychainError.duplicateItem) {
            let passwordCopy = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
            try await Keychain.InternetPassword.add(
                passwordCopy,
                account: keychainAccountName,
                server: keychainServer
            )
        }
    }
}

// MARK: - Private Helpers

private extension InternetPasswordAddIntegrationTests {
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
