import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("InternetPassword Attributes Integration Tests")
final class InternetPasswordAttributesIntegrationTests {
    private let keychainAccountName = "InternetPasswordAttributesIntegrationTests-account-\(UUID().uuidString)"
    private let keychainServer = "InternetPasswordAttributesIntegrationTests-server-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Attributes returns all metadata")
    func attributesReturnsAllMetadata() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
        let label = "Test Internet Attributes Label"

        let itemReference = try await Keychain.InternetPassword.add(
            password,
            account: keychainAccountName,
            server: keychainServer,
            protocol: .http,
            authenticationType: .httpBasic,
            port: 80,
            path: "/test",
            securityDomain: "example.com",
            label: label,
            accessControl: .whenUnlockedThisDeviceOnly
        )

        let attributes = try await Keychain.InternetPassword.queryAttributes(
            account: .specific(keychainAccountName),
            server: .specific(keychainServer)
        )

        #expect(attributes.count == 1)
        let first = try requireUnwrapped(attributes.first)
        #expect(first.itemReference == itemReference)
        #expect(first.account == keychainAccountName)
        #expect(first.server == keychainServer)
        #expect(first.networkProtocol == .http)
        #expect(first.authenticationType == .httpBasic)
        #expect(first.port == 80)
        #expect(first.path == "/test")
        #expect(first.securityDomain == "example.com")
        #expect(first.label == label)
        #expect(first.itemAccessibility == .whenUnlockedThisDeviceOnly)
    }

    @Test("Attributes returns minimal metadata")
    func attributesReturnsMinimalMetadata() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")

        let itemReference = try await Keychain.InternetPassword.add(
            password,
            account: keychainAccountName,
            server: keychainServer
        )

        let attributes = try await Keychain.InternetPassword.queryAttributes(
            account: .specific(keychainAccountName),
            server: .specific(keychainServer)
        )

        #expect(attributes.count == 1)
        let first = try requireUnwrapped(attributes.first)
        #expect(first.itemReference == itemReference)
        #expect(first.account == keychainAccountName)
        #expect(first.server == keychainServer)
    }
}

// MARK: - Private Helpers

private extension InternetPasswordAttributesIntegrationTests {
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
