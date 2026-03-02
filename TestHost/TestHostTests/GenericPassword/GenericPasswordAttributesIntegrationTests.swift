import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("GenericPassword Attributes Integration Tests")
final class GenericPasswordAttributesIntegrationTests {
    private let keychainServiceName = "GenericPasswordAttributesIntegrationTests-service-\(UUID().uuidString)"
    private let keychainAccountName = "GenericPasswordAttributesIntegrationTests-account-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Attributes returns all metadata")
    func attributesReturnsAllMetadata() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
        let label = "Test Attributes Label"

        try await Keychain.GenericPassword.add(
            password,
            account: keychainAccountName,
            service: keychainServiceName,
            label: label,
            accessControl: .whenUnlockedThisDeviceOnly
        )

        let attributes = try await Keychain.GenericPassword.queryAttributes(
            account: .specific(keychainAccountName),
            service: .specific(keychainServiceName)
        )

        #expect(attributes.count == 1)
        let first = try requireUnwrapped(attributes.first)
        #expect(first.account == keychainAccountName)
        #expect(first.service == keychainServiceName)
        #expect(first.label == label)
        #expect(first.itemAccessibility == .whenUnlockedThisDeviceOnly)
    }

    @Test("Attributes returns minimal metadata")
    func attributesReturnsMinimalMetadata() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")

        try await Keychain.GenericPassword.add(
            password,
            account: keychainAccountName,
            service: keychainServiceName
        )

        let attributes = try await Keychain.GenericPassword.queryAttributes(
            account: .specific(keychainAccountName),
            service: .specific(keychainServiceName)
        )

        #expect(attributes.count == 1)
        let first = try requireUnwrapped(attributes.first)
        #expect(first.account == keychainAccountName)
        #expect(first.service == keychainServiceName)
    }
}

// MARK: - Private Helpers

private extension GenericPasswordAttributesIntegrationTests {
    func cleanup() {
        do {
            try Keychain.GenericPassword.delete(
                account: .specific(keychainAccountName),
                service: .specific(keychainServiceName),
                accessGroup: .default
            )
        } catch {
            print("Failed to clean up generic password after test: \(error)")
        }
    }
}
