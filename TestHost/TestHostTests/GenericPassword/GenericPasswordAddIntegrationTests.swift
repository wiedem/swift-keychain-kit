import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("GenericPassword Add Integration Tests")
final class GenericPasswordAddIntegrationTests {
    private let keychainServiceName = "GenericPasswordAddIntegrationTests-service-\(UUID().uuidString)"
    private let keychainAccountName = "GenericPasswordAddIntegrationTests-account-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Add and retrieve password")
    func addAndRetrieve() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret123")
        let passwordCopy = try password.duplicate()

        try await Keychain.GenericPassword.add(
            password,
            account: keychainAccountName,
            service: keychainServiceName
        )

        var items = try await Keychain.GenericPassword.query(
            account: .specific(keychainAccountName),
            service: .specific(keychainServiceName),
            limit: .count(2)
        )

        #expect(items.count == 1)
        let firstItem = items.remove(at: 0)
        #expect((firstItem == passwordCopy) == true)
    }

    @Test("Add with label")
    func addWithLabel() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
        let label = "Test Password Label"

        try await Keychain.GenericPassword.add(
            password,
            account: keychainAccountName,
            service: keychainServiceName,
            label: label
        )

        let items = try await Keychain.GenericPassword.queryAttributes(
            account: .specific(keychainAccountName),
            service: .specific(keychainServiceName),
            limit: .count(2)
        )

        #expect(items.count == 1)
        let attributes = try requireUnwrapped(items.first)
        #expect(attributes.label == label)
    }

    @Test("Add duplicate throws duplicateItem error")
    func addDuplicateThrows() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")

        try await Keychain.GenericPassword.add(
            password,
            account: keychainAccountName,
            service: keychainServiceName
        )

        await #expect(throws: KeychainError.duplicateItem) {
            let password2 = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
            try await Keychain.GenericPassword.add(
                password2,
                account: keychainAccountName,
                service: keychainServiceName
            )
        }
    }
}

// MARK: - Private Helpers

private extension GenericPasswordAddIntegrationTests {
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
