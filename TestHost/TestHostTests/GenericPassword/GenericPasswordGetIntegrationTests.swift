import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("GenericPassword Get Integration Tests")
final class GenericPasswordGetIntegrationTests {
    private let keychainServiceName = "GenericPasswordGetIntegrationTests-service-\(UUID().uuidString)"
    private let keychainAccountName = "GenericPasswordGetIntegrationTests-account-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Get returns password for existing item")
    func getExisting() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret123")
        let expected = try password.duplicate()

        try await Keychain.GenericPassword.add(
            password,
            account: keychainAccountName,
            service: keychainServiceName
        )

        let retrieved = try await requireUnwrapped(Keychain.GenericPassword.get(
            account: keychainAccountName,
            service: keychainServiceName
        ))
        #expect((expected == retrieved) == true)
    }

    @Test("Get returns nil for non-existent item")
    func getNonExistent() async throws {
        let password = try await Keychain.GenericPassword.get(
            account: keychainAccountName,
            service: keychainServiceName
        )
        #expect((password == nil) == true)
    }
}

// MARK: - Private Helpers

private extension GenericPasswordGetIntegrationTests {
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
