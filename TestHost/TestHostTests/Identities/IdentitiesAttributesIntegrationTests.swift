import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("Identities Attributes Integration Tests")
final class IdentitiesAttributesIntegrationTests {
    private let keychainLabel = "IdentitiesAttributesIntegrationTests-label-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Attributes returns metadata")
    func attributesReturnsMetadata() async throws {
        let identity = try TestCertificateGenerator.generateSecIdentity(
            commonName: "Test-Attributes-\(UUID().uuidString)"
        )

        let itemReference = try await Keychain.Identities.add(
            identity,
            label: .custom(keychainLabel),
            accessGroup: .default,
            synchronizable: false
        )

        let attrs = try await Keychain.Identities.queryAttributes(
            label: .specific(keychainLabel)
        )

        #expect(attrs.count == 1)
        let first = try requireUnwrapped(attrs.first)
        #expect(first.itemReference == itemReference)
        #expect(first.label == keychainLabel)
        #expect(first.accessGroup.isEmpty == false)
        #expect(first.synchronizable == false)
    }
}

// MARK: - Private Helpers

private extension IdentitiesAttributesIntegrationTests {
    func cleanup() {
        do {
            try Keychain.Identities.delete(
                label: .specific(keychainLabel)
            )
        } catch {
            print("Failed to clean up identity after test: \(error)")
        }
    }
}
