import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("Certificates Attributes Integration Tests")
final class CertificatesAttributesIntegrationTests {
    private let keychainLabel = "CertificatesAttributesIntegrationTests-label-\(UUID().uuidString)"

    deinit {
        cleanup()
    }

    @Test("Attributes returns all metadata")
    func attributesReturnsAllMetadata() async throws {
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: "Test-Attributes-\(UUID().uuidString)"
        )

        try await Keychain.Certificates.add(
            certificate,
            label: .custom(keychainLabel),
            accessGroup: .default,
            synchronizable: false
        )

        let attrs = try await Keychain.Certificates.queryAttributes(
            label: .specific(keychainLabel)
        )

        #expect(attrs.count == 1)
        let first = try requireUnwrapped(attrs.first)
        #expect(first.label == keychainLabel)
        #expect(first.accessGroup.isEmpty == false)
        #expect(first.synchronizable == false)
    }

    @Test("Attributes returns minimal metadata")
    func attributesReturnsMinimalMetadata() async throws {
        let (certificate, _) = try TestCertificateGenerator.generateSecCertificate(
            commonName: "Test-Attributes-Minimal-\(UUID().uuidString)"
        )

        try await Keychain.Certificates.add(
            certificate,
            label: .custom(keychainLabel)
        )

        let attrs = try await Keychain.Certificates.queryAttributes(
            label: .specific(keychainLabel)
        )

        #expect(attrs.count == 1)
        let first = try requireUnwrapped(attrs.first)
        #expect(first.label == keychainLabel)
    }
}

// MARK: - Private Helpers

private extension CertificatesAttributesIntegrationTests {
    func cleanup() {
        do {
            try Keychain.Certificates.delete(
                label: .specific(keychainLabel),
                synchronizable: .any
            )
        } catch {
            print("Failed to clean up certificate after test: \(error)")
        }
    }
}
