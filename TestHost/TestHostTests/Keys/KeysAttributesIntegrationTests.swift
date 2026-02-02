import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("Keys Attributes Integration Tests")
final class KeysAttributesIntegrationTests {
    private let keychainApplicationTag = "KeysAttributesIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!

    deinit {
        cleanup()
    }

    @Test("Attributes returns all metadata")
    func attributesReturnsAllMetadata() async throws {
        let (_, privateKey) = try Self.makeRSAKeyPair()
        let label = "keys-attributes-label-\(UUID().uuidString)"
        let applicationLabel = "keys-attributes-application-label-\(UUID().uuidString)".data(using: .utf8)!

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag,
            applicationLabel: .data(applicationLabel),
            label: label,
            accessGroup: .default,
            synchronizable: false
        )

        let attrs = try await Keychain.Keys.queryAttributes(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(attrs.count == 1)
        let first = try requireUnwrapped(attrs.first)

        #expect(first.keyClass == .privateKey)
        #expect(first.algorithm == .rsa)
        #expect(first.applicationLabel == applicationLabel)
        #expect(first.applicationTag == keychainApplicationTag)
        #expect(first.label == label)
        #expect(first.accessGroup?.isEmpty == false)
        #expect(first.synchronizable == false)
    }

    @Test("Attributes returns minimal metadata")
    func attributesReturnsMinimalMetadata() async throws {
        let (_, privateKey) = try Self.makeECCKeyPair()

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag
        )

        let attrs = try await Keychain.Keys.queryAttributes(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(attrs.count == 1)
        let first = try requireUnwrapped(attrs.first)

        #expect(first.keyClass == .privateKey)
        #expect(first.algorithm == .ellipticCurve)
        #expect(first.applicationTag == keychainApplicationTag)
    }
}

// MARK: - Private Helpers

private extension KeysAttributesIntegrationTests {
    enum TestError: Error, Sendable {
        case keyCreationFailure
    }

    static func makeRSAKeyPair() throws -> (publicKey: SecKey, privateKey: SecKey) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            Issue.record("Failed to create test RSA key pair: \(error!)")
            throw TestError.keyCreationFailure
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            Issue.record("Failed to get RSA public key")
            throw TestError.keyCreationFailure
        }

        return (publicKey, privateKey)
    }

    static func makeECCKeyPair() throws -> (publicKey: SecKey, privateKey: SecKey) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            Issue.record("Failed to create test ECC key pair: \(error!)")
            throw TestError.keyCreationFailure
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            Issue.record("Failed to get ECC public key")
            throw TestError.keyCreationFailure
        }

        return (publicKey, privateKey)
    }

    func cleanup() {
        do {
            try Keychain.Keys.delete(
                keyType: .rsa(.privateKey),
                applicationTag: .specific(keychainApplicationTag),
                accessGroup: .any,
                synchronizable: .any
            )
        } catch {
            print("Failed to clean up RSA private key after test: \(error)")
        }

        do {
            try Keychain.Keys.delete(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(keychainApplicationTag),
                accessGroup: .any,
                synchronizable: .any
            )
        } catch {
            print("Failed to clean up ECC private key after test: \(error)")
        }
    }
}
