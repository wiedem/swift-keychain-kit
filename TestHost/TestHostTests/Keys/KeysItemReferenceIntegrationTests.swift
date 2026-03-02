import BasicContainers
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("Keys ItemReference Integration Tests")
final class KeysItemReferenceIntegrationTests {
    private let keychainApplicationTag = "KeysItemReferenceIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!

    deinit {
        cleanup()
    }

    @Test("ItemReference lifecycle: add, get, attributes, delete")
    func itemReferenceLifecycle() async throws {
        let privateKey = try Self.makePrivateKey()

        // Add
        let itemReference = try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag
        )

        // Get by reference
        let retrieved: SecKey? = try await Keychain.Keys.get(itemReference: itemReference)
        #expect(retrieved != nil)

        // Attributes by reference
        let attributes = try await Keychain.Keys.attributes(itemReference: itemReference)
        let attributeValues = try requireUnwrapped(attributes)
        #expect(attributeValues.applicationTag == keychainApplicationTag)
        #expect(attributeValues.keyClass == .privateKey)

        // Delete by reference
        let deleted = try await Keychain.Keys.delete(itemReference: itemReference)
        #expect(deleted == true)

        // Verify deletion
        let afterDelete = try await Keychain.Keys.get(itemReference: itemReference)
        #expect(afterDelete == nil)
    }

    @Test("Operations with stale ItemReference return nil or false")
    func staleItemReference() async throws {
        let privateKey = try Self.makePrivateKey()

        let itemReference = try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag
        )

        // Delete via normal API to make the reference stale
        try await Keychain.Keys.delete(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag)
        )

        let retrieved: SecKey? = try await Keychain.Keys.get(itemReference: itemReference)
        #expect(retrieved == nil)

        let attributes = try await Keychain.Keys.attributes(itemReference: itemReference)
        #expect(attributes == nil)

        let deleted = try await Keychain.Keys.delete(itemReference: itemReference)
        #expect(deleted == false)
    }
}

// MARK: - Private Helpers

private extension KeysItemReferenceIntegrationTests {
    static func makePrivateKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return privateKey
    }

    func cleanup() {
        do {
            try Keychain.Keys.delete(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(keychainApplicationTag)
            )
        } catch {
            print("Failed to clean up key after test: \(error)")
        }
    }
}
