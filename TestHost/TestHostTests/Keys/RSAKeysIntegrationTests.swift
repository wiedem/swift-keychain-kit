import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("RSA Keys Integration Tests")
final class RSAKeysIntegrationTests {
    private let keychainApplicationTag = "RSAKeysIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!

    deinit {
        cleanup()
    }

    @Test("Add and retrieve RSA private key")
    func addAndRetrieveRSAPrivateKey() async throws {
        let (_, privateKey) = try Self.makeKeyPair()

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag
        )

        let retrieved = try await Keychain.Keys.query(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(keychainApplicationTag),
            limit: .unlimited
        )
        #expect(retrieved.count == 1)
    }

    @Test("Add RSA public key throws")
    func addRSAPublicKeyThrows() async throws {
        let (publicKey, _) = try Self.makeKeyPair()

        await #expect(throws: KeychainError.publicKeyNotSupported) {
            try await Keychain.Keys.addPrivateKey(
                publicKey,
                applicationTag: keychainApplicationTag
            )
        }
    }

    @Test("Add and retrieve RSA key with string application label")
    func addAndRetrieveRSAKeyWithStringApplicationLabel() async throws {
        let (_, privateKey) = try Self.makeKeyPair()
        let applicationLabel = "rsa-label-\(UUID().uuidString)".data(using: .utf8)!

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag,
            applicationLabel: .data(applicationLabel)
        )

        let retrieved = try await Keychain.Keys.query(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(keychainApplicationTag),
            applicationLabel: .specific(applicationLabel),
            limit: .unlimited
        )
        #expect(retrieved.count == 1)
    }

    // MARK: - Duplicate Tests

    @Test("Add duplicate key throws duplicateItem error")
    func addDuplicateThrows() async throws {
        let (_, privateKey) = try Self.makeKeyPair()

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag
        )

        await #expect(throws: KeychainError.duplicateItem) {
            try await Keychain.Keys.addPrivateKey(
                privateKey,
                applicationTag: keychainApplicationTag
            )
        }
    }

    // MARK: - Get Tests

    @Test("Get returns nil for non-existent key")
    func getNonExistent() async throws {
        let tag = "test-nonexistent-\(UUID().uuidString)".data(using: .utf8)!

        let result = try await Keychain.Keys.query(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(tag)
        )
        #expect(result.isEmpty == true)
    }

    // MARK: - Query Tests

    @Test("Query finds keys by type")
    func queryFindsByType() async throws {
        let (_, privateKey) = try Self.makeKeyPair()

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag
        )

        let results = try await Keychain.Keys.query(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(keychainApplicationTag),
            limit: .unlimited
        )
        #expect(results.count == 1)
    }

    @Test("Query returns empty array when no matches")
    func queryReturnsEmptyArrayWhenNoMatches() async throws {
        let tag = "test-query-nonexistent-\(UUID().uuidString)".data(using: .utf8)!

        let results = try await Keychain.Keys.query(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(tag)
        )
        #expect(results.isEmpty == true)
    }

    // MARK: - Delete Tests

    @Test("Delete removes key")
    func deleteRemovesKey() async throws {
        let (_, privateKey) = try Self.makeKeyPair()

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag
        )

        let deleted = try await Keychain.Keys.delete(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(deleted == true)

        let retrieved = try await Keychain.Keys.query(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(keychainApplicationTag)
        )
        #expect(retrieved.isEmpty == true)
    }

    @Test("Delete returns false for non-existent key")
    func deleteReturnsFalseForNonExistent() async throws {
        let tag = "test-delete-nonexistent-\(UUID().uuidString)".data(using: .utf8)!

        let deleted = try await Keychain.Keys.delete(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(tag)
        )
        #expect(deleted == false)
    }

    @Test("Delete with synchronized scope removes only synchronized key with same applicationTag")
    func deleteSynchronizedRemovesOnlySynchronizedKey() async throws {
        let sharedTag = "rsa-sync-test-\(UUID().uuidString)".data(using: .utf8)!
        let (_, privateKeySync) = try Self.makeKeyPair()
        let (_, privateKeyNonSync) = try Self.makeKeyPair()

        defer {
            _ = try? Keychain.Keys.delete(
                keyType: .rsa(.privateKey),
                applicationTag: .specific(sharedTag),
                accessGroup: .default,
                synchronizable: .any
            )
        }

        // Add non-synchronized key
        try await Keychain.Keys.addPrivateKey(
            privateKeyNonSync,
            applicationTag: sharedTag,
            synchronizable: false
        )

        // Add synchronized key (same applicationTag)
        try await Keychain.Keys.addPrivateKey(
            privateKeySync,
            applicationTag: sharedTag,
            synchronizable: true
        )

        // Delete only synchronized key
        let deleted = try await Keychain.Keys.delete(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(sharedTag),
            accessGroup: .default,
            synchronizable: .synchronized
        )
        #expect(deleted == true)

        // Verify non-synchronized key still exists
        let remaining = try await Keychain.Keys.query(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(sharedTag),
            synchronizable: .notSynchronized,
            limit: .unlimited
        )
        #expect(remaining.count == 1)
    }

    @Test("Delete with not synchronized scope removes only non-synchronized key with same applicationTag")
    func deleteNotSynchronizedRemovesOnlyNonSynchronizedKey() async throws {
        let sharedTag = "rsa-nonsync-test-\(UUID().uuidString)".data(using: .utf8)!
        let (_, privateKeySync) = try Self.makeKeyPair()
        let (_, privateKeyNonSync) = try Self.makeKeyPair()

        defer {
            _ = try? Keychain.Keys.delete(
                keyType: .rsa(.privateKey),
                applicationTag: .specific(sharedTag),
                accessGroup: .default,
                synchronizable: .any
            )
        }

        // Add non-synchronized key
        try await Keychain.Keys.addPrivateKey(
            privateKeyNonSync,
            applicationTag: sharedTag,
            synchronizable: false
        )

        // Add synchronized key (same applicationTag)
        try await Keychain.Keys.addPrivateKey(
            privateKeySync,
            applicationTag: sharedTag,
            synchronizable: true
        )

        // Delete only non-synchronized key
        let deleted = try await Keychain.Keys.delete(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(sharedTag),
            accessGroup: .default,
            synchronizable: .notSynchronized
        )
        #expect(deleted == true)

        // Verify synchronized key still exists
        let remaining = try await Keychain.Keys.query(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(sharedTag),
            synchronizable: .synchronized,
            limit: .unlimited
        )
        #expect(remaining.count == 1)
    }

    @Test("Delete with any scope removes both synchronized and non-synchronized keys with same applicationTag")
    func deleteAnyRemovesBothKeys() async throws {
        let sharedTag = "rsa-any-test-\(UUID().uuidString)".data(using: .utf8)!
        let (_, privateKeySync) = try Self.makeKeyPair()
        let (_, privateKeyNonSync) = try Self.makeKeyPair()

        defer {
            _ = try? Keychain.Keys.delete(
                keyType: .rsa(.privateKey),
                applicationTag: .specific(sharedTag),
                accessGroup: .default,
                synchronizable: .any
            )
        }

        // Add non-synchronized key
        try await Keychain.Keys.addPrivateKey(
            privateKeyNonSync,
            applicationTag: sharedTag,
            synchronizable: false
        )

        // Add synchronized key (same applicationTag)
        try await Keychain.Keys.addPrivateKey(
            privateKeySync,
            applicationTag: sharedTag,
            synchronizable: true
        )

        // Delete both keys
        let deleted = try await Keychain.Keys.delete(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(sharedTag),
            accessGroup: .default,
            synchronizable: .any
        )
        #expect(deleted == true)

        // Verify no keys remain
        let remainingNonSync = try await Keychain.Keys.query(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(sharedTag),
            synchronizable: .notSynchronized
        )
        #expect(remainingNonSync.isEmpty == true)

        let remainingSync = try await Keychain.Keys.query(
            keyType: .rsa(.privateKey),
            applicationTag: .specific(sharedTag),
            synchronizable: .synchronized
        )
        #expect(remainingSync.isEmpty == true)
    }
}

// MARK: - Private Helpers

private extension RSAKeysIntegrationTests {
    enum TestError: Error, Sendable {
        case keyCreationFailure
    }

    static func makeKeyPair() throws -> (publicKey: SecKey, privateKey: SecKey) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            Issue.record("Failed to create test key pair: \(error!)")
            throw TestError.keyCreationFailure
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            Issue.record("Failed to get public key")
            throw TestError.keyCreationFailure
        }

        return (publicKey, privateKey)
    }

    static func cleanup(applicationTag: Data) {
        do {
            try Keychain.Keys.delete(
                keyType: .rsa(.privateKey),
                applicationTag: .specific(applicationTag),
                accessGroup: .default
            )
        } catch {
            print("Failed to clean up private key after test: \(error)")
        }
    }

    func cleanup() {
        Self.cleanup(applicationTag: keychainApplicationTag)
    }
}
