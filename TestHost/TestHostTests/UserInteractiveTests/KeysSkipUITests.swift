import Foundation
import LocalAuthentication
import Security
import SwiftKeychainKit
import Testing

@Suite(
    "Keys skipItemsIfUIRequired Tests",
    .tags(.userInteractive),
    .serialized
)
final class KeysSkipUITests {
    private let keychainApplicationTag = "KeysSkipUITests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!

    deinit {
        cleanup()
    }

    // MARK: - Test: Skip item requiring user presence

    @Test("query() with skipItemsIfUIRequired skips item requiring user presence")
    func skipItemRequiringUserPresence() async throws {
        // Generate key with user presence requirement
        let (_, privateKey) = try Self.makeKeyPair()

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .userPresence
            )
        )

        // Query with skipItemsIfUIRequired: false - should show biometry prompt
        do {
            let results = try await Keychain.Keys.query(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(keychainApplicationTag),
                skipItemsIfUIRequired: false,
                limit: .count(2)
            )
            #expect(results.count == 1)
        } catch KeychainError.authenticationCancelled {
            Issue.record("Authentication prompt was cancelled by user")
            return
        }

        // Query with skipItemsIfUIRequired: true - should NOT show prompt, returns empty result
        let skippedResults = try await Keychain.Keys.query(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag),
            skipItemsIfUIRequired: true
        )
        #expect(skippedResults.isEmpty == true)
    }

    // MARK: - Test: Skip item requiring application password (UI on add and query)

    @Test("query() with skipItemsIfUIRequired skips item requiring application password (UI prompt on add and query)")
    func skipItemRequiringApplicationPasswordOnAddAndQuery() async throws {
        // Generate key with application password requirement
        // Shows UI prompt to SET the password
        do {
            let addContext = LAContext()
            // Password NOT set - will show UI prompt
            let (_, privateKey) = try Self.makeKeyPair()

            try await Keychain.Keys.addPrivateKey(
                privateKey,
                applicationTag: keychainApplicationTag,
                accessControl: .make(
                    accessibility: .whenUnlockedThisDeviceOnly,
                    constraint: .applicationPassword
                ),
                authenticationContext: addContext
            )
        } catch KeychainError.authenticationCancelled {
            Issue.record("Set password prompt was cancelled by user during add")
            return
        }

        // Query with skipItemsIfUIRequired: false - shows UI prompt to VERIFY the password
        do {
            let queryContext = LAContext()
            // Password NOT set - will show UI prompt
            let results = try await Keychain.Keys.query(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(keychainApplicationTag),
                skipItemsIfUIRequired: false,
                authenticationContext: queryContext,
                limit: .count(2)
            )
            #expect(results.count == 1)
        } catch KeychainError.authenticationCancelled {
            Issue.record("Verify password prompt was cancelled by user during query")
            return
        }

        // Query with skipItemsIfUIRequired: true - should NOT show prompt, returns empty result
        let skippedResults = try await Keychain.Keys.query(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag),
            skipItemsIfUIRequired: true
        )
        #expect(skippedResults.isEmpty == true)
    }

    // MARK: - Test: Don't skip when credentials are in LAContext

    @Test("query() with skipItemsIfUIRequired does not skip when credentials are in LAContext")
    func dontSkipWhenCredentialsProvided() async throws {
        // Test password value
        let appPassword = "app-password-123".data(using: .utf8)!

        // Generate key with application password requirement
        let addContext = LAContext()
        addContext.setCredential(appPassword, type: .applicationPassword)

        let (_, privateKey) = try Self.makeKeyPair()

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            ),
            authenticationContext: addContext
        )

        // Query with skipItemsIfUIRequired: true AND credentials in LAContext
        // Should NOT skip the item - returns result without UI
        let queryContext = LAContext()
        queryContext.setCredential(appPassword, type: .applicationPassword)

        let results = try await Keychain.Keys.query(
            keyType: .ellipticCurve(.privateKey),
            applicationTag: .specific(keychainApplicationTag),
            skipItemsIfUIRequired: true,
            authenticationContext: queryContext,
            limit: .count(2)
        )

        #expect(results.count == 1)
    }

    // MARK: - Test: Throws error when interaction not allowed

    @Test("query() throws interactionNotAllowed when context disallows interaction")
    func queryThrowsErrorWhenInteractionNotAllowed() async throws {
        // Test password value
        let appPassword = "app-password-123".data(using: .utf8)!

        // Generate key with application password requirement
        let addContext = LAContext()
        addContext.setCredential(appPassword, type: .applicationPassword)

        let (_, privateKey) = try Self.makeKeyPair()

        try await Keychain.Keys.addPrivateKey(
            privateKey,
            applicationTag: keychainApplicationTag,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            ),
            authenticationContext: addContext
        )

        // query() with skipItemsIfUIRequired: false and LAContext.interactionNotAllowed = true
        // Should throw KeychainError.interactionNotAllowed
        let queryContext = LAContext()
        queryContext.interactionNotAllowed = true

        await #expect(throws: KeychainError.interactionNotAllowed) {
            _ = try await Keychain.Keys.query(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(keychainApplicationTag),
                skipItemsIfUIRequired: false,
                authenticationContext: queryContext
            )
        }
    }

    // MARK: - Test: Query multiple items with mixed requirements

    @Test("query() with skipItemsIfUIRequired filters out items requiring UI")
    func queryMultipleItemsWithMixedRequirements() async throws {
        // Test password value
        let appPassword = "app-password-123".data(using: .utf8)!

        // Different application tags for different items
        let tag1 = "test-key-1".data(using: .utf8)!
        let tag2 = "test-key-2".data(using: .utf8)!
        let tag3 = "test-key-3".data(using: .utf8)!

        defer {
            // Cleanup items with different tags than the class default
            _ = try? Keychain.Keys.delete(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(tag1),
                accessGroup: .any
            )
            _ = try? Keychain.Keys.delete(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(tag2),
                accessGroup: .any
            )
            _ = try? Keychain.Keys.delete(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(tag3),
                accessGroup: .any
            )
        }

        // Item 1: No access control - accessible without UI
        let (_, privateKey1) = try Self.makeKeyPair()
        try await Keychain.Keys.addPrivateKey(
            privateKey1,
            applicationTag: tag1
        )

        // Item 2: User presence required - requires UI
        let (_, privateKey2) = try Self.makeKeyPair()
        try await Keychain.Keys.addPrivateKey(
            privateKey2,
            applicationTag: tag2,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .userPresence
            )
        )

        // Item 3: Application password - requires UI
        let addContext = LAContext()
        addContext.setCredential(appPassword, type: .applicationPassword)

        let (_, privateKey3) = try Self.makeKeyPair()
        try await Keychain.Keys.addPrivateKey(
            privateKey3,
            applicationTag: tag3,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            ),
            authenticationContext: addContext
        )

        // Query all items with skipItemsIfUIRequired: true
        // Should return only item 1 (no UI required)
        let results = try await Keychain.Keys.query(
            keyType: .ellipticCurve(.privateKey),
            accessGroup: .any,
            skipItemsIfUIRequired: true,
            limit: .count(2)
        )

        // Should contain only the item without access control
        #expect(results.count == 1)
    }
}

// MARK: - Private Helpers

private extension KeysSkipUITests {
    enum TestError: Error, Sendable {
        case keyCreationFailure
    }

    static func makeKeyPair() throws -> (publicKey: SecKey, privateKey: SecKey) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
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

    func cleanup() {
        do {
            try Keychain.Keys.delete(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(keychainApplicationTag),
                accessGroup: .any
            )
        } catch {
            print("Failed to clean up key after test: \(error)")
        }
    }
}
