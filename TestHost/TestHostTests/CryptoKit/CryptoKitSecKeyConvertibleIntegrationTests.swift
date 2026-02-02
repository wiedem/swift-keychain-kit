import CryptoKit
import Foundation
import SwiftKeychainKit
import Testing

@Suite("CryptoKit SecKeyConvertible Integration Tests")
struct CryptoKitSecKeyConvertibleIntegrationTests {
    @Test("P256.Signing.PrivateKey round-trips through Keychain.Keys")
    func p256SigningPrivateKeyRoundtrip() async throws {
        let applicationTag = "CryptoKitSecKeyConvertibleIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!
        let key = P256.Signing.PrivateKey()

        try await Keychain.Keys.addPrivateKey(
            key,
            applicationTag: applicationTag
        )

        defer {
            Self.cleanup(applicationTag: applicationTag)
        }

        let queried: P256.Signing.PrivateKey = try #require(await Keychain.Keys.queryOne(
            applicationTag: applicationTag
        ))
        #expect(queried.rawRepresentation == key.rawRepresentation)
    }

    @Test("P256.KeyAgreement.PrivateKey round-trips through Keychain.Keys")
    func p256KeyAgreementPrivateKeyRoundtrip() async throws {
        let applicationTag = "CryptoKitSecKeyConvertibleIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!
        let key = P256.KeyAgreement.PrivateKey()

        try await Keychain.Keys.addPrivateKey(
            key,
            applicationTag: applicationTag
        )

        defer {
            Self.cleanup(applicationTag: applicationTag)
        }

        let queried: P256.KeyAgreement.PrivateKey = try #require(await Keychain.Keys.queryOne(
            applicationTag: applicationTag
        ))
        #expect(queried.rawRepresentation == key.rawRepresentation)
    }

    @Test("P384.Signing.PrivateKey round-trips through Keychain.Keys")
    func p384SigningPrivateKeyRoundtrip() async throws {
        let applicationTag = "CryptoKitSecKeyConvertibleIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!
        let key = P384.Signing.PrivateKey()

        try await Keychain.Keys.addPrivateKey(
            key,
            applicationTag: applicationTag
        )

        defer {
            Self.cleanup(applicationTag: applicationTag)
        }

        let queried: P384.Signing.PrivateKey = try #require(await Keychain.Keys.queryOne(
            applicationTag: applicationTag
        ))
        #expect(queried.rawRepresentation == key.rawRepresentation)
    }

    @Test("P384.KeyAgreement.PrivateKey round-trips through Keychain.Keys")
    func p384KeyAgreementPrivateKeyRoundtrip() async throws {
        let applicationTag = "CryptoKitSecKeyConvertibleIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!
        let key = P384.KeyAgreement.PrivateKey()

        try await Keychain.Keys.addPrivateKey(
            key,
            applicationTag: applicationTag
        )

        defer {
            Self.cleanup(applicationTag: applicationTag)
        }

        let queried: P384.KeyAgreement.PrivateKey = try #require(await Keychain.Keys.queryOne(
            applicationTag: applicationTag
        ))
        #expect(queried.rawRepresentation == key.rawRepresentation)
    }

    @Test("P521.Signing.PrivateKey round-trips through Keychain.Keys")
    func p521SigningPrivateKeyRoundtrip() async throws {
        let applicationTag = "CryptoKitSecKeyConvertibleIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!
        let key = P521.Signing.PrivateKey()

        try await Keychain.Keys.addPrivateKey(
            key,
            applicationTag: applicationTag
        )

        defer {
            Self.cleanup(applicationTag: applicationTag)
        }

        let queried: P521.Signing.PrivateKey = try #require(await Keychain.Keys.queryOne(
            applicationTag: applicationTag
        ))
        #expect(queried.rawRepresentation == key.rawRepresentation)
    }

    @Test("P521.KeyAgreement.PrivateKey round-trips through Keychain.Keys")
    func p521KeyAgreementPrivateKeyRoundtrip() async throws {
        let applicationTag = "CryptoKitSecKeyConvertibleIntegrationTests-applicationTag-\(UUID().uuidString)".data(using: .utf8)!
        let key = P521.KeyAgreement.PrivateKey()

        try await Keychain.Keys.addPrivateKey(
            key,
            applicationTag: applicationTag
        )

        defer {
            Self.cleanup(applicationTag: applicationTag)
        }

        let queried: P521.KeyAgreement.PrivateKey = try #require(await Keychain.Keys.queryOne(
            applicationTag: applicationTag
        ))
        #expect(queried.rawRepresentation == key.rawRepresentation)
    }
}

// MARK: - Cleanup

private extension CryptoKitSecKeyConvertibleIntegrationTests {
    static func cleanup(applicationTag: Data) {
        do {
            try Keychain.Keys.delete(
                keyType: .ellipticCurve(.privateKey),
                applicationTag: .specific(applicationTag),
                accessGroup: .any,
                synchronizable: .any
            )
        } catch {
            print("Error cleaning up: \(error)")
        }
    }
}
