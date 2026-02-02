import BasicContainers
import CryptoKit
import Foundation
import SwiftKeychainKit
import Testing

@Suite("CryptoKit GenericPasswordConvertible Integration Tests")
struct CryptoKitGenericPasswordConvertibleIntegrationTests {
    @Test("Curve25519.KeyAgreement.PrivateKey round-trips through GenericPassword")
    func curve25519KeyAgreementPrivateKeyRoundtripsThroughGenericPassword() async throws {
        let account = "CryptoKitGenericPasswordConvertibleIntegrationTests-account-\(UUID().uuidString)"
        let service = "CryptoKitGenericPasswordConvertibleIntegrationTests-service-\(UUID().uuidString)"

        defer {
            Self.cleanup(
                account: account,
                service: service
            )
        }

        let key = Curve25519.KeyAgreement.PrivateKey()

        try await Keychain.GenericPassword.add(
            key,
            account: account,
            service: service
        )

        let queried: Curve25519.KeyAgreement.PrivateKey = try #require(await Keychain.GenericPassword.get(
            account: account,
            service: service
        ))
        #expect(queried.rawRepresentation == key.rawRepresentation)
    }

    @Test("Curve25519.Signing.PrivateKey round-trips through GenericPassword")
    func curve25519SigningPrivateKeyRoundtripsThroughGenericPassword() async throws {
        let account = "CryptoKitGenericPasswordConvertibleIntegrationTests-account-\(UUID().uuidString)"
        let service = "CryptoKitGenericPasswordConvertibleIntegrationTests-service-\(UUID().uuidString)"

        defer {
            Self.cleanup(
                account: account,
                service: service
            )
        }

        let key = Curve25519.Signing.PrivateKey()

        try await Keychain.GenericPassword.add(
            key,
            account: account,
            service: service
        )

        let queried: Curve25519.Signing.PrivateKey = try #require(await Keychain.GenericPassword.get(
            account: account,
            service: service
        ))
        #expect(queried.rawRepresentation == key.rawRepresentation)
    }
}

// MARK: - Cleanup

private extension CryptoKitGenericPasswordConvertibleIntegrationTests {
    static func cleanup(
        account: String,
        service: String
    ) {
        do {
            try Keychain.GenericPassword.delete(
                account: .specific(account),
                service: .specific(service),
                accessGroup: .any,
                synchronizable: .any
            )
        } catch {
            print("Error cleaning up: \(error)")
        }
    }
}
