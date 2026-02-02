import BasicContainers
import CryptoKit
import Foundation
import SwiftKeychainKit
import Testing

@Suite(
    "CryptoKit SecureEnclave GenericPasswordConvertible Integration Tests",
    .enabled(if: Keychain.SecureEnclaveKeys.isAvailable, "Requires real device with Secure Enclave"),
    .tags(.secureEnclave)
)
struct CryptoKitSecureEnclaveGenericPasswordConvertibleIntegrationTests {
    @Test("SecureEnclave.P256.KeyAgreement.PrivateKey round-trips through GenericPassword")
    func secureEnclaveP256KeyAgreementPrivateKeyRoundtripsThroughGenericPassword() async throws {
        let account = "CryptoKitSecureEnclaveGenericPasswordConvertibleIntegrationTests-account-\(UUID().uuidString)"
        let service = "CryptoKitSecureEnclaveGenericPasswordConvertibleIntegrationTests-service-\(UUID().uuidString)"

        defer {
            Self.cleanup(
                account: account,
                service: service
            )
        }

        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey()

        try await Keychain.GenericPassword.add(
            key,
            account: account,
            service: service
        )

        let queried: SecureEnclave.P256.KeyAgreement.PrivateKey = try #require(await Keychain.GenericPassword.get(
            account: account,
            service: service
        ))
        #expect(queried.dataRepresentation == key.dataRepresentation)
    }

    @Test("SecureEnclave.P256.Signing.PrivateKey round-trips through GenericPassword")
    func secureEnclaveP256SigningPrivateKeyRoundtripsThroughGenericPassword() async throws {
        let account = "CryptoKitSecureEnclaveGenericPasswordConvertibleIntegrationTests-account-\(UUID().uuidString)"
        let service = "CryptoKitSecureEnclaveGenericPasswordConvertibleIntegrationTests-service-\(UUID().uuidString)"

        defer {
            Self.cleanup(
                account: account,
                service: service
            )
        }

        let key = try SecureEnclave.P256.Signing.PrivateKey()

        try await Keychain.GenericPassword.add(
            key,
            account: account,
            service: service
        )

        let queried: SecureEnclave.P256.Signing.PrivateKey = try #require(await Keychain.GenericPassword.get(
            account: account,
            service: service
        ))
        #expect(queried.dataRepresentation == key.dataRepresentation)
    }
}

// MARK: - Cleanup

private extension CryptoKitSecureEnclaveGenericPasswordConvertibleIntegrationTests {
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
