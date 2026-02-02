@testable import SwiftKeychainKit
import CryptoKit
import Testing

@Suite("CryptoKit GenericPasswordConvertible Tests")
struct CryptoKitGenericPasswordConvertibleTests {
    @Test("Curve25519.KeyAgreement.PrivateKey converts to generic password and back")
    func curve25519KeyAgreementRoundTrip() throws {
        let original = Curve25519.KeyAgreement.PrivateKey()

        let representation = try original.genericPasswordRepresentation()
        let converted = try Curve25519.KeyAgreement.PrivateKey(
            genericPasswordRepresentation: representation
        )

        #expect(original.rawRepresentation == converted.rawRepresentation)
    }

    @Test("Curve25519.Signing.PrivateKey converts to generic password and back")
    func curve25519SigningRoundTrip() throws {
        let original = Curve25519.Signing.PrivateKey()

        let representation = try original.genericPasswordRepresentation()
        let converted = try Curve25519.Signing.PrivateKey(
            genericPasswordRepresentation: representation
        )

        #expect(original.rawRepresentation == converted.rawRepresentation)
    }

    @Test("SecureEnclave.P256.KeyAgreement.PrivateKey converts to generic password and back")
    func secureEnclaveKeyAgreementRoundTrip() throws {
        let original = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        let representation = try original.genericPasswordRepresentation()
        let converted = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            genericPasswordRepresentation: representation
        )

        #expect(original.publicKey.rawRepresentation == converted.publicKey.rawRepresentation)
    }

    @Test("SecureEnclave.P256.Signing.PrivateKey converts to generic password and back")
    func secureEnclaveSigningRoundTrip() throws {
        let original = try SecureEnclave.P256.Signing.PrivateKey()
        let representation = try original.genericPasswordRepresentation()
        let converted = try SecureEnclave.P256.Signing.PrivateKey(
            genericPasswordRepresentation: representation
        )

        #expect(original.publicKey.rawRepresentation == converted.publicKey.rawRepresentation)
    }
}
