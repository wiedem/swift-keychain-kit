import CryptoKit
import Foundation
import Security
import SwiftKeychainKit
import Testing

@Suite("Keys Application Label Tests")
struct KeysApplicationLabelTests {
    @Test("Resolves application label for P256 Signing key")
    func p256SigningKey() throws {
        let key = P256.Signing.PrivateKey()

        let label = try #require(Keychain.Keys.ApplicationLabel.resolve(for: key))

        #expect(label.isEmpty == false)
    }

    @Test("Resolves application label for P256 KeyAgreement key")
    func p256KeyAgreementKey() throws {
        let key = P256.KeyAgreement.PrivateKey()

        let label = try #require(Keychain.Keys.ApplicationLabel.resolve(for: key))

        #expect(label.isEmpty == false)
    }

    @Test("Resolves application label for P384 Signing key")
    func p384SigningKey() throws {
        let key = P384.Signing.PrivateKey()

        let label = try #require(Keychain.Keys.ApplicationLabel.resolve(for: key))

        #expect(label.isEmpty == false)
    }

    @Test("Resolves application label for P521 Signing key")
    func p521SigningKey() throws {
        let key = P521.Signing.PrivateKey()

        let label = try #require(Keychain.Keys.ApplicationLabel.resolve(for: key))

        #expect(label.isEmpty == false)
    }

    @Test("Same key returns same application label")
    func sameKeyReturnsSameLabel() throws {
        let key = P256.Signing.PrivateKey()

        let label1 = try Keychain.Keys.ApplicationLabel.resolve(for: key)
        let label2 = try Keychain.Keys.ApplicationLabel.resolve(for: key)

        #expect(label1 == label2)
    }

    @Test("Different keys return different application labels")
    func differentKeysReturnDifferentLabels() throws {
        let key1 = P256.Signing.PrivateKey()
        let key2 = P256.Signing.PrivateKey()

        let label1 = try Keychain.Keys.ApplicationLabel.resolve(for: key1)
        let label2 = try Keychain.Keys.ApplicationLabel.resolve(for: key2)

        #expect(label1 != label2)
    }

    @Test("Resolves application label for SecKey directly")
    func secKeyDirectly() throws {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]

        var error: Unmanaged<CFError>?
        let secKey = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, &error))

        let label = try #require(Keychain.Keys.ApplicationLabel.resolve(for: secKey))

        #expect(label.isEmpty == false)
    }
}
