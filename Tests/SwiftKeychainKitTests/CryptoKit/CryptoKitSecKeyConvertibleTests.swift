@testable import SwiftKeychainKit
import CryptoKit
import Security
import Testing

@Suite("CryptoKit SecKeyConvertible Tests")
struct CryptoKitSecKeyConvertibleTests {
    // MARK: - P256.Signing.PrivateKey Tests

    @Test("P256.Signing.PrivateKey converts to SecKey and back")
    func p256SigningPrivateKeyRoundTrip() throws {
        let original = P256.Signing.PrivateKey()

        let secKey = try original.makeSecKey()
        let converted = try P256.Signing.PrivateKey(secKey: secKey)

        #expect(original.x963Representation == converted.x963Representation)
    }

    @Test("P256.Signing.PrivateKey makeSecKey creates valid SecKey")
    func p256SigningMakeSecKeyCreatesValidSecKey() throws {
        let privateKey = P256.Signing.PrivateKey()

        let secKey = try privateKey.makeSecKey()

        // Verify it's a valid private key
        let attributes = SecKeyCopyAttributes(secKey) as! [String: Any]
        #expect(attributes[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(attributes[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeECSECPrimeRandom)
    }

    // MARK: - P256.KeyAgreement.PrivateKey Tests

    @Test("P256.KeyAgreement.PrivateKey converts to SecKey and back")
    func p256KeyAgreementPrivateKeyRoundTrip() throws {
        let original = P256.KeyAgreement.PrivateKey()

        let secKey = try original.makeSecKey()
        let converted = try P256.KeyAgreement.PrivateKey(secKey: secKey)

        #expect(original.x963Representation == converted.x963Representation)
    }

    @Test("P256.KeyAgreement.PrivateKey makeSecKey creates valid SecKey")
    func p256KeyAgreementMakeSecKeyCreatesValidSecKey() throws {
        let privateKey = P256.KeyAgreement.PrivateKey()

        let secKey = try privateKey.makeSecKey()

        // Verify it's a valid private key
        let attributes = SecKeyCopyAttributes(secKey) as! [String: Any]
        #expect(attributes[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(attributes[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeECSECPrimeRandom)
    }

    // MARK: - P384.Signing.PrivateKey Tests

    @Test("P384.Signing.PrivateKey converts to SecKey and back")
    func p384SigningPrivateKeyRoundTrip() throws {
        let original = P384.Signing.PrivateKey()

        let secKey = try original.makeSecKey()
        let converted = try P384.Signing.PrivateKey(secKey: secKey)

        #expect(original.x963Representation == converted.x963Representation)
    }

    @Test("P384.Signing.PrivateKey makeSecKey creates valid SecKey")
    func p384SigningMakeSecKeyCreatesValidSecKey() throws {
        let privateKey = P384.Signing.PrivateKey()

        let secKey = try privateKey.makeSecKey()

        // Verify it's a valid private key
        let attributes = SecKeyCopyAttributes(secKey) as! [String: Any]
        #expect(attributes[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(attributes[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeECSECPrimeRandom)
    }

    // MARK: - P384.KeyAgreement.PrivateKey Tests

    @Test("P384.KeyAgreement.PrivateKey converts to SecKey and back")
    func p384KeyAgreementPrivateKeyRoundTrip() throws {
        let original = P384.KeyAgreement.PrivateKey()

        let secKey = try original.makeSecKey()
        let converted = try P384.KeyAgreement.PrivateKey(secKey: secKey)

        #expect(original.x963Representation == converted.x963Representation)
    }

    @Test("P384.KeyAgreement.PrivateKey makeSecKey creates valid SecKey")
    func p384KeyAgreementMakeSecKeyCreatesValidSecKey() throws {
        let privateKey = P384.KeyAgreement.PrivateKey()

        let secKey = try privateKey.makeSecKey()

        // Verify it's a valid private key
        let attributes = SecKeyCopyAttributes(secKey) as! [String: Any]
        #expect(attributes[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(attributes[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeECSECPrimeRandom)
    }

    // MARK: - P521.Signing.PrivateKey Tests

    @Test("P521.Signing.PrivateKey converts to SecKey and back")
    func p521SigningPrivateKeyRoundTrip() throws {
        let original = P521.Signing.PrivateKey()

        let secKey = try original.makeSecKey()
        let converted = try P521.Signing.PrivateKey(secKey: secKey)

        #expect(original.x963Representation == converted.x963Representation)
    }

    @Test("P521.Signing.PrivateKey makeSecKey creates valid SecKey")
    func p521SigningMakeSecKeyCreatesValidSecKey() throws {
        let privateKey = P521.Signing.PrivateKey()

        let secKey = try privateKey.makeSecKey()

        // Verify it's a valid private key
        let attributes = SecKeyCopyAttributes(secKey) as! [String: Any]
        #expect(attributes[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(attributes[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeECSECPrimeRandom)
    }

    // MARK: - P521.KeyAgreement.PrivateKey Tests

    @Test("P521.KeyAgreement.PrivateKey converts to SecKey and back")
    func p521KeyAgreementPrivateKeyRoundTrip() throws {
        let original = P521.KeyAgreement.PrivateKey()

        let secKey = try original.makeSecKey()
        let converted = try P521.KeyAgreement.PrivateKey(secKey: secKey)

        #expect(original.x963Representation == converted.x963Representation)
    }

    @Test("P521.KeyAgreement.PrivateKey makeSecKey creates valid SecKey")
    func p521KeyAgreementMakeSecKeyCreatesValidSecKey() throws {
        let privateKey = P521.KeyAgreement.PrivateKey()

        let secKey = try privateKey.makeSecKey()

        // Verify it's a valid private key
        let attributes = SecKeyCopyAttributes(secKey) as! [String: Any]
        #expect(attributes[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(attributes[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeECSECPrimeRandom)
    }

    // MARK: - Negative Tests: Wrong Curve Size

    @Test("P256 key init throws when given P384 SecKey")
    func p256InitThrowsWithP384SecKey() throws {
        let p384Key = P384.Signing.PrivateKey()
        let secKey = try p384Key.makeSecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P256.Signing.PrivateKey(secKey: secKey)
        }
    }

    @Test("P256 key init throws when given P521 SecKey")
    func p256InitThrowsWithP521SecKey() throws {
        let p521Key = P521.Signing.PrivateKey()
        let secKey = try p521Key.makeSecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P256.Signing.PrivateKey(secKey: secKey)
        }
    }

    @Test("P384 key init throws when given P256 SecKey")
    func p384InitThrowsWithP256SecKey() throws {
        let p256Key = P256.Signing.PrivateKey()
        let secKey = try p256Key.makeSecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P384.Signing.PrivateKey(secKey: secKey)
        }
    }

    @Test("P384 key init throws when given P521 SecKey")
    func p384InitThrowsWithP521SecKey() throws {
        let p521Key = P521.Signing.PrivateKey()
        let secKey = try p521Key.makeSecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P384.Signing.PrivateKey(secKey: secKey)
        }
    }

    @Test("P521 key init throws when given P256 SecKey")
    func p521InitThrowsWithP256SecKey() throws {
        let p256Key = P256.Signing.PrivateKey()
        let secKey = try p256Key.makeSecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P521.Signing.PrivateKey(secKey: secKey)
        }
    }

    @Test("P521 key init throws when given P384 SecKey")
    func p521InitThrowsWithP384SecKey() throws {
        let p384Key = P384.Signing.PrivateKey()
        let secKey = try p384Key.makeSecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P521.Signing.PrivateKey(secKey: secKey)
        }
    }

    // MARK: - Negative Tests: RSA Key

    @Test("P256 key init throws when given RSA SecKey")
    func p256InitThrowsWithRSASecKey() throws {
        let rsaKey = try createRSASecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P256.Signing.PrivateKey(secKey: rsaKey)
        }
    }

    @Test("P384 key init throws when given RSA SecKey")
    func p384InitThrowsWithRSASecKey() throws {
        let rsaKey = try createRSASecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P384.Signing.PrivateKey(secKey: rsaKey)
        }
    }

    @Test("P521 key init throws when given RSA SecKey")
    func p521InitThrowsWithRSASecKey() throws {
        let rsaKey = try createRSASecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P521.Signing.PrivateKey(secKey: rsaKey)
        }
    }

    // MARK: - Negative Tests: Public Key

    @Test("P256 key init throws when given public key")
    func p256InitThrowsWithPublicKey() throws {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicSecKey = try publicKey.makeSecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P256.Signing.PrivateKey(secKey: publicSecKey)
        }
    }

    @Test("P384 key init throws when given public key")
    func p384InitThrowsWithPublicKey() throws {
        let privateKey = P384.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicSecKey = try publicKey.makeSecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P384.Signing.PrivateKey(secKey: publicSecKey)
        }
    }

    @Test("P521 key init throws when given public key")
    func p521InitThrowsWithPublicKey() throws {
        let privateKey = P521.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicSecKey = try publicKey.makeSecKey()

        #expect(throws: CryptoKitError.self) {
            _ = try P521.Signing.PrivateKey(secKey: publicSecKey)
        }
    }
}

// MARK: - Test Helpers

private extension CryptoKitSecKeyConvertibleTests {
    /// Creates an RSA private key as SecKey for testing incompatible key types
    func createRSASecKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as any Error
        }
        return secKey
    }
}

// MARK: - CryptoKit Public Key SecKeyRepresentable Extensions

private extension P256.Signing.PublicKey {
    func makeSecKey() throws -> SecKey {
        try .make(
            keyType: .ellipticCurve(.publicKey),
            keyData: x963Representation as CFData
        )
    }
}

private extension P384.Signing.PublicKey {
    func makeSecKey() throws -> SecKey {
        try .make(
            keyType: .ellipticCurve(.publicKey),
            keyData: x963Representation as CFData
        )
    }
}

private extension P521.Signing.PublicKey {
    func makeSecKey() throws -> SecKey {
        try .make(
            keyType: .ellipticCurve(.publicKey),
            keyData: x963Representation as CFData
        )
    }
}
