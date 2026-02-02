import Crypto
import Foundation
import Security
import SwiftASN1
import X509

// MARK: - Security Framework Conversion

extension TestCertificateGenerator {
    static func generateSecCertificate(
        commonName: String = "Test Certificate",
        organization: String = "Test Organization",
        validityDays: Int = 365
    ) throws -> (certificate: SecCertificate, privateKey: SecKey) {
        let (certificate, privateKey) = try generateSelfSignedCertificate(
            commonName: commonName,
            organization: organization,
            validityDays: validityDays
        )

        let secCertificate = try convertToSecCertificate(certificate)
        let secPrivateKey = try convertToSecKey(privateKey: privateKey)

        return (secCertificate, secPrivateKey)
    }

    static func generateSecCertificateChain(
        rootCommonName: String = "Test Root CA",
        leafCommonName: String = "Test Leaf Certificate",
        validityDays: Int = 365
    ) throws -> (rootCertificate: SecCertificate, leafCertificate: SecCertificate, leafPrivateKey: SecKey) {
        let (rootCertificate, leafCertificate, leafPrivateKey) = try generateCertificateChain(
            rootCommonName: rootCommonName,
            leafCommonName: leafCommonName,
            validityDays: validityDays
        )

        let secRootCertificate = try convertToSecCertificate(rootCertificate)
        let secLeafCertificate = try convertToSecCertificate(leafCertificate)
        let secLeafPrivateKey = try convertToSecKey(privateKey: leafPrivateKey)

        return (secRootCertificate, secLeafCertificate, secLeafPrivateKey)
    }

    static func generateSecIdentity(
        commonName: String = "Test Identity",
        organization: String = "Test Organization",
        validityDays: Int = 365
    ) throws -> SecIdentity {
        let (certificate, privateKey) = try generateSecCertificate(
            commonName: commonName,
            organization: organization,
            validityDays: validityDays
        )

        guard let identity = SecIdentityCreate(nil, certificate, privateKey) else {
            throw TestCertificateError.identityCreationFailed
        }

        return identity
    }
}

// MARK: - Private Helpers

private extension TestCertificateGenerator {
    static func convertToSecCertificate(_ certificate: Certificate) throws -> SecCertificate {
        var serializer = DER.Serializer()
        try certificate.serialize(into: &serializer)
        let derData = Data(serializer.serializedBytes)

        guard let secCertificate = SecCertificateCreateWithData(nil, derData as CFData) else {
            throw TestCertificateError.certificateCreationFailed
        }

        return secCertificate
    }

    static func convertToSecKey(privateKey: P256.Signing.PrivateKey) throws -> SecKey {
        // Export private key in X9.63 format
        let x963Data = privateKey.x963Representation

        // Create SecKey from X9.63 data
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(
            x963Data as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            if let error = error?.takeRetainedValue() {
                throw error
            }
            throw TestCertificateError.keyConversionFailed
        }

        return secKey
    }
}
