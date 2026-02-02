import Crypto
import Foundation
import SwiftASN1
import X509

enum TestCertificateGenerator {
    static func generateSelfSignedCertificate(
        commonName: String = "Test Certificate",
        organization: String = "Test Organization",
        validityDays: Int = 365
    ) throws -> (certificate: Certificate, privateKey: P256.Signing.PrivateKey) {
        // Generate P-256 key pair
        let privateKey = P256.Signing.PrivateKey()

        // Create distinguished name
        let name = try DistinguishedName {
            CommonName(commonName)
            OrganizationName(organization)
        }

        // Set validity period
        let notBefore = Date()
        let notAfter = notBefore.addingTimeInterval(TimeInterval(validityDays * 24 * 60 * 60))

        // Create certificate
        let certificate = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(privateKey.publicKey),
            notValidBefore: notBefore,
            notValidAfter: notAfter,
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions(),
            issuerPrivateKey: .init(privateKey)
        )

        return (certificate, privateKey)
    }

    static func generateCertificateChain(
        rootCommonName: String = "Test Root CA",
        leafCommonName: String = "Test Leaf Certificate",
        validityDays: Int = 365
    ) throws -> (rootCertificate: Certificate, leafCertificate: Certificate, leafPrivateKey: P256.Signing.PrivateKey) {
        // Generate root CA key pair
        let rootPrivateKey = P256.Signing.PrivateKey()
        let rootName = try DistinguishedName {
            CommonName(rootCommonName)
            OrganizationName("Test CA Organization")
        }

        let notBefore = Date()
        let notAfter = notBefore.addingTimeInterval(TimeInterval(validityDays * 24 * 60 * 60))

        // Create root CA certificate
        let rootCertificate = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(rootPrivateKey.publicKey),
            notValidBefore: notBefore,
            notValidAfter: notAfter,
            issuer: rootName,
            subject: rootName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
            },
            issuerPrivateKey: .init(rootPrivateKey)
        )

        // Generate leaf certificate key pair
        let leafPrivateKey = P256.Signing.PrivateKey()
        let leafName = try DistinguishedName {
            CommonName(leafCommonName)
            OrganizationName("Test Organization")
        }

        // Create leaf certificate signed by root CA
        let leafCertificate = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(leafPrivateKey.publicKey),
            notValidBefore: notBefore,
            notValidAfter: notAfter,
            issuer: rootName,
            subject: leafName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions(),
            issuerPrivateKey: .init(rootPrivateKey)
        )

        return (rootCertificate, leafCertificate, leafPrivateKey)
    }
}

// MARK: - Error Type

enum TestCertificateError: Error {
    case certificateCreationFailed
    case keyConversionFailed
    case identityCreationFailed
}
