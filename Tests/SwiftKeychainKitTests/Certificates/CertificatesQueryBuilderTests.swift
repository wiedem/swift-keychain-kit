@testable import SwiftKeychainKit
import Foundation
import LocalAuthentication
import Security
import Testing

@Suite("Certificates QueryBuilder Tests")
struct CertificatesQueryBuilderTests {
    // MARK: - baseQuery Tests

    @Test("baseQuery contains class and data protection keychain flag")
    func baseQueryContainsRequiredAttributes() {
        let query = Keychain.Certificates.baseQuery()

        #expect(query[kSecClass as String].cast() == kSecClassCertificate)
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query.count == 2)
    }

    // MARK: - applyQueryParameters Tests

    @Test("applyQueryParameters with specific values sets all attributes")
    func applyQueryParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let certificateType = 1
        let subject = "subject"
        let issuer = "issuer"
        let serialNumber = "serial"
        let subjectKeyID = "subjectKeyID"
        let publicKeyHash = "publicKeyHash"

        try Keychain.Certificates.applyQueryParameters(
            certificateTypeScope: .specific(certificateType),
            subjectScope: .utf8(subject),
            issuerScope: .utf8(issuer),
            serialNumberScope: .utf8(serialNumber),
            subjectKeyIDScope: .utf8(subjectKeyID),
            publicKeyHashScope: .utf8(publicKeyHash),
            labelScope: .specific("Test Label"),
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            skipItemsIfUIRequired: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrCertificateType as String] as? Int == certificateType)
        #expect(query[kSecAttrSubject as String] as? Data == Data(subject.utf8))
        #expect(query[kSecAttrIssuer as String] as? Data == Data(issuer.utf8))
        #expect(query[kSecAttrSerialNumber as String] as? Data == Data(serialNumber.utf8))
        #expect(query[kSecAttrSubjectKeyID as String] as? Data == Data(subjectKeyID.utf8))
        #expect(query[kSecAttrPublicKeyHash as String] as? Data == Data(publicKeyHash.utf8))
        #expect(query[kSecAttrLabel as String] as? String == "Test Label")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 11)
    }

    @Test("applyQueryParameters with any values omits those attributes")
    func applyQueryParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.Certificates.applyQueryParameters(
            certificateTypeScope: .any,
            subjectScope: .any,
            issuerScope: .any,
            serialNumberScope: .any,
            subjectKeyIDScope: .any,
            publicKeyHashScope: .any,
            labelScope: .any,
            accessGroupScope: .any,
            synchronizableScope: .any,
            skipItemsIfUIRequired: false,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrCertificateType as String] == nil)
        #expect(query[kSecAttrSubject as String] == nil)
        #expect(query[kSecAttrIssuer as String] == nil)
        #expect(query[kSecAttrSerialNumber as String] == nil)
        #expect(query[kSecAttrSubjectKeyID as String] == nil)
        #expect(query[kSecAttrPublicKeyHash as String] == nil)
        #expect(query[kSecAttrLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query[kSecUseAuthenticationUI as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 1)
    }

    // MARK: - applyAddParameters Tests

    @Test("applyAddParameters with all parameters sets all attributes")
    func applyAddParametersWithAllParameters() throws {
        var query: [String: Any] = [:]
        let certificate = try makeTestCertificate()

        Keychain.Certificates.applyAddParameters(
            certificate: certificate,
            label: .custom("Test Label"),
            accessGroup: .identifier("com.example.group"),
            synchronizable: true,
            to: &query
        )

        #expect(query[kSecValueRef as String].cast() == certificate)
        #expect(query[kSecAttrLabel as String] as? String == "Test Label")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query.count == 4)
    }

    @Test("applyAddParameters with default values omits label and access group")
    func applyAddParametersWithDefaultValues() throws {
        var query: [String: Any] = [:]
        let certificate = try makeTestCertificate()

        Keychain.Certificates.applyAddParameters(
            certificate: certificate,
            label: .default,
            accessGroup: .default,
            synchronizable: false,
            to: &query
        )

        #expect(query[kSecValueRef as String].cast() == certificate)
        #expect(query[kSecAttrLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(query.count == 2)
    }

    // MARK: - applyDeleteParameters Tests

    @Test("applyDeleteParameters with specific values sets all attributes")
    func applyDeleteParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let issuer = "issuer".data(using: .utf8)!
        let serialNumber = "serial".data(using: .utf8)!

        try Keychain.Certificates.applyDeleteParameters(
            issuer: issuer,
            serialNumber: serialNumber,
            label: "Test Label",
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            to: &query
        )

        #expect(query[kSecAttrIssuer as String] as? Data == issuer)
        #expect(query[kSecAttrSerialNumber as String] as? Data == serialNumber)
        #expect(query[kSecAttrLabel as String] as? String == "Test Label")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query.count == 5)
    }

    @Test("applyDeleteParameters with nil values omits those attributes")
    func applyDeleteParametersWithNilValues() throws {
        var query: [String: Any] = [:]

        try Keychain.Certificates.applyDeleteParameters(
            issuer: nil,
            serialNumber: nil,
            label: nil,
            accessGroupScope: .any,
            synchronizableScope: .any,
            to: &query
        )

        #expect(query[kSecAttrIssuer as String] == nil)
        #expect(query[kSecAttrSerialNumber as String] == nil)
        #expect(query[kSecAttrLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query.count == 1)
    }

    // MARK: - applyAttributesParameters Tests

    @Test("applyAttributesParameters with specific values sets all attributes")
    func applyAttributesParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let certificateType = 1
        let subject = "subject"
        let issuer = "issuer"
        let serialNumber = "serial"
        let subjectKeyID = "subjectKeyID"
        let publicKeyHash = "publicKeyHash"

        try Keychain.Certificates.applyAttributesParameters(
            certificateTypeScope: .specific(certificateType),
            subjectScope: .utf8(subject),
            issuerScope: .utf8(issuer),
            serialNumberScope: .utf8(serialNumber),
            subjectKeyIDScope: .utf8(subjectKeyID),
            publicKeyHashScope: .utf8(publicKeyHash),
            labelScope: .specific("Test Label"),
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            skipItemsIfUIRequired: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrCertificateType as String] as? Int == certificateType)
        #expect(query[kSecAttrSubject as String] as? Data == Data(subject.utf8))
        #expect(query[kSecAttrIssuer as String] as? Data == Data(issuer.utf8))
        #expect(query[kSecAttrSerialNumber as String] as? Data == Data(serialNumber.utf8))
        #expect(query[kSecAttrSubjectKeyID as String] as? Data == Data(subjectKeyID.utf8))
        #expect(query[kSecAttrPublicKeyHash as String] as? Data == Data(publicKeyHash.utf8))
        #expect(query[kSecAttrLabel as String] as? String == "Test Label")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 11)
    }

    @Test("applyAttributesParameters with any values omits those attributes")
    func applyAttributesParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.Certificates.applyAttributesParameters(
            certificateTypeScope: .any,
            subjectScope: .any,
            issuerScope: .any,
            serialNumberScope: .any,
            subjectKeyIDScope: .any,
            publicKeyHashScope: .any,
            labelScope: .any,
            accessGroupScope: .any,
            synchronizableScope: .any,
            skipItemsIfUIRequired: false,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrCertificateType as String] == nil)
        #expect(query[kSecAttrSubject as String] == nil)
        #expect(query[kSecAttrIssuer as String] == nil)
        #expect(query[kSecAttrSerialNumber as String] == nil)
        #expect(query[kSecAttrSubjectKeyID as String] == nil)
        #expect(query[kSecAttrPublicKeyHash as String] == nil)
        #expect(query[kSecAttrLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query[kSecUseAuthenticationUI as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 1)
    }
}

private extension CertificatesQueryBuilderTests {
    enum TestError: Error {
        case testCertificateCreationFailed
    }

    static let certificateDataBase64 = """
    MIIDFzCCAf+gAwIBAgIUDjzcKYqc3xJW9KgtOSyfuHI1DEYwDQYJKoZIhvcNAQEL\
    BQAwGzEZMBcGA1UEAwwQU3dpZnRLZXljaGFpbktpdDAeFw0yNjAyMTMxNzA0MjZa\
    Fw0yNjAyMTQxNzA0MjZaMBsxGTAXBgNVBAMMEFN3aWZ0S2V5Y2hhaW5LaXQwggEi\
    MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIFSolVA6baYB7Oh6Cter70rNc\
    8t2o1NDZqJos086CiWBLHCyspmGZd0TSL8YSm0Qsms97Tgc1zE9HjQCK+ZJ+dpjx\
    oEtDE9bEtTisOh1epay9A9G2HcWcB3gEBHcu5nAmYCRo9JBu+FkC/r7kspzz+1yl\
    gKFRbtfrjTrAKBHPmvOlB1zt/Y9azzbQFidGnuDAVFjxE/JaZ2mKRWocIHofnIsn\
    a/Q4pZBhM06ycxvQA1dJ4VeMDIk8xkGY5hMEyJC1RQSO+F/87j2brK8gig08jCjx\
    8Sn3LQ/VAW5goPEDWPUfKTv8N+AnHsIse80i356E487ukXlvJG77TUhHS1RDAgMB\
    AAGjUzBRMB0GA1UdDgQWBBQ2XSPonW3xrQprXyCSv3LbA1lBujAfBgNVHSMEGDAW\
    gBQ2XSPonW3xrQprXyCSv3LbA1lBujAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\
    DQEBCwUAA4IBAQB/twDoRKm3zX3Ia6VVuc1aNd8X02j0WUM4KPltXRa+nGS3emzR\
    v8qVR0ijMy/N7TencNCWAc8LmHjgC6NwU1a0/G9KcGPdMpPY7ruS0zYOP5uWzJN/\
    lB++UYWRiSGLIiAmSrysuYi7rj6OArwbto7VRIuXOo6bhe+jCNyu+TXhXpdQF8p1\
    +Ms2n2sKPG+WWoig5A2z28g0gYo/5PdQoTJeCYCL26W8JWaiQcbywOgiW2izy5md\
    Lx8YMZyTKbrNCJ2mN/Yemk4nchr5M9HreykB98PYWfKR/snYnGcylGNBWucSAq0x\
    q23E98yaWDRxHu7M7A5QNYg3IeV7FBj/6cqz
    """

    func makeTestCertificate() throws -> SecCertificate {
        guard let data = Data(base64Encoded: Self.certificateDataBase64),
              let certificate = SecCertificateCreateWithData(nil, data as CFData)
        else {
            throw TestError.testCertificateCreationFailed
        }
        return certificate
    }
}
