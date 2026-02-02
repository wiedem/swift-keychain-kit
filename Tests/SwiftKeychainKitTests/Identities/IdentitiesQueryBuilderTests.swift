@testable import SwiftKeychainKit
import Foundation
import LocalAuthentication
import Security
import Testing

@Suite("Identities QueryBuilder Tests")
struct IdentitiesQueryBuilderTests {
    // MARK: - baseQuery Tests

    @Test("baseQuery contains class and data protection keychain flag")
    func baseQueryContainsRequiredAttributes() {
        let query = Keychain.Identities.baseQuery()

        #expect(query[kSecClass as String].cast() == kSecClassIdentity)
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query.count == 2)
    }

    // MARK: - applyAddParameters Tests

    @Test("applyAddParameters with all parameters sets all attributes")
    func applyAddParametersWithAllParameters() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let identity = try makeTestIdentity()

        do {
            try Keychain.Identities.applyAddParameters(
                identity: identity,
                label: "Test Label",
                accessGroup: "com.example.group",
                synchronizable: true,
                accessControl: .whenUnlocked,
                authenticationContext: context,
                to: &query
            )
        } catch {
            #expect(Bool(false))
        }

        #expect(query[kSecValueRef as String].cast() == identity)
        #expect(query[kSecAttrLabel as String] as? String == "Test Label")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecAttrAccessible as String].cast() == kSecAttrAccessibleWhenUnlocked)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 6)
    }

    @Test("applyAddParameters with nil optional parameters omits those attributes")
    func applyAddParametersWithNilOptionalParameters() throws {
        var query: [String: Any] = [:]
        let identity = try makeTestIdentity()

        do {
            try Keychain.Identities.applyAddParameters(
                identity: identity,
                label: nil,
                accessGroup: nil,
                synchronizable: false,
                accessControl: .whenUnlocked,
                authenticationContext: nil,
                to: &query
            )
        } catch {
            #expect(Bool(false))
        }

        #expect(query[kSecValueRef as String].cast() == identity)
        #expect(query[kSecAttrLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(query[kSecAttrAccessible as String].cast() == kSecAttrAccessibleWhenUnlocked)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 3)
    }

    // MARK: - applyQueryParameters Tests

    @Test("applyQueryParameters with specific values sets all attributes")
    func applyQueryParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let certificateType = 1
        let subject = "subject".data(using: .utf8)!
        let issuer = "issuer".data(using: .utf8)!
        let serialNumber = "serial".data(using: .utf8)!
        let subjectKeyID = "subjectKeyID".data(using: .utf8)!
        let publicKeyHash = "publicKeyHash".data(using: .utf8)!

        try Keychain.Identities.applyQueryParameters(
            certificateType: certificateType,
            subject: subject,
            issuer: issuer,
            serialNumber: serialNumber,
            subjectKeyID: subjectKeyID,
            publicKeyHash: publicKeyHash,
            label: "Test Label",
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            skipItemsIfUIRequired: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrCertificateType as String] as? Int == certificateType)
        #expect(query[kSecAttrSubject as String] as? Data == subject)
        #expect(query[kSecAttrIssuer as String] as? Data == issuer)
        #expect(query[kSecAttrSerialNumber as String] as? Data == serialNumber)
        #expect(query[kSecAttrSubjectKeyID as String] as? Data == subjectKeyID)
        #expect(query[kSecAttrPublicKeyHash as String] as? Data == publicKeyHash)
        #expect(query[kSecAttrLabel as String] as? String == "Test Label")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 11)
    }

    @Test("applyQueryParameters with nil values omits those attributes")
    func applyQueryParametersWithNilValues() throws {
        var query: [String: Any] = [:]

        try Keychain.Identities.applyQueryParameters(
            certificateType: nil,
            subject: nil,
            issuer: nil,
            serialNumber: nil,
            subjectKeyID: nil,
            publicKeyHash: nil,
            label: nil,
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

    // MARK: - applyDeleteParameters Tests

    @Test("applyDeleteParameters with specific values sets all attributes")
    func applyDeleteParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let issuer = "issuer".data(using: .utf8)!
        let serialNumber = "serial".data(using: .utf8)!

        try Keychain.Identities.applyDeleteParameters(
            issuer: issuer,
            serialNumber: serialNumber,
            label: "Test Label",
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrIssuer as String] as? Data == issuer)
        #expect(query[kSecAttrSerialNumber as String] as? Data == serialNumber)
        #expect(query[kSecAttrLabel as String] as? String == "Test Label")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 6)
    }

    @Test("applyDeleteParameters with nil values omits those attributes")
    func applyDeleteParametersWithNilValues() throws {
        var query: [String: Any] = [:]

        try Keychain.Identities.applyDeleteParameters(
            issuer: nil,
            serialNumber: nil,
            label: nil,
            accessGroupScope: .any,
            synchronizableScope: .any,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrIssuer as String] == nil)
        #expect(query[kSecAttrSerialNumber as String] == nil)
        #expect(query[kSecAttrLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
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

        try Keychain.Identities.applyAttributesParameters(
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

        try Keychain.Identities.applyAttributesParameters(
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

private extension IdentitiesQueryBuilderTests {
    enum TestError: Error {
        case testIdentityCreationFailed
    }

    static let identityDataBase64 = """
    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
    """

    func makeTestIdentity() throws -> SecIdentity {
        guard let data = Data(base64Encoded: Self.identityDataBase64) else {
            throw TestError.testIdentityCreationFailed
        }

        let options = [kSecImportExportPassphrase as String: "password"]
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess,
              let array = items as? [[String: Any]],
              let identity = array.first?[kSecImportItemIdentity as String].cast(as: SecIdentity.self)
        else {
            throw TestError.testIdentityCreationFailed
        }
        return identity
    }
}
