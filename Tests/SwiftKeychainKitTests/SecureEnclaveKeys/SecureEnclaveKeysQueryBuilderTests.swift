@testable import SwiftKeychainKit
import Foundation
import LocalAuthentication
import Security
import Testing

@Suite("SecureEnclaveKeys QueryBuilder Tests")
struct SecureEnclaveKeysQueryBuilderTests {
    // MARK: - baseQuery Tests

    @Test("baseQuery contains required attributes")
    func baseQueryContainsRequiredAttributes() {
        let query = Keychain.SecureEnclaveKeys.baseQuery()

        #expect(query[kSecClass as String].cast() == kSecClassKey)
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query[kSecAttrTokenID as String].cast() == kSecAttrTokenIDSecureEnclave)
        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeECSECPrimeRandom)
        #expect(query[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(query.count == 5)
    }

    // MARK: - applyQueryParameters Tests

    @Test("applyQueryParameters with specific values sets all attributes")
    func applyQueryParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let applicationTag = "tag"
        let applicationLabel = "label"

        try Keychain.SecureEnclaveKeys.applyQueryParameters(
            applicationTagScope: .utf8(applicationTag),
            applicationLabelScope: .utf8(applicationLabel),
            accessGroupScope: .specific("group.keys"),
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrApplicationTag as String] as? Data == Data(applicationTag.utf8))
        #expect(query[kSecAttrApplicationLabel as String] as? Data == Data(applicationLabel.utf8))
        #expect(query[kSecAttrAccessGroup as String] as? String == "group.keys")
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 4)
    }

    @Test("applyQueryParameters with any values omits those attributes")
    func applyQueryParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.SecureEnclaveKeys.applyQueryParameters(
            applicationTagScope: .any,
            applicationLabelScope: .any,
            accessGroupScope: .any,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrApplicationTag as String] == nil)
        #expect(query[kSecAttrApplicationLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 0)
    }

    // MARK: - applyDeleteParameters Tests

    @Test("applyDeleteParameters with specific values sets all attributes")
    func applyDeleteParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let applicationTag = "tag"
        let applicationLabel = "label"

        try Keychain.SecureEnclaveKeys.applyDeleteParameters(
            applicationTagScope: .utf8(applicationTag),
            applicationLabelScope: .utf8(applicationLabel),
            accessGroupScope: .specific("group.keys"),
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrApplicationTag as String] as? Data == Data(applicationTag.utf8))
        #expect(query[kSecAttrApplicationLabel as String] as? Data == Data(applicationLabel.utf8))
        #expect(query[kSecAttrAccessGroup as String] as? String == "group.keys")
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 4)
    }

    @Test("applyDeleteParameters with any values omits those attributes")
    func applyDeleteParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.SecureEnclaveKeys.applyDeleteParameters(
            applicationTagScope: .any,
            applicationLabelScope: .any,
            accessGroupScope: .any,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrApplicationTag as String] == nil)
        #expect(query[kSecAttrApplicationLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 0)
    }

    // MARK: - applyAttributesParameters Tests

    @Test("applyAttributesParameters with specific values sets all attributes")
    func applyAttributesParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let applicationTag = "tag"
        let applicationLabel = "label"

        try Keychain.SecureEnclaveKeys.applyAttributesParameters(
            applicationTagScope: .utf8(applicationTag),
            applicationLabelScope: .utf8(applicationLabel),
            accessGroupScope: .specific("group.keys"),
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrApplicationTag as String] as? Data == Data(applicationTag.utf8))
        #expect(query[kSecAttrApplicationLabel as String] as? Data == Data(applicationLabel.utf8))
        #expect(query[kSecAttrAccessGroup as String] as? String == "group.keys")
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 4)
    }

    @Test("applyAttributesParameters with any values omits those attributes")
    func applyAttributesParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.SecureEnclaveKeys.applyAttributesParameters(
            applicationTagScope: .any,
            applicationLabelScope: .any,
            accessGroupScope: .any,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrApplicationTag as String] == nil)
        #expect(query[kSecAttrApplicationLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 0)
    }

    // MARK: - applyGenerateParameters Tests

    @Test("applyGenerateParameters with all parameters sets all attributes")
    func applyGenerateParametersWithAllParameters() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let applicationTag = Data("tag".utf8)
        let applicationLabel = Data("label".utf8)

        try Keychain.SecureEnclaveKeys.applyGenerateParameters(
            applicationTag: applicationTag,
            applicationLabel: applicationLabel,
            label: "Test Label",
            accessGroup: "group.keys",
            accessControl: .whenUnlockedThisDeviceOnly,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query[kSecAttrTokenID as String].cast() == kSecAttrTokenIDSecureEnclave)
        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeECSECPrimeRandom)
        #expect(query[kSecAttrKeySizeInBits as String] as? Int == 256)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 6)

        let privateKeyAttributes = try #require(query[kSecPrivateKeyAttrs as String] as? [String: Any])
        #expect(privateKeyAttributes[kSecAttrIsPermanent as String] as? Bool == true)
        #expect(privateKeyAttributes[kSecAttrApplicationTag as String] as? Data == applicationTag)
        #expect(privateKeyAttributes[kSecAttrApplicationLabel as String] as? Data == applicationLabel)
        #expect(privateKeyAttributes[kSecAttrLabel as String] as? String == "Test Label")
        #expect(privateKeyAttributes[kSecAttrAccessGroup as String] as? String == "group.keys")

        // SecureEnclaveKeys always use a SecAccessControl
        let secAccessControl = try Keychain.AccessControl.makeSecAccessControl(
            protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            secAccessControlCreateFlags: .privateKeyUsage
        )

        #expect(privateKeyAttributes[kSecAttrAccessControl as String].cast() == secAccessControl)
        #expect(privateKeyAttributes.count == 6)
    }

    @Test("applyGenerateParameters with nil optional parameters omits those attributes")
    func applyGenerateParametersWithNilOptionalParameters() throws {
        var query: [String: Any] = [:]
        let applicationTag = Data("tag".utf8)

        try Keychain.SecureEnclaveKeys.applyGenerateParameters(
            applicationTag: applicationTag,
            applicationLabel: nil,
            label: nil,
            accessGroup: nil,
            accessControl: .whenUnlockedThisDeviceOnly,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 5)

        let privateKeyAttributes = try #require(query[kSecPrivateKeyAttrs as String] as? [String: Any])
        #expect(privateKeyAttributes[kSecAttrApplicationTag as String] as? Data == applicationTag)
        #expect(privateKeyAttributes[kSecAttrApplicationLabel as String] == nil)
        #expect(privateKeyAttributes[kSecAttrLabel as String] == nil)
        #expect(privateKeyAttributes[kSecAttrAccessGroup as String] == nil)

        // SecureEnclaveKeys always use a SecAccessControl
        let secAccessControl = try Keychain.AccessControl.makeSecAccessControl(
            protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            secAccessControlCreateFlags: .privateKeyUsage
        )

        #expect(privateKeyAttributes[kSecAttrAccessControl as String].cast() == secAccessControl)
        #expect(privateKeyAttributes.count == 3)
    }
}
