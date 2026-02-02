@testable import SwiftKeychainKit
import Foundation
import LocalAuthentication
import Security
import Testing

@Suite("Keys QueryBuilder Tests")
struct KeysQueryBuilderTests {
    // MARK: - baseQuery Tests

    @Test("baseQuery contains class and data protection keychain flag")
    func baseQueryContainsRequiredAttributes() {
        let query = Keychain.Keys.baseQuery()

        #expect(query[kSecClass as String].cast() == kSecClassKey)
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query.count == 2)
    }

    // MARK: - applyQueryParameters Tests

    @Test("applyQueryParameters with specific values sets all attributes")
    func applyQueryParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let applicationLabel = "label"
        let applicationTag = "tag"

        try Keychain.Keys.applyQueryParameters(
            keyTypeScope: .rsa(.privateKey),
            applicationTagScope: .utf8(applicationTag),
            applicationLabelScope: .utf8(applicationLabel),
            keySizeInBitsScope: 2048,
            accessGroupScope: .specific("group.keys"),
            synchronizableScope: .synchronized,
            skipItemsIfUIRequired: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeRSA)
        #expect(query[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(query[kSecAttrApplicationLabel as String] as? Data == Data(applicationLabel.utf8))
        #expect(query[kSecAttrApplicationTag as String] as? Data == Data(applicationTag.utf8))
        #expect(query[kSecAttrKeySizeInBits as String] as? Int == 2048)
        #expect(query[kSecAttrAccessGroup as String] as? String == "group.keys")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 9)
    }

    @Test("applyQueryParameters with any values omits those attributes")
    func applyQueryParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.Keys.applyQueryParameters(
            keyTypeScope: .rsa(.any),
            applicationTagScope: .any,
            applicationLabelScope: .any,
            keySizeInBitsScope: .any,
            accessGroupScope: .any,
            synchronizableScope: .any,
            skipItemsIfUIRequired: false,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeRSA)
        #expect(query[kSecAttrKeyClass as String] == nil)
        #expect(query[kSecAttrApplicationLabel as String] == nil)
        #expect(query[kSecAttrApplicationTag as String] == nil)
        #expect(query[kSecAttrKeySizeInBits as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query[kSecUseAuthenticationUI as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 2)
    }

    // MARK: - applyAddParameters Tests

    @Test("applyAddParameters with all parameters sets all attributes")
    func applyAddParametersWithAllParameters() throws {
        var query: [String: Any] = [:]
        let key = try Self.makeTestKey()
        let applicationLabel = Data("label".utf8)
        let applicationTag = Data("tag".utf8)

        Keychain.Keys.applyAddParameters(
            key: key,
            applicationTag: applicationTag,
            applicationLabel: .data(applicationLabel),
            label: "Test Label",
            accessGroup: .identifier("group.keys"),
            synchronizable: true,
            to: &query
        )

        #expect(query[kSecValueRef as String] as AnyObject === key)
        #expect(query[kSecAttrApplicationLabel as String] as? Data == applicationLabel)
        #expect(query[kSecAttrApplicationTag as String] as? Data == applicationTag)
        #expect(query[kSecAttrLabel as String] as? String == "Test Label")
        #expect(query[kSecAttrAccessGroup as String] as? String == "group.keys")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query.count == 6)
    }

    @Test("applyAddParameters with nil optional parameters omits those attributes")
    func applyAddParametersWithNilOptionalParameters() throws {
        var query: [String: Any] = [:]
        let key = try Self.makeTestKey()
        let applicationLabel = Data("label".utf8)

        Keychain.Keys.applyAddParameters(
            key: key,
            applicationTag: nil,
            applicationLabel: .data(applicationLabel),
            label: nil,
            accessGroup: .default,
            synchronizable: false,
            to: &query
        )

        #expect(query[kSecValueRef as String] as AnyObject === key)
        #expect(query[kSecAttrApplicationLabel as String] as? Data == applicationLabel)
        #expect(query[kSecAttrApplicationTag as String] == nil)
        #expect(query[kSecAttrLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(query.count == 3)
    }

    // MARK: - applyDeleteParameters Tests

    @Test("applyDeleteParameters with specific values sets all attributes")
    func applyDeleteParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let applicationLabel = Data("label".utf8)
        let applicationTag = Data("tag".utf8)

        try Keychain.Keys.applyDeleteParameters(
            keyTypeScope: .rsa(.privateKey),
            applicationTag: applicationTag,
            applicationLabel: applicationLabel,
            keySizeInBits: 2048,
            accessGroupScope: .specific("group.keys"),
            synchronizableScope: .synchronized,
            to: &query
        )

        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeRSA)
        #expect(query[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(query[kSecAttrApplicationLabel as String] as? Data == applicationLabel)
        #expect(query[kSecAttrApplicationTag as String] as? Data == applicationTag)
        #expect(query[kSecAttrKeySizeInBits as String] as? Int == 2048)
        #expect(query[kSecAttrAccessGroup as String] as? String == "group.keys")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query.count == 7)
    }

    @Test("applyDeleteParameters with nil values omits those attributes")
    func applyDeleteParametersWithNilValues() throws {
        var query: [String: Any] = [:]

        try Keychain.Keys.applyDeleteParameters(
            keyTypeScope: .rsa(.any),
            applicationTag: nil,
            applicationLabel: nil,
            keySizeInBits: nil,
            accessGroupScope: .any,
            synchronizableScope: .any,
            to: &query
        )

        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeRSA)
        #expect(query[kSecAttrKeyClass as String] == nil)
        #expect(query[kSecAttrApplicationLabel as String] == nil)
        #expect(query[kSecAttrApplicationTag as String] == nil)
        #expect(query[kSecAttrKeySizeInBits as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query.count == 2)
    }

    // MARK: - applyAttributesParameters Tests

    @Test("applyAttributesParameters with specific values sets all attributes")
    func applyAttributesParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()
        let applicationLabel = "label"
        let applicationTag = "tag"

        try Keychain.Keys.applyAttributesParameters(
            keyTypeScope: .rsa(.privateKey),
            applicationTagScope: .utf8(applicationTag),
            applicationLabelScope: .utf8(applicationLabel),
            keySizeInBitsScope: 2048,
            accessGroupScope: .specific("group.keys"),
            synchronizableScope: .synchronized,
            skipItemsIfUIRequired: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeRSA)
        #expect(query[kSecAttrKeyClass as String].cast() == kSecAttrKeyClassPrivate)
        #expect(query[kSecAttrApplicationLabel as String] as? Data == Data(applicationLabel.utf8))
        #expect(query[kSecAttrApplicationTag as String] as? Data == Data(applicationTag.utf8))
        #expect(query[kSecAttrKeySizeInBits as String] as? Int == 2048)
        #expect(query[kSecAttrAccessGroup as String] as? String == "group.keys")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 9)
    }

    @Test("applyAttributesParameters with any values omits those attributes")
    func applyAttributesParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.Keys.applyAttributesParameters(
            keyTypeScope: .rsa(.any),
            applicationTagScope: .any,
            applicationLabelScope: .any,
            keySizeInBitsScope: .any,
            accessGroupScope: .any,
            synchronizableScope: .any,
            skipItemsIfUIRequired: false,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrKeyType as String].cast() == kSecAttrKeyTypeRSA)
        #expect(query[kSecAttrKeyClass as String] == nil)
        #expect(query[kSecAttrApplicationLabel as String] == nil)
        #expect(query[kSecAttrApplicationTag as String] == nil)
        #expect(query[kSecAttrKeySizeInBits as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query[kSecUseAuthenticationUI as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 2)
    }
}

private extension KeysQueryBuilderTests {
    enum TestError: Error {
        case testKeyCreationFailed(NSError)
    }

    static func makeTestKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw TestError.testKeyCreationFailed(error!.takeRetainedValue() as any Error as NSError)
        }
        return key
    }
}
