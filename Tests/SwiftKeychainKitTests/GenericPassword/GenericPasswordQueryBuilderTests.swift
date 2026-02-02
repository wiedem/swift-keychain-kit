@testable import SwiftKeychainKit
import Foundation
import LocalAuthentication
import Security
import Testing

@Suite("GenericPassword QueryBuilder Tests")
struct GenericPasswordQueryBuilderTests {
    // MARK: - baseQuery Tests

    @Test("baseQuery contains class and data protection keychain flag")
    func baseQueryContainsRequiredAttributes() {
        let query = Keychain.GenericPassword.baseQuery()

        #expect(query[kSecClass as String].cast() == kSecClassGenericPassword)
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query.count == 2)
    }

    // MARK: - applyQueryParameters Tests

    @Test("applyQueryParameters with specific values sets all attributes")
    func applyQueryParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()

        try Keychain.GenericPassword.applyQueryParameters(
            accountScope: .specific("test-account"),
            serviceScope: .specific("test-service"),
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            skipItemsIfUIRequired: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrService as String] as? String == "test-service")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 6)
    }

    @Test("applyQueryParameters with any values omits those attributes")
    func applyQueryParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.GenericPassword.applyQueryParameters(
            accountScope: .any,
            serviceScope: .any,
            accessGroupScope: .any,
            synchronizableScope: .any,
            skipItemsIfUIRequired: false,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] == nil)
        #expect(query[kSecAttrService as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query[kSecUseAuthenticationUI as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 1)
    }

    // MARK: - applyAddParameters Tests

    @Test("applyAddParameters with all parameters sets all attributes")
    func applyAddParametersWithAllParameters() {
        var query: [String: Any] = [:]
        let data = "password".data(using: .utf8)! as CFData
        let context = LAContext()

        Keychain.GenericPassword.applyAddParameters(
            data: data,
            account: "test-account",
            service: "test-service",
            label: "Test Label",
            accessGroup: "com.example.group",
            synchronizable: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecValueData as String].cast() == data)
        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrService as String] as? String == "test-service")
        #expect(query[kSecAttrLabel as String] as? String == "Test Label")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 7)
    }

    @Test("applyAddParameters with nil optional parameters omits those attributes")
    func applyAddParametersWithNilOptionalParameters() {
        var query: [String: Any] = [:]
        let data = "password".data(using: .utf8)! as CFData

        Keychain.GenericPassword.applyAddParameters(
            data: data,
            account: "test-account",
            service: "test-service",
            label: nil,
            accessGroup: nil,
            synchronizable: false,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecValueData as String].cast() == data)
        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrService as String] as? String == "test-service")
        #expect(query[kSecAttrLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 4)
    }

    // MARK: - applyUpdateParameters Tests

    @Test("applyUpdateParameters with all parameters sets all attributes")
    func applyUpdateParametersWithAllParameters() {
        var query: [String: Any] = [:]
        let context = LAContext()

        Keychain.GenericPassword.applyUpdateParameters(
            account: "test-account",
            service: "test-service",
            accessGroup: "com.example.group",
            synchronizable: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrService as String] as? String == "test-service")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 5)
    }

    @Test("applyUpdateParameters with nil authentication context omits context")
    func applyUpdateParametersWithNilAuthenticationContext() {
        var query: [String: Any] = [:]

        Keychain.GenericPassword.applyUpdateParameters(
            account: "test-account",
            service: "test-service",
            accessGroup: "com.example.group",
            synchronizable: false,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrService as String] as? String == "test-service")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 4)
    }

    // MARK: - applyDeleteParameters Tests

    @Test("applyDeleteParameters with specific scopes sets all attributes")
    func applyDeleteParametersWithSpecificScopes() throws {
        var query: [String: Any] = [:]
        let context = LAContext()

        try Keychain.GenericPassword.applyDeleteParameters(
            accountScope: .specific("test-account"),
            serviceScope: .specific("test-service"),
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrService as String] as? String == "test-service")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 5)
    }

    @Test("applyDeleteParameters with any scopes omits those attributes")
    func applyDeleteParametersWithAnyScopes() throws {
        var query: [String: Any] = [:]

        try Keychain.GenericPassword.applyDeleteParameters(
            accountScope: .any,
            serviceScope: .any,
            accessGroupScope: .any,
            synchronizableScope: .any,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] == nil)
        #expect(query[kSecAttrService as String] == nil)
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

        try Keychain.GenericPassword.applyAttributesParameters(
            accountScope: .specific("test-account"),
            serviceScope: .specific("test-service"),
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            skipItemsIfUIRequired: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrService as String] as? String == "test-service")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 6)
    }

    @Test("applyAttributesParameters with any values omits those attributes")
    func applyAttributesParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.GenericPassword.applyAttributesParameters(
            accountScope: .any,
            serviceScope: .any,
            accessGroupScope: .any,
            synchronizableScope: .any,
            skipItemsIfUIRequired: false,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] == nil)
        #expect(query[kSecAttrService as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query[kSecUseAuthenticationUI as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 1)
    }
}
