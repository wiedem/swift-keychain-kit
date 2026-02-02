@testable import SwiftKeychainKit
import Foundation
import LocalAuthentication
import Security
import Testing

@Suite("InternetPassword QueryBuilder Tests")
struct InternetPasswordQueryBuilderTests {
    // MARK: - baseQuery Tests

    @Test("baseQuery contains class and data protection keychain flag")
    func baseQueryContainsRequiredAttributes() {
        let query = Keychain.InternetPassword.baseQuery()

        #expect(query[kSecClass as String].cast() == kSecClassInternetPassword)
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query.count == 2)
    }

    // MARK: - applyQueryParameters Tests

    @Test("applyQueryParameters with specific values sets all attributes")
    func applyQueryParametersWithSpecificValues() throws {
        var query: [String: Any] = [:]
        let context = LAContext()

        try Keychain.InternetPassword.applyQueryParameters(
            accountScope: .specific("test-account"),
            serverScope: .specific("example.com"),
            protocolScope: .specific(.https),
            authenticationTypeScope: .specific(.httpBasic),
            portScope: .specific(443),
            pathScope: .specific("/login"),
            securityDomainScope: .specific("example.com"),
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            skipItemsIfUIRequired: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrServer as String] as? String == "example.com")
        #expect(query[kSecAttrProtocol as String].cast() == kSecAttrProtocolHTTPS)
        #expect(query[kSecAttrAuthenticationType as String].cast() == kSecAttrAuthenticationTypeHTTPBasic)
        #expect(query[kSecAttrPort as String] as? Int == 443)
        #expect(query[kSecAttrPath as String] as? String == "/login")
        #expect(query[kSecAttrSecurityDomain as String] as? String == "example.com")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 11)
    }

    @Test("applyQueryParameters with any values omits those attributes")
    func applyQueryParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.InternetPassword.applyQueryParameters(
            accountScope: .any,
            serverScope: .any,
            protocolScope: .any,
            authenticationTypeScope: .any,
            portScope: .any,
            pathScope: .any,
            securityDomainScope: .any,
            accessGroupScope: .any,
            synchronizableScope: .any,
            skipItemsIfUIRequired: false,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] == nil)
        #expect(query[kSecAttrServer as String] == nil)
        #expect(query[kSecAttrProtocol as String] == nil)
        #expect(query[kSecAttrAuthenticationType as String] == nil)
        #expect(query[kSecAttrPort as String] == nil)
        #expect(query[kSecAttrPath as String] == nil)
        #expect(query[kSecAttrSecurityDomain as String] == nil)
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
        let data = "password".data(using: .utf8)!

        try Keychain.InternetPassword.applyAddParameters(
            data: data as NSData,
            account: "test-account",
            server: "example.com",
            protocol: .https,
            authenticationType: .httpBasic,
            port: 443,
            path: "/login",
            securityDomain: "example.com",
            label: "Test Label",
            accessGroup: "com.example.group",
            synchronizable: true,
            to: &query
        )

        #expect(query[kSecValueData as String] as? Data == data)
        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrServer as String] as? String == "example.com")
        #expect(query[kSecAttrProtocol as String].cast() == kSecAttrProtocolHTTPS)
        #expect(query[kSecAttrAuthenticationType as String].cast() == kSecAttrAuthenticationTypeHTTPBasic)
        #expect(query[kSecAttrPort as String] as? Int == 443)
        #expect(query[kSecAttrPath as String] as? String == "/login")
        #expect(query[kSecAttrSecurityDomain as String] as? String == "example.com")
        #expect(query[kSecAttrLabel as String] as? String == "Test Label")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query.count == 11)
    }

    @Test("applyAddParameters with default values sets defaults for port, path, securityDomain")
    func applyAddParametersWithDefaultValues() throws {
        var query: [String: Any] = [:]
        let data = "password".data(using: .utf8)!

        try Keychain.InternetPassword.applyAddParameters(
            data: data as NSData,
            account: "test-account",
            server: "example.com",
            protocol: nil,
            authenticationType: nil,
            port: 0,
            path: "",
            securityDomain: "",
            label: nil,
            accessGroup: nil,
            synchronizable: false,
            to: &query
        )

        #expect(query[kSecValueData as String] as? Data == data)
        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrServer as String] as? String == "example.com")
        #expect(query[kSecAttrProtocol as String] == nil)
        #expect(query[kSecAttrAuthenticationType as String] == nil)
        #expect(query[kSecAttrPort as String] as? Int == 0)
        #expect(query[kSecAttrPath as String] as? String == "")
        #expect(query[kSecAttrSecurityDomain as String] as? String == "")
        #expect(query[kSecAttrLabel as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(query.count == 7)
    }

    // MARK: - applyUpdateParameters Tests

    @Test("applyUpdateParameters with all parameters sets all attributes")
    func applyUpdateParametersWithAllParameters() throws {
        var query: [String: Any] = [:]
        let context = LAContext()

        try Keychain.InternetPassword.applyUpdateParameters(
            account: "test-account",
            server: "example.com",
            protocol: .https,
            authenticationType: .httpBasic,
            port: 443,
            path: "/login",
            securityDomain: "example.com",
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrServer as String] as? String == "example.com")
        #expect(query[kSecAttrProtocol as String].cast() == kSecAttrProtocolHTTPS)
        #expect(query[kSecAttrAuthenticationType as String].cast() == kSecAttrAuthenticationTypeHTTPBasic)
        #expect(query[kSecAttrPort as String] as? Int == 443)
        #expect(query[kSecAttrPath as String] as? String == "/login")
        #expect(query[kSecAttrSecurityDomain as String] as? String == "example.com")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 10)
    }

    @Test("applyUpdateParameters with nil optional parameters omits those attributes")
    func applyUpdateParametersWithNilOptionalParameters() throws {
        var query: [String: Any] = [:]

        try Keychain.InternetPassword.applyUpdateParameters(
            account: "test-account",
            server: "example.com",
            protocol: nil,
            authenticationType: nil,
            port: nil,
            path: nil,
            securityDomain: nil,
            accessGroupScope: .any,
            synchronizableScope: .any,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrServer as String] as? String == "example.com")
        #expect(query[kSecAttrProtocol as String] == nil)
        #expect(query[kSecAttrAuthenticationType as String] == nil)
        #expect(query[kSecAttrPort as String] == nil)
        #expect(query[kSecAttrPath as String] == nil)
        #expect(query[kSecAttrSecurityDomain as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 3)
    }

    // MARK: - applyDeleteParameters Tests

    @Test("applyDeleteParameters with specific scopes sets all attributes")
    func applyDeleteParametersWithSpecificScopes() throws {
        var query: [String: Any] = [:]
        let context = LAContext()

        try Keychain.InternetPassword.applyDeleteParameters(
            accountScope: .specific("test-account"),
            serverScope: .specific("example.com"),
            protocolScope: .specific(.https),
            authenticationTypeScope: .specific(.httpBasic),
            portScope: .specific(443),
            pathScope: .specific("/login"),
            securityDomainScope: .specific("example.com"),
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrServer as String] as? String == "example.com")
        #expect(query[kSecAttrProtocol as String].cast() == kSecAttrProtocolHTTPS)
        #expect(query[kSecAttrAuthenticationType as String].cast() == kSecAttrAuthenticationTypeHTTPBasic)
        #expect(query[kSecAttrPort as String] as? Int == 443)
        #expect(query[kSecAttrPath as String] as? String == "/login")
        #expect(query[kSecAttrSecurityDomain as String] as? String == "example.com")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 10)
    }

    @Test("applyDeleteParameters with any scopes omits those attributes")
    func applyDeleteParametersWithAnyScopes() throws {
        var query: [String: Any] = [:]

        try Keychain.InternetPassword.applyDeleteParameters(
            accountScope: .any,
            serverScope: .any,
            protocolScope: .any,
            authenticationTypeScope: .any,
            portScope: .any,
            pathScope: .any,
            securityDomainScope: .any,
            accessGroupScope: .any,
            synchronizableScope: .any,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] == nil)
        #expect(query[kSecAttrServer as String] == nil)
        #expect(query[kSecAttrProtocol as String] == nil)
        #expect(query[kSecAttrAuthenticationType as String] == nil)
        #expect(query[kSecAttrPort as String] == nil)
        #expect(query[kSecAttrPath as String] == nil)
        #expect(query[kSecAttrSecurityDomain as String] == nil)
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

        try Keychain.InternetPassword.applyAttributesParameters(
            accountScope: .specific("test-account"),
            serverScope: .specific("example.com"),
            protocolScope: .specific(.https),
            authenticationTypeScope: .specific(.httpBasic),
            portScope: .specific(443),
            pathScope: .specific("/login"),
            securityDomainScope: .specific("example.com"),
            accessGroupScope: .specific("com.example.group"),
            synchronizableScope: .synchronized,
            skipItemsIfUIRequired: true,
            authenticationContext: context,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] as? String == "test-account")
        #expect(query[kSecAttrServer as String] as? String == "example.com")
        #expect(query[kSecAttrProtocol as String].cast() == kSecAttrProtocolHTTPS)
        #expect(query[kSecAttrAuthenticationType as String].cast() == kSecAttrAuthenticationTypeHTTPBasic)
        #expect(query[kSecAttrPort as String] as? Int == 443)
        #expect(query[kSecAttrPath as String] as? String == "/login")
        #expect(query[kSecAttrSecurityDomain as String] as? String == "example.com")
        #expect(query[kSecAttrAccessGroup as String] as? String == "com.example.group")
        #expect(query[kSecAttrSynchronizable as String] as? Bool == true)
        #expect(query[kSecUseAuthenticationUI as String].cast() == kSecUseAuthenticationUISkip)
        #expect(query[kSecUseAuthenticationContext as String] is LAContext)
        #expect(query.count == 11)
    }

    @Test("applyAttributesParameters with any values omits those attributes")
    func applyAttributesParametersWithAnyValues() throws {
        var query: [String: Any] = [:]

        try Keychain.InternetPassword.applyAttributesParameters(
            accountScope: .any,
            serverScope: .any,
            protocolScope: .any,
            authenticationTypeScope: .any,
            portScope: .any,
            pathScope: .any,
            securityDomainScope: .any,
            accessGroupScope: .any,
            synchronizableScope: .any,
            skipItemsIfUIRequired: false,
            authenticationContext: nil,
            to: &query
        )

        #expect(query[kSecAttrAccount as String] == nil)
        #expect(query[kSecAttrServer as String] == nil)
        #expect(query[kSecAttrProtocol as String] == nil)
        #expect(query[kSecAttrAuthenticationType as String] == nil)
        #expect(query[kSecAttrPort as String] == nil)
        #expect(query[kSecAttrPath as String] == nil)
        #expect(query[kSecAttrSecurityDomain as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
        #expect(query[kSecAttrSynchronizable as String].cast() == kSecAttrSynchronizableAny)
        #expect(query[kSecUseAuthenticationUI as String] == nil)
        #expect(query[kSecUseAuthenticationContext as String] == nil)
        #expect(query.count == 1)
    }
}
