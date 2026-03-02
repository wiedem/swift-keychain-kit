@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("Query Scope Tests")
struct QueryScopeTests {
    @Test("Any scope has no value to filter by")
    func anyScopeHasNoValue() {
        let scope: TestQueryScope = .any
        #expect(scope.value == nil)
    }

    @Test("Specific scope contains the specified value")
    func specificScopeContainsValue() {
        let scope: TestQueryScope = .specific("Test")
        #expect(scope.value == "Test")
    }

    @Test("ProtocolScope applies NetworkProtocol correctly")
    func protocolScopeAppliesNetworkProtocolCorrectly() throws {
        var query: [String: Any] = [:]

        let scope: Keychain.ProtocolScope = .specific(.https)
        try scope.apply(to: &query)

        let protocolValue: CFString = try #require(
            query[kSecAttrProtocol as String].cast()
        )
        #expect(protocolValue == kSecAttrProtocolHTTPS)
    }

    @Test("AuthenticationTypeScope applies AuthenticationType correctly")
    func authenticationTypeScopeAppliesAuthenticationTypeCorrectly() throws {
        var query: [String: Any] = [:]

        let scope: Keychain.AuthenticationTypeScope = .specific(.httpBasic)
        try scope.apply(to: &query)

        let authenticationTypeValue: CFString = try #require(
            query[kSecAttrAuthenticationType as String].cast()
        )
        #expect(authenticationTypeValue == kSecAttrAuthenticationTypeHTTPBasic)
    }
}

private extension QueryScopeTests {
    typealias TestQueryScope = Keychain.QueryScope<String, TestAttribute>

    enum TestAttribute: Keychain.ItemAttributes.Attribute {
        typealias ValueType = String

        static var keychainAttributeKey: CFString {
            kSecAttrAccount
        }
    }
}
