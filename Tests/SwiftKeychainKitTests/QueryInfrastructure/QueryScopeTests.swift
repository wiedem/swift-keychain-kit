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
        
        let value = query[kSecAttrProtocol as String]
        #expect(value != nil, "Protocol value should be set")
        #expect((value as! CFString) == kSecAttrProtocolHTTPS, "Protocol value should be kSecAttrProtocolHTTPS")
    }
    
    @Test("AuthenticationTypeScope applies AuthenticationType correctly")
    func authenticationTypeScopeAppliesAuthenticationTypeCorrectly() throws {
        var query: [String: Any] = [:]
        
        let scope: Keychain.AuthenticationTypeScope = .specific(.httpBasic)
        try scope.apply(to: &query)
        
        let value = query[kSecAttrAuthenticationType as String]
        #expect(value != nil, "AuthenticationType value should be set")
        #expect((value as! CFString) == kSecAttrAuthenticationTypeHTTPBasic, "AuthenticationType value should be kSecAttrAuthenticationTypeHTTPBasic")
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
