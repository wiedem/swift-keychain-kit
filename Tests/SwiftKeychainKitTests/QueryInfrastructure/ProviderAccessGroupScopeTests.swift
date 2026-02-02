@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("ProviderAccessGroupScope Tests")
struct ProviderAccessGroupScopeTests {
    // MARK: - keychainValue Tests

    @Test(
        "keychainValue returns expected value",
        arguments: [
            TestCase(
                "any scope",
                scope: .any,
                expected: nil
            ),
            TestCase(
                "specific scope",
                scope: .specific("ABCDE12345.com.example.myapp"),
                expected: "ABCDE12345.com.example.myapp"
            ),
            TestCase(
                "default scope with provider",
                scope: .default,
                expected: "test.access.group"
            ),
        ]
    )
    func keychainValueReturnsExpectedValue(testCase: TestCase) throws {
        switch testCase.expected() {
        case let .success(expectedValue):
            let value = try testCase.scope().keychainValue
            #expect(value == expectedValue)
        case let .failure(expectedError):
            #expect(throws: expectedError) {
                try testCase.scope().keychainValue
            }
        }
    }

    @Test("keychainValue throws when default provider throws")
    func keychainValueThrowsWhenDefaultProviderThrows() {
        let scope: Keychain.ProviderAccessGroupScope<ThrowingProvider> = .default

        #expect(throws: KeychainError.anyAppEntitlementsError) {
            try scope.keychainValue
        }
    }

    // MARK: - apply(to:) Tests

    @Test("Any scope does not add kSecAttrAccessGroup to query")
    func anyScopeDoesNotAddAttributeToQuery() throws {
        var query: [String: Any] = [:]
        let scope: Keychain.ProviderAccessGroupScope<TestProvider> = .any

        try scope.apply(to: &query)

        #expect(query[kSecAttrAccessGroup as String] == nil)
    }

    @Test("Specific scope adds kSecAttrAccessGroup to query")
    func specificScopeAddsAttributeToQuery() throws {
        var query: [String: Any] = [:]
        let groupId = "ABCDE12345.com.example.myapp"
        let scope: Keychain.ProviderAccessGroupScope<TestProvider> = .specific(groupId)

        try scope.apply(to: &query)

        let value = query[kSecAttrAccessGroup as String] as? String
        #expect(value == groupId)
    }

    @Test("Default scope adds provider value to query")
    func defaultScopeAddsProviderValueToQuery() throws {
        var query: [String: Any] = [:]
        let scope: Keychain.ProviderAccessGroupScope<TestProvider> = .default

        try scope.apply(to: &query)

        let value = query[kSecAttrAccessGroup as String] as? String
        #expect(try value == TestProvider.defaultKeychainAccessGroup)
    }

    @Test("Default scope throws when provider throws during apply")
    func defaultScopeThrowsWhenProviderThrowsDuringApply() {
        var query: [String: Any] = [:]
        let scope: Keychain.ProviderAccessGroupScope<ThrowingProvider> = .default

        #expect(throws: KeychainError.anyAppEntitlementsError) {
            try scope.apply(to: &query)
        }
    }
}

// MARK: - Test Providers

extension ProviderAccessGroupScopeTests {
    enum TestProvider: Sendable, Keychain.AccessGroupProviding & Keychain.ApplicationIdentifierProviding {
        static let applicationIdentifier: String? = "TEAMID.com.example.default"
        static let keychainAccessGroups = ["test.access.group"]
        static let applicationGroups = [String]()
    }

    enum ThrowingProvider: Sendable, Keychain.AccessGroupProviding {
        static var defaultKeychainAccessGroup: String {
            get throws(KeychainError) {
                throw KeychainError.appEntitlementsError(underlyingError: EntitlementError.noDefaultAccessGroup)
            }
        }

        static let keychainAccessGroups = [String]()
        static let applicationGroups = [String]()
    }
}

// MARK: - Test Cases

extension ProviderAccessGroupScopeTests {
    typealias TestCase = KeychainValueTestCase<TestProvider>

    struct KeychainValueTestCase<Provider: Keychain.AccessGroupProviding>: Sendable {
        let name: String
        let scope: @Sendable () -> Keychain.ProviderAccessGroupScope<Provider>
        let expected: @Sendable () -> Result<String?, KeychainError>

        init(
            _ name: String,
            scope: @Sendable @escaping @autoclosure () -> Keychain.ProviderAccessGroupScope<Provider>,
            expected: @Sendable @escaping @autoclosure () -> Result<String?, KeychainError>
        ) {
            self.name = name
            self.scope = scope
            self.expected = expected
        }

        init(
            _ name: String,
            scope: @Sendable @escaping @autoclosure () -> Keychain.ProviderAccessGroupScope<Provider>,
            expected: @Sendable @escaping @autoclosure () -> String?
        ) {
            self.init(
                name,
                scope: scope(),
                expected: .success(expected())
            )
        }
    }
}
