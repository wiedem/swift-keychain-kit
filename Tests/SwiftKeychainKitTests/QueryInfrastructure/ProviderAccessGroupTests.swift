@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("ProviderAccessGroup Tests")
struct ProviderAccessGroupTests {
    // MARK: - valueForGet Tests

    @Test(
        "valueForGet returns expected value",
        arguments: [
            TestCase(
                "identifier case",
                accessGroup: .identifier("ABCDE12345.com.example.myapp"),
                expected: "ABCDE12345.com.example.myapp"
            ),
            TestCase(
                "default case with provider",
                accessGroup: .default,
                expected: "test.access.group"
            ),
        ]
    )
    func valueForGetReturnsExpectedValue(testCase: TestCase) throws {
        switch testCase.expected() {
        case let .success(expectedValue):
            let value = try testCase.accessGroup().valueForGet
            #expect(value == expectedValue)
        case let .failure(expectedError):
            #expect(throws: expectedError) {
                try testCase.accessGroup().valueForGet
            }
        }
    }

    @Test("valueForGet throws when default provider throws")
    func valueForGetThrowsWhenDefaultProviderReturnsNil() {
        let accessGroup: Keychain.ProviderAccessGroup<ThrowingProvider> = .default

        #expect(throws: KeychainError.anyAppEntitlementsError) {
            try accessGroup.valueForGet
        }
    }
}

// MARK: - Test Providers

extension ProviderAccessGroupTests {
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

extension ProviderAccessGroupTests {
    typealias TestCase = ValueForGetTestCase<TestProvider>

    struct ValueForGetTestCase<Provider: Keychain.AccessGroupProviding>: Sendable {
        let name: String
        let accessGroup: @Sendable () -> Keychain.ProviderAccessGroup<Provider>
        let expected: @Sendable () -> Result<String, KeychainError>

        init(
            _ name: String,
            accessGroup: @Sendable @escaping @autoclosure () -> Keychain.ProviderAccessGroup<Provider>,
            expected: @Sendable @escaping @autoclosure () -> Result<String, KeychainError>
        ) {
            self.name = name
            self.accessGroup = accessGroup
            self.expected = expected
        }

        init(
            _ name: String,
            accessGroup: @Sendable @escaping @autoclosure () -> Keychain.ProviderAccessGroup<Provider>,
            expected: @Sendable @escaping @autoclosure () -> String
        ) {
            self.init(
                name,
                accessGroup: accessGroup(),
                expected: .success(expected())
            )
        }
    }
}
