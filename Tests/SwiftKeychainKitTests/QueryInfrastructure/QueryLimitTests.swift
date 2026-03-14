@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("Query Limit Tests")
struct QueryLimitTests {
    @Test("Unlimited query limit maps to kSecMatchLimitAll")
    func unlimitedMapsToMatchLimitAll() {
        let limit = Keychain.QueryLimit.unlimited.keychainValue as? String
        #expect(limit == kSecMatchLimitAll as String)
    }

    @Test("One query limit maps to kSecMatchLimitOne")
    func oneMapsToMatchLimitOne() {
        let limit = Keychain.QueryLimit.one.keychainValue as? String
        #expect(limit == kSecMatchLimitOne as String)
    }

    @Test("Count of 1 maps to kSecMatchLimitOne instead of numeric 1")
    func countOfOneMapsToMatchLimitOne() {
        let limit = Keychain.QueryLimit.count(1).keychainValue as? String
        #expect(limit == kSecMatchLimitOne as String)
    }

    @Test("Count greater than 1 maps to numeric value")
    func countGreaterThanOneMapsToNumericValue() {
        let limit = Keychain.QueryLimit.count(3).keychainValue as? Int
        #expect(limit == 3)
    }

    // MARK: - ExpressibleByIntegerLiteral

    @Test("Integer literal creates count-based limit")
    func integerLiteralCreatesCountLimit() {
        let limit: Keychain.QueryLimit = 5
        guard case .count(5) = limit else {
            Issue.record("Expected .count(5)")
            return
        }
    }

    @Test("Integer literal 1 maps to kSecMatchLimitOne")
    func integerLiteralOneMapsToMatchLimitOne() {
        let limit: Keychain.QueryLimit = 1
        let value = limit.keychainValue as? String
        #expect(value == kSecMatchLimitOne as String)
    }
}
