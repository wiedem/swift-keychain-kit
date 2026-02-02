@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("Port Attribute Tests")
struct PortAttributeTests {
    @Test(
        "apply with Int value",
        arguments: [
            TestCase(
                "positive value sets port",
                input: 443,
                expectedValue: 443
            ),
            TestCase(
                "zero sets port to zero",
                input: 0,
                expectedValue: 0
            ),
            TestCase(
                "negative value sets port to negative",
                input: -1,
                expectedValue: -1
            ),
        ]
    )
    func applyWithIntValue(testCase: TestCase<Int>) {
        var query: [String: Any] = [
            kSecAttrPort as String: 999,
        ]

        Keychain.ItemAttributes.Port.apply(testCase.input, to: &query)

        #expect(query[kSecAttrPort as String] as? Int == testCase.expectedValue)
    }

    @Test(
        "apply with optional Int value",
        arguments: [
            TestCase(
                "positive value sets port",
                input: 8080,
                expectedValue: 8080
            ),
            TestCase(
                "nil removes port",
                input: nil,
                expectedValue: nil
            ),
            TestCase(
                "zero sets port to zero",
                input: 0,
                expectedValue: 0
            ),
            TestCase(
                "negative value sets port to negative",
                input: -10,
                expectedValue: -10
            ),
        ]
    )
    func applyWithOptionalIntValue(testCase: TestCase<Int?>) {
        var query: [String: Any] = [
            kSecAttrPort as String: 999,
        ]

        Keychain.ItemAttributes.Port.apply(testCase.input, to: &query)

        #expect(query[kSecAttrPort as String] as? Int == testCase.expectedValue)
    }
}

extension PortAttributeTests {
    struct TestCase<Input: Sendable>: Sendable {
        let name: String
        let input: Input
        let expectedValue: Int?

        init(
            _ name: String,
            input: @Sendable @escaping @autoclosure () -> Input,
            expectedValue: Int?
        ) {
            self.name = name
            self.input = input()
            self.expectedValue = expectedValue
        }
    }
}
