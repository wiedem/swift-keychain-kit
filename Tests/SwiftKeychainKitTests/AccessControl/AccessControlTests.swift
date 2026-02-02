@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("AccessControl Tests")
struct AccessControlTests {
    // MARK: - optimizeFlags Tests

    @Test(
        "optimizeFlags optimizes userPresence pattern",
        arguments: [
            OptimizeFlagsTestCase(
                "userPresence pattern only",
                input: [.or, .devicePasscode, .biometryAny],
                expected: [.userPresence]
            ),
            OptimizeFlagsTestCase(
                "userPresence pattern with and flag",
                input: [.or, .devicePasscode, .biometryAny, .and],
                expected: [.userPresence, .and]
            ),
            OptimizeFlagsTestCase(
                "userPresence pattern with applicationPassword and and flag",
                input: [.or, .devicePasscode, .biometryAny, .and, .applicationPassword],
                expected: [.userPresence, .and, .applicationPassword]
            ),
        ]
    )
    func optimizeFlagsOptimizesUserPresencePattern(testCase: OptimizeFlagsTestCase) {
        let optimized = Keychain.AccessControl.optimizeFlags(testCase.input())
        #expect(optimized == testCase.expected)
    }

    @Test(
        "optimizeFlags does not modify non-userPresence patterns",
        arguments: [
            OptimizeFlagsTestCase(
                "devicePasscode only",
                input: [.devicePasscode],
                expected: [.devicePasscode]
            ),
            OptimizeFlagsTestCase(
                "biometryAny only",
                input: [.biometryAny],
                expected: [.biometryAny]
            ),
            OptimizeFlagsTestCase(
                "devicePasscode and biometryAny without or",
                input: [.devicePasscode, .biometryAny, .and],
                expected: [.devicePasscode, .biometryAny, .and]
            ),
            OptimizeFlagsTestCase(
                "devicePasscode or biometryCurrentSet",
                input: [.or, .devicePasscode, .biometryCurrentSet],
                expected: [.or, .devicePasscode, .biometryCurrentSet]
            ),
            OptimizeFlagsTestCase(
                "devicePasscode with or but no biometry",
                input: [.or, .devicePasscode],
                expected: [.or, .devicePasscode]
            ),
            OptimizeFlagsTestCase(
                "biometryAny with or but no devicePasscode",
                input: [.or, .biometryAny],
                expected: [.or, .biometryAny]
            ),
            OptimizeFlagsTestCase(
                "empty flags",
                input: [],
                expected: []
            ),
        ]
    )
    func optimizeFlagsDoesNotModifyNonUserPresencePatterns(testCase: OptimizeFlagsTestCase) {
        let optimized = Keychain.AccessControl.optimizeFlags(testCase.input())
        #expect(optimized == testCase.expected)
    }
}

// MARK: - Test Cases

extension AccessControlTests {
    struct OptimizeFlagsTestCase: Sendable {
        let name: String
        let input: @Sendable () -> SecAccessControlCreateFlags
        let expected: SecAccessControlCreateFlags

        init(
            _ name: String,
            input: @Sendable @escaping @autoclosure () -> SecAccessControlCreateFlags,
            expected: SecAccessControlCreateFlags
        ) {
            self.name = name
            self.input = input
            self.expected = expected
        }
    }
}
