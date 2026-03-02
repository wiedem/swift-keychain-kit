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

    // MARK: - makeSecAccessControl Tests

    @Test("makeSecAccessControl without constraints")
    func makeSecAccessControlWithoutConstraints() throws {
        let accessControl = Keychain.AccessControl.afterFirstUnlock
        let result = try accessControl.makeSecAccessControl()

        let expected = try #require(SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlock, [], nil
        ))
        #expect(result == expected)
    }

    @Test("makeSecAccessControl with constraint")
    func makeSecAccessControlWithConstraint() throws {
        let accessControl = Keychain.AccessControl.make(
            accessibility: .whenUnlockedThisDeviceOnly,
            constraint: Keychain.AccessConstraint.devicePasscode
        )
        let result = try accessControl.makeSecAccessControl()

        let expected = try #require(SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .devicePasscode, nil
        ))
        #expect(result == expected)
    }

    @Test(
        "makeSecAccessControl for all accessibility levels without constraints",
        arguments: [
            (Keychain.ItemAccessibility.whenUnlocked, kSecAttrAccessibleWhenUnlocked as String),
            (.afterFirstUnlock, kSecAttrAccessibleAfterFirstUnlock as String),
            (.whenUnlockedThisDeviceOnly, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String),
            (.afterFirstUnlockThisDeviceOnly, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String),
            (.whenPasscodeSetThisDeviceOnly, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String),
        ]
    )
    func makeSecAccessControlForAllAccessibilityLevels(
        accessibility: Keychain.ItemAccessibility,
        protection: String
    ) throws {
        let accessControl = Keychain.AccessControl.make(accessibility: accessibility)
        let result = try accessControl.makeSecAccessControl()

        let expected = SecAccessControlCreateWithFlags(
            nil, protection as CFString, [], nil
        )!
        #expect(result == expected)
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
