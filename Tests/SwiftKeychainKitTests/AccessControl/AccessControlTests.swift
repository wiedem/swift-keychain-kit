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
            OptimizeFlagsTestCase(
                "userPresence pattern with companion is not optimized",
                input: Self.companionFlag.union([.or, .devicePasscode, .biometryAny]),
                expected: Self.companionFlag.union([.or, .devicePasscode, .biometryAny])
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

    @Test(
        "makeSecAccessControl succeeds for all valid constraint combinations",
        arguments: validConstraintCombinations
    )
    func makeSecAccessControlForAllValidConstraints(constraint: Keychain.AnyAccessConstraint) throws {
        _ = try Keychain.AccessControl.makeSecAccessControl(
            protection: kSecAttrAccessibleWhenUnlocked,
            secAccessControlCreateFlags: constraint.secAccessControlCreateFlags
        )
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

// MARK: - Test Data

extension AccessControlTests {
    static var companionFlag: SecAccessControlCreateFlags {
        if #available(iOS 18.0, macOS 15.0, *) {
            return [.companion]
        }
        return SecAccessControlCreateFlags(rawValue: 1 << 5)
    }

    // swiftlint:disable:next identifier_name
    private static let AC = (
        devicePasscode: Keychain.AccessConstraint.devicePasscode,
        biometryAny: Keychain.AccessConstraint.biometryAny,
        biometryCurrentSet: Keychain.AccessConstraint.biometryCurrentSet,
        applicationPassword: Keychain.AccessConstraint.applicationPassword,
        companion: Keychain.AccessConstraint.companion
    )

    static let validConstraintCombinations: [Keychain.AnyAccessConstraint] = [
        // Single constraints
        AC.devicePasscode.eraseToAny(),
        AC.biometryAny.eraseToAny(),
        AC.biometryCurrentSet.eraseToAny(),
        AC.applicationPassword.eraseToAny(),
        AC.companion.eraseToAny(),
        Keychain.AccessConstraint.userPresence.eraseToAny(),

        // OR combinations
        (AC.devicePasscode | AC.biometryAny).eraseToAny(),
        (AC.devicePasscode | AC.biometryCurrentSet).eraseToAny(),
        (AC.devicePasscode | AC.companion).eraseToAny(),
        (AC.biometryAny | AC.companion).eraseToAny(),
        (AC.biometryCurrentSet | AC.companion).eraseToAny(),
        ((AC.devicePasscode | AC.biometryAny) | AC.companion).eraseToAny(),
        ((AC.devicePasscode | AC.biometryCurrentSet) | AC.companion).eraseToAny(),

        // AND combinations
        (AC.devicePasscode & AC.biometryAny).eraseToAny(),
        (AC.devicePasscode & AC.biometryCurrentSet).eraseToAny(),
        (AC.devicePasscode & AC.applicationPassword).eraseToAny(),
        (AC.devicePasscode & AC.companion).eraseToAny(),
        (AC.applicationPassword & AC.biometryAny).eraseToAny(),
        (AC.applicationPassword & AC.biometryCurrentSet).eraseToAny(),
        (AC.applicationPassword & AC.companion).eraseToAny(),
        (AC.biometryAny & AC.companion).eraseToAny(),
        (AC.biometryCurrentSet & AC.companion).eraseToAny(),

        // Three-way AND combinations
        ((AC.devicePasscode & AC.applicationPassword) & AC.biometryAny).eraseToAny(),
        ((AC.devicePasscode & AC.applicationPassword) & AC.biometryCurrentSet).eraseToAny(),
        ((AC.devicePasscode & AC.biometryAny) & AC.companion).eraseToAny(),
        ((AC.devicePasscode & AC.biometryCurrentSet) & AC.companion).eraseToAny(),
        ((AC.devicePasscode & AC.applicationPassword) & AC.companion).eraseToAny(),
        ((AC.applicationPassword & AC.biometryAny) & AC.companion).eraseToAny(),
        ((AC.applicationPassword & AC.biometryCurrentSet) & AC.companion).eraseToAny(),

        // Four-way AND combinations
        (((AC.devicePasscode & AC.applicationPassword) & AC.biometryAny) & AC.companion).eraseToAny(),
        (((AC.devicePasscode & AC.applicationPassword) & AC.biometryCurrentSet) & AC.companion).eraseToAny(),
    ]
}

// MARK: - Test Cases

extension AccessControlTests {
    struct OptimizeFlagsTestCase: Sendable, CustomTestStringConvertible {
        let name: String
        let input: @Sendable () -> SecAccessControlCreateFlags
        let expected: SecAccessControlCreateFlags
        var testDescription: String {
            name
        }

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
