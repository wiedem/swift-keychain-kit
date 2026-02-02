@testable import SwiftKeychainKit
import Foundation
import Security
import Testing

@Suite("Access Constraint Tests")
struct AccessConstraintTests {
    // MARK: - Base Constraints

    @Test(
        "Base constraint returns correct flags",
        arguments: [
            ConstraintsTestCase(
                "devicePasscode",
                Keychain.AccessConstraint.devicePasscode,
                expectedFlags: [.devicePasscode]
            ),
            ConstraintsTestCase(
                "biometryAny",
                Keychain.AccessConstraint.biometryAny,
                expectedFlags: [.biometryAny]
            ),
            ConstraintsTestCase(
                "biometryCurrentSet",
                Keychain.AccessConstraint.biometryCurrentSet,
                expectedFlags: [.biometryCurrentSet]
            ),
            ConstraintsTestCase(
                "applicationPassword",
                Keychain.AccessConstraint.applicationPassword,
                expectedFlags: [.applicationPassword]
            ),
            ConstraintsTestCase(
                "companion",
                Keychain.AccessConstraint.companion,
                expectedFlags: Self.companionExpectedFlags
            )
        ]
    )
    func baseConstraintFlags(testCase: ConstraintsTestCase) {
        #expect(testCase.createFlags() == testCase.expected)
    }

    // MARK: - Convenience Aliases

    @Test("Convenience userPresence constraint returns correct flags")
    func convenienceConstraintFlags() throws {
        let constraint = Keychain.AccessConstraint.userPresence

        let flags = try #require(
            (constraint as? any Keychain.AccessConstraint.SecAccessControlFlagsCreating)?.secAccessControlCreateFlags
        )
        #expect(flags == [.devicePasscode, .biometryAny, .or])
    }

    @Test("DevicePasscode OR biometryAny expands to individual flags")
    func devicePasscodeOrBiometryAnyExpandsToIndividualFlags() throws {
        let constraint = Keychain.AccessConstraint.devicePasscode | .biometryAny
        // Explicit combination uses individual flags
        #expect(constraint.secAccessControlCreateFlags == [.devicePasscode, .biometryAny, .or])
    }

    // MARK: - OR Combinations

    @Test(
        "OR combination returns correct flags",
        arguments: [
            ConstraintsTestCase(
                "devicePasscode | biometryAny",
                Keychain.AccessConstraint.devicePasscode | .biometryAny,
                expectedFlags: [.devicePasscode, .biometryAny, .or]
            ),
            ConstraintsTestCase(
                "devicePasscode | biometryCurrentSet",
                Keychain.AccessConstraint.devicePasscode | .biometryCurrentSet,
                expectedFlags: [.devicePasscode, .biometryCurrentSet, .or]
            ),
            ConstraintsTestCase(
                "devicePasscode | companion",
                Keychain.AccessConstraint.devicePasscode | Keychain.AccessConstraint.companion,
                expectedFlags: Self.companionExpectedFlags.union([.devicePasscode, .or])
            ),
            ConstraintsTestCase(
                "companion | devicePasscode (commutative)",
                Keychain.AccessConstraint.companion | .devicePasscode,
                expectedFlags: Self.companionExpectedFlags.union([.devicePasscode, .or])
            ),
            ConstraintsTestCase(
                "biometryAny | companion",
                Keychain.AccessConstraint.biometryAny | Keychain.AccessConstraint.companion,
                expectedFlags: Self.companionExpectedFlags.union([.biometryAny, .or])
            ),
            ConstraintsTestCase(
                "(devicePasscode | biometryAny) | companion",
                (Keychain.AccessConstraint.devicePasscode | .biometryAny) | Keychain.AccessConstraint.companion,
                expectedFlags: Self.companionExpectedFlags.union([.devicePasscode, .biometryAny, .or])
            ),
        ]
    )
    func orCombinationFlags(testCase: ConstraintsTestCase) {
        #expect(testCase.createFlags() == testCase.expected)
    }

    // MARK: - AND Combinations (Two-way)

    @Test(
        "AND combination returns correct flags",
        arguments: [
            // Device Passcode AND combinations
            ConstraintsTestCase(
                "devicePasscode & biometryAny",
                Keychain.AccessConstraint.devicePasscode & .biometryAny,
                expectedFlags: [.devicePasscode, .biometryAny, .and]
            ),
            ConstraintsTestCase(
                "devicePasscode & biometryCurrentSet",
                Keychain.AccessConstraint.devicePasscode & .biometryCurrentSet,
                expectedFlags: [.devicePasscode, .biometryCurrentSet, .and]
            ),
            ConstraintsTestCase(
                "devicePasscode & applicationPassword",
                Keychain.AccessConstraint.devicePasscode & .applicationPassword,
                expectedFlags: [.devicePasscode, .applicationPassword, .and]
            ),
            // Application Password AND combinations
            ConstraintsTestCase(
                "applicationPassword & biometryAny",
                Keychain.AccessConstraint.applicationPassword & .biometryAny,
                expectedFlags: [.applicationPassword, .biometryAny, .and]
            ),
            ConstraintsTestCase(
                "applicationPassword & biometryCurrentSet",
                Keychain.AccessConstraint.applicationPassword & .biometryCurrentSet,
                expectedFlags: [.applicationPassword, .biometryCurrentSet, .and]
            ),
            ConstraintsTestCase(
                "applicationPassword & companion",
                Keychain.AccessConstraint.applicationPassword & Keychain.AccessConstraint.companion,
                expectedFlags: Self.companionExpectedFlags.union([.applicationPassword, .and])
            ),
            ConstraintsTestCase(
                "companion & devicePasscode",
                Keychain.AccessConstraint.companion & .devicePasscode,
                expectedFlags: Self.companionExpectedFlags.union([.devicePasscode, .and])
            ),
            ConstraintsTestCase(
                "(devicePasscode & biometryAny) & companion",
                (Keychain.AccessConstraint.devicePasscode & .biometryAny) & Keychain.AccessConstraint.companion,
                expectedFlags: Self.companionExpectedFlags.union([.devicePasscode, .biometryAny, .and])
            ),
        ]
    )
    func andCombinationFlags(testCase: ConstraintsTestCase) {
        #expect(testCase.createFlags() == testCase.expected)
    }

    // MARK: - Three-way AND Combinations

    @Test(
        "Three-way AND combination returns correct flags",
        arguments: [
            ConstraintsTestCase(
                "(devicePasscode & applicationPassword) & biometryAny",
                (Keychain.AccessConstraint.devicePasscode & Keychain.AccessConstraint.applicationPassword) & .biometryAny,
                expectedFlags: [.devicePasscode, .applicationPassword, .biometryAny, .and]
            ),
            ConstraintsTestCase(
                "(devicePasscode & applicationPassword) & biometryCurrentSet",
                (Keychain.AccessConstraint.devicePasscode & Keychain.AccessConstraint.applicationPassword) & .biometryCurrentSet,
                expectedFlags: [.devicePasscode, .applicationPassword, .biometryCurrentSet, .and]
            ),
        ]
    )
    func threeWayAndCombinationFlags(testCase: ConstraintsTestCase) {
        #expect(testCase.createFlags() == testCase.expected)
    }

    // MARK: - Four-way AND Combinations

    @Test(
        "Four-way AND combination returns correct flags",
        arguments: [
            ConstraintsTestCase(
                "devicePasscode & applicationPassword & biometryAny & companion",
                (Keychain.AccessConstraint.devicePasscode & Keychain.AccessConstraint.applicationPassword) & .biometryAny & Keychain.AccessConstraint.companion,
                expectedFlags: Self.companionExpectedFlags.union([.devicePasscode, .applicationPassword, .biometryAny, .and])
            ),
        ]
    )
    func fourWayAndCombinationFlags(testCase: ConstraintsTestCase) {
        #expect(testCase.createFlags() == testCase.expected)
    }
}

extension AccessConstraintTests {
    // MARK: - Test Data Structures

    static var companionExpectedFlags: SecAccessControlCreateFlags {
        if #available(iOS 18.0, macOS 15.0, *) {
            return [.companion]
        }
        return SecAccessControlCreateFlags(rawValue: 1 << 5)
    }

    struct ConstraintsTestCase: Sendable {
        let name: String
        let createFlags: @Sendable () -> SecAccessControlCreateFlags
        let expected: SecAccessControlCreateFlags

        init(
            _ name: String,
            _ constraints: @Sendable @escaping @autoclosure () -> some (Keychain.AccessConstraint.Constrainable & Keychain.AccessConstraint.SecAccessControlFlagsCreating),
            expectedFlags: SecAccessControlCreateFlags
        ) {
            self.name = name
            createFlags = { constraints().secAccessControlCreateFlags }
            self.expected = expectedFlags
        }
    }
}
