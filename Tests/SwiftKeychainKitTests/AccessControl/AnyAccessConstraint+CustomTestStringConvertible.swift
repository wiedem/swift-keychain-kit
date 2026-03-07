@testable public import SwiftKeychainKit
public import Testing
private import Security

extension Keychain.AnyAccessConstraint: CustomTestStringConvertible {
    private static let flagNames: KeyValuePairs<SecAccessControlCreateFlags, String> = [
        .or: "or",
        .and: "and",
        .devicePasscode: "devicePasscode",
        .biometryAny: "biometryAny",
        .biometryCurrentSet: "biometryCurrentSet",
        .applicationPassword: "applicationPassword",
        .userPresence: "userPresence",
        .privateKeyUsage: "privateKeyUsage",
        AccessControlTests.companionFlag: "companion",
    ]

    public var testDescription: String {
        let flags = secAccessControlCreateFlags
        let names = Self.flagNames.filter { flags.contains($0.key) }.map(\.value)
        return names.isEmpty ? "(none)" : names.joined(separator: ", ")
    }
}
