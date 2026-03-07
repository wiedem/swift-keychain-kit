private import Foundation
internal import Security

extension Keychain.AccessControl {
    static func optimizeFlags(_ flags: SecAccessControlCreateFlags) -> SecAccessControlCreateFlags {
        assert(!flags.contains([.or, .and]), "Flags must not contain both .or and .and")

        let userPresencePattern: SecAccessControlCreateFlags = [.or, .devicePasscode, .biometryAny]

        // Check if flags contain the userPresence pattern
        guard flags.contains(userPresencePattern) else {
            return flags
        }

        // Only optimize if the pattern is exactly [.or, .devicePasscode, .biometryAny] with no other flags.
        // userPresence can only be combined with .applicationPassword and .privateKeyUsage.
        // The expanded form remains combinable with additional flags, .userPresence does not.
        guard flags == userPresencePattern else {
            return flags
        }

        return [.userPresence]
    }
}

extension Keychain.AccessControl {
    static func makeSecAccessControl(
        protection: CFTypeRef,
        secAccessControlCreateFlags: SecAccessControlCreateFlags
    ) throws(KeychainError) -> SecAccessControl {
        let secAccessControlCreateFlags = optimizeFlags(secAccessControlCreateFlags)

        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            protection,
            secAccessControlCreateFlags,
            &error
        ) else {
            if let cfError = error?.takeRetainedValue() {
                throw KeychainError.accessControlError(cfError as any Error as NSError)
            }
            throw KeychainError.invalidParameters
        }
        return accessControl
    }
}
