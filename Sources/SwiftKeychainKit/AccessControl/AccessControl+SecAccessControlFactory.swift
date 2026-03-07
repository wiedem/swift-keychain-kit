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

        // Remove the constraint components, keep .or for now
        var optimized = flags.subtracting([.devicePasscode, .biometryAny])

        // Remove .or only if it is the sole remaining flag
        if optimized == [.or] {
            optimized = []
        }

        // Insert the optimized .userPresence flag
        optimized.insert(.userPresence)

        return optimized
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
