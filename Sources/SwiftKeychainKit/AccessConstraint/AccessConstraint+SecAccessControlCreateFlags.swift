internal import Security

extension Keychain.AccessConstraint {
    protocol SecAccessControlFlagsCreating: Sendable {
        var secAccessControlCreateFlags: SecAccessControlCreateFlags { get }
    }
}

extension Keychain.AccessConstraint.DevicePasscode: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        [.devicePasscode]
    }
}

extension Keychain.AccessConstraint.BiometryAny: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    /// The Security framework flags representing this constraint.
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        [.biometryAny]
    }
}

extension Keychain.AccessConstraint.BiometryCurrentSet: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        [.biometryCurrentSet]
    }
}

extension Keychain.AccessConstraint.ApplicationPassword: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        [.applicationPassword]
    }
}

extension Keychain.AccessConstraint.Companion: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        if #available(iOS 18.0, macOS 15.0, *) {
            return [.companion]
        }
        // Legacy name "kSecAccessControlWatch" used on older systems, same bit value.
        return SecAccessControlCreateFlags(rawValue: 1 << 5)
    }
}

extension Keychain.AccessConstraint.DevicePasscodeAnd: Keychain.AccessConstraint.SecAccessControlFlagsCreating where AndConstraint: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        var flags = devicePasscode.secAccessControlCreateFlags.union(andConstraint.secAccessControlCreateFlags)
        flags.insert(.and)
        return flags
    }
}

extension Keychain.AccessConstraint.ApplicationPasswordAnd: Keychain.AccessConstraint.SecAccessControlFlagsCreating where AndConstraint: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        var flags = applicationPassword.secAccessControlCreateFlags.union(andConstraint.secAccessControlCreateFlags)
        flags.insert(.and)
        return flags
    }
}

extension Keychain.AccessConstraint.CompanionAnd: Keychain.AccessConstraint.SecAccessControlFlagsCreating where AndConstraint: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        var flags = companion.secAccessControlCreateFlags.union(andConstraint.secAccessControlCreateFlags)
        flags.insert(.and)
        return flags
    }
}

extension Keychain.AccessConstraint.DevicePasscodeOr: Keychain.AccessConstraint.SecAccessControlFlagsCreating where OrConstraint: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        var flags = devicePasscode.secAccessControlCreateFlags.union(orConstraint.secAccessControlCreateFlags)
        flags.insert(.or)
        return flags
    }
}

extension Keychain.AccessConstraint.CompanionOr: Keychain.AccessConstraint.SecAccessControlFlagsCreating where OrConstraint: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        var flags = companion.secAccessControlCreateFlags.union(orConstraint.secAccessControlCreateFlags)
        flags.insert(.or)
        return flags
    }
}

extension Keychain.AccessConstraint.DevicePasscodeApplicationPasswordAnd: Keychain.AccessConstraint.SecAccessControlFlagsCreating where AndConstraint: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        var flags = devicePasscode.secAccessControlCreateFlags
            .union(applicationPassword.secAccessControlCreateFlags)
            .union(andConstraint.secAccessControlCreateFlags)
        flags.insert(.and)
        return flags
    }
}
