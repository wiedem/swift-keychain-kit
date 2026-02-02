
// MARK: - UserPresence

public extension Keychain.AccessConstraint {
    /// User presence constraint (device passcode OR biometry).
    ///
    /// This constraint represents the most common access control pattern: requiring **either** the device passcode **or** any
    /// enrolled biometric authentication (Touch ID or Face ID).
    ///
    /// This constraint is optimized to use the Security framework's `.userPresence` flag directly, which is semantically
    /// equivalent to `devicePasscode | biometryAny`.
    ///
    /// Use this constraint when you want to protect a Keychain item but allow the user flexibility in how they authenticate -
    /// either with their passcode or biometry. This is the recommended default for most user-facing authentication scenarios.
    ///
    /// - SeeAlso: [kSecAccessControlUserPresence](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-userpresence)
    static var userPresence: some Constrainable {
        Keychain.AccessConstraint.devicePasscode | Keychain.AccessConstraint.biometryAny
    }
}

public extension Keychain.AccessConstraint {
    /// Type-erased constraint for constraint literal syntax.
    ///
    /// This type enables the use of constraint literals (like `.devicePasscode`, `.biometryAny`) in API parameters that accept
    /// `some Constrainable`. It serves as a generic placeholder that all constraint types can be converted to.
    ///
    /// You typically don't use this type directly - it's used internally to enable constraint literal syntax in method
    /// parameters.
    struct ConstraintLiteral: Keychain.AccessConstraint.Constrainable {}
}

/// Convenience extension for constraint literals.
///
/// This extension enables the use of constraint literals (like `.devicePasscode`, `.biometryAny`) in API parameters that
/// accept `some Constrainable`. It provides static properties for all base constraints and the `userPresence` convenience
/// constraint.
public extension Keychain.AccessConstraint.Constrainable where Self == Keychain.AccessConstraint.ConstraintLiteral {
    /// Device passcode constraint literal.
    ///
    /// - SeeAlso: ``Keychain/AccessConstraint/DevicePasscode``
    static var devicePasscode: Keychain.AccessConstraint.DevicePasscode {
        Keychain.AccessConstraint.devicePasscode
    }

    /// Biometry constraint for any enrolled biometric data literal.
    ///
    /// - SeeAlso: ``Keychain/AccessConstraint/BiometryAny``
    static var biometryAny: Keychain.AccessConstraint.BiometryAny {
        Keychain.AccessConstraint.biometryAny
    }

    /// Biometry constraint for currently enrolled biometric data literal.
    ///
    /// - SeeAlso: ``Keychain/AccessConstraint/BiometryCurrentSet``
    static var biometryCurrentSet: Keychain.AccessConstraint.BiometryCurrentSet {
        Keychain.AccessConstraint.biometryCurrentSet
    }

    /// Application password constraint literal.
    ///
    /// - SeeAlso: ``Keychain/AccessConstraint/ApplicationPassword``
    static var applicationPassword: Keychain.AccessConstraint.ApplicationPassword {
        Keychain.AccessConstraint.applicationPassword
    }

    /// Companion device constraint literal.
    ///
    /// - SeeAlso: ``Keychain/AccessConstraint/Companion``
    static var companion: Keychain.AccessConstraint.Companion {
        Keychain.AccessConstraint.companion
    }

    /// User presence constraint literal (device passcode OR biometry).
    ///
    /// - SeeAlso: ``Keychain/AccessConstraint/userPresence``
    static var userPresence: some Keychain.AccessConstraint.Constrainable {
        Keychain.AccessConstraint.userPresence
    }
}
