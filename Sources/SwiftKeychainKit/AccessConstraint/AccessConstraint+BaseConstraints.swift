// MARK: - DevicePasscode

public extension Keychain.AccessConstraint {
    /// Device passcode constraint.
    ///
    /// Requires authentication with the device passcode. This constraint can be combined with other constraints using `&` (AND)
    /// or `|` (OR) operators.
    ///
    /// ## Valid Combinations
    ///
    /// ### OR
    ///
    /// - `devicePasscode | biometryAny`
    /// - `devicePasscode | biometryCurrentSet`
    ///
    /// ### AND
    ///
    /// - `devicePasscode & biometryAny`
    /// - `devicePasscode & biometryCurrentSet`
    /// - `devicePasscode & applicationPassword`
    ///
    /// - SeeAlso: [kSecAccessControlDevicePasscode](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-devicepasscode)
    struct DevicePasscode: Constrainable, CompanionOrable, CompanionAndable {}
}

// MARK: - BiometryAny

public extension Keychain.AccessConstraint {
    /// Biometry constraint for any enrolled biometric data.
    ///
    /// Requires Touch ID or Face ID authentication. Access remains possible even if biometric data (fingerprints or face) is
    /// added or removed after item creation.
    ///
    /// ## Valid Combinations
    ///
    /// ### OR
    ///
    /// - `devicePasscode | biometryAny`
    ///
    /// ### AND
    ///
    /// - `devicePasscode & biometryAny`
    /// - `applicationPassword & biometryAny`
    ///
    /// ## Important
    ///
    /// Cannot be combined with ``BiometryCurrentSet`` - use either one or the other.
    ///
    /// - SeeAlso: [kSecAccessControlBiometryAny](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-biometryany)
    struct BiometryAny: Constrainable, DevicePasscodeOrable, DevicePasscodeAndable, ApplicationPasswordAndable, CompanionOrable, CompanionAndable {}
}

// MARK: - BiometryCurrentSet

public extension Keychain.AccessConstraint {
    /// Biometry constraint for currently enrolled biometric data.
    ///
    /// Requires Touch ID or Face ID authentication. The item becomes inaccessible if biometric data (fingerprints or face) is
    /// added or removed after item creation.
    ///
    /// Use this constraint for high-security items where you want to ensure that only the current biometric configuration can
    /// access the item.
    ///
    /// ## Valid Combinations
    ///
    /// ### OR
    ///
    /// - `devicePasscode | biometryCurrentSet`
    ///
    /// ### AND
    ///
    /// - `devicePasscode & biometryCurrentSet`
    /// - `applicationPassword & biometryCurrentSet`
    ///
    /// ## Important
    ///
    /// Cannot be combined with ``BiometryAny`` - use either one or the other.
    ///
    /// - SeeAlso: [kSecAccessControlBiometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-biometrycurrentset)
    struct BiometryCurrentSet: Constrainable, DevicePasscodeOrable, DevicePasscodeAndable, ApplicationPasswordAndable, CompanionOrable, CompanionAndable {}
}

// MARK: - ApplicationPassword

public extension Keychain.AccessConstraint {
    /// Application password constraint.
    ///
    /// Requires an application-specific password that is prompted interactively when accessing the item. The password is
    /// separate from the device passcode and is set using
    /// [LAContext.setCredential(_:type:)](https://developer.apple.com/documentation/localauthentication/lacontext/setcredential(_:type:)).
    ///
    /// ## Valid Combinations
    ///
    /// ### AND
    ///
    /// - `devicePasscode & applicationPassword`
    /// - `applicationPassword & biometryAny`
    /// - `applicationPassword & biometryCurrentSet`
    ///
    /// ## Important
    ///
    /// Application password can **never** be used with OR logic - it only supports AND combinations.
    ///
    /// - SeeAlso: [kSecAccessControlApplicationPassword](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-applicationpassword)
    struct ApplicationPassword: Constrainable, DevicePasscodeAndable, CompanionAndable {}
}

// MARK: - Companion

public extension Keychain.AccessConstraint {
    /// Companion device constraint.
    ///
    /// Requires a companion device (Apple Watch or companion device) for access.
    ///
    /// ## Valid Combinations
    ///
    /// ### OR
    ///
    /// - `devicePasscode | companion`
    /// - `biometryAny | companion`
    /// - `biometryCurrentSet | companion`
    ///
    /// ### AND
    ///
    /// - `devicePasscode & companion`
    /// - `biometryAny & companion`
    /// - `biometryCurrentSet & companion`
    /// - `applicationPassword & companion`
    ///
    /// - SeeAlso: [kSecAccessControlCompanion](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)
    struct Companion: Constrainable {}
}
