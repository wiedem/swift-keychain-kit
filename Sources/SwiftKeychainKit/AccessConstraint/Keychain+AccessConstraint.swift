public extension Keychain {
    /// Namespace for type-safe access control constraints.
    ///
    /// Access constraints define authentication requirements for Keychain items. This type-safe system prevents invalid
    /// constraint combinations at compile time.
    ///
    /// ## Base Constraints
    ///
    /// Five base constraints are available as static properties:
    /// - ``devicePasscode`` - Requires device passcode
    /// - ``biometryAny`` - Requires biometry (Touch ID/Face ID) with any enrolled biometric data
    /// - ``biometryCurrentSet`` - Requires biometry with currently enrolled biometric data
    /// - ``applicationPassword`` - Requires application-specific password (AND-only, adds additional protection)
    /// - ``companion`` - Requires a companion device
    ///
    /// ## Combining Constraints
    ///
    /// Constraints can be combined using `&` (AND) and `|` (OR) operators. Only specific combinations are valid - invalid
    /// combinations are prevented at compile time through the type system.
    ///
    /// - SeeAlso: [SecAccessControlCreateFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)
    enum AccessConstraint: Sendable {
        /// Device passcode constraint.
        ///
        /// Requires the device passcode for access.
        ///
        /// - SeeAlso: [kSecAccessControlDevicePasscode](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-devicepasscode)
        public static var devicePasscode: DevicePasscode {
            .init()
        }

        /// Biometry constraint for any enrolled biometric data.
        ///
        /// Requires Touch ID or Face ID authentication. Access remains possible even if biometric data is added or removed after
        /// item creation.
        ///
        /// - SeeAlso: [kSecAccessControlBiometryAny](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-biometryany)
        public static var biometryAny: BiometryAny {
            .init()
        }

        /// Biometry constraint for currently enrolled biometric data.
        ///
        /// Requires Touch ID or Face ID authentication. The item becomes inaccessible if biometric data is added or removed after
        /// item creation.
        ///
        /// - SeeAlso: [kSecAccessControlBiometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-biometrycurrentset)
        public static var biometryCurrentSet: BiometryCurrentSet {
            .init()
        }

        /// Application password constraint.
        ///
        /// Requires an application-specific password that is prompted interactively when accessing the item. The password is
        /// separate from the device passcode.
        ///
        /// ## Important
        ///
        /// Application password can **only** be combined using AND (`&`), never OR (`|`). This ensures it always acts as
        /// **additional required protection** on top of other constraints, rather than an alternative authentication method.
        ///
        /// - SeeAlso: [kSecAccessControlApplicationPassword](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-applicationpassword)
        public static var applicationPassword: ApplicationPassword {
            .init()
        }

        /// Companion device constraint.
        ///
        /// Requires a companion device (Apple Watch or companion device) for access.
        ///
        /// - SeeAlso: [kSecAccessControlCompanion](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)
        public static var companion: Companion {
            .init()
        }
    }
}

public extension Keychain.AccessConstraint {
    /// Protocol for types that can be used as access constraints.
    ///
    /// All constraint types (base constraints and combinations) conform to this protocol.
    ///
    /// - Important: This protocol is public to enable constraint combination syntax, but is not
    ///   intended for implementation by types outside of SwiftKeychainKit. Only the library's
    ///   built-in constraint types should conform to this protocol.
    protocol Constrainable: Sendable  {}
}
