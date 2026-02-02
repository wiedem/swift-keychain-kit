// MARK: - DevicePasscodeAnd

public extension Keychain.AccessConstraint {
    /// Device passcode AND constraint combination.
    ///
    /// Represents a constraint that requires **both** the device passcode **and** another constraint to be satisfied for
    /// access.
    ///
    /// ## Valid Combinations
    ///
    /// - `devicePasscode & biometryAny`
    /// - `devicePasscode & biometryCurrentSet`
    /// - `devicePasscode & applicationPassword`
    /// - `devicePasscode & companion`
    ///
    /// Created using the `&` operator between device passcode and a conforming constraint.
    ///
    /// This type can be further combined with application password or companion to create three-way combinations.
    ///
    /// - SeeAlso: [kSecAccessControlAnd](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-and)
    struct DevicePasscodeAnd<AndConstraint: DevicePasscodeAndable>: Constrainable, ApplicationPasswordAndable, CompanionAndable {
        let devicePasscode: DevicePasscode
        let andConstraint: AndConstraint

        init(
            _ devicePasscode: DevicePasscode,
            _ andConstraint: AndConstraint
        ) {
            self.devicePasscode = devicePasscode
            self.andConstraint = andConstraint
        }
    }
}

// MARK: - ApplicationPasswordAnd

public extension Keychain.AccessConstraint {
    /// Application password AND constraint combination.
    ///
    /// Represents a constraint that requires **both** the application password **and** another constraint to be satisfied for
    /// access.
    ///
    /// ## Valid Combinations
    ///
    /// - `applicationPassword & biometryAny`
    /// - `applicationPassword & biometryCurrentSet`
    /// - `applicationPassword & companion`
    ///
    /// Created using the `&` operator between application password and a conforming constraint.
    ///
    /// This type can be further combined with device passcode or companion to create three-way combinations.
    ///
    /// ## Important
    ///
    /// Application password can **never** be used with OR logic - it only supports AND combinations.
    ///
    /// - SeeAlso: [kSecAccessControlAnd](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-and)
    struct ApplicationPasswordAnd<AndConstraint: ApplicationPasswordAndable>: Constrainable, DevicePasscodeAndable, CompanionAndable {
        let applicationPassword: ApplicationPassword
        let andConstraint: AndConstraint

        init(
            _ applicationPassword: ApplicationPassword,
            _ andConstraint: AndConstraint
        ) {
            self.applicationPassword = applicationPassword
            self.andConstraint = andConstraint
        }
    }
}

// MARK: - CompanionAnd

public extension Keychain.AccessConstraint {
    /// Companion AND constraint combination.
    ///
    /// Represents a constraint that requires **both** the companion device **and** another constraint to be satisfied for
    /// access.
    ///
    /// ## Valid Combinations
    ///
    /// - `devicePasscode & companion`
    /// - `biometryAny & companion`
    /// - `biometryCurrentSet & companion`
    /// - `applicationPassword & companion`
    /// - `(devicePasscode & biometryAny) & companion`
    /// - `(devicePasscode & applicationPassword) & companion`
    ///
    /// Created using the `&` operator between companion and a conforming constraint.
    ///
    /// - SeeAlso: [kSecAccessControlAnd](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-and)
    struct CompanionAnd<AndConstraint: CompanionAndable>: Constrainable, DevicePasscodeAndable, ApplicationPasswordAndable {
        let companion: Companion
        let andConstraint: AndConstraint

        init(
            _ companion: Companion,
            _ andConstraint: AndConstraint
        ) {
            self.companion = companion
            self.andConstraint = andConstraint
        }
    }
}
