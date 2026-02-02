// MARK: - DevicePasscodeOr

public extension Keychain.AccessConstraint {
    /// Device passcode OR constraint combination.
    ///
    /// Represents a constraint that requires **either** the device passcode **or** another constraint to be satisfied for
    /// access.
    ///
    /// ## Valid Combinations
    ///
    /// - `devicePasscode | biometryAny`
    /// - `devicePasscode | biometryCurrentSet`
    ///
    /// Created using the `|` operator between device passcode and a conforming constraint.
    ///
    /// - SeeAlso: [kSecAccessControlOr](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-or)
    struct DevicePasscodeOr<OrConstraint: DevicePasscodeOrable>: Constrainable, CompanionOrable {
        let devicePasscode: DevicePasscode
        let orConstraint: OrConstraint

        init(
            _ devicePasscode: DevicePasscode,
            _ orConstraint: OrConstraint
        ) {
            self.devicePasscode = devicePasscode
            self.orConstraint = orConstraint
        }
    }
}

// MARK: - CompanionOr

public extension Keychain.AccessConstraint {
    /// Companion OR constraint combination.
    ///
    /// Represents a constraint that requires **either** the companion device **or** another constraint to be satisfied for
    /// access.
    ///
    /// ## Valid Combinations
    ///
    /// - `devicePasscode | companion`
    /// - `biometryAny | companion`
    /// - `biometryCurrentSet | companion`
    /// - `(devicePasscode | biometryAny) | companion`
    /// - `(devicePasscode | biometryCurrentSet) | companion`
    ///
    /// Created using the `|` operator between companion and a conforming constraint.
    ///
    /// This type can be further combined with device passcode to create three-way OR combinations.
    ///
    /// - SeeAlso: [kSecAccessControlOr](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-or)
    struct CompanionOr<OrConstraint: CompanionOrable>: Constrainable, DevicePasscodeOrable {
        let companion: Companion
        let orConstraint: OrConstraint

        init(
            _ companion: Companion,
            _ orConstraint: OrConstraint
        ) {
            self.companion = companion
            self.orConstraint = orConstraint
        }
    }
}
