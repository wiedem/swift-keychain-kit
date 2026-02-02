// MARK: - DevicePasscodeApplicationPasswordAnd

public extension Keychain.AccessConstraint {
    /// Three-way device passcode, application password, and biometry AND constraint combination.
    ///
    /// Represents a constraint that requires **all three** of the following to be satisfied:
    /// - Device passcode
    /// - Application password
    /// - Biometry (Touch ID or Face ID)
    ///
    /// ## Valid Combinations
    ///
    /// - `devicePasscode & applicationPassword & biometryAny`
    /// - `devicePasscode & applicationPassword & biometryCurrentSet`
    ///
    /// Created by combining a two-way AND constraint with a third constraint using the `&` operator. The combination is
    /// commutative - it works in any order.
    ///
    /// This provides the highest level of security by requiring three different authentication factors.
    ///
    /// - SeeAlso: [kSecAccessControlAnd](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/1392879-and)
    struct DevicePasscodeApplicationPasswordAnd<AndConstraint: ApplicationPasswordAndable>: Constrainable, CompanionAndable {
        let devicePasscode: DevicePasscode
        let applicationPassword: ApplicationPassword
        let andConstraint: AndConstraint

        init(
            _ devicePasscodeAndAppPassword: DevicePasscodeAnd<ApplicationPassword>,
            _ andConstraint: AndConstraint
        ) {
            devicePasscode = devicePasscodeAndAppPassword.devicePasscode
            applicationPassword = devicePasscodeAndAppPassword.andConstraint
            self.andConstraint = andConstraint
        }

        init(
            _ appPasswordAndBiometry: ApplicationPasswordAnd<AndConstraint>,
            _ devicePasscode: DevicePasscode
        ) {
            self.devicePasscode = devicePasscode
            applicationPassword = appPasswordAndBiometry.applicationPassword
            andConstraint = appPasswordAndBiometry.andConstraint
        }
    }
}
