// MARK: - Base Constraints

extension Keychain.AccessConstraint.DevicePasscode: CustomDebugStringConvertible {
    public var debugDescription: String {
        "devicePasscode"
    }
}

extension Keychain.AccessConstraint.BiometryAny: CustomDebugStringConvertible {
    public var debugDescription: String {
        "biometryAny"
    }
}

extension Keychain.AccessConstraint.BiometryCurrentSet: CustomDebugStringConvertible {
    public var debugDescription: String {
        "biometryCurrentSet"
    }
}

extension Keychain.AccessConstraint.ApplicationPassword: CustomDebugStringConvertible {
    public var debugDescription: String {
        "applicationPassword"
    }
}

extension Keychain.AccessConstraint.Companion: CustomDebugStringConvertible {
    public var debugDescription: String {
        "companion"
    }
}

// MARK: - OR Combinations

extension Keychain.AccessConstraint.DevicePasscodeOr: CustomDebugStringConvertible
    where OrConstraint: CustomDebugStringConvertible
{
    public var debugDescription: String {
        "devicePasscode | \(orConstraint)"
    }
}

extension Keychain.AccessConstraint.CompanionOr: CustomDebugStringConvertible
    where OrConstraint: CustomDebugStringConvertible
{
    public var debugDescription: String {
        "\(orConstraint) | companion"
    }
}

// MARK: - AND Combinations

extension Keychain.AccessConstraint.DevicePasscodeAnd: CustomDebugStringConvertible
    where AndConstraint: CustomDebugStringConvertible
{
    public var debugDescription: String {
        "devicePasscode & \(andConstraint)"
    }
}

extension Keychain.AccessConstraint.ApplicationPasswordAnd: CustomDebugStringConvertible
    where AndConstraint: CustomDebugStringConvertible
{
    public var debugDescription: String {
        "applicationPassword & \(andConstraint)"
    }
}

extension Keychain.AccessConstraint.CompanionAnd: CustomDebugStringConvertible
    where AndConstraint: CustomDebugStringConvertible
{
    public var debugDescription: String {
        "\(andConstraint) & companion"
    }
}

// MARK: - Three-Way AND Combinations

extension Keychain.AccessConstraint.DevicePasscodeApplicationPasswordAnd: CustomDebugStringConvertible
    where AndConstraint: CustomDebugStringConvertible
{
    public var debugDescription: String {
        "devicePasscode & applicationPassword & \(andConstraint)"
    }
}
