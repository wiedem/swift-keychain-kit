
// MARK: - OR Operator (|)

/// Combines device passcode with another constraint using OR logic.
///
/// Creates a constraint that requires **either** the device passcode **or** the other constraint to be satisfied for
/// access.
///
/// ## Valid Combinations
///
/// - `devicePasscode | biometryAny`
/// - `devicePasscode | biometryCurrentSet`
///
/// The combination is commutative - both orders produce the same result.
///
/// - Parameters:
///   - lhs: The device passcode constraint.
///   - rhs: The constraint to combine with device passcode.
/// - Returns: A combined OR constraint.
public func | <Constraint: Keychain.AccessConstraint.DevicePasscodeOrable>(
    lhs: Keychain.AccessConstraint.DevicePasscode,
    rhs: Constraint
) -> Keychain.AccessConstraint.DevicePasscodeOr<Constraint> {
    .init(lhs, rhs)
}

/// Combines device passcode with another constraint using OR logic (commutative variant).
///
/// Creates a constraint that requires **either** the device passcode **or** the other constraint to be satisfied for
/// access.
///
/// ## Valid Combinations
///
/// - `biometryAny | devicePasscode`
/// - `biometryCurrentSet | devicePasscode`
///
/// The combination is commutative - both orders produce the same result.
///
/// - Parameters:
///   - lhs: The constraint to combine with device passcode.
///   - rhs: The device passcode constraint.
/// - Returns: A combined OR constraint.
public func | <Constraint: Keychain.AccessConstraint.DevicePasscodeOrable>(
    lhs: Constraint,
    rhs: Keychain.AccessConstraint.DevicePasscode
) -> Keychain.AccessConstraint.DevicePasscodeOr<Constraint> {
    .init(rhs, lhs)
}

// MARK: - OR Operator (|) - Companion

/// Combines companion with another constraint using OR logic.
///
/// Creates a constraint that requires **either** the companion device **or** the other constraint to be satisfied for
/// access.
///
/// ## Valid Combinations
///
/// - `companion | devicePasscode`
/// - `companion | biometryAny`
/// - `companion | biometryCurrentSet`
/// - `companion | (devicePasscode | biometryAny)`
///
/// - Parameters:
///   - lhs: The companion constraint.
///   - rhs: The constraint to combine with companion.
/// - Returns: A combined OR constraint.
public func | <Constraint: Keychain.AccessConstraint.CompanionOrable>(
    lhs: Keychain.AccessConstraint.Companion,
    rhs: Constraint
) -> Keychain.AccessConstraint.CompanionOr<Constraint> {
    .init(lhs, rhs)
}

/// Combines companion with another constraint using OR logic (commutative variant).
///
/// Creates a constraint that requires **either** the companion device **or** the other constraint to be satisfied for
/// access.
///
/// ## Valid Combinations
///
/// - `devicePasscode | companion`
/// - `biometryAny | companion`
/// - `biometryCurrentSet | companion`
/// - `(devicePasscode | biometryAny) | companion`
///
/// - Parameters:
///   - lhs: The constraint to combine with companion.
///   - rhs: The companion constraint.
/// - Returns: A combined OR constraint.
public func | <Constraint: Keychain.AccessConstraint.CompanionOrable>(
    lhs: Constraint,
    rhs: Keychain.AccessConstraint.Companion
) -> Keychain.AccessConstraint.CompanionOr<Constraint> {
    .init(rhs, lhs)
}

// MARK: - AND Operator (&) - Device Passcode

/// Combines device passcode with another constraint using AND logic.
///
/// Creates a constraint that requires **both** the device passcode **and** the other constraint to be satisfied for access.
///
/// ## Valid Combinations
///
/// - `devicePasscode & biometryAny`
/// - `devicePasscode & biometryCurrentSet`
/// - `devicePasscode & applicationPassword`
///
/// The combination is commutative - both orders produce the same result.
///
/// - Parameters:
///   - lhs: The device passcode constraint.
///   - rhs: The constraint to combine with device passcode.
/// - Returns: A combined AND constraint.
public func & <Constraint: Keychain.AccessConstraint.DevicePasscodeAndable>(
    lhs: Keychain.AccessConstraint.DevicePasscode,
    rhs: Constraint
) -> Keychain.AccessConstraint.DevicePasscodeAnd<Constraint> {
    .init(lhs, rhs)
}

/// Combines device passcode with another constraint using AND logic (commutative variant).
///
/// Creates a constraint that requires **both** the device passcode **and** the other constraint to be satisfied for access.
///
/// ## Valid Combinations
///
/// - `biometryAny & devicePasscode`
/// - `biometryCurrentSet & devicePasscode`
/// - `applicationPassword & devicePasscode`
///
/// The combination is commutative - both orders produce the same result.
///
/// - Parameters:
///   - lhs: The constraint to combine with device passcode.
///   - rhs: The device passcode constraint.
/// - Returns: A combined AND constraint.
public func & <Constraint: Keychain.AccessConstraint.DevicePasscodeAndable>(
    lhs: Constraint,
    rhs: Keychain.AccessConstraint.DevicePasscode
) -> Keychain.AccessConstraint.DevicePasscodeAnd<Constraint> {
    .init(rhs, lhs)
}

// MARK: - AND Operator (&) - Companion

/// Combines companion with another constraint using AND logic.
///
/// Creates a constraint that requires **both** the companion device **and** the other constraint to be satisfied for
/// access.
///
/// ## Valid Combinations
///
/// - `companion & devicePasscode`
/// - `companion & biometryAny`
/// - `companion & biometryCurrentSet`
/// - `companion & applicationPassword`
/// - `companion & (devicePasscode & biometryAny)`
///
/// - Parameters:
///   - lhs: The companion constraint.
///   - rhs: The constraint to combine with companion.
/// - Returns: A combined AND constraint.
public func & <Constraint: Keychain.AccessConstraint.CompanionAndable>(
    lhs: Keychain.AccessConstraint.Companion,
    rhs: Constraint
) -> Keychain.AccessConstraint.CompanionAnd<Constraint> {
    .init(lhs, rhs)
}

/// Combines companion with another constraint using AND logic (commutative variant).
///
/// Creates a constraint that requires **both** the companion device **and** the other constraint to be satisfied for
/// access.
///
/// ## Valid Combinations
///
/// - `devicePasscode & companion`
/// - `biometryAny & companion`
/// - `biometryCurrentSet & companion`
/// - `applicationPassword & companion`
/// - `(devicePasscode & biometryAny) & companion`
///
/// - Parameters:
///   - lhs: The constraint to combine with companion.
///   - rhs: The companion constraint.
/// - Returns: A combined AND constraint.
public func & <Constraint: Keychain.AccessConstraint.CompanionAndable>(
    lhs: Constraint,
    rhs: Keychain.AccessConstraint.Companion
) -> Keychain.AccessConstraint.CompanionAnd<Constraint> {
    .init(rhs, lhs)
}

// MARK: - AND Operator (&) - Application Password

/// Combines application password with another constraint using AND logic.
///
/// Creates a constraint that requires **both** the application password **and** the other constraint to be satisfied for
/// access.
///
/// ## Valid Combinations
///
/// - `applicationPassword & biometryAny`
/// - `applicationPassword & biometryCurrentSet`
///
/// The combination is commutative - both orders produce the same result.
///
/// - Parameters:
///   - lhs: The application password constraint.
///   - rhs: The constraint to combine with application password.
/// - Returns: A combined AND constraint.
public func & <Constraint: Keychain.AccessConstraint.ApplicationPasswordAndable>(
    lhs: Keychain.AccessConstraint.ApplicationPassword,
    rhs: Constraint
) -> Keychain.AccessConstraint.ApplicationPasswordAnd<Constraint> {
    .init(lhs, rhs)
}

/// Combines application password with another constraint using AND logic (commutative variant).
///
/// Creates a constraint that requires **both** the application password **and** the other constraint to be satisfied for
/// access.
///
/// ## Valid Combinations
///
/// - `biometryAny & applicationPassword`
/// - `biometryCurrentSet & applicationPassword`
///
/// The combination is commutative - both orders produce the same result.
///
/// - Parameters:
///   - lhs: The constraint to combine with application password.
///   - rhs: The application password constraint.
/// - Returns: A combined AND constraint.
public func & <Constraint: Keychain.AccessConstraint.ApplicationPasswordAndable>(
    lhs: Constraint,
    rhs: Keychain.AccessConstraint.ApplicationPassword
) -> Keychain.AccessConstraint.ApplicationPasswordAnd<Constraint> {
    .init(rhs, lhs)
}

// MARK: - AND Operator (&) - Three-way Combinations

/// Combines a device passcode and application password constraint with a third constraint.
///
/// Creates a three-way constraint that requires **all three** factors to be satisfied:
/// - Device passcode
/// - Application password
/// - Biometry (Touch ID or Face ID)
///
/// ## Valid Combinations
///
/// - `(devicePasscode & applicationPassword) & biometryAny`
/// - `(devicePasscode & applicationPassword) & biometryCurrentSet`
///
/// - Parameters:
///   - lhs: The device passcode and application password constraint.
///   - rhs: The biometry constraint to add.
/// - Returns: A three-way combined AND constraint.
public func & <Constraint: Keychain.AccessConstraint.ApplicationPasswordAndable>(
    lhs: Keychain.AccessConstraint.DevicePasscodeAnd<Keychain.AccessConstraint.ApplicationPassword>,
    rhs: Constraint
) -> Keychain.AccessConstraint.DevicePasscodeApplicationPasswordAnd<Constraint> {
    .init(lhs, rhs)
}

/// Combines a device passcode and application password constraint with a third constraint (commutative variant).
///
/// Creates a three-way constraint that requires **all three** factors to be satisfied:
/// - Device passcode
/// - Application password
/// - Biometry (Touch ID or Face ID)
///
/// ## Valid Combinations
///
/// - `biometryAny & (devicePasscode & applicationPassword)`
/// - `biometryCurrentSet & (devicePasscode & applicationPassword)`
///
/// - Parameters:
///   - lhs: The biometry constraint.
///   - rhs: The device passcode and application password constraint.
/// - Returns: A three-way combined AND constraint.
public func & <Constraint: Keychain.AccessConstraint.ApplicationPasswordAndable>(
    lhs: Constraint,
    rhs: Keychain.AccessConstraint.DevicePasscodeAnd<Keychain.AccessConstraint.ApplicationPassword>
) -> Keychain.AccessConstraint.DevicePasscodeApplicationPasswordAnd<Constraint> {
    .init(rhs, lhs)
}

/// Combines a device passcode with an application password and biometry constraint.
///
/// Creates a three-way constraint that requires **all three** factors to be satisfied:
/// - Device passcode
/// - Application password
/// - Biometry (Touch ID or Face ID)
///
/// ## Valid Combinations
///
/// - `devicePasscode & (applicationPassword & biometryAny)`
/// - `devicePasscode & (applicationPassword & biometryCurrentSet)`
///
/// - Parameters:
///   - lhs: The device passcode constraint.
///   - rhs: The application password and biometry constraint.
/// - Returns: A three-way combined AND constraint.
public func & <Constraint: Keychain.AccessConstraint.ApplicationPasswordAndable>(
    lhs: Keychain.AccessConstraint.DevicePasscode,
    rhs: Keychain.AccessConstraint.ApplicationPasswordAnd<Constraint>
) -> Keychain.AccessConstraint.DevicePasscodeApplicationPasswordAnd<Constraint> {
    .init(rhs, lhs)
}

/// Combines a device passcode with an application password and biometry constraint (commutative variant).
///
/// Creates a three-way constraint that requires **all three** factors to be satisfied:
/// - Device passcode
/// - Application password
/// - Biometry (Touch ID or Face ID)
///
/// ## Valid Combinations
///
/// - `(applicationPassword & biometryAny) & devicePasscode`
/// - `(applicationPassword & biometryCurrentSet) & devicePasscode`
///
/// - Parameters:
///   - lhs: The application password and biometry constraint.
///   - rhs: The device passcode constraint.
/// - Returns: A three-way combined AND constraint.
public func & <Constraint: Keychain.AccessConstraint.ApplicationPasswordAndable>(
    lhs: Keychain.AccessConstraint.ApplicationPasswordAnd<Constraint>,
    rhs: Keychain.AccessConstraint.DevicePasscode
) -> Keychain.AccessConstraint.DevicePasscodeApplicationPasswordAnd<Constraint> {
    .init(lhs, rhs)
}
