
// MARK: - Marker Protocols for Constraint Combinability

public extension Keychain.AccessConstraint {
    /// Marker protocol for constraints that can be combined with device passcode using OR logic.
    ///
    /// Only biometry constraints conform to this protocol, allowing combinations like:
    /// - `devicePasscode | biometryAny`
    /// - `devicePasscode | biometryCurrentSet`
    ///
    /// The type system prevents invalid OR combinations at compile time.
    protocol DevicePasscodeOrable: Constrainable {}

    /// Marker protocol for constraints that can be combined with device passcode using AND logic.
    ///
    /// Multiple constraint types conform to this protocol, allowing combinations like:
    /// - `devicePasscode & biometryAny`
    /// - `devicePasscode & biometryCurrentSet`
    /// - `devicePasscode & applicationPassword`
    ///
    /// The type system prevents invalid AND combinations at compile time.
    protocol DevicePasscodeAndable: Constrainable {}

    /// Marker protocol for constraints that can be combined with application password using AND logic.
    ///
    /// Biometry constraints conform to this protocol, allowing combinations like:
    /// - `applicationPassword & biometryAny`
    /// - `applicationPassword & biometryCurrentSet`
    ///
    /// Application password can never be used with OR logic - it only supports AND combinations. The type system enforces this
    /// at compile time.
    protocol ApplicationPasswordAndable: Constrainable {}

    /// Marker protocol for constraints that can be combined with companion using OR logic.
    ///
    /// This allows OR-only extensions for constraints that are already OR combinations, without permitting mixed AND/OR
    /// compositions.
    protocol CompanionOrable: Constrainable {}

    /// Marker protocol for constraints that can be combined with companion using AND logic.
    ///
    /// This allows AND-only extensions for constraints that are already AND combinations, without permitting mixed AND/OR
    /// compositions.
    protocol CompanionAndable: Constrainable {}
}
