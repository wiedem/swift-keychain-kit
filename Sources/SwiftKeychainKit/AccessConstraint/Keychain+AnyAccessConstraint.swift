internal import Security

public extension Keychain {
    /// A type-erased access constraint.
    ///
    /// Use `AnyAccessConstraint` to store heterogeneous access constraints in collections or when the concrete constraint type
    /// does not need to be preserved.
    ///
    /// You can create an `AnyAccessConstraint` directly or by calling ``AccessConstraint/Constrainable/eraseToAny()`` on any
    /// constraint:
    ///
    /// ```swift
    /// let constraints: [Keychain.AnyAccessConstraint] = [
    ///     (Keychain.AccessConstraint.devicePasscode | .biometryAny).eraseToAny(),
    ///     (Keychain.AccessConstraint.devicePasscode & .applicationPassword).eraseToAny(),
    /// ]
    /// ```
    struct AnyAccessConstraint: AccessConstraint.Constrainable {
        private let _secAccessControlCreateFlags: SecAccessControlCreateFlags

        /// Creates a type-erased access constraint from the specified constraint.
        ///
        /// - Parameter constraint: The constraint to type-erase.
        public init(_ constraint: some AccessConstraint.Constrainable) {
            switch constraint {
            case let flagsCreator as any AccessConstraint.SecAccessControlFlagsCreating:
                _secAccessControlCreateFlags = flagsCreator.secAccessControlCreateFlags
            default:
                assertionFailure("Constrainable of type \(type(of: constraint)) is not SecAccessControlFlagsCreating")
                _secAccessControlCreateFlags = []
            }
        }
    }
}

extension Keychain.AnyAccessConstraint: Keychain.AccessConstraint.SecAccessControlFlagsCreating {
    var secAccessControlCreateFlags: SecAccessControlCreateFlags {
        _secAccessControlCreateFlags
    }
}

public extension Keychain.AccessConstraint.Constrainable {
    /// Returns a type-erased version of this access constraint.
    ///
    /// Use this method to store heterogeneous access constraints in collections.
    ///
    /// - Returns: An ``Keychain/AnyAccessConstraint`` wrapping this constraint.
    func eraseToAny() -> Keychain.AnyAccessConstraint {
        Keychain.AnyAccessConstraint(self)
    }
}
