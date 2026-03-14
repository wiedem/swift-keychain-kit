public extension Keychain {
    /// The synchronization scope for query, delete, and update operations.
    ///
    /// Use `.synchronized` to match only iCloud Keychain items, `.notSynchronized` to match only local items, or `.any` to
    /// match both.
    enum SynchronizableScope: Equatable, Sendable {
        /// Match only synchronized items.
        case synchronized

        /// Match only non-synchronized items.
        case notSynchronized

        /// Match both synchronized and non-synchronized items.
        case any
    }
}

extension Keychain.SynchronizableScope: ExpressibleByBooleanLiteral {
    /// Creates a synchronization scope from a Boolean literal.
    ///
    /// `true` maps to ``synchronized``, `false` maps to ``notSynchronized``.
    public init(booleanLiteral value: Bool) {
        self = value ? .synchronized : .notSynchronized
    }
}
