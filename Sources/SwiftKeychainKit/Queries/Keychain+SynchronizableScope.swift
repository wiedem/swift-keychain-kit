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
