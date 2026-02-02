private import Security

public extension Keychain {
    /// Controls when and how a Keychain item can be accessed.
    ///
    /// Combines accessibility settings with optional access constraints. Use static constants for common configurations or the
    /// initializer for custom setups.
    ///
    /// Use access control when you need to restrict access to sensitive items beyond basic accessibility, such as requiring
    /// user presence, biometrics, or a device passcode.
    ///
    /// - SeeAlso: [Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
    struct AccessControl: Sendable {
        /// The accessibility level for the item.
        public let accessibility: ItemAccessibility

        private let secAccessControlCreateFlags: (@Sendable () -> SecAccessControlCreateFlags)?

        private init(accessibility: ItemAccessibility) {
            self.accessibility = accessibility
            secAccessControlCreateFlags = nil
        }

        private init(
            accessibility: ItemAccessibility,
            constraint: some AccessConstraint.Constrainable
        ) {
            self.accessibility = accessibility

            // This is just necessary because we don't want to make the SecAccessControlFlagsCreating public
            switch constraint {
            case let secAccessControlFlagsCreating as any AccessConstraint.SecAccessControlFlagsCreating:
                secAccessControlCreateFlags = { secAccessControlFlagsCreating.secAccessControlCreateFlags }
            default:
                assertionFailure("Constrainable of type \(type(of: constraint)) is not SecAccessControlFlagsCreating")
                secAccessControlCreateFlags = nil
            }
        }
    }
}

public extension Keychain.AccessControl {
    /// Creates access control with the specified accessibility.
    ///
    /// Use this when you only need an accessibility level without additional access constraints.
    ///
    /// - Parameter accessibility: The accessibility level for the item.
    /// - Returns: An access control configuration for the item.
    static func make(accessibility: Keychain.ItemAccessibility) -> Self {
        .init(accessibility: accessibility)
    }

    /// Creates access control with the specified accessibility and constraint.
    ///
    /// Use this when you need to require additional access constraints, such as user presence or biometrics.
    ///
    /// - Parameters:
    ///   - accessibility: The accessibility level for the item.
    ///   - constraint: The access constraint to enforce.
    /// - Returns: An access control configuration for the item.
    static func make(
        accessibility: Keychain.ItemAccessibility,
        constraint: some Keychain.AccessConstraint.Constrainable
    ) -> Self {
        .init(
            accessibility: accessibility,
            constraint: constraint
        )
    }
}

extension Keychain.AccessControl {
    func apply(to query: inout [String: Any]) throws(KeychainError) {
        // Check if we need a SecAccessControl instance for the SecAccessControlCreateFlags
        guard let secAccessControlCreateFlags else {
            try Keychain.ItemAttributes.ItemAccessibility.apply(accessibility, to: &query)
            return
        }

        let secAccessControl = try Self.makeSecAccessControl(
            protection: accessibility.keychainValue,
            secAccessControlCreateFlags: secAccessControlCreateFlags()
        )
        query[kSecAttrAccessControl as String] = secAccessControl
    }
}

// MARK: - Static Constants

public extension Keychain.AccessControl {
    /// The data in the Keychain item can be accessed only while the device is unlocked.
    ///
    /// This is recommended for items that need to be accessible only while the application is in the foreground. Items with this
    /// attribute migrate to a new device when using encrypted backups.
    static let whenUnlocked = make(accessibility: .whenUnlocked)

    /// The data in the Keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    ///
    /// After the first unlock, the data remains accessible until the next restart. This is recommended for items that need to
    /// be accessed by background applications. Items with this attribute migrate to a new device when using encrypted backups.
    static let afterFirstUnlock = make(accessibility: .afterFirstUnlock)

    /// The data in the Keychain item can be accessed only while the device is unlocked.
    ///
    /// This is recommended for items that need to be accessible only while the application is in the foreground. Items with
    /// this attribute do not migrate to a new device.
    static let whenUnlockedThisDeviceOnly = make(
        accessibility: .whenUnlockedThisDeviceOnly
    )

    /// The data in the Keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
    ///
    /// This is recommended for items that need to be accessible by background applications. Items with this attribute do not
    /// migrate to a new device.
    static let afterFirstUnlockThisDeviceOnly = make(
        accessibility: .afterFirstUnlockThisDeviceOnly
    )

    /// The data in the Keychain item can be accessed only while the device is unlocked.
    ///
    /// A passcode must be set on the device. Items with this attribute are never migrated to a new device. This attribute is
    /// not available on devices without a passcode. If the passcode is removed, the item is deleted.
    static let whenPasscodeSetThisDeviceOnly = make(
        accessibility: .whenPasscodeSetThisDeviceOnly
    )
}
