public extension Keychain {
    /// Specifies when a Keychain item is accessible.
    ///
    /// Determines under what conditions the system permits access to a Keychain item.
    ///
    /// - SeeAlso: [Keychain Item Accessibility](https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values#1679100)
    enum ItemAccessibility: Equatable, Sendable {
        /// The data in the Keychain item can be accessed only while the device is unlocked.
        ///
        /// This is recommended for items that need to be accessible only while the application is in the foreground. Items with
        /// this attribute migrate to a new device when using encrypted backups.
        case whenUnlocked

        /// The data in the Keychain item can be accessed only while the device is unlocked.
        ///
        /// This is recommended for items that need to be accessible only while the application is in the foreground. Items with
        /// this attribute do not migrate to a new device.
        case whenUnlockedThisDeviceOnly

        /// The data in the Keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
        ///
        /// After the first unlock, the data remains accessible until the next restart. This is recommended for items that need to
        /// be accessed by background applications. Items with this attribute migrate to a new device when using encrypted backups.
        case afterFirstUnlock

        /// The data in the Keychain item cannot be accessed after a restart until the device has been unlocked once by the user.
        ///
        /// This is recommended for items that need to be accessible by background applications. Items with this attribute do not
        /// migrate to a new device.
        case afterFirstUnlockThisDeviceOnly

        /// The data in the Keychain item can be accessed only while the device is unlocked.
        ///
        /// A passcode must be set on the device. Items with this attribute are never migrated to a new device. This attribute is
        /// not available on devices without a passcode. If the passcode is removed, the item is deleted.
        case whenPasscodeSetThisDeviceOnly
    }
}
