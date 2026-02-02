internal import Foundation
private import Security

public extension Keychain.SecureEnclaveKeys {
    enum ItemAccessibility: Equatable, Sendable {
        /// The data in the Keychain item can be accessed only while the device is unlocked.
        ///
        /// This is recommended for items that need to be accessible only while the application is in the foreground. Items with
        /// this attribute do not migrate to a new device.
        case whenUnlockedThisDeviceOnly

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

extension Keychain.SecureEnclaveKeys.ItemAccessibility: Keychain.KeychainValueConvertible {
    var keychainValue: CFString {
        switch self {
        case .whenUnlockedThisDeviceOnly:
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlockThisDeviceOnly:
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly:
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }

    init?(keychainValue: CFString) {
        switch keychainValue {
        case kSecAttrAccessibleWhenUnlockedThisDeviceOnly:
            self = .whenUnlockedThisDeviceOnly
        case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
            self = .afterFirstUnlockThisDeviceOnly
        case kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly:
            self = .whenPasscodeSetThisDeviceOnly
        default:
            return nil
        }
    }
}
