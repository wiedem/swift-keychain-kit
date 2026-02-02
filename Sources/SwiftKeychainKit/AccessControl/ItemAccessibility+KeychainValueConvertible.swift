internal import Foundation
internal import Security

extension Keychain.ItemAccessibility: Keychain.KeychainValueConvertible {
    var keychainValue: CFString {
        switch self {
        case .whenUnlocked:
            kSecAttrAccessibleWhenUnlocked
        case .whenUnlockedThisDeviceOnly:
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlock:
            kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly:
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly:
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }

    init?(keychainValue: CFString) {
        switch keychainValue {
        case kSecAttrAccessibleWhenUnlocked:
            self = .whenUnlocked
        case kSecAttrAccessibleWhenUnlockedThisDeviceOnly:
            self = .whenUnlockedThisDeviceOnly
        case kSecAttrAccessibleAfterFirstUnlock:
            self = .afterFirstUnlock
        case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
            self = .afterFirstUnlockThisDeviceOnly
        case kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly:
            self = .whenPasscodeSetThisDeviceOnly
        default:
            return nil
        }
    }
}
