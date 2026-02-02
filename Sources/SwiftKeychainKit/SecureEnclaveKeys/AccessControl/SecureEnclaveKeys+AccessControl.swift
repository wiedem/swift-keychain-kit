private import Security

public extension Keychain.SecureEnclaveKeys {
    struct AccessControl: Sendable {
        /// The accessibility level for the item.
        public let accessibility: ItemAccessibility

        private let secAccessControlCreateFlags: (@Sendable () -> SecAccessControlCreateFlags)?
    }
}

private extension Keychain.SecureEnclaveKeys.AccessControl {
    init(accessibility: Keychain.SecureEnclaveKeys.ItemAccessibility) {
        self.accessibility = accessibility
        secAccessControlCreateFlags = nil
    }

    init(
        accessibility: Keychain.SecureEnclaveKeys.ItemAccessibility,
        constraint: some Keychain.AccessConstraint.Constrainable
    ) {
        self.accessibility = accessibility

        switch constraint {
        case let secAccessControlFlagsCreating as any Keychain.AccessConstraint.SecAccessControlFlagsCreating:
            secAccessControlCreateFlags = { secAccessControlFlagsCreating.secAccessControlCreateFlags }
        default:
            assertionFailure("Constrainable of type \(type(of: constraint)) is not SecAccessControlFlagsCreating")
            secAccessControlCreateFlags = nil
        }
    }
}

public extension Keychain.SecureEnclaveKeys.AccessControl {
    static func make(accessibility: Keychain.SecureEnclaveKeys.ItemAccessibility) -> Self {
        .init(accessibility: accessibility)
    }

    static func make(
        accessibility: Keychain.SecureEnclaveKeys.ItemAccessibility,
        constraint: some Keychain.AccessConstraint.Constrainable
    ) -> Self {
        .init(
            accessibility: accessibility,
            constraint: constraint
        )
    }
}

extension Keychain.SecureEnclaveKeys.AccessControl {
    func apply(to query: inout [String: Any]) throws(KeychainError) {
        var secAccessControlCreateFlags = secAccessControlCreateFlags?() ?? []
        secAccessControlCreateFlags = Keychain.AccessControl.optimizeFlags(secAccessControlCreateFlags)

        // Implicitly set .privateKeyUsage for Secure Enclave keys.
        secAccessControlCreateFlags.insert(.privateKeyUsage)

        let secAccessControl = try Keychain.AccessControl.makeSecAccessControl(
            protection: accessibility.keychainValue,
            secAccessControlCreateFlags: secAccessControlCreateFlags
        )
        query[kSecAttrAccessControl as String] = secAccessControl
    }
}

// MARK: - Static Constants

public extension Keychain.SecureEnclaveKeys.AccessControl {
    /// Item is accessible when unlocked, not synced to other devices.
    static let whenUnlockedThisDeviceOnly = make(
        accessibility: .whenUnlockedThisDeviceOnly
    )

    /// Item is accessible after first unlock, not synced to other devices.
    ///
    /// This is the recommended default for most use cases.
    static let afterFirstUnlockThisDeviceOnly = make(
        accessibility: .afterFirstUnlockThisDeviceOnly
    )

    /// Item is accessible only when a passcode is set, not synced to other devices.
    static let whenPasscodeSetThisDeviceOnly = make(
        accessibility: .whenPasscodeSetThisDeviceOnly
    )
}
