internal import Foundation
internal import LocalAuthentication
private import Security

extension Keychain.Identities {
    static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassIdentity,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    static func applyAddParameters(
        identity: SecIdentity,
        label: String?,
        accessGroup: String?,
        synchronizable: Bool,
        accessControl: Keychain.AccessControl,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        query[kSecValueRef as String] = identity

        Keychain.ItemAttributes.Label.apply(label, to: &query)
        Keychain.ItemAttributes.AccessGroup.apply(accessGroup, to: &query)
        Keychain.ItemAttributes.Synchronizable.apply(synchronizable, to: &query)

        try accessControl.apply(to: &query)

        authenticationContext.apply(to: &query)
    }

    static func applyQueryParameters(
        certificateType: Int?,
        subject: Data?,
        issuer: Data?,
        serialNumber: Data?,
        subjectKeyID: Data?,
        publicKeyHash: Data?,
        label: String?,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        skipItemsIfUIRequired: Bool,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        Keychain.ItemAttributes.CertificateType.apply(certificateType, to: &query)
        Keychain.ItemAttributes.Subject.apply(subject, to: &query)
        Keychain.ItemAttributes.Issuer.apply(issuer, to: &query)
        Keychain.ItemAttributes.SerialNumber.apply(serialNumber, to: &query)
        Keychain.ItemAttributes.SubjectKeyID.apply(subjectKeyID, to: &query)
        Keychain.ItemAttributes.PublicKeyHash.apply(publicKeyHash, to: &query)
        Keychain.ItemAttributes.Label.apply(label, to: &query)

        try accessGroupScope.apply(to: &query)
        synchronizableScope.apply(to: &query)

        if skipItemsIfUIRequired {
            Keychain.ItemAttributes.AuthenticationUI.applySkipUI(to: &query)
        }

        authenticationContext.apply(to: &query)
    }

    static func applyDeleteParameters(
        issuer: Data?,
        serialNumber: Data?,
        label: String?,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        Keychain.ItemAttributes.Issuer.apply(issuer, to: &query)
        Keychain.ItemAttributes.SerialNumber.apply(serialNumber, to: &query)
        Keychain.ItemAttributes.Label.apply(label, to: &query)

        try accessGroupScope.apply(to: &query)
        synchronizableScope.apply(to: &query)
        authenticationContext.apply(to: &query)
    }

    static func applyAttributesParameters(
        certificateTypeScope: Keychain.CertificateTypeScope,
        subjectScope: Keychain.SubjectScope,
        issuerScope: Keychain.IssuerScope,
        serialNumberScope: Keychain.SerialNumberScope,
        subjectKeyIDScope: Keychain.SubjectKeyIDScope,
        publicKeyHashScope: Keychain.PublicKeyHashScope,
        labelScope: Keychain.LabelScope,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        skipItemsIfUIRequired: Bool,
        authenticationContext: LAContext?,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        certificateTypeScope.apply(to: &query)
        subjectScope.apply(to: &query)
        issuerScope.apply(to: &query)
        serialNumberScope.apply(to: &query)
        subjectKeyIDScope.apply(to: &query)
        publicKeyHashScope.apply(to: &query)
        labelScope.apply(to: &query)

        try accessGroupScope.apply(to: &query)
        synchronizableScope.apply(to: &query)

        if skipItemsIfUIRequired {
            Keychain.ItemAttributes.AuthenticationUI.applySkipUI(to: &query)
        }

        authenticationContext.apply(to: &query)
    }
}
