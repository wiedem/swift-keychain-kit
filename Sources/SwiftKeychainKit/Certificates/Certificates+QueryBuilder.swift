internal import Foundation
internal import LocalAuthentication
private import Security

extension Keychain.Certificates {
    static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassCertificate,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    static func applyQueryParameters(
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

    static func applyAddParameters(
        certificate: SecCertificate,
        label: Keychain.DefaultableLabel,
        accessGroup: Keychain.AccessGroup,
        synchronizable: Bool,
        to query: inout [String: Any]
    ) {
        query[kSecValueRef as String] = certificate

        Keychain.ItemAttributes.Label.apply(label.value, to: &query)
        Keychain.ItemAttributes.AccessGroup.apply(accessGroup.valueForAdd, to: &query)
        Keychain.ItemAttributes.Synchronizable.apply(synchronizable, to: &query)
    }

    static func applyDeleteParameters(
        issuer: Data?,
        serialNumber: Data?,
        label: String?,
        accessGroupScope: Keychain.AccessGroupScope,
        synchronizableScope: Keychain.SynchronizableScope,
        to query: inout [String: Any]
    ) throws(KeychainError) {
        Keychain.ItemAttributes.Issuer.apply(issuer, to: &query)
        Keychain.ItemAttributes.SerialNumber.apply(serialNumber, to: &query)
        Keychain.ItemAttributes.Label.apply(label, to: &query)

        try accessGroupScope.apply(to: &query)
        synchronizableScope.apply(to: &query)
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
