public import Foundation

public extension Keychain {
    /// A query scope for filtering by account name.
    typealias AccountScope = QueryScope<String, ItemAttributes.Account>
    /// A query scope for filtering by application label.
    typealias ApplicationLabelScope = QueryScope<Data, ItemAttributes.ApplicationLabel>
    /// A query scope for filtering by application tag.
    typealias ApplicationTagScope = QueryScope<Data, ItemAttributes.ApplicationTag>
    /// A query scope for filtering by certificate type.
    ///
    /// The value denotes the certificate type as defined by `CSSM_CERT_TYPE` in `cssmtype.h`
    /// (macOS only). Use `.any` to match any certificate type.
    ///
    /// - SeeAlso: [kSecAttrCertificateType](https://developer.apple.com/documentation/security/ksecattrcertificatetype)
    typealias CertificateTypeScope = QueryScope<Int, ItemAttributes.CertificateType>
    /// A query scope for filtering by certificate issuer.
    typealias IssuerScope = QueryScope<Data, ItemAttributes.Issuer>
    /// A query scope for filtering by key size in bits.
    typealias KeySizeInBitsScope = QueryScope<Int, ItemAttributes.KeySizeInBits>
    /// A query scope for filtering by label.
    typealias LabelScope = QueryScope<String, ItemAttributes.Label>
    /// A query scope for filtering by path.
    typealias PathScope = QueryScope<String, ItemAttributes.Path>
    /// A query scope for filtering by port number.
    typealias PortScope = QueryScope<Int, ItemAttributes.Port>
    /// A query scope for filtering by public key hash.
    typealias PublicKeyHashScope = QueryScope<Data, ItemAttributes.PublicKeyHash>
    /// A query scope for filtering by security domain.
    typealias SecurityDomainScope = QueryScope<String, ItemAttributes.SecurityDomain>
    /// A query scope for filtering by serial number.
    typealias SerialNumberScope = QueryScope<Data, ItemAttributes.SerialNumber>
    /// A query scope for filtering by server name.
    typealias ServerScope = QueryScope<String, ItemAttributes.Server>
    /// A query scope for filtering by service name.
    typealias ServiceScope = QueryScope<String, ItemAttributes.Service>
    /// A query scope for filtering by certificate subject.
    typealias SubjectScope = QueryScope<Data, ItemAttributes.Subject>
    /// A query scope for filtering by subject key identifier.
    typealias SubjectKeyIDScope = QueryScope<Data, ItemAttributes.SubjectKeyID>

    /// A query scope for filtering by authentication type.
    typealias AuthenticationTypeScope = QueryScope<InternetPassword.AuthenticationType, ItemAttributes.AuthenticationType>
    /// A query scope for filtering by network protocol.
    typealias ProtocolScope = QueryScope<InternetPassword.NetworkProtocol, ItemAttributes.NetworkProtocol>
}
