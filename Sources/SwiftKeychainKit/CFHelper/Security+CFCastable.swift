internal import Security

extension SecIdentity: CFCastable {
    static let cfTypeID = SecIdentityGetTypeID()
}

extension SecCertificate: CFCastable {
    static let cfTypeID = SecCertificateGetTypeID()
}

extension SecKey: CFCastable {
    static let cfTypeID = SecKeyGetTypeID()
}

extension SecAccessControl: CFCastable {
    static let cfTypeID = SecAccessControlGetTypeID()
}
