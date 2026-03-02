# ``Keychain/Certificates``


## Overview

The Certificates API provides secure storage and retrieval of X.509 certificates in the Keychain. Use this entry type to manage:
- SSL/TLS certificates
- Code signing certificates
- Client authentication certificates
- Root and intermediate CA certificates

Certificates are typically used together with ``Keys`` (for private keys) and ``Identities`` (for certificate + private key pairs).

## Adding Certificates

Store a certificate with a custom label:

```swift
let certData = try Data(contentsOf: certificateURL)
guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
    throw CertificateError.invalidData
}

try await Keychain.Certificates.add(
    certificate,
    label: .custom("Root CA")
)
```

## Retrieving Certificates

Query a single certificate by label:

```swift
if let certificate = try await Keychain.Certificates.queryOne(
    label: "Root CA"
) {
    let certData = SecCertificateCopyData(certificate) as Data
}
```

Query by issuer and serial number:

```swift
let issuerData = // ... normalized issuer sequence
let serialData = // ... serial number data

let certificates = try await Keychain.Certificates.query(
    issuer: .specific(issuerData),
    serialNumber: .specific(serialData)
)
if let certificate = certificates.first {
    // Found the specific certificate
}
```

Query all certificates:

```swift
let allCertificates = try await Keychain.Certificates.query(limit: .unlimited)

for certificate in allCertificates {
    let summary = SecCertificateCopySubjectSummary(certificate) as String?
    print("Certificate: \(summary ?? "Unknown")")
}
```

## Querying Certificate Attributes

Get metadata about a certificate:

```swift
let attributes = try await Keychain.Certificates.queryAttributes(
    label: .specific("Root CA")
)

if let attr = attributes.first {
    print("Issuer: \(attr.issuer?.base64EncodedString() ?? "N/A")")
    print("Serial: \(attr.serialNumber?.base64EncodedString() ?? "N/A")")
    print("Subject: \(attr.subject?.base64EncodedString() ?? "N/A")")
}
```

## Deleting Certificates

Remove certificates by label:

```swift
// Deletes all certificates matching the criteria
try await Keychain.Certificates.delete(
    label: .specific("Root CA")
)
```

> Important: Labels are not unique identifiers. Multiple certificates may share the same label. Narrow the scope with additional parameters like `issuer` and `serialNumber` to target specific certificates.

## Primary Key

Certificates are uniquely identified by:
- **issuer**: The certificate issuer (normalized issuer sequence from the certificate)
- **serialNumber**: The certificate serial number

These attributes are automatically derived from the certificate when you add it to the Keychain. The combination of issuer and serial number uniquely identifies a certificate in accordance with X.509 standards.

## Working with Certificate Labels

When adding certificates, you can specify how labels are handled using ``Keychain/DefaultableLabel``:

- `.default`: Let the Keychain automatically derive a label from the certificate's subject
- `.custom("My Label")`: Provide an explicit, user-visible label

Labels are useful for:
- Displaying certificates in a user interface
- Finding certificates by a meaningful name
- Distinguishing between similar certificates

## Topics

### Adding Certificates

- ``Keychain/Certificates/add(_:label:accessGroup:synchronizable:accessControl:authenticationContext:)``

### Retrieving Certificates by Reference

- ``Keychain/Certificates/get(itemReference:skipIfUIRequired:authenticationContext:)-1noyy``

### Querying Certificates

- ``Keychain/Certificates/query(certificateType:subject:issuer:serialNumber:subjectKeyID:publicKeyHash:label:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``
- ``Keychain/Certificates/queryOne(label:certificateType:subject:issuer:serialNumber:subjectKeyID:publicKeyHash:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)``

### Deleting Certificates

- ``Keychain/Certificates/delete(issuer:serialNumber:label:accessGroup:synchronizable:authenticationContext:)-5sspb``
- ``Keychain/Certificates/delete(issuer:serialNumber:label:accessGroup:synchronizable:authenticationContext:)-4hn5k``
- ``Keychain/Certificates/delete(itemReference:authenticationContext:)-35dbf``
- ``Keychain/Certificates/delete(itemReference:authenticationContext:)-574kx``

### Attributes

- ``Keychain/Certificates/Attributes``
- ``Keychain/Certificates/attributes(itemReference:skipIfUIRequired:authenticationContext:)``
- ``Keychain/Certificates/queryAttributes(certificateType:subject:issuer:serialNumber:subjectKeyID:publicKeyHash:label:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``

### Labels

- ``Keychain/DefaultableLabel``

## See Also

- ``Keychain/Keys``
- ``Keychain/Identities``
- ``Keychain/QueryScope``
- [kSecClassCertificate](https://developer.apple.com/documentation/security/ksecclasscertificate)
- [SecCertificate](https://developer.apple.com/documentation/security/seccertificate)
