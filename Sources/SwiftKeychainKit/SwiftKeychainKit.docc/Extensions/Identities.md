# ``Keychain/Identities``


## Overview

The Identities API provides secure storage and retrieval of digital identities in the Keychain. An identity combines a private key with its associated certificate, creating a complete credential for:
- Client authentication (mutual TLS)
- Code signing
- Email signing and encryption (S/MIME)
- Document signing

Identities represent the combination of a ``Keys`` entry (private key) and a ``Certificates`` entry (certificate) that share the same public key. Use identities when you need both the certificate and private key together for authentication or signing operations.

## Adding Identities

Create an identity from a PKCS#12 file:

```swift
// Load PKCS#12 data
let p12Data = try Data(contentsOf: p12URL)
let password = "password123"

// Import identity from PKCS#12
var items: CFArray?
let importOptions: [String: Any] = [
    kSecImportExportPassphrase as String: password
]
let status = SecPKCS12Import(p12Data as CFData, importOptions as CFDictionary, &items)

guard status == errSecSuccess,
      let itemsArray = items as? [[String: Any]],
      let firstItem = itemsArray.first,
      let identity = firstItem[kSecImportItemIdentity as String] as! SecIdentity? else {
    throw IdentityError.importFailed
}

// Store in Keychain
try await Keychain.Identities.add(
    identity,
    label: "Client Authentication"
)
```

Create an identity from separate certificate and key:

```swift
// This requires that both the certificate and private key are already in the Keychain
// The system automatically creates the identity when both are present

// First add the private key
try await Keychain.Keys.addPrivateKey(
    privateKey,
    applicationTag: "com.example.myapp.client-key".data(using: .utf8)!
)

// Then add the certificate (which references the same public key)
try await Keychain.Certificates.add(certificate)

// Now you can retrieve the identity
let identity = try await Keychain.Identities.queryOne(
    label: "My Identity"
)
```

## Retrieving Identities

Query a single identity by label:

```swift
if let identity = try await Keychain.Identities.queryOne(
    label: "Client Authentication"
) {
    // Use the identity for TLS authentication
    let urlCredential = URLCredential(identity: identity, certificates: nil, persistence: .none)
}
```

Query by issuer and serial number:

```swift
let issuerData = // ... normalized issuer sequence
let serialData = // ... serial number data

let identities = try await Keychain.Identities.query(
    issuer: .specific(issuerData),
    serialNumber: .specific(serialData),
    limit: .unlimited
)
if let identity = identities.first {
    // Found the specific identity
}
```

Query all identities:

```swift
let allIdentities = try await Keychain.Identities.query(
    skipItemsIfUIRequired: true,
    limit: .unlimited
)
```

> Important: Querying multiple identities may trigger an authentication prompt for each individual item that has access constraints. Use `skipItemsIfUIRequired` to silently skip those items instead.

## Working with Identity Components

Extract the certificate and private key from an identity:

```swift
if let identity = try await Keychain.Identities.queryOne(
    label: "My Identity"
) {
    // Extract certificate
    var certificate: SecCertificate?
    SecIdentityCopyCertificate(identity, &certificate)

    // Extract private key
    var privateKey: SecKey?
    SecIdentityCopyPrivateKey(identity, &privateKey)
}
```

## Querying Identity Attributes

The ``Attributes`` struct includes attributes from both the certificate and the key portion of the identity.

```swift
let attributes = try await Keychain.Identities.queryAttributes(
    label: "Client Authentication"
)

if let attr = attributes.first {
    print("Label: \(attr.label ?? "No label")")
    print("Issuer: \(attr.issuer.base64EncodedString())")

    // Use the item reference for subsequent operations
    let identity = try await Keychain.Identities.get(
        itemReference: attr.itemReference
    )
}
```

## Deleting Identities

Remove identities by label:

```swift
// Deletes all identities matching the criteria
try await Keychain.Identities.delete(
    label: "Client Authentication"
)
```

> Important: Labels are not unique identifiers. Multiple identities may share the same label. Narrow the scope with additional parameters like `issuer` and `serialNumber` to target specific identities.

## Primary Key

Identities are uniquely identified by the same attributes as their associated certificate:
- **issuer**: The certificate issuer (normalized issuer sequence)
- **serialNumber**: The certificate serial number

These attributes come from the certificate portion of the identity. When you add an identity to the Keychain, both the certificate and private key are stored, and the identity provides a unified reference to both.

## Identity vs. Separate Certificate and Key

You can work with certificates and keys separately using ``Certificates`` and ``Keys``, or as a unified identity:

**Use Identities when:**
- You need both certificate and key together for authentication
- Working with client authentication (mutual TLS)
- Performing operations that require a complete credential

**Use separate Certificate and Key when:**
- You only need the certificate (e.g., for verification)
- You only need the key (e.g., for encryption/decryption)
- Managing certificates and keys independently

## Topics

### Adding Identities

- ``add(_:label:accessGroup:synchronizable:accessControl:authenticationContext:)``

### Retrieving Identities by Reference

- ``get(itemReference:skipIfUIRequired:authenticationContext:)-81a2j``

### Querying Identities

- ``query(certificateType:subject:issuer:serialNumber:subjectKeyID:publicKeyHash:label:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``
- ``queryOne(label:certificateType:subject:issuer:serialNumber:subjectKeyID:publicKeyHash:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)``

### Deleting Identities

- ``delete(issuer:serialNumber:label:accessGroup:synchronizable:authenticationContext:)-63i1r``
- ``delete(issuer:serialNumber:label:accessGroup:synchronizable:authenticationContext:)-7zfgg``
- ``delete(itemReference:authenticationContext:)-9f5q2``
- ``delete(itemReference:authenticationContext:)-7v1oe``

### Attributes

- ``Attributes``
- ``attributes(itemReference:skipIfUIRequired:authenticationContext:)``
- ``queryAttributes(certificateType:subject:issuer:serialNumber:subjectKeyID:publicKeyHash:label:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``

### Labels

- ``DefaultableLabel``

## See Also

- ``Keychain/Keys``
- ``Keychain/Certificates``
- ``Keychain/QueryScope``
- [kSecClassIdentity](https://developer.apple.com/documentation/security/ksecclassidentity)
- [SecIdentity](https://developer.apple.com/documentation/security/secidentity)
