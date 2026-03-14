# ``Keychain/InternetPassword``


## Overview

Internet passwords store network credentials in the Keychain for accessing remote services. Use this entry type when working with:
- Web server credentials (HTTP/HTTPS)
- FTP server access
- Email server passwords (SMTP, IMAP, POP3)
- Other network protocols

Unlike ``GenericPassword``, internet passwords include additional network-specific attributes like server, protocol, port, and authentication type. These attributes help identify credentials for specific network services and ensure your app retrieves the correct password for a given server and protocol combination.

## Adding Internet Passwords

Store a user's credentials for a web service:

```swift
let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "SecureP@ssw0rd")

try await Keychain.InternetPassword.add(
    password,
    account: "user@example.com",
    server: "api.example.com",
    protocol: .https,
    authenticationType: .httpBasic,
    port: 443
)
```

## Retrieving Internet Passwords

### Retrieving a Single Password

Use ``queryOne(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)`` for convenient single-password retrieval:

```swift
// Retrieve password for account and server
if let password = try await Keychain.InternetPassword.queryOne(
    account: "user@example.com",
    server: "api.example.com"
) {
    let string = password.makeUnsafeUTF8String()
}
```

> Note: ``SecretData/makeUnsafeUTF8String()`` creates an unprotected `String` copy that remains in memory. For security-sensitive scenarios, prefer ``SecretData/withUnsafeBytes(_:)-1qbde`` to work with the data directly.

Narrow the query with additional parameters when multiple passwords exist:

```swift
// Specify protocol and port to disambiguate
let httpsPassword = try await Keychain.InternetPassword.queryOne(
    account: "user@example.com",
    server: "api.example.com",
    protocol: .specific(.https),
    port: 443
)
```

> Important: ``queryOne(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)`` throws ``SwiftKeychainKit/KeychainError/multipleItemsFound`` if multiple passwords match your criteria. See ``SwiftKeychainKit/KeychainError/multipleItemsFound`` for resolution strategies.

### Querying Multiple Passwords

Use ``query(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)`` when you need to handle multiple results:

```swift
let passwords = try await Keychain.InternetPassword.query(
    account: .any,
    server: "api.example.com",
    skipItemsIfUIRequired: true,
    limit: .unlimited
)

for password in passwords {
    let string = password.makeUnsafeUTF8String()
}
```

> Important: Querying multiple passwords may trigger an authentication prompt for each individual item that has access constraints. Use `skipItemsIfUIRequired` to silently skip those items instead.

## Updating Internet Passwords

Update a password for a specific server:

```swift
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "NewSecureP@ssw0rd")

try await Keychain.InternetPassword.updateMatching(
    account: "user@example.com",
    server: "api.example.com",
    to: newPassword
)
```

> Important: `updateMatching` updates **all** passwords matching the given criteria. Optional scope parameters like `protocol` and `port` default to `.any`, so multiple items may be affected if they share the same account and server. Narrow the scope with additional parameters to target a specific entry.

## Deleting Internet Passwords

Remove a specific password:

```swift
// Deletes all passwords matching the criteria
try await Keychain.InternetPassword.delete(
    account: "user@example.com",
    server: "api.example.com",
    accessGroup: .any
)
```

## Querying Attributes

Get metadata about stored passwords and obtain item references for subsequent operations:

```swift
let attributes = try await Keychain.InternetPassword.queryAttributes(
    server: "api.example.com",
    limit: .unlimited
)

for attr in attributes {
    print("Account: \(attr.account), Server: \(attr.server)")

    // Use the item reference to retrieve the password
    let password = try await Keychain.InternetPassword.get(
        itemReference: attr.itemReference
    )
}
```

## Primary Key

Internet passwords are uniquely identified by a combination of attributes:
- **account**: The account name (username)
- **server**: The server name or domain
- **protocol**: The network protocol (optional)
- **authenticationType**: The authentication type (optional)
- **port**: The port number (optional)
- **path**: The path on the server (optional)
- **securityDomain**: The security domain/HTTP realm (optional)

The minimum required attributes to uniquely identify an entry are `account` and `server`. The optional attributes further disambiguate entries when multiple credentials exist for the same account and server combination (e.g., different ports or protocols).

## Topics

### Adding Items

- ``add(_:account:server:protocol:authenticationType:port:path:securityDomain:label:accessGroup:synchronizable:accessControl:authenticationContext:)``

### Retrieving Items

- ``get(itemReference:skipIfUIRequired:authenticationContext:)``

### Querying Items

- ``queryOne(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)``
- ``query(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``

### Updating Items

- ``updateMatching(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:to:authenticationContext:)``
- ``update(itemReference:to:authenticationContext:)-20gtt``

### Deleting Items

- ``delete(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:authenticationContext:)-9sxri``
- ``delete(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:authenticationContext:)-70gwe``
- ``delete(itemReference:authenticationContext:)-15n8h``
- ``delete(itemReference:authenticationContext:)-uh0a``

### Attributes

- ``Attributes``
- ``attributes(itemReference:skipIfUIRequired:authenticationContext:)``
- ``queryAttributes(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``

### Network Types

- ``NetworkProtocol``
- ``AuthenticationType``

## See Also

- ``Keychain/GenericPassword``
- ``Keychain/QueryScope``
- ``SwiftKeychainKit/KeychainError``
- [kSecClassInternetPassword](https://developer.apple.com/documentation/security/ksecclassinternetpassword)
