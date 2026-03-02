# ``SwiftKeychainKit/KeychainError/multipleItemsFound``


## Overview

The ``multipleItemsFound`` error is thrown when a query unexpectedly returns more than one matching item, indicating that the query parameters are not specific enough to uniquely identify a single entry.

This error is specifically used by convenience methods like ``Keychain/InternetPassword/queryOne(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)`` that expect to return at most one result.

## When This Error Occurs

### Internet Password Queries

Internet passwords can have multiple entries with the same account and server but different optional attributes:

```swift
// Store two passwords for the same account and server
let httpPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "httpSecret")
let httpsPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "httpsSecret")

try await Keychain.InternetPassword.add(
    httpPassword,
    account: "user@example.com",
    server: "example.com",
    protocol: .http,
    port: 80
)

try await Keychain.InternetPassword.add(
    httpsPassword,
    account: "user@example.com",
    server: "example.com",
    protocol: .https,
    port: 443
)

// This will throw multipleItemsFound
do {
    let password = try await Keychain.InternetPassword.queryOne(
        account: "user@example.com",
        server: "example.com"
    )
} catch KeychainError.multipleItemsFound {
    print("Multiple passwords exist for this account and server")
}
```

## How to Resolve

### Option 1: Make Your Query More Specific

Add additional parameters to narrow down the results:

```swift
// Specify the protocol to get the HTTPS password
let password = try await Keychain.InternetPassword.queryOne(
    account: "user@example.com",
    server: "example.com",
    protocol: .specific(.https)
)
```

### Option 2: Use the Full Query Method

If you need to handle multiple results, use the full `query()` method instead:

```swift
let passwords = try await Keychain.InternetPassword.query(
    account: .specific("user@example.com"),
    server: .specific("example.com"),
    limit: .unlimited
)

// Handle all matching passwords
for password in passwords {
    // Process each password
}
```

### Option 3: Review Your Data Model

Consider whether having multiple entries with the same account and server is intentional. If not, you may need to:

1. Delete duplicate entries
2. Consolidate credentials
3. Use more specific identifiers when storing passwords

## Why This Error Exists

The ``multipleItemsFound`` error helps prevent subtle bugs by making you aware when your query matches multiple items. Without this error, convenience methods would silently return an arbitrary result, which could lead to:

- Using the wrong password or credential
- Unpredictable behavior when entries are added or removed
- Difficult-to-debug issues in production

## Methods That Can Throw This Error

- ``Keychain/InternetPassword/queryOne(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)``

## Methods That Never Throw This Error

- ``Keychain/GenericPassword/get(account:service:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)-1w6be`` - Guaranteed unique by primary key
- ``Keychain/GenericPassword/get(account:service:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)-p27p`` - Guaranteed unique by primary key

## See Also

- ``Keychain/InternetPassword/query(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``
