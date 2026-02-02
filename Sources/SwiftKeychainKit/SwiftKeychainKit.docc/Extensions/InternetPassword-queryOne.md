# ``Keychain/InternetPassword/queryOne(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)``


## Overview

The `queryOne()` method provides a convenient way to retrieve a single internet password when you know the account and server, but don't need to handle multiple results.

### Uniqueness and Error Handling

Unlike some other keychain methods, ``queryOne(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)`` does not guarantee uniqueness. Multiple internet password entries can share the same account and server while differing in optional attributes like port, protocol, or path.

When multiple entries match your query, ``queryOne(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipIfUIRequired:authenticationContext:)`` throws a ``SwiftKeychainKit/KeychainError/multipleItemsFound`` error to alert you. This helps prevent accidentally using the wrong password in your application.

## Topics

### Basic Usage

```swift
// Query for an HTTPS password
do {
    if let password = try await Keychain.InternetPassword.queryOne(
        account: "user@example.com",
        server: "api.example.com"
    ) {
        let string = password.makeUnsafeUTF8String()
    }
} catch KeychainError.multipleItemsFound {
    // Multiple passwords found - need more specific parameters
    print("Multiple passwords found for this account and server")
}
```

### Handling Multiple Matches

When `multipleItemsFound` is thrown, you have two options:

**Option 1: Add more specific parameters**

```swift
// Narrow the query with additional parameters
let password = try await Keychain.InternetPassword.queryOne(
    account: "user@example.com",
    server: "api.example.com",
    protocol: .specific(.https),  // Specify the protocol
    port: .specific(443)            // Specify the port
)
```

**Option 2: Use the full query method**

```swift
// Use query() to get all matches and handle them yourself
let passwords = try await Keychain.InternetPassword.query(
    account: .specific("user@example.com"),
    server: .specific("api.example.com"),
    limit: .unlimited
)

// Choose the appropriate password based on your logic
for password in passwords {
    let attrs = try await Keychain.InternetPassword.queryAttributes(
        account: .specific("user@example.com"),
        server: .specific("api.example.com")
    )
    // Inspect attributes to find the right one
}
```

### Common Scenarios

#### Web API Credentials

```swift
// Store credentials for different API environments
let productionPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "prod-secret")
let stagingPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "staging-secret")

try await Keychain.InternetPassword.add(
    productionPassword,
    account: "api-key",
    server: "api.example.com",
    port: 443
)

try await Keychain.InternetPassword.add(
    stagingPassword,
    account: "api-key",
    server: "api.example.com",
    port: 8443  // Different port for staging
)

// Query for production credentials
let password = try await Keychain.InternetPassword.queryOne(
    account: "api-key",
    server: "api.example.com",
    port: .specific(443)
)
```

#### HTTP vs HTTPS Credentials

```swift
// Different passwords for HTTP and HTTPS
let httpPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "http-secret")
let httpsPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "https-secret")

try await Keychain.InternetPassword.add(
    httpPassword,
    account: "user@example.com",
    server: "example.com",
    protocol: .http
)

try await Keychain.InternetPassword.add(
    httpsPassword,
    account: "user@example.com",
    server: "example.com",
    protocol: .https
)

// Query for HTTPS password specifically
let password = try await Keychain.InternetPassword.queryOne(
    account: "user@example.com",
    server: "example.com",
    protocol: .specific(.https)
)
```

## See Also

- ``Keychain/InternetPassword/query(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``
- ``SwiftKeychainKit/KeychainError/multipleItemsFound``
