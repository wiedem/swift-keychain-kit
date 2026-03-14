# ``Keychain/InternetPassword/updateMatching(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:to:authenticationContext:)``


## Usage Examples

### Update All Matching Entries

Update all passwords for an account and server, regardless of port or protocol:

```swift
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "updated-password")

try await Keychain.InternetPassword.updateMatching(
    account: "user@example.com",
    server: "api.example.com",
    to: newPassword
)
```

### Update Specific Entry

Update only passwords matching specific criteria (e.g., HTTPS on port 443):

```swift
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "updated-password")

try await Keychain.InternetPassword.updateMatching(
    account: "user@example.com",
    server: "api.example.com",
    protocol: .specific(.https),
    port: 443,
    to: newPassword
)
```

### Update by Protocol Only

Update all HTTPS passwords, regardless of port:

```swift
let newPassword = try SecretData.makeByCopyingUTF8(fromUnsafeString: "updated-password")

try await Keychain.InternetPassword.updateMatching(
    account: "user@example.com",
    server: "api.example.com",
    protocol: .specific(.https),
    to: newPassword
)
```

## Understanding Query Scope Parameters

The ``Keychain/QueryScope`` type provides explicit control over matching:

- ``Keychain/QueryScope/any`` - Matches entries regardless of the attribute's value
- ``Keychain/QueryScope/specific(_:)`` - Matches only entries with that exact value

By default, all optional scope parameters are set to `.any`, meaning they won't filter the results.

## See Also

- ``Keychain/QueryScope``
- ``Keychain/InternetPassword/add(_:account:server:protocol:authenticationType:port:path:securityDomain:label:accessGroup:synchronizable:accessControl:authenticationContext:)``
- ``Keychain/InternetPassword/query(account:server:protocol:authenticationType:port:path:securityDomain:accessGroup:synchronizable:skipItemsIfUIRequired:authenticationContext:limit:)``
