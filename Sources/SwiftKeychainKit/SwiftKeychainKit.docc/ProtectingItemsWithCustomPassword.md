# Protecting Items with a Custom Password

Protect Keychain items with an application-specific password.

## Overview

The `.applicationPassword` access constraint provides an additional layer of
security by requiring a separate password that is distinct from the device
passcode. It can be used alone or combined with other constraints like
`.devicePasscode` or `.biometryCurrentSet`.

By default, the system shows an interactive prompt when a password needs to be
set or verified. To present your own password dialog instead, set the password
programmatically using
[`LAContext.setCredential(_:type:)`](https://developer.apple.com/documentation/localauthentication/lacontext/setcredential(_:type:))
and pass the context as `authenticationContext`.

## Adding an Item

Without an authentication context, the system shows a prompt to set the
password:

```swift
let secretData = try SecretData.makeByCopyingUTF8(fromUnsafeString: "service-password")

try await Keychain.GenericPassword.add(
    secretData,
    account: "user@example.com",
    service: "com.example.app",
    accessControl: .make(
        accessibility: .whenUnlockedThisDeviceOnly,
        constraint: .applicationPassword
    )
)
```

To present your own password dialog, collect the password from the user and
pass it via
[`setCredential(_:type:)`](https://developer.apple.com/documentation/localauthentication/lacontext/setcredential(_:type:)):

```swift
import LocalAuthentication

let passwordData = userEnteredPassword.data(using: .utf8)!

let context = LAContext()
context.setCredential(passwordData, type: .applicationPassword)

let secretData = try SecretData.makeByCopyingUTF8(fromUnsafeString: "service-password")

try await Keychain.GenericPassword.add(
    secretData,
    account: "user@example.com",
    service: "com.example.app",
    accessControl: .make(
        accessibility: .whenUnlockedThisDeviceOnly,
        constraint: .applicationPassword
    ),
    authenticationContext: context
)
```

## Accessing a Protected Item

The same approach applies when retrieving a protected item. Without a pre-set
credential, the system shows a prompt automatically. To use your own dialog,
pass the credential via an authentication context:

```swift
let passwordData = userEnteredPassword.data(using: .utf8)!

let context = LAContext()
context.setCredential(passwordData, type: .applicationPassword)

let data = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    authenticationContext: context
)
```

If the password is incorrect, the operation fails with an authentication error.

### Suppressing the Prompt

To skip items that would require a password prompt, use the `skipIfUIRequired`
parameter:

```swift
let data = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    skipIfUIRequired: true
)
// Returns nil if a prompt would be required
```

> Important: Items are only skipped when a prompt **would** be required. If the
correct credential is already set in the authentication context, the item is
returned normally.

### Preventing Interaction

To fail with an error instead of silently skipping, set
[`interactionNotAllowed`](https://developer.apple.com/documentation/localauthentication/lacontext/interactionnotallowed)
on the authentication context. This is useful for background queries where UI
is not possible:

```swift
import LocalAuthentication

let context = LAContext()
context.interactionNotAllowed = true

let data = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    authenticationContext: context
)
```

If a prompt would be required, the operation throws
``KeychainError/interactionNotAllowed``.

## Combining with Other Constraints

The `.applicationPassword` constraint can be combined with other constraints
using `&`:

```swift
// Require both biometry and an application password
let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .biometryCurrentSet & .applicationPassword
)

// Require both device passcode and an application password
let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .devicePasscode & .applicationPassword
)
```

## See Also

- ``Keychain/AccessConstraint/ApplicationPassword``
- ``Keychain/AccessControl``
