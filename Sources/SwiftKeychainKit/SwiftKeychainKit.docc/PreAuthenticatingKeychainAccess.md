# Pre-Authenticating Keychain Access

Authenticate the user before accessing protected Keychain items.

## Overview

When a Keychain item is protected with an access constraint like
`.biometryAny` or `.devicePasscode`, the system prompts the user for
authentication at the time of access. With pre-authentication, you can
separate the authentication step from the Keychain operation itself.

This is useful when you want to:

- Authenticate at a specific point in your UI flow, then access the item later
- Access multiple protected items without repeated prompts
- Handle authentication errors separately from Keychain errors

## Evaluating Access Control

Use ``Keychain/AccessControl/evaluate(operation:localizedReason:context:)``
to authenticate the user against a specific access control configuration.
After a successful evaluation, pass the same
[`LAContext`](https://developer.apple.com/documentation/localauthentication/lacontext)
as `authenticationContext` to avoid a repeated prompt:

```swift
import LocalAuthentication
import SwiftKeychainKit

let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .biometryAny
)

let context = LAContext()
try await accessControl.evaluate(
    operation: .useItem,
    localizedReason: "Authenticate to access your credentials",
    context: context
)

// No additional prompt, the context is already authenticated
let data = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    authenticationContext: context
)
```

## Accessing Multiple Items

A single authenticated context can be reused for multiple Keychain operations,
avoiding repeated biometric prompts:

```swift
let context = LAContext()
try await accessControl.evaluate(
    operation: .useItem,
    localizedReason: "Authenticate to access your credentials",
    context: context
)

let password = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    authenticationContext: context
)

let apiKey = try await Keychain.GenericPassword.get(
    account: "api-key",
    service: "com.example.app",
    authenticationContext: context
)
```

## Handling Authentication Errors

Pre-authentication lets you handle biometric failures separately from
Keychain errors. The `evaluate` method throws errors from the
LocalAuthentication framework:

```swift
let context = LAContext()

do {
    try await accessControl.evaluate(
        operation: .useItem,
        localizedReason: "Authenticate to access your credentials",
        context: context
    )
} catch let error as LAError {
    switch error.code {
    case .userCancel:
        // User cancelled the biometric prompt
        return
    case .biometryLockout:
        // Too many failed attempts
        return
    default:
        throw error
    }
}

// Authentication succeeded, Keychain access will not prompt again
do {
    let data = try await Keychain.GenericPassword.get(
        account: "user@example.com",
        service: "com.example.app",
        authenticationContext: context
    )
} catch {
    // This is a Keychain error, not an authentication error
}
```

Without pre-authentication, both types of errors would be mixed together in
a single `catch` block.

## Application Password Items

Unlike biometry and device passcode, the
``Keychain/AccessConstraint/ApplicationPassword`` constraint can also require
a prompt when **adding** an item. You can use
``Keychain/AccessControl/evaluate(operation:localizedReason:context:)`` with
[`.createItem`](https://developer.apple.com/documentation/localauthentication/laaccesscontroloperation/createitem)
to trigger the system password prompt at a specific point in your UI flow:

```swift
let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .applicationPassword
)

let context = LAContext()

// Triggers a system prompt asking the user to set a password
try await accessControl.evaluate(
    operation: .createItem,
    localizedReason: "Set a password for this item",
    context: context
)

// No additional prompt, the password is already set on the context
let secretData = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")
try await Keychain.GenericPassword.add(
    secretData,
    account: "user@example.com",
    service: "com.example.app",
    accessControl: accessControl,
    authenticationContext: context
)
```

Alternatively, you can bypass the system prompt entirely and provide the
password through your own UI. See <doc:ProtectingItemsWithCustomPassword>
for details.

## See Also

- ``Keychain/AccessControl``
- ``Keychain/AccessControl/evaluate(operation:localizedReason:context:)``
- ``Keychain/AccessConstraint``
