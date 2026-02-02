# ``Keychain/AccessConstraint/userPresence``


## Overview

The `userPresence` constraint is a convenience for the most common access control pattern. It represents requiring **either** the device passcode **or** any enrolled biometric authentication (Touch ID or Face ID).

This constraint is optimized to use the Security framework's `.userPresence` flag directly, which is semantically equivalent to `devicePasscode | biometryAny` but more efficient.

## Usage Example

### Using the Convenience Constraint

```swift
// Using the convenience constant
let constraint = Keychain.AccessConstraint.userPresence

// Equivalent to (but more efficient than)
let equivalentConstraint = Keychain.AccessConstraint.devicePasscode | .biometryAny

let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: constraint
)
```

### Adding an Item with User Presence

```swift
let secretData = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret")

try await Keychain.GenericPassword.add(
    secretData,
    account: "user@example.com",
    service: "com.example.app",
    accessControl: .make(
        accessibility: .whenUnlockedThisDeviceOnly,
        constraint: .userPresence
    )
)
```

## When to Use

Use this constraint when you want to protect a Keychain item but allow the user flexibility in how they authenticate - either with their passcode or biometry. This is the recommended default for most user-facing authentication scenarios.
