# ``Keychain/AccessConstraint/ConstraintLiteral``

## Overview

The `ConstraintLiteral` type enables the use of constraint literals with leading dot syntax (like `.devicePasscode`, `.biometryAny`) in API parameters that accept `some Constrainable`.

This type-erasure mechanism allows for more concise constraint syntax when the concrete constraint type can be inferred from context.

## Example

Instead of writing the fully-qualified type name:
```swift
let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: Keychain.AccessConstraint.devicePasscode
)
```

You can use the literal syntax:
```swift
let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .devicePasscode
)
```

## Available Constraint Literals

All base constraints are available as static properties:

- `.devicePasscode` - Device passcode constraint
- `.biometryAny` - Biometry with any enrolled data
- `.biometryCurrentSet` - Biometry with current enrolled data
- `.applicationPassword` - Application-specific password
- `.companion` - Companion device constraint
- `.userPresence` - Convenience for device passcode OR biometry (any)
