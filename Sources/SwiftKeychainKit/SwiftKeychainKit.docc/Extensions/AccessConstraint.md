# ``Keychain/AccessConstraint``


## Overview

Access constraints define authentication requirements for Keychain items. The type-safe system prevents invalid constraint combinations at compile time.

You can use constraints individually or combine them using `&` (AND) and `|` (OR) operators to create complex authentication requirements.

## Basic Usage

### Single Constraint

```swift
let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: .devicePasscode
)
```

### OR Combinations

OR combinations allow access when **any one** of the constraints is satisfied:

```swift
// Either device passcode OR biometry
let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: Keychain.AccessConstraint.devicePasscode | .biometryAny
)
```

### AND Combinations

AND combinations require **all** constraints to be satisfied:

```swift
// Both device passcode AND biometry required
let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: Keychain.AccessConstraint.devicePasscode & .biometryAny
)
```

### Three-Way AND Combinations

You can combine up to three constraints using AND logic:

```swift
// All three constraints required
let constraint = Keychain.AccessConstraint.devicePasscode & Keychain.AccessConstraint.applicationPassword & .biometryCurrentSet

let accessControl = Keychain.AccessControl.make(
    accessibility: .whenUnlockedThisDeviceOnly,
    constraint: constraint
)
```

For detailed examples and specific constraint behavior, see the individual constraint documentation.

## Topics

### Base Constraints

- ``Keychain/AccessConstraint/DevicePasscode``
- ``Keychain/AccessConstraint/BiometryAny``
- ``Keychain/AccessConstraint/BiometryCurrentSet``
- ``Keychain/AccessConstraint/ApplicationPassword``
- ``Keychain/AccessConstraint/Companion``

### Constraint Protocol

- ``Keychain/AccessConstraint/Constrainable``
