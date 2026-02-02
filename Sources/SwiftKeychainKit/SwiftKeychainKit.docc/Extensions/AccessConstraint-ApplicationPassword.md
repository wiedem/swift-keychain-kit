# ``Keychain/AccessConstraint/ApplicationPassword``


## Overview

Application password provides an additional layer of security by requiring a separate password that is distinct from the device passcode. This password is set using `LAContext.setCredential(_:type:)` and must be provided to access the protected Keychain item.

## Usage Example

### Adding an Item with Application Password

When adding a Keychain item with application password constraint, set the password in the authentication context:

```swift
import LocalAuthentication

let context = LAContext()
let passwordData = "my-app-password".data(using: .utf8)!
context.setCredential(passwordData, type: .applicationPassword)
let secretData = try SecretData.makeByCopyingUTF8(fromUnsafeString: "service-password")

try await Keychain.GenericPassword.add(
    secretData,
    account: "user@example.com",
    service: "com.example.app",
    accessControl: .make(
        accessibility: .whenUnlockedThisDeviceOnly,
        constraint: Keychain.AccessConstraint.devicePasscode & .applicationPassword
    ),
    authenticationContext: context
)
```

### Accessing an Item Protected by Application Password

**Scenario 1: Password set in LAContext**

If the correct password is set in the authentication context, access is granted without a UI prompt:

```swift
import LocalAuthentication

let context = LAContext()
let passwordData = "my-app-password".data(using: .utf8)!
context.setCredential(passwordData, type: .applicationPassword)

// No UI prompt - direct access if password is correct
let data = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    authenticationContext: context
)
```

**Scenario 2: Password not set in LAContext**

If the password is not set (or is incorrect), the system shows an interactive password prompt to the user:

```swift
let context = LAContext()
// Password NOT set in context

// System shows password prompt to user
let data = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    authenticationContext: context
)
```

**Scenario 3: Suppressing the UI prompt**

To prevent the UI prompt and skip the item if authentication UI would be required, use the `skipIfUIRequired` parameter:

```swift
let context = LAContext()
// Password NOT set in context

// Skip item if UI would be required - returns nil without showing prompt
let data = try await Keychain.GenericPassword.get(
    account: "user@example.com",
    service: "com.example.app",
    skipIfUIRequired: true,
    authenticationContext: context
)
// Result: nil (item was skipped, no UI shown)
```

**Important**: When `skipIfUIRequired: true`, items are only skipped if UI **would** be required. If credentials are already set in the `LAContext`, the item is returned normally without being skipped.
