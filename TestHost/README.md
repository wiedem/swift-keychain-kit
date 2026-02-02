# TestHost - Integration Tests

Xcode project with a minimal SwiftUI app serving as a test host for SwiftKeychainKit integration tests against the real Keychain.

The Data Protection Keychain requires code signing and entitlements, which cannot be provided by `swift test` alone, hence the need for a dedicated host app. The app targets both iOS (15.6+) and macOS (12.4+).

## Setup

### 1. Configure Development Team

The Data Protection Keychain on macOS requires code signing with a valid certificate and app identity. Without proper signing, all Keychain operations will fail with permission errors.

```bash
cp BuildConfiguration/Local.xcconfig.template BuildConfiguration/Local.xcconfig
```

Edit `Local.xcconfig` and fill in your values:

```
PRODUCT_DOMAIN = your.domain.here
DEVELOPMENT_TEAM = YOUR_TEAM_ID
```

This file is gitignored.

### 2. Open the Project

Open `TestHost/TestHost.xcodeproj` in Xcode.

The SwiftKeychainKit package is included as a local dependency via a folder reference (`SwiftKeychainKit` -> `Sources/SwiftKeychainKit`). The package root is one level above the TestHost project.

## Running Tests

### Xcode

Select the **TestHost** scheme, then press `⌘U`.

### Command Line

```bash
cd TestHost

# macOS
xcodebuild test \
    -project TestHost.xcodeproj \
    -scheme TestHost \
    -destination 'platform=macOS'

# iOS Simulator
xcodebuild test \
    -project TestHost.xcodeproj \
    -scheme TestHost \
    -destination 'platform=iOS Simulator,name=iPhone 16'
```

## Test Plan

The test plan `TestHost.xctestplan` enables parallelized execution and skips all **User-Interactive Tests** by default (see below). These require manual user interaction (biometric prompts, password dialogs) and cannot run in automation.

Most tests run on both real devices and iOS Simulators, but behavior may differ between the two environments.

## Test Structure

```
TestHostTests/
├── GenericPassword/          Add, Get, Delete, Update, Query, Attributes
├── InternetPassword/         Add, QueryOne, Delete, Update, Query, Attributes
├── Keys/                     ECC Keys, RSA Keys, Attributes
├── Certificates/             Add/Delete/Query, Attributes
├── Identities/               Add/Delete/Query, Attributes
├── CryptoKit/                GenericPasswordConvertible, SecKeyConvertible, SecureEnclave
├── SecureEnclave/            Key generation, simulator behavior
├── Helpers/                  Test utilities (see below)
├── UserInteractiveTests/     Tests with UI prompts (disabled by default)
└── TestHost.xctestplan
```

## Conventions

### Side-Effect Freedom

All tests must be free of side effects to allow parallel execution:

- **Always specify primary keys**: GenericPassword (`account` + `service`), InternetPassword (`account` + `server`), Keys (`keyType` + `applicationTag`)
- **Unique IDs per instance**: Use `UUID().uuidString` in account/service names
- **Never** call `delete()` without primary keys - this deletes *all* items

### Cleanup

Keychain entries persist across test runs if not explicitly removed.

Test classes are `final class` with `deinit` that cleans up their own entries via synchronous delete APIs. Where `deinit` is not possible, `defer` at the **beginning** of the test method is used instead.

If tests fail unexpectedly, cleanup may not run completely. In that case, delete the TestHost app from the device or simulator so it gets reinstalled on the next test run.

### No Security Framework Helpers

Integration tests must not use Security framework APIs as helpers that implicitly create Keychain entries.

Private key test resources are generated via a temporary test (`SecKeyCopyExternalRepresentation`) and stored as DER files under `Resources/`.

### Shared Test Resources and Serialization

Tests that share resources (e.g., the same DER files) must be serialized to avoid interference. All other tests should run in parallel.

## Entitlements and Access Groups

The host app declares three Keychain access groups in `TestHost.entitlements`:

| Access Group | Pattern |
|---|---|
| Default | `$(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)` |
| Group1 | `$(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER).Group1` |
| Group2 | `$(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER).Group2` |

`AppIdentifierPrefix` corresponds to the `DEVELOPMENT_TEAM` from `Local.xcconfig`.

On macOS, access groups are read dynamically via `SecTaskCreateFromSelf` + `SecTaskCopyValueForEntitlement` (see `TestAccessGroups.swift`). This is not available on iOS.

## Test Helpers

| Helper | Purpose |
|---|---|
| `TestCertificateGenerator` | Generates self-signed X.509 certificates and certificate chains at runtime (via `swift-certificates`) |
| `requireUnwrapped(_:)` | `#require` wrapper for `~Copyable` optionals |

## User-Interactive Tests

The `UserInteractiveTests/` folder contains tests that require real user interaction:

- **SkipUI tests**: Behavior of `skipIfUIRequired` / `skipItemsIfUIRequired` with access constraints
- **ApplicationPassword tests**: `kSecAccessControlApplicationPassword` with and without `LAContext` credentials
- **UIConstraints tests**: Key operations with biometric and passcode constraints (including Secure Enclave)

These tests are disabled in the test plan and tagged with `.userInteractive`. They must be run individually and manually.

## Secure Enclave Tests

The `SecureEnclave/` folder contains tests for Secure Enclave key operations. These require a real device with Secure Enclave support and cannot run on the iOS Simulator.

Tests check for hardware availability at runtime and skip with a descriptive message when the Secure Enclave is not present.

## Build Configuration

```
BuildConfiguration/
├── TestHost.xcconfig            Base configuration (includes Local.xcconfig)
├── Local.xcconfig.template      Template for local configuration
└── Local.xcconfig               Local team ID and domain (gitignored)
```

`TestHost.xcconfig` defines `PRODUCT_DOMAIN` and `DEVELOPMENT_TEAM` as empty and optionally includes `Local.xcconfig`, which overrides these values.
