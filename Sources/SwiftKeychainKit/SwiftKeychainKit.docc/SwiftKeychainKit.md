# ``SwiftKeychainKit``

A modern, type-safe Swift API for Keychain Services.

## Overview

SwiftKeychainKit provides a simple and robust interface for storing and retrieving
sensitive data in the Keychain on iOS and macOS. It supports the Data Protection Keychain
with full Swift 6 concurrency support.

Common operations like storing or retrieving a password need only a few lines of
code with sensible defaults. At the same time, the API prevents accidental misuse:
``SecretData`` automatically zeroes sensitive memory when it goes out of scope,
invalid access constraint combinations are caught at compile time, and required
scope parameters guard against unintended mass deletions.

## Topics

### Guides

- <doc:GettingStarted>
- <doc:SharingKeychainItems>
- <doc:UsingSecureEnclaveKeys>
- <doc:UsingCryptoKit>
- <doc:PreAuthenticatingKeychainAccess>
- <doc:ProtectingItemsWithCustomPassword>
- <doc:HandlingSecretData>
- <doc:ErrorHandling>

### Keychain Items

- ``Keychain/GenericPassword``
- ``Keychain/InternetPassword``
- ``Keychain/Keys``
- ``Keychain/SecureEnclaveKeys``
- ``Keychain/Certificates``
- ``Keychain/Identities``
- ``SecKeyConvertible``
- ``SecKeyInitializable``
- ``SecKeyRepresentable``
- ``AsymmetricKeyTypeProviding``
- ``AsymmetricKeyType``
- ``AsymmetricKeyClass``

### Access Control

- ``Keychain/AccessControl``
- ``Keychain/ItemAccessibility``
- ``Keychain/AccessConstraint``
- ``AppEntitlementsAccessGroupProvider``

### Sensitive Data

- ``SecretData``
- ``SecretDataProtocol``
- ``SecretDataError``

### Query Options

- ``Keychain/QueryScope``
- ``Keychain/QueryLimit``

### Error Handling

- ``KeychainError``
- ``SecurityFrameworkError``
- ``SecKeyConversionError``
- ``EntitlementError``
