# ``SwiftKeychainKit``

A modern, type-safe Swift API for Keychain Services.

## Overview

SwiftKeychainKit provides a simple and robust interface for storing and retrieving
sensitive data in the Keychain on iOS and macOS. It supports the Data Protection Keychain
with full Swift 6 concurrency support.

The package is motivated by the complexity and sharp edges of the native Keychain APIs,
and aims to make correct usage easy in modern Swift.

## Topics

### Essentials

- <doc:GettingStarted>
- ``Keychain``
- ``KeychainError``

### Guides

- <doc:ErrorHandling>
- <doc:UsingCryptoKit>

### Passwords

- ``Keychain/GenericPassword``
- ``Keychain/InternetPassword``

### Cryptographic Keys

- ``Keychain/Keys``
- ``Keychain/SecureEnclaveKeys``
- ``SecKeyConvertible``

### Certificates and Identities

- ``Keychain/Certificates``
- ``Keychain/Identities``

### Access Control

- ``Keychain/AccessControl``
- ``Keychain/ItemAccessibility``
- ``Keychain/AccessConstraint``

### Query Options

- ``Keychain/QueryScope``
- ``Keychain/QueryLimit``
