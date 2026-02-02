import BasicContainers
import LocalAuthentication
import SwiftKeychainKit
import Testing

@Suite(
    "InternetPassword.query() Skip UI (Manual)",
    .tags(.userInteractive),
    .serialized
)
final class InternetPasswordSkipUITests {
    private let testAccount = "skip-ui-test-\(UUID().uuidString)"
    private let testServer = "example-\(UUID().uuidString).com"

    deinit {
        cleanup()
    }

    // MARK: - Test: Skip item with user presence requirement

    @Test("query() with skipItemsIfUIRequired skips item requiring user presence")
    func skipItemRequiringUserPresence() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let passwordExpected = try password.duplicate()

        // Add item with user presence requirement
        try await Keychain.InternetPassword.add(
            password,
            account: testAccount,
            server: testServer,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .userPresence
            )
        )

        // Query with skipItemsIfUIRequired: false - should show biometry prompt
        do {
            var results = try await Keychain.InternetPassword.query(
                account: .specific(testAccount),
                server: .specific(testServer),
                skipItemsIfUIRequired: false
            )
            // If user authenticates, we get the password
            #expect(results.count == 1)
            let firstResult = results.remove(at: 0)
            #expect((firstResult == passwordExpected) == true)
        } catch KeychainError.authenticationCancelled {
            // User cancelled biometry prompt
            Issue.record("Authentication prompt was cancelled by user")
            return
        }

        // Query with skipItemsIfUIRequired: true - should NOT show prompt, returns empty result
        let skippedResults = try await Keychain.InternetPassword.query(
            account: .specific(testAccount),
            server: .specific(testServer),
            skipItemsIfUIRequired: true
        )
        #expect(skippedResults.isEmpty == true)
    }

    // MARK: - Test: Skip item with application password requirement showing prompt on add and query

    @Test("query() with skipItemsIfUIRequired skips item requiring application password (UI prompt on add and query)")
    func skipItemRequiringApplicationPasswordOnAddAndQuery() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let passwordExpected = try password.duplicate()

        // Should show password prompt to set the application password
        try await Keychain.InternetPassword.add(
            password,
            account: testAccount,
            server: testServer,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            )
        )

        // Query with skipItemsIfUIRequired: false - should show password prompt
        do {
            let result = try await Keychain.InternetPassword.queryOne(
                account: testAccount,
                server: testServer,
                skipIfUIRequired: false
            )
            // If user enters correct password, we get the data
            let firstResult = try requireUnwrapped(result)
            #expect((firstResult == passwordExpected) == true)
        } catch KeychainError.authenticationCancelled {
            // User cancelled password prompt
            Issue.record("Authentication prompt was cancelled by user")
            return
        }

        // Query with skipItemsIfUIRequired: true - should NOT show prompt, returns nil
        let skippedResult = try await Keychain.InternetPassword.queryOne(
            account: testAccount,
            server: testServer,
            skipIfUIRequired: true
        )
        #expect((skippedResult == nil) == true)
    }

    // MARK: - Test: Skip item with application password requirement, providing password with LAContext to add, showing prompt on query

    @Test("query() with skipItemsIfUIRequired skips item requiring application password (context on add, UI prompt on query)")
    func skipItemRequiringApplicationPasswordOnQuery() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let passwordExpected = try password.duplicate()
        let appPassword = "1" // User must enter this password at the UI prompt during query

        let addContext = LAContext()
        addContext.setCredential(
            appPassword.data(using: .utf8)!,
            type: .applicationPassword
        )

        // Should not show password prompt
        try await Keychain.InternetPassword.add(
            password,
            account: testAccount,
            server: testServer,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            ),
            authenticationContext: addContext
        )

        // Query with skipItemsIfUIRequired: false - should show password prompt
        do {
            let result = try await Keychain.InternetPassword.queryOne(
                account: testAccount,
                server: testServer,
                skipIfUIRequired: false
            )
            // If user enters correct password, we get the data
            let firstResult = try requireUnwrapped(result)
            #expect((firstResult == passwordExpected) == true)
        } catch KeychainError.authenticationCancelled {
            // User cancelled password prompt
            Issue.record("Authentication prompt was cancelled by user")
            return
        } catch KeychainError.authenticationFailed {
            // User entered invalid password prompt
            Issue.record("Invalid authentication credentials, use '\(appPassword)' for the password prompt")
            return
        }

        // Query with skipItemsIfUIRequired: true - should NOT show prompt, returns nil
        let skippedResult = try await Keychain.InternetPassword.queryOne(
            account: testAccount,
            server: testServer,
            skipIfUIRequired: true
        )
        #expect((skippedResult == nil) == true)
    }

    // MARK: - Test: Don't skip when credentials are in context

    @Test("query() with skipItemsIfUIRequired does not skip when credentials are in LAContext")
    func dontSkipWhenCredentialsProvided() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let passwordExpected = try password.duplicate()
        let appPassword = "app-password-123".data(using: .utf8)!

        // Add item with application password requirement
        let addContext = LAContext()
        addContext.setCredential(appPassword, type: .applicationPassword)

        try await Keychain.InternetPassword.add(
            password,
            account: testAccount,
            server: testServer,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            ),
            authenticationContext: addContext
        )

        // Query with skipIfUIRequired: true BUT with correct credentials
        // Item should NOT be skipped because no UI is required
        let queryContext = LAContext()
        queryContext.setCredential(appPassword, type: .applicationPassword)

        let result = try await Keychain.InternetPassword.queryOne(
            account: testAccount,
            server: testServer,
            skipIfUIRequired: true,
            authenticationContext: queryContext
        )

        // Item should be returned, not skipped
        let firstResult = try requireUnwrapped(result)
        #expect((firstResult == passwordExpected) == true)
    }

    // MARK: - Test: Throws error when interaction not allowed

    @Test("query() throws interactionNotAllowed when context disallows interaction")
    func queryThrowsErrorWhenInteractionNotAllowed() async throws {
        let password = try SecretData.makeByCopyingUTF8(fromUnsafeString: "secret-password")
        let appPassword = "app-password-123".data(using: .utf8)!

        // Add item with application password requirement
        let addContext = LAContext()
        addContext.setCredential(appPassword, type: .applicationPassword)

        try await Keychain.InternetPassword.add(
            password,
            account: testAccount,
            server: testServer,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .applicationPassword
            ),
            authenticationContext: addContext
        )

        // query() with skipItemsIfUIRequired: false and LAContext.interactionNotAllowed = true
        // Should throw KeychainError.interactionNotAllowed
        let queryContext = LAContext()
        queryContext.interactionNotAllowed = true

        await #expect(throws: KeychainError.interactionNotAllowed) {
            _ = try await Keychain.InternetPassword.query(
                account: .specific(testAccount),
                server: .specific(testServer),
                skipItemsIfUIRequired: false,
                authenticationContext: queryContext
            )
        }
    }

    // MARK: - Test: Query multiple items with mixed authentication requirements

    @Test("query() with skipItemsIfUIRequired filters out items requiring UI")
    func queryMultipleItemsWithMixedRequirements() async throws {
        let password1 = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password-no-auth")
        let password1Expected = try password1.duplicate()
        let password2 = try SecretData.makeByCopyingUTF8(fromUnsafeString: "password-with-user-presence")
        let account1 = "account-1-\(UUID().uuidString)"
        let account2 = "account-2-\(UUID().uuidString)"

        defer {
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(account1),
                server: .specific(testServer),
                accessGroup: .any,
                synchronizable: .any
            )
            _ = try? Keychain.InternetPassword.delete(
                account: .specific(account2),
                server: .specific(testServer),
                accessGroup: .any,
                synchronizable: .any
            )
        }

        // Add item without authentication requirement
        try await Keychain.InternetPassword.add(
            password1,
            account: account1,
            server: testServer
        )

        // Add item with user presence requirement
        try await Keychain.InternetPassword.add(
            password2,
            account: account2,
            server: testServer,
            accessControl: .make(
                accessibility: .whenUnlockedThisDeviceOnly,
                constraint: .userPresence
            )
        )

        // Query with skipItemsIfUIRequired: true
        // Should only return the first item (no auth requirement)
        let result = try await Keychain.InternetPassword.queryOne(
            account: account1,
            server: testServer,
            skipIfUIRequired: true
        )

        // Should return the item without auth requirement
        let firstResult = try requireUnwrapped(result)
        #expect((firstResult == password1Expected) == true)
    }
}

// MARK: - Helpers

private extension InternetPasswordSkipUITests {
    func cleanup() {
        do {
            try Keychain.InternetPassword.delete(
                account: .specific(testAccount),
                server: .specific(testServer),
                accessGroup: .any,
                synchronizable: .any
            )
        } catch {
            print("Failed to clean up internet password after test: \(error)")
        }
    }
}
