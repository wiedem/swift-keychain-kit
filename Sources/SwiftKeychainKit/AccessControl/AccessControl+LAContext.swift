public import LocalAuthentication

public extension Keychain.AccessControl {
    /// Evaluates this access control using the specified authentication context.
    ///
    /// Use this method to pre-authenticate the user before performing a Keychain operation. After a successful evaluation,
    /// pass the same context as `authenticationContext` to avoid a repeated authentication prompt.
    ///
    /// > Tip: You can call this method from synchronous code using a completion handler.
    /// See ``evaluate(operation:localizedReason:context:reply:)``.
    ///
    /// - Parameters:
    ///   - operation: The type of operation to evaluate the access control for.
    ///   - localizedReason: A localized explanation for why authentication is needed. Do not include the app name.
    ///   - context: The authentication context to evaluate with.
    /// - Returns: `true` if the evaluation succeeded.
    /// - Throws: An error from the LocalAuthentication framework if the evaluation fails.
    ///
    /// - SeeAlso: [`LAContext.evaluateAccessControl(_:operation:localizedReason:reply:)`](https://developer.apple.com/documentation/localauthentication/lacontext/evaluateaccesscontrol(_:operation:localizedreason:reply:))
    func evaluate(
        operation: LAAccessControlOperation,
        localizedReason: String,
        context: LAContext
    ) async throws -> Bool {
        let secAccessControl = try makeSecAccessControl()
        return try await context.evaluateAccessControl(
            secAccessControl,
            operation: operation,
            localizedReason: localizedReason
        )
    }

    /// Evaluates this access control using the specified authentication context.
    ///
    /// Use this method to pre-authenticate the user before performing a Keychain operation. After a successful evaluation,
    /// pass the same context as `authenticationContext` to avoid a repeated authentication prompt.
    ///
    /// - Parameters:
    ///   - operation: The type of operation to evaluate the access control for.
    ///   - localizedReason: A localized explanation for why authentication is needed. Do not include the app name.
    ///   - context: The authentication context to evaluate with.
    ///   - reply: A closure called with the evaluation result: `true` if successful, or an error if it failed.
    ///
    /// - SeeAlso: [`LAContext.evaluateAccessControl(_:operation:localizedReason:reply:)`](https://developer.apple.com/documentation/localauthentication/lacontext/evaluateaccesscontrol(_:operation:localizedreason:reply:))
    func evaluate(
        operation: LAAccessControlOperation,
        localizedReason: String,
        context: LAContext,
        reply: @escaping @Sendable (Bool, (any Error)?) -> Void
    ) {
        do {
            let secAccessControl = try makeSecAccessControl()
            context.evaluateAccessControl(
                secAccessControl,
                operation: operation,
                localizedReason: localizedReason,
                reply: reply
            )
        } catch {
            reply(false, error)
        }
    }
}
