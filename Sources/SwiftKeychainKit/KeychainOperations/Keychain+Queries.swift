internal import BasicContainers
internal import Foundation
private import Security

extension Keychain {
    static func queryItems<T>(
        query: [String: Any],
        transform: (CFTypeRef) throws(KeychainError) -> [T]
    ) throws(KeychainError) -> [T] {
        var result: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &result) {
        case errSecSuccess:
            // A success error code but no result means sth. went wrong.
            guard let result else {
                throw KeychainError.dataConversionFailed
            }
            // Transform the result.
            return try transform(result)

        case errSecItemNotFound:
            return []

        case let status:
            throw KeychainError.securityError(status)
        }
    }

    static func queryItems<T: ~Copyable>(
        query: [String: Any],
        transform: (CFTypeRef) throws -> UniqueArray<T>
    ) throws -> UniqueArray<T> {
        var result: CFTypeRef?

        switch SecItemCopyMatching(query as CFDictionary, &result) {
        case errSecSuccess:
            // A success error code but no result means sth. went wrong.
            guard let result else {
                throw KeychainError.dataConversionFailed
            }
            // Transform the result.
            return try transform(result)

        case errSecItemNotFound:
            return UniqueArray<T>()

        case let status:
            throw KeychainError.securityError(status)
        }
    }
}

// MARK: - Data items query

extension Keychain {
    static func queryItems(
        query: [String: Any],
        limit: Keychain.QueryLimit
    ) throws(KeychainError) -> [NSData] {
        var query = query
        query[kSecReturnData as String] = true
        try ItemAttributes.QueryLimit.apply(limit, to: &query)

        return try queryItems(query: query) { result throws(KeychainError) -> [NSData] in
            // Check if the query only returns one matching item.
            if limit.isSingle {
                guard let data = result as? NSData else {
                    throw KeychainError.dataConversionFailed
                }
                return [data]
            }

            // For limits higher than one an array of matching items will be returned.
            guard let items = result as? [NSData] else {
                throw KeychainError.dataConversionFailed
            }
            return items
        }
    }

    static func queryItems(
        query: [String: Any],
        limit: Keychain.QueryLimit
    ) throws -> UniqueArray<SecretData> {
        var query = query
        query[kSecReturnData as String] = true
        try ItemAttributes.QueryLimit.apply(limit, to: &query)

        return try queryItems(query: query) { result throws -> UniqueArray<SecretData> in
            // Check if the query only returns one matching item.
            if limit.isSingle {
                let data = (result as! CFData)

                return try UniqueArray<SecretData>(capacity: 1) {
                    let secretData = try SecretData.makeByCopying(fromUnsafeData: data)
                    $0.append(secretData)
                }
            }

            // For limits higher than one an array of matching items will be returned.
            // Note: The Swift Array here does not cause additional copies.
            guard let dataItems = result as? [CFData] else {
                throw KeychainError.dataConversionFailed
            }

            return try UniqueArray<SecretData>(capacity: dataItems.count) {
                for dataItem in dataItems {
                    let secretData = try SecretData.makeByCopying(fromUnsafeData: dataItem)
                    $0.append(secretData)
                }
            }
        }
    }
}

// MARK: - CFCastable items query

extension Keychain {
    static func queryItems<T: CFCastable>(
        query: [String: Any],
        limit: Keychain.QueryLimit
    ) throws(KeychainError) -> [T] {
        var query = query
        query[kSecReturnRef as String] = true
        try ItemAttributes.QueryLimit.apply(limit, to: &query)

        return try queryItems(query: query) { result throws(KeychainError) -> [T] in
            // Check if the query only returns one matching item.
            if limit.isSingle {
                guard let reference: T = cast(result) else {
                    throw KeychainError.dataConversionFailed
                }
                return [reference]
            }

            // For limits higher than one an array of matching items will be returned.
            guard let references = result as? [T] else {
                throw KeychainError.dataConversionFailed
            }
            return references
        }
    }
}

// MARK: - Attributes query

extension Keychain {
    static func queryAttributes<T>(
        query: [String: Any],
        limit: Keychain.QueryLimit,
        transform: ([[String: Any]]) throws(KeychainError) -> [T]
    ) throws(KeychainError) -> [T] {
        var query = query
        query[kSecReturnAttributes as String] = true
        query[kSecReturnPersistentRef as String] = true
        try ItemAttributes.QueryLimit.apply(limit, to: &query)

        return try queryItems(query: query) { result throws(KeychainError) -> [T] in
            // Check if the query only returns one matching item.
            if limit.isSingle {
                guard let attributes = result as? [String: Any] else {
                    throw KeychainError.dataConversionFailed
                }
                return try transform([attributes])
            }

            // For limits higher than one an array of matching items will be returned.
            guard let attributes = result as? [[String: Any]] else {
                throw KeychainError.dataConversionFailed
            }
            return try transform(attributes)
        }
    }
}
