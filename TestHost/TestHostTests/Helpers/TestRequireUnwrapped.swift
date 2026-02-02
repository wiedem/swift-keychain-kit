import Testing

@discardableResult
func requireUnwrapped<T: ~Copyable>(
    _ optionalValue: consuming T?,
    _ comment: @autoclosure () -> Comment? = nil,
    sourceLocation: SourceLocation = #_sourceLocation
) throws -> T {
    let mutableValue = optionalValue

    try #require(
        (mutableValue != nil) == true,
        comment(),
        sourceLocation: sourceLocation
    )
    return mutableValue!
}
