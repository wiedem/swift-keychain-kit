/// A type that provides its asymmetric key type.
///
/// Conform to this protocol to indicate the key algorithm a type represents, enabling convenience APIs that infer
/// the key type from the generic parameter.
public protocol AsymmetricKeyTypeProviding: ~Copyable {
    /// The asymmetric key type this type represents.
    static var asymmetricKeyType: AsymmetricKeyType { get }
}
