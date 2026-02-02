internal import Foundation

extension SecretDataProtocol where Self: ~Copyable {
    func makeUnownedCFData() throws -> CFData {
        try withUnsafeBytes { buffer throws(SecretDataError) in
            guard let baseAddress = buffer.baseAddress else {
                throw SecretDataError.invalidBuffer
            }

            let base = baseAddress.assumingMemoryBound(to: UInt8.self)
            let mutableBase = UnsafeMutablePointer<UInt8>(mutating: base)

            guard let cfData = CFDataCreateWithBytesNoCopy(
                kCFAllocatorDefault,
                mutableBase,
                buffer.count,
                kCFAllocatorNull // caller must keep the SecretDataProtocol instance alive
            ) else {
                throw SecretDataError.invalidBuffer
            }
            return cfData
        }
    }
}
