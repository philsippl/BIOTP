import Foundation
import CryptoKit

public struct OTPGenerator: Sendable {
    public static let period: TimeInterval = 30
    public static let digits = 6

    public static func generate(sharedSecret: Data, time: Date = Date()) -> String {
        let counter = Self.counter(for: time)
        return generate(sharedSecret: sharedSecret, counter: counter)
    }

    public static func generate(sharedSecret: Data, counter: UInt64) -> String {
        var bigEndian = counter.bigEndian
        let counterData = Data(bytes: &bigEndian, count: 8)

        let key = SymmetricKey(data: sharedSecret)
        let hmac = HMAC<SHA256>.authenticationCode(for: counterData, using: key)
        let hmacBytes = Array(hmac)

        // RFC 4226 dynamic truncation
        let offset = Int(hmacBytes[hmacBytes.count - 1] & 0x0f)
        let truncated = (UInt32(hmacBytes[offset]) & 0x7f) << 24
            | UInt32(hmacBytes[offset + 1]) << 16
            | UInt32(hmacBytes[offset + 2]) << 8
            | UInt32(hmacBytes[offset + 3])

        let modulus = UInt32(pow(10.0, Double(digits)))
        let otp = truncated % modulus
        return String(format: "%0\(digits)d", otp)
    }

    public static func counter(for time: Date = Date()) -> UInt64 {
        UInt64(time.timeIntervalSince1970 / period)
    }

    public static func secondsRemaining(for time: Date = Date()) -> Int {
        Int(period) - Int(time.timeIntervalSince1970.truncatingRemainder(dividingBy: period))
    }
}
