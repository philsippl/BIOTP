import Foundation
import CryptoKit

// MARK: - 256-bit unsigned integer (4 x UInt64 limbs, little-endian)

public struct UInt256: Equatable, Sendable {
    public var w: (UInt64, UInt64, UInt64, UInt64) // w.0 = least significant

    public static let zero = UInt256(w: (0, 0, 0, 0))
    public static let one  = UInt256(w: (1, 0, 0, 0))

    public init(w: (UInt64, UInt64, UInt64, UInt64)) { self.w = w }

    public init(data: Data) {
        precondition(data.count == 32)
        let bytes = Array(data)
        func limb(_ start: Int) -> UInt64 {
            var v: UInt64 = 0
            for i in 0..<8 { v = (v << 8) | UInt64(bytes[start + i]) }
            return v
        }
        self.w = (limb(24), limb(16), limb(8), limb(0))
    }

    public var data: Data {
        var out = Data(count: 32)
        func store(_ v: UInt64, at offset: Int) {
            for i in 0..<8 { out[offset + 7 - i] = UInt8((v >> (i * 8)) & 0xFF) }
        }
        store(w.3, at: 0); store(w.2, at: 8); store(w.1, at: 16); store(w.0, at: 24)
        return out
    }

    public static func == (a: UInt256, b: UInt256) -> Bool {
        a.w.0 == b.w.0 && a.w.1 == b.w.1 && a.w.2 == b.w.2 && a.w.3 == b.w.3
    }

    public func isZero() -> Bool { self == .zero }
    public func isEven() -> Bool { (w.0 & 1) == 0 }
    public func isOdd() -> Bool { (w.0 & 1) == 1 }

    public func compare(_ other: UInt256) -> Int {
        if w.3 != other.w.3 { return w.3 < other.w.3 ? -1 : 1 }
        if w.2 != other.w.2 { return w.2 < other.w.2 ? -1 : 1 }
        if w.1 != other.w.1 { return w.1 < other.w.1 ? -1 : 1 }
        if w.0 != other.w.0 { return w.0 < other.w.0 ? -1 : 1 }
        return 0
    }

    public static func addWithCarry(_ a: UInt256, _ b: UInt256) -> (UInt256, Bool) {
        var r = UInt256.zero
        var carry = false
        (r.w.0, carry) = a.w.0.addingReportingOverflow(b.w.0)
        let c0 = carry
        (r.w.1, carry) = a.w.1.addingReportingOverflow(b.w.1)
        if c0 { let c1: Bool; (r.w.1, c1) = r.w.1.addingReportingOverflow(1); carry = carry || c1 }
        let c1 = carry
        (r.w.2, carry) = a.w.2.addingReportingOverflow(b.w.2)
        if c1 { let c2: Bool; (r.w.2, c2) = r.w.2.addingReportingOverflow(1); carry = carry || c2 }
        let c2 = carry
        (r.w.3, carry) = a.w.3.addingReportingOverflow(b.w.3)
        if c2 { let c3: Bool; (r.w.3, c3) = r.w.3.addingReportingOverflow(1); carry = carry || c3 }
        return (r, carry)
    }

    public static func subWithBorrow(_ a: UInt256, _ b: UInt256) -> (UInt256, Bool) {
        var r = UInt256.zero
        var borrow = false
        (r.w.0, borrow) = a.w.0.subtractingReportingOverflow(b.w.0)
        let b0 = borrow
        (r.w.1, borrow) = a.w.1.subtractingReportingOverflow(b.w.1)
        if b0 { let b1: Bool; (r.w.1, b1) = r.w.1.subtractingReportingOverflow(1); borrow = borrow || b1 }
        let b1 = borrow
        (r.w.2, borrow) = a.w.2.subtractingReportingOverflow(b.w.2)
        if b1 { let b2: Bool; (r.w.2, b2) = r.w.2.subtractingReportingOverflow(1); borrow = borrow || b2 }
        let b2 = borrow
        (r.w.3, borrow) = a.w.3.subtractingReportingOverflow(b.w.3)
        if b2 { let b3: Bool; (r.w.3, b3) = r.w.3.subtractingReportingOverflow(1); borrow = borrow || b3 }
        return (r, borrow)
    }


    public func shiftedRight1(withExtraBit extraBit: Bool = false) -> UInt256 {
        let extra: UInt64 = extraBit ? 1 : 0
        let n3 = (w.3 >> 1) | (extra << 63)
        let n2 = (w.2 >> 1) | ((w.3 & 1) << 63)
        let n1 = (w.1 >> 1) | ((w.2 & 1) << 63)
        let n0 = (w.0 >> 1) | ((w.1 & 1) << 63)
        return UInt256(w: (n0, n1, n2, n3))
    }
}

// MARK: - Modular arithmetic over P-256 field prime

public struct P256Field: Sendable {
    public static let p = UInt256(w: (
        0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF,
        0x0000000000000000, 0xFFFFFFFF00000001
    ))

    public static let n = UInt256(w: (
        0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000
    ))

    public static let pPlus1Over4 = UInt256(w: (
        0x0000000000000000, 0x0000000040000000,
        0x4000000000000000, 0x3FFFFFFFC0000000
    ))

    public static func modAdd(_ a: UInt256, _ b: UInt256, _ mod: UInt256) -> UInt256 {
        let (sum, carry) = UInt256.addWithCarry(a, b)
        guard carry else {
            if sum.compare(mod) >= 0 { return UInt256.subWithBorrow(sum, mod).0 }
            return sum
        }
        let maxValue = UInt256(w: (UInt64.max, UInt64.max, UInt64.max, UInt64.max))
        let minusModMinusOne = UInt256.subWithBorrow(maxValue, mod).0
        let (radixMinusMod, _) = UInt256.addWithCarry(minusModMinusOne, .one)
        let (corrected, _) = UInt256.addWithCarry(sum, radixMinusMod)
        if corrected.compare(mod) >= 0 { return UInt256.subWithBorrow(corrected, mod).0 }
        return corrected
    }

    public static func modSub(_ a: UInt256, _ b: UInt256, _ mod: UInt256) -> UInt256 {
        let (diff, borrow) = UInt256.subWithBorrow(a, b)
        if borrow { return UInt256.addWithCarry(diff, mod).0 }
        return diff
    }

    public static func modMul(_ a: UInt256, _ b: UInt256, _ mod: UInt256) -> UInt256 {
        var result = UInt256.zero
        var addend = a
        var multiplier = b
        for _ in 0..<256 {
            if !multiplier.isEven() { result = modAdd(result, addend, mod) }
            multiplier = multiplier.shiftedRight1()
            if multiplier.isZero() { break }
            addend = modAdd(addend, addend, mod)
        }
        return result
    }

    public static func modInv(_ a: UInt256, _ mod: UInt256) -> UInt256 {
        precondition(!a.isZero(), "Inverse of zero is undefined")
        precondition((mod.w.0 & 1) == 1, "Binary inversion requires odd modulus")
        var u = a
        if u.compare(mod) >= 0 { u = UInt256.subWithBorrow(u, mod).0 }
        var v = mod
        var x1 = UInt256.one
        var x2 = UInt256.zero
        while u != .one && v != .one {
            while u.isEven() {
                u = u.shiftedRight1()
                if x1.isEven() { x1 = x1.shiftedRight1() }
                else { let (sum, carry) = UInt256.addWithCarry(x1, mod); x1 = sum.shiftedRight1(withExtraBit: carry) }
            }
            while v.isEven() {
                v = v.shiftedRight1()
                if x2.isEven() { x2 = x2.shiftedRight1() }
                else { let (sum, carry) = UInt256.addWithCarry(x2, mod); x2 = sum.shiftedRight1(withExtraBit: carry) }
            }
            if u.compare(v) >= 0 { u = UInt256.subWithBorrow(u, v).0; x1 = modSub(x1, x2, mod) }
            else { v = UInt256.subWithBorrow(v, u).0; x2 = modSub(x2, x1, mod) }
        }
        return u == .one ? x1 : x2
    }

    public static func modPow(_ base: UInt256, _ exponent: UInt256, _ mod: UInt256) -> UInt256 {
        if base.isZero() { return .zero }
        precondition(!mod.isZero(), "Modulus must be non-zero")
        if exponent.isZero() { return .one }
        var result = UInt256.one
        var resultBase = base
        var exp = exponent
        while !exp.isZero() {
            if exp.isOdd() { result = modMul(result, resultBase, mod) }
            exp = exp.shiftedRight1()
            if exp.isZero() { break }
            resultBase = modMul(resultBase, resultBase, mod)
        }
        return result
    }

    public static func modSqrt(_ a: UInt256) -> UInt256 {
        let root = modPow(a, pPlus1Over4, p)
        let check = modMul(root, root, p)
        return check == a ? root : modSub(p, root, p)
    }
}

// MARK: - P-256 elliptic curve point operations

public struct ECPoint: Equatable, Sendable {
    public let x: UInt256
    public let y: UInt256
    public let isInfinity: Bool

    public static let infinity = ECPoint(x: .zero, y: .zero, isInfinity: true)

    public init(x: UInt256, y: UInt256, isInfinity: Bool = false) {
        self.x = x; self.y = y; self.isInfinity = isInfinity
    }

    public init?(uncompressed data: Data) {
        guard data.count == 65, data[0] == 0x04 else { return nil }
        self.x = UInt256(data: data[1..<33])
        self.y = UInt256(data: data[33..<65])
        self.isInfinity = false
    }

    public init?(raw data: Data) {
        guard data.count == 64 else { return nil }
        self.x = UInt256(data: data[0..<32])
        self.y = UInt256(data: data[32..<64])
        self.isInfinity = false
    }

    public var rawData: Data {
        var out = Data()
        out.append(x.data); out.append(y.data)
        return out
    }
}

public struct P256Curve: Sendable {
    public typealias F = P256Field
    private static let p = F.p
    private static let n = F.n

    public static let G = ECPoint(
        x: UInt256(w: (0xF4A13945D898C296, 0x77037D812DEB33A0, 0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247)),
        y: UInt256(w: (0xCBB6406837BF51F5, 0x2BCE33576B315ECE, 0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B)),
        isInfinity: false
    )

    public static func scalarMul(_ scalar: UInt256, _ point: ECPoint) -> ECPoint {
        if scalar.isZero() || point.isInfinity { return .infinity }
        var result = ECPoint.infinity
        var addend = point
        var k = scalar
        while !k.isZero() {
            if k.isOdd() { result = add(result, addend) }
            k = k.shiftedRight1()
            if k.isZero() { break }
            addend = double(addend)
        }
        return result
    }

    public static func add(_ P: ECPoint, _ Q: ECPoint) -> ECPoint {
        if P.isInfinity { return Q }
        if Q.isInfinity { return P }
        if P.x == Q.x {
            if P.y == Q.y { return double(P) }
            return .infinity
        }
        let dy = F.modSub(Q.y, P.y, p)
        let dx = F.modSub(Q.x, P.x, p)
        let lambda = F.modMul(dy, F.modInv(dx, p), p)
        let lambda2 = F.modMul(lambda, lambda, p)
        let rx = F.modSub(F.modSub(lambda2, P.x, p), Q.x, p)
        let ry = F.modSub(F.modMul(lambda, F.modSub(P.x, rx, p), p), P.y, p)
        return ECPoint(x: rx, y: ry)
    }

    public static func double(_ P: ECPoint) -> ECPoint {
        if P.isInfinity { return P }
        if P.y.isZero() { return .infinity }
        let px2 = F.modMul(P.x, P.x, p)
        let three_px2 = F.modAdd(F.modAdd(px2, px2, p), px2, p)
        let a = F.modSub(p, UInt256(w: (3, 0, 0, 0)), p)
        let num = F.modAdd(three_px2, a, p)
        let den = F.modAdd(P.y, P.y, p)
        let lambda = F.modMul(num, F.modInv(den, p), p)
        let lambda2 = F.modMul(lambda, lambda, p)
        let rx = F.modSub(F.modSub(lambda2, P.x, p), P.x, p)
        let ry = F.modSub(F.modMul(lambda, F.modSub(P.x, rx, p), p), P.y, p)
        return ECPoint(x: rx, y: ry)
    }

    /// Derive child public key via additive tweak:
    /// child_public = master_public + tweak * G
    public static func deriveChildPublicKey(
        masterPublicKey: Data,
        counter: UInt64,
        operationId: String = "n/a"
    ) throws -> Data {
        // tweak = HMAC-SHA256(master_public, counter_BE)
        let key = SymmetricKey(data: masterPublicKey)
        var counterBE = counter.bigEndian
        let message = Data(bytes: &counterBE, count: 8)
        let hmac = HMAC<SHA256>.authenticationCode(for: message, using: key)
        let tweakBytes = Data(hmac)

        // Reduce tweak mod n
        let tweak = UInt256(data: tweakBytes)
        var tweakReduced = tweak.compare(n) >= 0
            ? UInt256.subWithBorrow(tweak, n).0
            : tweak
        if tweakReduced.isZero() { tweakReduced = .one }

        // tweak*G via CryptoKit
        let tweakPriv = try P256.KeyAgreement.PrivateKey(rawRepresentation: tweakReduced.data)
        guard let tweakPoint = ECPoint(uncompressed: tweakPriv.publicKey.x963Representation) else {
            throw BIOTPError.invalidPublicKey
        }

        guard let masterPoint = ECPoint(raw: masterPublicKey) else {
            throw BIOTPError.invalidPublicKey
        }

        let childPoint = add(masterPoint, tweakPoint)
        guard !childPoint.isInfinity else {
            throw BIOTPError.invalidDerivedKey
        }
        return childPoint.rawData
    }
}
