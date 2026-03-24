import Testing
import BIOTP
import Foundation

struct HumanCheckTests {

    @Test func testP256ChildKeyDerivation() async throws {
        // Test vector from Python: tweak = HMAC-SHA256(master_public, counter_BE)
        // master_pub (raw, no 04 prefix)
        let masterPubHex = "6f4fac2b4a0927a12ff69c21b823cc116cc8396ab94e41dbe45e324a564724ec9e171852b17829ecc811c91a4096cd77cdbd632ed4178ff0f5e696ec5cbe502a"
        let counter: UInt64 = 42
        let expectedChildPubHex = "c8243b07c0fb2a3aa62a0840a517fcd4ffb17ac964c05c6fe56d913a6a1d4e239fbc0b6640c3f3beb18e370453e0b0fbcbc795d8cb3e8580fc9e20a35d26f999"

        let masterPub = Data(hexString: masterPubHex)!

        let childPub = try! P256Curve.deriveChildPublicKey(
            masterPublicKey: masterPub,
            counter: counter
        )

        #expect(childPub.hexString == expectedChildPubHex)
    }

    @Test func testP256GeneratorMultiplication() async throws {
        // Verify scalar 1 * G = G
        let result = P256Curve.scalarMul(UInt256.one, P256Curve.G)
        #expect(result.x == P256Curve.G.x)
        #expect(result.y == P256Curve.G.y)
    }

    @Test func testP256PointAdditionIdentity() async throws {
        // P + infinity = P
        let result = P256Curve.add(P256Curve.G, .infinity)
        #expect(result.x == P256Curve.G.x)
        #expect(result.y == P256Curve.G.y)
    }

    @Test func testModSqrt() async throws {
        // (p+1)/4 exists and sqrt should be consistent
        let val = UInt256(w: (9, 0, 0, 0))
        let sq = P256Field.modMul(val, val, P256Field.p)
        let root = P256Field.modSqrt(sq)
        // root should be val or p - val
        let negRoot = P256Field.modSub(P256Field.p, root, P256Field.p)
        #expect(root == val || negRoot == val)
    }
}
