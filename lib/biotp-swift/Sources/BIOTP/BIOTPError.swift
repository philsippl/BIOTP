import Foundation

public enum BIOTPError: Error, LocalizedError {
    case invalidPublicKey
    case invalidDerivedKey

    public var errorDescription: String? {
        switch self {
        case .invalidPublicKey: return "Invalid public key data"
        case .invalidDerivedKey: return "Invalid derived child key"
        }
    }
}
