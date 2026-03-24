import Foundation
import Security
import CryptoKit
import LocalAuthentication
import DeviceCheck

enum KeychainError: Error, LocalizedError {
    case keyGenerationFailed(String)
    case keyNotFound
    case publicKeyExportFailed
    case deletionFailed
    case dhFailed(String)
    case appAttestNotSupported
    case appAttestFailed(String)
    case invalidPublicKey
    case invalidRegistrationData

    var errorDescription: String? {
        switch self {
        case .keyGenerationFailed(let msg): return "Key generation failed: \(msg)"
        case .keyNotFound: return "Key not found for this relying party"
        case .publicKeyExportFailed: return "Failed to export public key"
        case .deletionFailed: return "Failed to delete key"
        case .dhFailed(let msg): return "Key exchange failed: \(msg)"
        case .appAttestNotSupported: return "App Attest is not supported on this device"
        case .appAttestFailed(let msg): return "App Attest failed: \(msg)"
        case .invalidPublicKey: return "Invalid public key data"
        case .invalidRegistrationData: return "Missing or invalid server registration data"
        }
    }
}

extension KeychainManager {
    struct AppAttestationMaterial {
        let keyId: String
        let clientDataHash: Data
        let attestationObject: Data
    }
}

final class KeychainManager {
    static let shared = KeychainManager()
    private let tagPrefix = "com.humancheck.rp."
    private let rpConfigDefaultsPrefix = "com.humancheck.rpconfig."
    private let legacyRPURLDefaultsPrefix = "com.humancheck.rpurl."
    private let rpConfigKeychainService = "com.humancheck.rpconfig"

    struct RPConfig {
        let serverURL: String
        let masterPublicKey: Data // raw X||Y (64 bytes) or uncompressed 04||X||Y (65 bytes)
        let relyingParty: String
        let registrationId: String
        let userPublicKey: Data
    }

    private init() {}

    nonisolated private func tag(for registrationId: String) -> String {
        "\(tagPrefix)\(registrationId)"
    }

    // MARK: - Key Generation

    func generateKeyPair(for registrationId: String) throws -> Data {
        try? deleteKeyPair(for: registrationId)

        var error: Unmanaged<CFError>?

        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            throw KeychainError.keyGenerationFailed(error?.takeRetainedValue().localizedDescription ?? "Access control creation failed")
        }

        let keyTag = tag(for: registrationId).data(using: .utf8)!

        let attributes: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String:  256,
            kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String:    true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String:  access,
            ] as [String: Any],
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw KeychainError.keyGenerationFailed(error?.takeRetainedValue().localizedDescription ?? "Unknown error")
        }

        return try exportPublicKey(privateKey)
    }

    @available(iOS 14.0, *)
    nonisolated func generateAppAttestationMaterial(
        for registrationId: String,
        challenge: Data,
        publicKey: Data
    ) async throws -> AppAttestationMaterial {
        _ = registrationId
        guard DCAppAttestService.shared.isSupported else {
            throw KeychainError.appAttestNotSupported
        }

        let normalizeData: (Any) -> Data? = { raw in
            if let rawData = raw as? Data {
                return rawData
            }
            if let rawString = raw as? String {
                return Data(base64Encoded: rawString) ?? Data(rawString.utf8)
            }
            if let rawNSString = raw as? NSString {
                let rawString = rawNSString as String
                return Data(base64Encoded: rawString) ?? Data(rawString.utf8)
            }
            return nil
        }
        let normalizeKeyId: (Any) -> String? = { raw in
            if let rawString = raw as? String {
                return rawString
            }
            if let rawData = raw as? Data {
                return rawData.base64EncodedString()
            }
            if let rawNSString = raw as? NSString {
                return rawNSString as String
            }
            if let rawNSData = raw as? NSData {
                return rawNSData.base64EncodedString(options: [])
            }
            return nil
        }

        let keyId: String = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            DCAppAttestService.shared.generateKey { keyId, error in
                if let error {
                    continuation.resume(
                        throwing: KeychainError.appAttestFailed(
                            "generateKey failed: \(error.localizedDescription)"
                        )
                    )
                    return
                }
                guard let keyIdString = normalizeKeyId(keyId) else {
                    continuation.resume(
                        throwing: KeychainError.appAttestFailed("generateKey returned nil key id")
                    )
                    return
                }
                continuation.resume(returning: keyIdString)
            }
        }

        var clientDataInput = challenge
        clientDataInput.append(publicKey)
        let clientDataHash = Data(SHA256.hash(data: clientDataInput))

        let attestationObject: Data = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash) { attestationObject, error in
                if let error {
                    continuation.resume(
                        throwing: KeychainError.appAttestFailed(
                            "attestKey failed: \(error.localizedDescription)"
                        )
                    )
                    return
                }
                guard let attestationObjectData = normalizeData(attestationObject) else {
                    continuation.resume(
                        throwing: KeychainError.appAttestFailed(
                            "attestKey returned empty attestation object"
                        )
                    )
                    return
                }
                continuation.resume(returning: attestationObjectData)
            }
        }

        return AppAttestationMaterial(
            keyId: keyId,
            clientDataHash: clientDataHash,
            attestationObject: attestationObject
        )
    }

    nonisolated func getPublicKey(for registrationId: String) throws -> Data {
        let privateKey = try loadPrivateKey(for: registrationId)
        return try exportPublicKey(privateKey)
    }

    // MARK: - ECDH Key Exchange (triggers biometric)

    nonisolated func performDH(
        for registrationId: String,
        serverPublicKeyData: Data,
        operationId: String = "n/a"
    ) throws -> Data {
        let startedAt = Date()
        Swift.print("[OTP][op=\(operationId)] performDH start rp=\(registrationId) pub_len=\(serverPublicKeyData.count) ts=\(startedAt.timeIntervalSince1970)")
        let privateKey = try loadPrivateKey(
            for: registrationId,
            operationPrompt: "Authenticate to generate OTP",
            operationId: operationId
        )
        let afterKeyMs = Int((Date().timeIntervalSince(startedAt)) * 1000)
        Swift.print("[OTP][op=\(operationId)] performDH private key loaded elapsed_ms=\(afterKeyMs)")
        let normalizedServerPublicKeyData: Data
        if serverPublicKeyData.count == 64 {
            var prefixed = Data([0x04])
            prefixed.append(serverPublicKeyData)
            normalizedServerPublicKeyData = prefixed
        } else if serverPublicKeyData.count == 65, serverPublicKeyData.first == 0x04 {
            normalizedServerPublicKeyData = serverPublicKeyData
        } else {
            Swift.print("[OTP][op=\(operationId)] performDH invalid server key len=\(serverPublicKeyData.count)")
            throw KeychainError.invalidPublicKey
        }
        Swift.print("[OTP][op=\(operationId)] performDH normalized_server_key_len=\(normalizedServerPublicKeyData.count)")

        let pubKeyAttributes: [String: Any] = [
            kSecAttrKeyType as String:  kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]

        var error: Unmanaged<CFError>?
        guard let serverPublicKey = SecKeyCreateWithData(
            normalizedServerPublicKeyData as CFData,
            pubKeyAttributes as CFDictionary,
            &error
        ) else {
            let errMsg = error?.takeRetainedValue().localizedDescription ?? "unknown"
            Swift.print("[OTP][op=\(operationId)] performDH SecKeyCreateWithData failed error=\(errMsg)")
            throw KeychainError.invalidPublicKey
        }
        Swift.print("[OTP][op=\(operationId)] performDH server pubkey ref created")

        let params: [String: Any] = [
            SecKeyKeyExchangeParameter.requestedSize.rawValue as String: 32,
            SecKeyKeyExchangeParameter.sharedInfo.rawValue as String: Data(),
        ]

        guard let sharedSecret = SecKeyCopyKeyExchangeResult(
            privateKey,
            .ecdhKeyExchangeStandardX963SHA256,
            serverPublicKey,
            params as CFDictionary,
            &error
        ) else {
            let errMsg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            Swift.print("[OTP][op=\(operationId)] performDH exchange failed error=\(errMsg)")
            throw KeychainError.dhFailed(errMsg)
        }
        let out = sharedSecret as Data
        let elapsedMs = Int((Date().timeIntervalSince(startedAt)) * 1000)
        Swift.print("[OTP][op=\(operationId)] performDH success shared_len=\(out.count) elapsed_ms=\(elapsedMs)")
        return out
    }

    // MARK: - RP Registration Config Storage

    nonisolated func storeRPConfig(
        serverURL: String,
        masterPublicKey: Data,
        for registrationId: String,
        relyingParty: String,
        userPublicKey: Data
    ) throws {
        guard !serverURL.isEmpty,
              (masterPublicKey.count == 64 || (masterPublicKey.count == 65 && masterPublicKey.first == 0x04)),
              !userPublicKey.isEmpty else {
            throw KeychainError.invalidRegistrationData
        }

        let jsonPayload: [String: String] = [
            "server_url": serverURL,
            "master_public_key": masterPublicKey.base64EncodedString(),
            "relying_party": relyingParty,
            "registration_id": registrationId,
            "user_public_key": userPublicKey.base64EncodedString(),
        ]
        let data = try JSONSerialization.data(withJSONObject: jsonPayload)

        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: rpConfigKeychainService,
            kSecAttrAccount as String: registrationId,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: rpConfigKeychainService,
            kSecAttrAccount as String: registrationId,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status != errSecSuccess {
            throw KeychainError.keyGenerationFailed("Failed to store RP config: \(status)")
        }

        // Clean up legacy UserDefaults storage
        UserDefaults.standard.removeObject(forKey: rpConfigDefaultsPrefix + registrationId)
        UserDefaults.standard.removeObject(forKey: legacyRPURLDefaultsPrefix + registrationId)
    }

    nonisolated func loadRPConfig(for registrationId: String) -> RPConfig? {
        // Try Keychain first
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: rpConfigKeychainService,
            kSecAttrAccount as String: registrationId,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        let kcStatus = SecItemCopyMatching(query as CFDictionary, &result)
        if kcStatus == errSecSuccess,
           let data = result as? Data,
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
           let serverURL = json["server_url"],
           let masterPublicKeyB64 = json["master_public_key"],
           let masterPublicKey = Data(base64Encoded: masterPublicKeyB64),
           (masterPublicKey.count == 64 || (masterPublicKey.count == 65 && masterPublicKey.first == 0x04)) {
            let relyingParty = json["relying_party"] ?? registrationId
            let regId = json["registration_id"] ?? registrationId
            let userPubKey = json["user_public_key"].flatMap { Data(base64Encoded: $0) } ?? Data()
            return RPConfig(
                serverURL: serverURL,
                masterPublicKey: masterPublicKey,
                relyingParty: relyingParty,
                registrationId: regId,
                userPublicKey: userPubKey
            )
        }

        // Fall back to legacy UserDefaults and migrate
        guard let payload = UserDefaults.standard.dictionary(forKey: rpConfigDefaultsPrefix + registrationId),
              let serverURL = payload["server_url"] as? String,
              let masterPublicKey = payload["master_public_key"] as? Data,
              (masterPublicKey.count == 64 || (masterPublicKey.count == 65 && masterPublicKey.first == 0x04)) else {
            return nil
        }

        let resolvedRelyingParty = payload["relying_party"] as? String ?? registrationId
        let resolvedRegistrationId = payload["registration_id"] as? String ?? registrationId
        var resolvedUserPublicKey = payload["user_public_key"] as? Data ?? Data()
        if resolvedUserPublicKey.isEmpty {
            if let derivedPublicKey = try? getPublicKey(for: registrationId),
               !derivedPublicKey.isEmpty {
                resolvedUserPublicKey = derivedPublicKey
            }
        }

        let config = RPConfig(
            serverURL: serverURL,
            masterPublicKey: masterPublicKey,
            relyingParty: resolvedRelyingParty,
            registrationId: resolvedRegistrationId,
            userPublicKey: resolvedUserPublicKey
        )
        // Migrate to Keychain
        try? storeRPConfig(
            serverURL: serverURL,
            masterPublicKey: masterPublicKey,
            for: registrationId,
            relyingParty: resolvedRelyingParty,
            userPublicKey: resolvedUserPublicKey
        )
        return config
    }

    // MARK: - Enumeration & Deletion

    nonisolated func listRelyingParties() -> [String] {
        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String:        kSecAttrTokenIDSecureEnclave,
            kSecReturnAttributes as String:   true,
            kSecMatchLimit as String:         kSecMatchLimitAll,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }

        let parties = items.compactMap { item -> String? in
            guard let tagData = item[kSecAttrApplicationTag as String] as? Data,
                  let tagString = String(data: tagData, encoding: .utf8),
                  tagString.hasPrefix(tagPrefix) else {
                return nil
            }
            return String(tagString.dropFirst(tagPrefix.count))
        }.sorted()
        return parties
    }

    nonisolated func deleteKeyPair(for registrationId: String) throws {
        let keyTag = tag(for: registrationId).data(using: .utf8)!

        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
        ]

        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.deletionFailed
        }

        // Delete RP config from Keychain
        let configQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: rpConfigKeychainService,
            kSecAttrAccount as String: registrationId,
        ]
        SecItemDelete(configQuery as CFDictionary)

        // Clean up legacy UserDefaults storage
        UserDefaults.standard.removeObject(forKey: rpConfigDefaultsPrefix + registrationId)
        UserDefaults.standard.removeObject(forKey: legacyRPURLDefaultsPrefix + registrationId)
    }

    // MARK: - Private

    nonisolated private func loadPrivateKey(
        for registrationId: String,
        operationPrompt: String? = nil,
        operationId: String = "n/a"
    ) throws -> SecKey {
        let keyTag = tag(for: registrationId).data(using: .utf8)!

        var query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:          true,
        ]
        if let operationPrompt, !operationPrompt.isEmpty {
            let context = LAContext()
            context.localizedReason = operationPrompt
            query[kSecUseAuthenticationContext as String] = context
            Swift.print("[OTP][op=\(operationId)] loadPrivateKey context set reason=\(operationPrompt)")
        }

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let key = result else {
            let statusMessage = SecCopyErrorMessageString(status, nil) as String? ?? "n/a"
            Swift.print("[OTP][op=\(operationId)] loadPrivateKey failed status=\(status) message=\(statusMessage)")
            throw KeychainError.keyNotFound
        }
        Swift.print("[OTP][op=\(operationId)] loadPrivateKey success")

        return key as! SecKey
    }

    private nonisolated func exportPublicKey(_ privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw KeychainError.publicKeyExportFailed
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            throw KeychainError.publicKeyExportFailed
        }

        return publicKeyData as Data
    }
}
