import SwiftUI
import Combine
import BIOTP

// MARK: - Color helper

extension Color {
    private static let rpColorHexes: [String] = [
        "#6366f1",
        "#ec4899",
        "#14b8a6",
        "#f59e0b",
        "#8b5cf6",
        "#ef4444",
        "#06b6d4",
        "#22c55e",
    ]

    private static func stableHash(_ value: String) -> UInt64 {
        var hash = UInt64(1469598103934665603)
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1099511628211
        }
        return hash
    }

    static func forRP(_ name: String) -> Color {
        let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else {
            return .indigo
        }
        let index = Int(stableHash(normalized) % UInt64(rpColorHexes.count))
        return Color.hex(rpColorHexes[index]) ?? .indigo
    }

    static func hex(_ hex: String) -> Color? {
        let hexString = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalized = hexString.hasPrefix("#") ? String(hexString.dropFirst()) : hexString
        guard normalized.count == 6,
              let rgbValue = UInt64(normalized, radix: 16) else {
            return nil
        }

        let r = Double((rgbValue >> 16) & 0xFF) / 255.0
        let g = Double((rgbValue >> 8) & 0xFF) / 255.0
        let b = Double(rgbValue & 0xFF) / 255.0
        return Color(.sRGB, red: r, green: g, blue: b, opacity: 1.0)
    }
}

// MARK: - Server key resolution (offline only)

private enum ServerKeyError: Error {
    case invalidDerivedKey
}

nonisolated private enum ServerKeyResolver {
    static func resolve(
        config: KeychainManager.RPConfig,
        localCounter: UInt64,
        now: Date,
        operationId: String
    ) async throws -> (publicKey: Data, counter: UInt64, secondsRemaining: Int) {
        let startedAt = Date()
        Swift.print("[OTP][op=\(operationId)] resolver start counter=\(localCounter) ts=\(startedAt.timeIntervalSince1970)")
        let masterPublicKeyRaw: Data
        if config.masterPublicKey.count == 65 {
            masterPublicKeyRaw = Data(config.masterPublicKey.dropFirst())
        } else {
            masterPublicKeyRaw = config.masterPublicKey
        }
        Swift.print("[OTP][op=\(operationId)] resolver master_key_len=\(masterPublicKeyRaw.count)")

        let deriveStartAt = Date()
        Swift.print("[OTP][op=\(operationId)] resolver calling deriveChild")
        let childPublicKey = try P256Curve.deriveChildPublicKey(
            masterPublicKey: masterPublicKeyRaw,
            counter: localCounter,
            operationId: operationId
        )
        let deriveElapsedMs = Int((Date().timeIntervalSince(deriveStartAt)) * 1000)
        Swift.print("[OTP][op=\(operationId)] resolver deriveChild finished elapsed_ms=\(deriveElapsedMs)")
        guard childPublicKey.count == 64 else {
            Swift.print("[OTP][op=\(operationId)] resolver invalid child key length=\(childPublicKey.count)")
            throw ServerKeyError.invalidDerivedKey
        }
        let elapsedMs = Int((Date().timeIntervalSince(startedAt)) * 1000)
        Swift.print("[OTP][op=\(operationId)] resolver done counter=\(localCounter) elapsed_ms=\(elapsedMs)")
        return (childPublicKey, localCounter, OTPGenerator.secondsRemaining(for: now))
    }
}

// MARK: - Main View (Google Authenticator style)

struct ContentView: View {
    @State private var registrations: [RegisteredAccount] = []
    @State private var showScanner = false
    @State private var otpStates: [String: OTPState] = [:]
    @State private var refreshTask: Task<Void, Never>?
    @State private var isLoadingRelyingParties = false
    @State private var copyToastMessage: String? = nil
    @State private var copyToastTask: Task<Void, Never>? = nil

    private let keychain = KeychainManager.shared
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    struct OTPState {
        var code: String
        var counter: UInt64
        var secondsRemaining: Int
        var isGenerating: Bool = false
    }

    struct RegisteredAccount: Identifiable {
        let id: String
        let config: KeychainManager.RPConfig
    }

    private func displayTitle(for account: RegisteredAccount) -> String {
        let rp = account.config.relyingParty
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if rp.isEmpty {
            return account.id
        }
        return rp
    }

    private func iconSeed(for account: RegisteredAccount) -> String {
        let normalizedUserKey = account.config.userPublicKey
            .map { String(format: "%02x", $0) }
            .joined()
            .trimmingCharacters(in: .whitespacesAndNewlines)

        if !normalizedUserKey.isEmpty {
            return normalizedUserKey
        }

        let normalizedKey = account.config.masterPublicKey
            .map { String(format: "%02x", $0) }
            .joined()
            .trimmingCharacters(in: .whitespacesAndNewlines)

        if !normalizedKey.isEmpty {
            return normalizedKey
        }
        return account.config.relyingParty
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Color(.systemGroupedBackground)
                    .ignoresSafeArea()

                if isLoadingRelyingParties && registrations.isEmpty {
                    VStack(spacing: 16) {
                        ProgressView()
                            .scaleEffect(1.2)
                        Text("Loading accounts...")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                } else if registrations.isEmpty {
                    VStack(spacing: 16) {
                        Image(systemName: "shield.checkered")
                            .font(.system(size: 56))
                            .foregroundStyle(.secondary)
                        Text("No accounts yet")
                            .font(.title3)
                            .foregroundStyle(.secondary)
                        Text("Scan a QR code to add an account")
                            .font(.subheadline)
                            .foregroundStyle(.tertiary)
                    }
                } else {
                    List {
                        ForEach(registrations) { account in
                            let title = displayTitle(for: account)
                            RPCardView(
                                relyingParty: title,
                                colorSeed: iconSeed(for: account),
                                otpState: otpStates[account.id],
                                onGenerate: { generateOTP(for: account.id) },
                                onCopy: { code in
                                    UIPasteboard.general.string = code
                                    showCopyToast("OTP copied to clipboard")
                                },
                                onDelete: { deleteRP(account.id) }
                            )
                            .padding(.horizontal, 14)
                            .padding(.vertical, 6)
                            .listRowInsets(EdgeInsets())
                            .listRowSeparator(.hidden)
                            .listRowBackground(Color.clear)
                            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                Button(role: .destructive) {
                                    deleteRP(account.id)
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                }
            }
            .navigationTitle("HumanCheck")
            .toolbar {
                Button {
                    showScanner = true
                } label: {
                    Image(systemName: "qrcode.viewfinder")
                        .font(.title3)
                }
            }
            .sheet(isPresented: $showScanner) {
                QRRegistrationFlow(onComplete: { refreshRPs() })
            }
            .onAppear { refreshRPs() }
            .onDisappear {
                refreshTask?.cancel()
                copyToastTask?.cancel()
            }
            .onReceive(timer) { _ in
                if !otpStates.isEmpty {
                    updateCountdowns()
                }
            }
            .overlay(alignment: .bottom) {
                if let message = copyToastMessage {
                    Text(message)
                        .font(.subheadline)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .foregroundStyle(.white)
                        .background(.black.opacity(0.75), in: Capsule())
                        .padding(.bottom, 24)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                        .animation(.easeOut(duration: 0.18), value: copyToastMessage)
                }
            }
        }
    }

    private func generateOTP(for accountId: String) {
        guard let config = keychain.loadRPConfig(for: accountId) else {
            Swift.print("[OTP] generate aborted no config for rp=\(accountId)")
            return
        }
        let operationId = String(UUID().uuidString.prefix(8))
        Swift.print("[OTP][op=\(operationId)] generate requested rp=\(accountId)")

        otpStates[accountId] = OTPState(code: "", counter: 0, secondsRemaining: 0, isGenerating: true)
        Swift.print("[OTP][op=\(operationId)] state set isGenerating=true")

        Task.detached(priority: .userInitiated) {
            do {
                let startedAt = Date()
                let now = Date()
                let localCounter = OTPGenerator.counter(for: now)
                Swift.print("[OTP][op=\(operationId)] generate loop start counter=\(localCounter) ts=\(startedAt.timeIntervalSince1970)")
                let resolved = try await ServerKeyResolver.resolve(
                    config: config,
                    localCounter: localCounter,
                    now: now,
                    operationId: operationId
                )
                let afterResolveMs = Int((Date().timeIntervalSince(startedAt)) * 1000)
                Swift.print("[OTP][op=\(operationId)] resolved key counter=\(resolved.counter) elapsed_ms=\(afterResolveMs)")

                let sharedSecret = try keychain.performDH(
                    for: accountId,
                    serverPublicKeyData: resolved.publicKey,
                    operationId: operationId
                )
                let afterDHMs = Int((Date().timeIntervalSince(startedAt)) * 1000)
                Swift.print("[OTP][op=\(operationId)] dh success shared_len=\(sharedSecret.count) elapsed_ms=\(afterDHMs)")
                let code = OTPGenerator.generate(sharedSecret: sharedSecret, counter: resolved.counter)
                let totalMs = Int((Date().timeIntervalSince(startedAt)) * 1000)
                Swift.print("[OTP][op=\(operationId)] generate success elapsed_ms=\(totalMs)")

                    await MainActor.run {
                        otpStates[accountId] = OTPState(
                            code: code,
                            counter: resolved.counter,
                            secondsRemaining: resolved.secondsRemaining
                        )
                        UIPasteboard.general.string = code
                        showCopyToast("OTP copied to clipboard")
                    }
            } catch {
                Swift.print("[OTP][op=\(operationId)] generate failed error=\(String(describing: error))")
                await MainActor.run {
                    otpStates[accountId] = nil
                }
            }
        }
    }

    private func updateCountdowns() {
        for (accountId, state) in otpStates {
            guard !state.code.isEmpty else { continue }
            let currentCounter = OTPGenerator.counter()
            if currentCounter != state.counter {
                otpStates[accountId] = nil
            } else {
                otpStates[accountId]?.secondsRemaining = OTPGenerator.secondsRemaining()
            }
        }
    }

    private func deleteRP(_ accountId: String) {
        try? keychain.deleteKeyPair(for: accountId)
        otpStates[accountId] = nil
        refreshRPs()
    }

    private func showCopyToast(_ message: String) {
        copyToastTask?.cancel()
        copyToastMessage = message
        copyToastTask = Task {
            try? await Task.sleep(for: .seconds(1.4))
            await MainActor.run {
                copyToastMessage = nil
            }
        }
    }

    private func refreshRPs() {
        let startedAt = Date()
        Swift.print("[UI] refreshRPs start ts=\(startedAt.timeIntervalSince1970)")
        isLoadingRelyingParties = true

        refreshTask?.cancel()
        refreshTask = Task.detached(priority: .utility) {
            let latest = self.keychain.listRelyingParties().compactMap { accountId in
                self.keychain.loadRPConfig(for: accountId).map { config in
                    RegisteredAccount(id: accountId, config: config)
                }
            }.sorted {
                if $0.config.relyingParty != $1.config.relyingParty {
                    return $0.config.relyingParty.lowercased() < $1.config.relyingParty.lowercased()
                }
                return $0.id < $1.id
            }
            let elapsedMs = Int((Date().timeIntervalSince(startedAt)) * 1000)
            Swift.print("[UI] refreshRPs latest count=\(latest.count) elapsed_ms=\(elapsedMs)")
            await MainActor.run {
                self.isLoadingRelyingParties = false
                self.registrations = latest
            }
        }
    }
}

// MARK: - RP Card (Authenticator style row)

struct RPCardView: View {
    let relyingParty: String
    let colorSeed: String
    let otpState: ContentView.OTPState?
    let onGenerate: () -> Void
    let onCopy: (String) -> Void
    let onDelete: () -> Void
    private let actionButtonSize: CGFloat = 38

    var body: some View {
        let hasCode = otpState?.code.isEmpty == false
        let isGenerating = otpState?.isGenerating == true

        VStack(spacing: 0) {
            HStack(alignment: .center, spacing: 14) {
                // Colored circle with initial
                let iconSeed = colorSeed.trimmingCharacters(in: .whitespacesAndNewlines)
                let iconLabelSeed = relyingParty.trimmingCharacters(in: .whitespacesAndNewlines)
                let iconText = String(iconLabelSeed.prefix(1)).uppercased()
                ZStack {
                    Circle()
                        .fill(
                            LinearGradient(
                                gradient: Gradient(colors: [
                                    Color.forRP(iconSeed),
                                    Color.forRP(iconSeed).opacity(0.55)
                                ]),
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .frame(width: 44, height: 44)
                    Circle()
                        .stroke(.white.opacity(0.28), lineWidth: 1)
                        .frame(width: 44, height: 44)
                    Text(iconText.isEmpty ? "A" : iconText)
                        .font(.system(size: 17, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text(relyingParty)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)

                    // OTP code or placeholder
                    if let state = otpState, hasCode {
                        HStack(alignment: .center, spacing: 12) {
                            Text(formatOTP(state.code))
                                .font(.system(size: 28, weight: .bold, design: .monospaced))
                                .tracking(-0.5)
                                .foregroundStyle(.primary)

                            // Countdown ring
                            ZStack {
                                Circle()
                                    .stroke(Color.secondary.opacity(0.2), lineWidth: 2.5)
                                    .frame(width: 24, height: 24)
                                Circle()
                                    .trim(from: 0, to: CGFloat(state.secondsRemaining) / CGFloat(OTPGenerator.period))
                                    .stroke(
                                        state.secondsRemaining > 5 ? Color.indigo : Color.red,
                                        style: StrokeStyle(lineWidth: 2.5, lineCap: .round)
                                    )
                                    .frame(width: 24, height: 24)
                                    .rotationEffect(.degrees(-90))
                                Text("\(state.secondsRemaining)")
                                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                                    .foregroundStyle(state.secondsRemaining > 5 ? Color.secondary : Color.red)
                            }
                        }
                        .padding(.vertical, 1)
                    } else if isGenerating {
                        HStack(spacing: 8) {
                            ProgressView()
                                .scaleEffect(0.8)
                            Text("Authenticating...")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                Spacer()

                // Generate / Copy button
                if let state = otpState, hasCode {
                    Button {
                        onCopy(state.code)
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(.white)
                            .frame(width: actionButtonSize, height: actionButtonSize)
                            .background(
                                Circle()
                                    .fill(Color.indigo.opacity(0.85))
                            )
                    }
                } else if !isGenerating {
                    Button(action: onGenerate) {
                        Image(systemName: "faceid")
                            .font(.system(size: 22))
                            .foregroundStyle(.indigo)
                            .frame(width: actionButtonSize, height: actionButtonSize)
                    }
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
            .background(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(Color(.secondarySystemGroupedBackground))
                    .shadow(color: Color.black.opacity(0.12), radius: 16, x: 0, y: 8)
            )
            .contextMenu {
                Button(role: .destructive, action: onDelete) {
                    Label("Delete Account", systemImage: "trash")
                }
            }

            Divider()
                .padding(.leading, 72)
        }
    }

    private func splitOTP(_ code: String) -> (left: String, right: String) {
        let trimmed = String(code.prefix(6))
        let mid = trimmed.index(trimmed.startIndex, offsetBy: min(3, max(0, trimmed.count / 2)))
        let left = String(trimmed[..<mid])
        let right = String(trimmed[mid...])
        return (left, right)
    }

    private func formatOTP(_ code: String) -> String {
        let parts = splitOTP(code)
        return "\(parts.left)\u{2008}\(parts.right)"
    }
}

// MARK: - QR Registration Flow

struct QRRegistrationFlow: View {
    @Environment(\.dismiss) private var dismiss
    @State private var status: RegistrationStatus = .scanning
    @State private var errorMessage = ""

    let onComplete: () -> Void
    private let keychain = KeychainManager.shared

    enum RegistrationStatus {
        case scanning, registering, success, error
    }

    var body: some View {
        NavigationStack {
            ZStack {
                switch status {
                case .scanning:
                    QRScannerView { code in
                        handleScan(code)
                    }
                    .ignoresSafeArea()

                case .registering:
                    VStack(spacing: 16) {
                        ProgressView()
                            .scaleEffect(1.5)
                        Text("Registering...")
                            .foregroundStyle(.secondary)
                    }

                case .success:
                    VStack(spacing: 16) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 64))
                            .foregroundStyle(.green)
                        Text("Registered!")
                            .font(.title2.bold())
                    }

                case .error:
                    VStack(spacing: 16) {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 64))
                            .foregroundStyle(.red)
                        Text("Registration Failed")
                            .font(.title2.bold())
                        Text(errorMessage)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                        Button("Try Again") {
                            status = .scanning
                        }
                    }
                }
            }
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func handleScan(_ code: String) {
        guard let data = code.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let callbackURL = json["callback_url"] as? String,
              let rpName = json["rp_name"] as? String,
              let sessionId = json["session_id"] as? String,
              let masterPublicHex = json["master_public"] as? String,
              let attestChallengeBase64 = json["attest_challenge"] as? String,
              let masterPublicKey = Data(hexString: masterPublicHex),
              (masterPublicKey.count == 64 || (masterPublicKey.count == 65 && masterPublicKey.first == 0x04)) else {
            errorMessage = "Invalid QR code format"
            status = .error
            return
        }

        guard let parsedURL = URL(string: callbackURL),
              let scheme = parsedURL.scheme?.lowercased(),
              scheme == "https" || (scheme == "http" && Self.isLocalURL(parsedURL)) else {
            errorMessage = "Callback URL must use HTTPS"
            status = .error
            return
        }

        status = .registering

        Task {
            do {
                // Create a user ID from the RP name + short random suffix
                let suffix = String(UUID().uuidString.prefix(4))
                let userId = "\(rpName)-\(suffix)"

                // Generate keypair in Secure Enclave
                let pubKeyData = try keychain.generateKeyPair(for: userId)
                let pubKeyHex = pubKeyData.hexString
                guard let attestChallengeData = Data(base64Encoded: attestChallengeBase64) else {
                    throw KeychainError.appAttestFailed("Invalid attestation challenge")
                }
                let appAttest: KeychainManager.AppAttestationMaterial
                if #available(iOS 14.0, *) {
                    appAttest = try await keychain.generateAppAttestationMaterial(
                        for: userId,
                        challenge: attestChallengeData,
                        publicKey: pubKeyData
                    )
                } else {
                    throw KeychainError.appAttestNotSupported
                }

                // Post back to server
                var urlRequest = URLRequest(url: parsedURL)
                urlRequest.httpMethod = "POST"
                urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
                let body: [String: String] = [
                    "session_id": sessionId,
                    "user_id": userId,
                    "public_key": pubKeyHex,
                    "attest_challenge": attestChallengeBase64,
                    "attest_key_id": appAttest.keyId,
                    "attest_client_data_hash": appAttest.clientDataHash.base64EncodedString(),
                    "attest_object": appAttest.attestationObject.base64EncodedString(),
                ]
                urlRequest.httpBody = try JSONSerialization.data(withJSONObject: body)

                let (responseData, response) = try await URLSession.shared.data(for: urlRequest)
                guard let httpResponse = response as? HTTPURLResponse,
                      httpResponse.statusCode == 200 else {
                    let serverMsg = String(data: responseData, encoding: .utf8) ?? "unknown"
                    throw KeychainError.keyGenerationFailed("Server error: \(serverMsg)")
                }

                let registrationSucceeded = await MainActor.run {
                    do {
                        try keychain.storeRPConfig(
                            serverURL: callbackURL,
                            masterPublicKey: masterPublicKey,
                            for: userId,
                            relyingParty: rpName,
                            userPublicKey: pubKeyData
                        )
                        status = .success
                        onComplete()
                        return true
                    } catch {
                        errorMessage = error.localizedDescription
                        status = .error
                        return false
                    }
                }

                if registrationSucceeded {
                    try? await Task.sleep(for: .seconds(1.5))
                    await MainActor.run { dismiss() }
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    status = .error
                }
            }
        }
    }

    private static func isLocalURL(_ url: URL) -> Bool {
        guard let host = url.host?.lowercased() else { return false }
        return host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host.hasPrefix("192.168.")
            || host.hasPrefix("10.")
    }
}

#Preview {
    ContentView()
}
