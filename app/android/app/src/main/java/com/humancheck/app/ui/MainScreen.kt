package com.humancheck.app.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.*
import androidx.compose.material3.LocalTextStyle
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import com.biotp.toHex
import com.biotp.OTPGenerator
import com.biotp.P256Math
import com.humancheck.app.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.UUID

data class OTPState(
    val code: String = "",
    val counter: Long = 0,
    val secondsRemaining: Int = 0,
    val isGenerating: Boolean = false,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    keyStore: KeyStoreManager,
    configStore: RPConfigStore,
) {
    val scope = rememberCoroutineScope()
    val activity = LocalContext.current as FragmentActivity

    var accounts by remember { mutableStateOf(listOf<RPConfig>()) }
    var otpStates by remember { mutableStateOf(mapOf<String, OTPState>()) }
    var showScanner by remember { mutableStateOf(false) }
    var showPasteDialog by remember { mutableStateOf(false) }
    var registrationError by remember { mutableStateOf<String?>(null) }

    fun refresh() {
        accounts = configStore.allIds().mapNotNull { configStore.load(it) }
    }

    LaunchedEffect(Unit) { refresh() }

    // Countdown ticker
    LaunchedEffect(otpStates) {
        while (otpStates.isNotEmpty()) {
            delay(1000)
            val now = System.currentTimeMillis() / 1000
            val currentCounter = OTPGenerator.counter(now)
            otpStates = otpStates.mapValues { (_, state) ->
                if (state.code.isEmpty()) state
                else if (currentCounter != state.counter) OTPState()
                else state.copy(secondsRemaining = OTPGenerator.secondsRemaining(now))
            }.filterValues { it.code.isNotEmpty() || it.isGenerating }
        }
    }

    fun handleQRPayload(raw: String?) {
        if (raw == null) return
        val payload = RegistrationClient.parseQR(raw)
        if (payload == null) {
            registrationError = "Invalid QR code"
            return
        }
        scope.launch {
            try {
                val suffix = UUID.randomUUID().toString().take(4)
                val userId = "${payload.rpName}-$suffix"
                val challengeBytes = try {
                    android.util.Base64.decode(payload.attestChallenge, android.util.Base64.DEFAULT)
                } catch (_: Exception) { null }
                val keyResult = keyStore.generateKeyPair(userId, activity, challenge = challengeBytes)
                val result = RegistrationClient.completeRegistration(
                    callbackURL = payload.callbackURL,
                    sessionId = payload.sessionId,
                    userId = userId,
                    publicKeyHex = keyResult.publicKey.toHex(),
                    attestChallenge = payload.attestChallenge,
                    attestationChain = keyResult.attestationChain,
                )
                result.onSuccess {
                    configStore.store(RPConfig(
                        callbackURL = payload.callbackURL,
                        masterPublicKey = payload.masterPublicKey,
                        relyingParty = payload.rpName,
                        registrationId = userId,
                        userPublicKey = keyResult.publicKey,
                    ))
                    refresh()
                }.onFailure {
                    registrationError = it.message
                    keyStore.delete(userId)
                }
            } catch (e: Exception) {
                registrationError = e.message
            }
        }
    }

    if (showScanner) {
        QRScannerLauncher { raw ->
            showScanner = false
            handleQRPayload(raw)
        }
    }

    if (showPasteDialog) {
        PastePayloadDialog(
            onConfirm = { text ->
                showPasteDialog = false
                handleQRPayload(text)
            },
            onDismiss = { showPasteDialog = false },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("HumanCheck") },
                actions = {
                    IconButton(onClick = { showPasteDialog = true }) {
                        Icon(Icons.Default.Edit, contentDescription = "Paste QR payload")
                    }
                    IconButton(onClick = { showScanner = true }) {
                        Icon(Icons.Default.Add, contentDescription = "Scan QR")
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            if (accounts.isEmpty()) {
                Column(
                    Modifier.align(Alignment.Center),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text("No accounts yet", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(8.dp))
                    Text("Scan a QR code to add an account", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(accounts, key = { it.registrationId }) { config ->
                        AccountCard(
                            config = config,
                            otpState = otpStates[config.registrationId] ?: OTPState(),
                            onGenerate = {
                                otpStates = otpStates + (config.registrationId to OTPState(isGenerating = true))
                                scope.launch {
                                    try {
                                        val now = System.currentTimeMillis() / 1000
                                        val counter = OTPGenerator.counter(now)
                                        val masterRaw = if (config.masterPublicKey.size == 65)
                                            config.masterPublicKey.copyOfRange(1, 65) else config.masterPublicKey
                                        val childPub = P256Math.deriveChildPublicKey(masterRaw, counter)
                                        val shared = keyStore.performECDH(config.registrationId, childPub, activity)
                                        val code = OTPGenerator.generate(shared, counter)
                                        otpStates = otpStates + (config.registrationId to OTPState(
                                            code = code, counter = counter,
                                            secondsRemaining = OTPGenerator.secondsRemaining(now),
                                        ))
                                    } catch (e: Exception) {
                                        otpStates = otpStates - config.registrationId
                                    }
                                }
                            },
                            onDelete = {
                                keyStore.delete(config.registrationId)
                                configStore.delete(config.registrationId)
                                otpStates = otpStates - config.registrationId
                                refresh()
                            },
                        )
                    }
                }
            }

            registrationError?.let { error ->
                Snackbar(
                    modifier = Modifier.align(Alignment.BottomCenter).padding(16.dp),
                    action = { TextButton(onClick = { registrationError = null }) { Text("OK") } },
                ) { Text(error) }
            }
        }
    }
}

@Composable
private fun AccountCard(
    config: RPConfig,
    otpState: OTPState,
    onGenerate: () -> Unit,
    onDelete: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val label = config.relyingParty.ifBlank { config.registrationId }
    val initial = label.firstOrNull()?.uppercase() ?: "?"

    Card(
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // Icon circle
            Box(
                Modifier.size(44.dp).clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary),
                contentAlignment = Alignment.Center,
            ) {
                Text(initial, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
            }

            Spacer(Modifier.width(14.dp))

            Column(Modifier.weight(1f)) {
                Text(label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))

                when {
                    otpState.code.isNotEmpty() -> {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            val formatted = otpState.code.take(3) + "\u2008" + otpState.code.drop(3)
                            Text(formatted, fontSize = 28.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
                            Spacer(Modifier.width(12.dp))
                            val progress by animateFloatAsState(
                                otpState.secondsRemaining.toFloat() / OTPGenerator.PERIOD.toFloat(),
                                label = "countdown",
                            )
                            CircularProgressIndicator(
                                progress = { progress },
                                modifier = Modifier.size(24.dp),
                                strokeWidth = 2.5.dp,
                                color = if (otpState.secondsRemaining > 5) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                            )
                            Spacer(Modifier.width(4.dp))
                            Text("${otpState.secondsRemaining}", fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                        }
                    }
                    otpState.isGenerating -> {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(8.dp))
                            Text("Authenticating...", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            if (otpState.code.isNotEmpty()) {
                IconButton(onClick = { clipboard.setText(AnnotatedString(otpState.code)) }) {
                    Text("Copy", fontSize = 12.sp, color = MaterialTheme.colorScheme.primary)
                }
            } else if (!otpState.isGenerating) {
                FilledIconButton(onClick = onGenerate, modifier = Modifier.size(40.dp)) {
                    Text("\uD83D\uDD13", fontSize = 18.sp) // lock emoji as biometric hint
                }
            }

            IconButton(onClick = onDelete) {
                Icon(Icons.Default.Delete, contentDescription = "Delete", tint = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
fun PastePayloadDialog(
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var text by remember { mutableStateOf("") }
    val clipboard = LocalClipboardManager.current

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Paste QR Payload") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Paste the JSON payload from the server's registration dialog.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp),
                    placeholder = { Text("{\"server_url\":...}", fontSize = 12.sp, fontFamily = FontFamily.Monospace) },
                    textStyle = LocalTextStyle.current.copy(fontSize = 12.sp, fontFamily = FontFamily.Monospace),
                    singleLine = false,
                )
                TextButton(onClick = {
                    clipboard.getText()?.text?.let { text = it }
                }) {
                    Text("Paste from clipboard")
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(text) },
                enabled = text.trimStart().startsWith("{"),
            ) { Text("Register") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
