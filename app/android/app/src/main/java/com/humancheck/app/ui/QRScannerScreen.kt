package com.humancheck.app.ui

import android.app.Activity
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext
import com.google.zxing.integration.android.IntentIntegrator
import com.journeyapps.barcodescanner.CaptureActivity

@Composable
fun QRScannerLauncher(
    onResult: (String?) -> Unit,
) {
    val context = LocalContext.current
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val parsed = IntentIntegrator.parseActivityResult(
            IntentIntegrator.REQUEST_CODE, result.resultCode, result.data
        )
        onResult(parsed?.contents)
    }
    LaunchedEffect(Unit) {
        val intent = IntentIntegrator(context as Activity)
            .setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
            .setPrompt("Scan registration QR code")
            .setBeepEnabled(false)
            .setOrientationLocked(true)
            .setCaptureActivity(CaptureActivity::class.java)
            .createScanIntent()
        launcher.launch(intent)
    }
}
