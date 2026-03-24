package com.humancheck.app

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import com.humancheck.app.ui.MainScreen
import com.humancheck.app.ui.theme.HumanCheckTheme

class MainActivity : FragmentActivity() {

    private val keyStore = KeyStoreManager()
    private lateinit var configStore: RPConfigStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        configStore = RPConfigStore(applicationContext)

        setContent {
            HumanCheckTheme {
                MainScreen(keyStore = keyStore, configStore = configStore)
            }
        }
    }
}
