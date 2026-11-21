package com.example.wos_forensic_extractor

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.wos_forensic_extractor.ui.ExtractorHomeScreen
import com.example.wos_forensic_extractor.ui.ExtractorViewModel
import com.example.wos_forensic_extractor.ui.theme.WoSForensicExtractorTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            WoSForensicExtractorTheme {
                val vm: ExtractorViewModel = viewModel()
                val uiState by vm.uiState.collectAsStateWithLifecycle()
                val snackbarHostState = remember { SnackbarHostState() }
                val coroutineScope = rememberCoroutineScope()

                val isoPickerLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.OpenDocument()
                ) { uri ->
                    uri?.let { vm.onIsoPicked(it) }
                }

                val outputDirLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.OpenDocumentTree()
                ) { uri ->
                    uri?.let { vm.onOutputDirPicked(it) }
                }

                val dumpDirLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.OpenDocumentTree()
                ) { uri ->
                    uri?.let { vm.onDumpDirPicked(it) }
                }

                val notifPermissionLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.RequestPermission()
                ) { granted ->
                    vm.onNotificationPermissionResult(granted)
                }

                LaunchedEffect(Unit) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        val hasNotif = ContextCompat.checkSelfPermission(
                            this@MainActivity,
                            Manifest.permission.POST_NOTIFICATIONS
                        ) == PackageManager.PERMISSION_GRANTED
                        if (!hasNotif) {
                            notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        }
                    }
                }

                LaunchedEffect(uiState.errorMessage) {
                    val err = uiState.errorMessage
                    if (!err.isNullOrBlank()) {
                        snackbarHostState.showSnackbar("Error: $err")
                        vm.clearError()
                    }
                }

                ExtractorHomeScreen(
                    state = uiState,
                    snackbarHostState = snackbarHostState,
                    onPickIsoClick = {
                        isoPickerLauncher.launch(arrayOf("*/*"))
                    },
                    onPickOutputDirClick = {
                        outputDirLauncher.launch(null)
                    },
                    onStartExtractionClick = {
                        vm.startFullExtraction { msg ->
                            coroutineScope.launch { snackbarHostState.showSnackbar(msg) }
                        }
                    },
                    onPickDumpDirClick = {
                        dumpDirLauncher.launch(null)
                    },
                    onStartConversionClick = {
                        vm.startPortBatchConversion { msg ->
                            coroutineScope.launch { snackbarHostState.showSnackbar(msg) }
                        }
                    },
                    onDismissDialog = {
                        vm.dismissCompletionDialog()
                    }
                )
            }
        }
    }
}
