package com.example.wos_forensic_extractor.ui

import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import com.example.wos_forensic_extractor.R
import com.example.wos_forensic_extractor.data.storage.SafStorageHelper
import com.example.wos_forensic_extractor.model.ForensicUiState
import com.example.wos_forensic_extractor.service.ForensicForegroundService
import com.example.wos_forensic_extractor.service.ForensicJobStateHolder
import kotlinx.coroutines.flow.StateFlow
import java.util.Locale

class ExtractorViewModel(application: Application) : AndroidViewModel(application) {
    private val storageHelper = SafStorageHelper(application)
    val uiState: StateFlow<ForensicUiState> = ForensicJobStateHolder.state

    fun onIsoPicked(uri: Uri) {
        if (uiState.value.isRunning) return
        runCatching {
            getApplication<Application>().contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        }
        val info = storageHelper.queryIsoInfo(uri)
        if (info == null) {
            ForensicJobStateHolder.appendLog("[ERROR] No se pudo obtener una ruta o tamaño válido para la ISO.")
            return
        }
        if (!info.displayName.lowercase().endsWith(".iso")) {
            ForensicJobStateHolder.appendLog("[WARN] El archivo elegido no tiene extensión .iso (${info.displayName}).")
        }
        ForensicJobStateHolder.setSelectedIso(info.uriString, info.displayName, info.sizeGb)
        ForensicJobStateHolder.appendLog(
            String.format(Locale.US, "[ISO] Seleccionada: %s (%.2f GB)", info.displayName, info.sizeGb)
        )
    }

    fun onOutputDirPicked(uri: Uri) {
        if (uiState.value.isRunning) return
        runCatching {
            getApplication<Application>().contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        }
        val info = storageHelper.describeTreeUri(uri)
        ForensicJobStateHolder.setSelectedOutputDir(info.uriString, info.displayPath)
        ForensicJobStateHolder.appendLog("[DESTINO] Carpeta seleccionada: ${info.displayPath}")
    }

    fun onDumpDirPicked(uri: Uri) {
        if (uiState.value.isRunning) return
        runCatching {
            getApplication<Application>().contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        }
        val info = storageHelper.describeTreeUri(uri)
        ForensicJobStateHolder.setSelectedDumpDir(info.uriString, info.displayPath)
        ForensicJobStateHolder.appendLog("[PORT-INPUT] Carpeta WoS_Full_Port_Dump seleccionada: ${info.displayPath}")
    }

    fun startFullExtraction(onMissingInputs: (String) -> Unit) {
        val state = uiState.value
        if (state.isRunning) return
        if (state.selectedIsoUri.isNullOrBlank() || state.selectedOutputDirUri.isNullOrBlank()) {
            onMissingInputs(getApplication<Application>().getString(R.string.msg_select_iso_and_dir))
            return
        }

        val app = getApplication<Application>()
        ForensicJobStateHolder.startExtractionUi(app.getString(R.string.stage_init_service))
        ForensicJobStateHolder.appendLog("[SERVICIO] Lanzando pipeline de extracción en segundo plano...")

        val intent = Intent(app, ForensicForegroundService::class.java).apply {
            action = ForensicForegroundService.ACTION_EXTRACT_ISO
            putExtra(ForensicForegroundService.EXTRA_ISO_URI, state.selectedIsoUri)
            putExtra(ForensicForegroundService.EXTRA_ISO_NAME, state.selectedIsoName ?: "game.iso")
            putExtra(ForensicForegroundService.EXTRA_OUTPUT_URI, state.selectedOutputDirUri)
        }
        ContextCompat.startForegroundService(app, intent)
    }

    fun startPortBatchConversion(onMissingInputs: (String) -> Unit) {
        val state = uiState.value
        if (state.isRunning) return
        val dumpUri = state.selectedDumpDirUri
        if (dumpUri.isNullOrBlank()) {
            onMissingInputs(getApplication<Application>().getString(R.string.msg_select_dump_dir))
            return
        }

        val app = getApplication<Application>()
        ForensicJobStateHolder.startConversionUi(app.getString(R.string.stage_convert_init))
        ForensicJobStateHolder.appendLog("[SERVICIO] Lanzando PortBatchConverter en segundo plano...")

        val intent = Intent(app, ForensicForegroundService::class.java).apply {
            action = ForensicForegroundService.ACTION_CONVERT_DUMP
            putExtra(ForensicForegroundService.EXTRA_DUMP_URI, dumpUri)
        }
        ContextCompat.startForegroundService(app, intent)
    }

    fun onNotificationPermissionResult(granted: Boolean) {
        if (!granted) {
            ForensicJobStateHolder.appendLog("[WARN] ${getApplication<Application>().getString(R.string.msg_notif_denied)}")
        }
    }

    fun dismissCompletionDialog() {
        ForensicJobStateHolder.dismissCompletionDialog()
    }

    fun clearError() {
        ForensicJobStateHolder.clearErrorMessage()
    }
}
