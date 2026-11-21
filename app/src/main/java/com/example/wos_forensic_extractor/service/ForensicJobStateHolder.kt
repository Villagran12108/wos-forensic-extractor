package com.example.wos_forensic_extractor.service

import com.example.wos_forensic_extractor.model.ActiveMode
import com.example.wos_forensic_extractor.model.ConversionCompletedInfo
import com.example.wos_forensic_extractor.model.ForensicCategories
import com.example.wos_forensic_extractor.model.ForensicUiState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.ArrayDeque

object ForensicJobStateHolder {
    private const val MAX_UI_LOG_LINES = 1500
    private val logBuffer = ArrayDeque<String>(MAX_UI_LOG_LINES)

    private val _state = MutableStateFlow(
        ForensicUiState(
            currentStageLabel = "Listo para iniciar extracción o conversión forense",
            logs = listOf("[SISTEMA] WoS Forensic Extractor inicializado (ARM64 Streaming Mode).")
        ).also {
            logBuffer.addLast("[SISTEMA] WoS Forensic Extractor inicializado (ARM64 Streaming Mode).")
        }
    )
    val state: StateFlow<ForensicUiState> = _state.asStateFlow()

    @Synchronized
    fun appendLog(line: String) {
        if (logBuffer.size >= MAX_UI_LOG_LINES) {
            logBuffer.removeFirst()
        }
        logBuffer.addLast(line)
        val snapshot = logBuffer.toList()
        _state.update { it.copy(logs = snapshot) }
    }

    fun setSelectedIso(uriString: String, name: String, sizeGb: Double) {
        _state.update {
            it.copy(
                selectedIsoUri = uriString,
                selectedIsoName = name,
                selectedIsoSizeGb = sizeGb
            )
        }
    }

    fun setSelectedOutputDir(uriString: String, displayPath: String) {
        _state.update {
            it.copy(
                selectedOutputDirUri = uriString,
                selectedOutputDirDisplay = displayPath
            )
        }
    }

    fun setSelectedDumpDir(uriString: String, displayPath: String) {
        _state.update {
            it.copy(
                selectedDumpDirUri = uriString,
                selectedDumpDirDisplay = displayPath,
                convertedOutputDirBanner = null
            )
        }
    }

    fun startExtractionUi(initialStage: String) {
        _state.update {
            it.copy(
                isRunning = true,
                activeMode = ActiveMode.EXTRACT,
                globalProgress = 0.01f,
                currentStageLabel = initialStage,
                classifiedProcessed = 0,
                classifiedTotal = 0,
                ddsReconstructedCount = 0,
                audioConverted48kHzCount = 0,
                manifestResultPath = null,
                convertedOutputDirBanner = null,
                categoryCounts = ForensicCategories.emptyCountsMap(),
                errorMessage = null
            )
        }
    }

    fun startConversionUi(initialStage: String) {
        _state.update {
            it.copy(
                isRunning = true,
                activeMode = ActiveMode.CONVERT,
                globalProgress = 0.01f,
                currentStageLabel = initialStage,
                classifiedProcessed = 0,
                classifiedTotal = 0,
                manifestResultPath = null,
                convertedOutputDirBanner = null,
                convertedBannerTotal = 0,
                convertedBannerSkipped = 0,
                categoryCounts = ForensicCategories.emptyCountsMap(),
                errorMessage = null
            )
        }
    }

    fun updateExtractionProgress(
        progress: Float,
        stage: String,
        processed: Int? = null,
        total: Int? = null
    ) {
        _state.update { cur ->
            cur.copy(
                globalProgress = progress.coerceIn(0f, 1f),
                currentStageLabel = stage,
                classifiedProcessed = processed ?: cur.classifiedProcessed,
                classifiedTotal = total ?: cur.classifiedTotal
            )
        }
    }

    fun updateConversionProgress(
        progress: Float,
        stage: String,
        processed: Int,
        total: Int,
        categoryKey: String?,
        convertedOk: Boolean
    ) {
        _state.update { cur ->
            val updatedCounts = if (categoryKey != null && convertedOk && cur.categoryCounts.containsKey(categoryKey)) {
                cur.categoryCounts.toMutableMap().apply {
                    this[categoryKey] = (this[categoryKey] ?: 0) + 1
                }
            } else {
                cur.categoryCounts
            }
            cur.copy(
                globalProgress = progress.coerceIn(0f, 1f),
                currentStageLabel = stage,
                classifiedProcessed = processed,
                classifiedTotal = total,
                categoryCounts = updatedCounts
            )
        }
    }

    fun finishExtractionSuccess(
        dumpUriOrPath: String,
        dumpDisplayPath: String,
        counts: Map<String, Int>,
        ddsCount: Int,
        audioCount: Int,
        manifestPath: String
    ) {
        _state.update { cur ->
            cur.copy(
                isRunning = false,
                activeMode = ActiveMode.NONE,
                globalProgress = 1f,
                currentStageLabel = "Extracción forense completada al 100%",
                ddsReconstructedCount = ddsCount,
                audioConverted48kHzCount = audioCount,
                manifestResultPath = manifestPath,
                selectedDumpDirUri = dumpUriOrPath,
                selectedDumpDirDisplay = dumpDisplayPath,
                categoryCounts = ForensicCategories.ALL_CATEGORIES.associateWith { counts[it] ?: 0 }
            )
        }
    }

    fun finishConversionSuccess(
        outputConvertedDisplay: String,
        manifestPath: String,
        totalAnalyzed: Int,
        totalConverted: Int,
        totalSkipped: Int,
        convertedCountsByCategory: Map<String, Int>
    ) {
        _state.update { cur ->
            cur.copy(
                isRunning = false,
                activeMode = ActiveMode.NONE,
                globalProgress = 1f,
                currentStageLabel = "Conversión para Port completada al 100%",
                manifestResultPath = manifestPath,
                convertedOutputDirBanner = outputConvertedDisplay,
                convertedBannerTotal = totalConverted,
                convertedBannerSkipped = totalSkipped,
                categoryCounts = ForensicCategories.ALL_CATEGORIES.associateWith {
                    convertedCountsByCategory[it] ?: 0
                },
                completionDialog = ConversionCompletedInfo(
                    outputDir = outputConvertedDisplay,
                    manifestPath = manifestPath,
                    totalAnalyzed = totalAnalyzed,
                    totalConverted = totalConverted,
                    totalSkipped = totalSkipped
                )
            )
        }
    }

    fun finishWithError(stageLabel: String, errorMsg: String) {
        _state.update {
            it.copy(
                isRunning = false,
                activeMode = ActiveMode.NONE,
                currentStageLabel = stageLabel,
                errorMessage = errorMsg
            )
        }
    }

    fun dismissCompletionDialog() {
        _state.update { it.copy(completionDialog = null) }
    }

    fun clearErrorMessage() {
        _state.update { it.copy(errorMessage = null) }
    }
}
