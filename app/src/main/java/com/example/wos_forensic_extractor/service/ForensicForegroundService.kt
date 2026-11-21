package com.example.wos_forensic_extractor.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import com.example.wos_forensic_extractor.R
import com.example.wos_forensic_extractor.data.storage.SafStorageHelper
import com.example.wos_forensic_extractor.domain.converter.PortBatchConverter
import com.example.wos_forensic_extractor.domain.extractor.ForensicClassifier
import com.example.wos_forensic_extractor.domain.extractor.InstallerCabinetExtractor
import com.example.wos_forensic_extractor.domain.extractor.IsoArchiveExtractor
import com.example.wos_forensic_extractor.domain.extractor.MediaAudioTranscoder
import com.example.wos_forensic_extractor.domain.extractor.WosPcpackParser
import com.example.wos_forensic_extractor.model.ForensicCategories
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File
import kotlin.math.roundToInt

class ForensicForegroundService : Service() {
    companion object {
        const val ACTION_EXTRACT_ISO = "com.example.wos_forensic_extractor.ACTION_EXTRACT_ISO"
        const val ACTION_CONVERT_DUMP = "com.example.wos_forensic_extractor.ACTION_CONVERT_DUMP"

        const val EXTRA_ISO_URI = "extra_iso_uri"
        const val EXTRA_ISO_NAME = "extra_iso_name"
        const val EXTRA_OUTPUT_URI = "extra_output_uri"
        const val EXTRA_DUMP_URI = "extra_dump_uri"

        private const val CHANNEL_ID = "wos_forensic_channel"
        private const val NOTIF_ID_EXTRACT = 4040
        private const val NOTIF_ID_CONVERT = 4041
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var activeJob: Job? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: return START_NOT_STICKY
        if (activeJob?.isActive == true) {
            return START_NOT_STICKY
        }

        acquireWakeLock()
        when (action) {
            ACTION_EXTRACT_ISO -> {
                val isoUri = intent.getStringExtra(EXTRA_ISO_URI).orEmpty()
                val isoName = intent.getStringExtra(EXTRA_ISO_NAME).orEmpty().ifBlank { "game.iso" }
                val outputUri = intent.getStringExtra(EXTRA_OUTPUT_URI).orEmpty()
                startForegroundWithType(
                    NOTIF_ID_EXTRACT,
                    buildNotification("WoS Forensic Extractor", "Extrayendo recursos de $isoName...")
                )
                activeJob = serviceScope.launch {
                    runExtractionPipeline(isoUri, isoName, outputUri)
                    releaseWakeLock()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }

            ACTION_CONVERT_DUMP -> {
                val dumpUri = intent.getStringExtra(EXTRA_DUMP_URI).orEmpty()
                startForegroundWithType(
                    NOTIF_ID_CONVERT,
                    buildNotification("WoS Port Batch Converter", "Convirtiendo recursos para Port...")
                )
                activeJob = serviceScope.launch {
                    runConversionPipeline(dumpUri)
                    releaseWakeLock()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        releaseWakeLock()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun runExtractionPipeline(isoUri: String, isoName: String, outputUri: String) {
        val storageHelper = SafStorageHelper(applicationContext)
        val tempDir = File(filesDir, "wos_temp_${System.currentTimeMillis()}")
        var stagingOutputRoot: File? = null

        try {
            var isoProgress = 0.02f
            var cabProgress = 0.30f
            var packProgress = 0.50f

            fun publishProgress(value: Float, stage: String, processed: Int? = null, total: Int? = null) {
                ForensicJobStateHolder.updateExtractionProgress(value, stage, processed, total)
                val pct = (value * 100f).roundToInt()
                updateNotification(NOTIF_ID_EXTRACT, "WoS Forensic Extractor ($pct%)", stage)
            }

            // Step 1: Extract .ISO
            publishProgress(0.02f, "Paso 1/4: Extrayendo imagen .ISO...")
            val isoExtractor = IsoArchiveExtractor(applicationContext, storageHelper) { msg ->
                ForensicJobStateHolder.appendLog(msg)
                if (msg.startsWith("[7ZZ-ISO]") && isoProgress < 0.28f) {
                    isoProgress += 0.002f
                    publishProgress(isoProgress, "Paso 1/4: Extrayendo imagen .ISO...")
                }
            }
            isoExtractor.extractIso(isoUri, isoName, tempDir)
            publishProgress(0.30f, "Paso 1/4 completado. Analizando .msi y .cab...")

            // Step 2: Extract .msi / .cab
            publishProgress(0.30f, "Paso 2/4: Extrayendo MSI / InstallShield CAB...")
            val cabExtractor = InstallerCabinetExtractor(applicationContext) { msg ->
                ForensicJobStateHolder.appendLog(msg)
                if ((msg.startsWith("[UNSHIELD]") || msg.startsWith("[7ZZ-MSI]") || msg.startsWith("[7ZZ-CAB]")) &&
                    cabProgress < 0.48f
                ) {
                    cabProgress += 0.004f
                    publishProgress(cabProgress, "Paso 2/4: Extrayendo MSI / InstallShield CAB...")
                }
            }
            cabExtractor.extractInstallersAndCabinets(tempDir)
            publishProgress(0.50f, "Paso 2/4 completado. Escaneando contenedores PCPACK...")

            // Step 3: Unpack PCPACK/APKF
            val parser = WosPcpackParser { msg ->
                ForensicJobStateHolder.appendLog(msg)
                if (msg.startsWith("[PACK]") && packProgress < 0.74f) {
                    packProgress += 0.005f
                    publishProgress(packProgress, "Paso 3/4: Desempaquetando contenedores PCPACK/APKF...")
                }
            }
            val unpackedCount = parser.unpackAllContainers(tempDir)
            ForensicJobStateHolder.appendLog("[PACK] Total de sub-archivos desempaquetados: $unpackedCount")
            publishProgress(0.75f, "Paso 3/4 completado. Clasificando y convirtiendo assets...")

            // Step 4: Classify, DDS reconstruct, Audio 48kHz, Manifest
            val directWritable = storageHelper.resolveDirectWritableDirOrNull(outputUri)
            val useSafSync = directWritable == null && outputUri.startsWith("content://")
            val workOutputRoot = directWritable ?: File(filesDir, "wos_output_stage_${System.currentTimeMillis()}").also {
                it.mkdirs()
                stagingOutputRoot = it
            }

            val mediaTranscoder = MediaAudioTranscoder { ForensicJobStateHolder.appendLog(it) }
            val classifier = ForensicClassifier(
                mediaTranscoder = mediaTranscoder,
                onLog = { ForensicJobStateHolder.appendLog(it) },
                onProgress = { processed, total ->
                    val ratio = if (total > 0) processed.toFloat() / total.toFloat() else 1f
                    val overall = 0.75f + (0.20f * ratio)
                    publishProgress(
                        overall,
                        "Paso 4/4: Clasificando y transcodificando ($processed/$total)...",
                        processed,
                        total
                    )
                }
            )
            val summary = classifier.classifyAndFinalize(
                isoSourceName = isoName,
                tempDir = tempDir,
                outputRootDir = workOutputRoot
            )

            var finalDumpUriOrPath = summary.dumpRootDir
            var finalDumpDisplay = summary.dumpRootDir
            var finalManifestDisplay = summary.manifestPath

            if (useSafSync) {
                publishProgress(0.96f, "Sincronizando WoS_Full_Port_Dump hacia carpeta SAF seleccionada...")
                val localDump = File(summary.dumpRootDir)
                val syncedPath = storageHelper.syncLocalFolderToSafTree(
                    localRootDir = localDump,
                    treeUri = Uri.parse(outputUri),
                    targetFolderName = ForensicCategories.DUMP_FOLDER_NAME
                ) { copied, total ->
                    val syncFrac = if (total > 0) copied.toFloat() / total.toFloat() else 1f
                    publishProgress(
                        0.96f + (0.04f * syncFrac),
                        "Guardando en destino ($copied/$total archivos)..."
                    )
                }
                finalDumpDisplay = syncedPath
                finalManifestDisplay = "$syncedPath/MANIFIESTO_EXTRACCION.json"
                // Keep localDump or point Card 2 to the localDump path for instant conversion without re-downloading SAF
                finalDumpUriOrPath = localDump.absolutePath
            }

            ForensicJobStateHolder.appendLog("[TARJETA-2] Carpeta asignada automáticamente para conversión Port: $finalDumpDisplay")
            ForensicJobStateHolder.finishExtractionSuccess(
                dumpUriOrPath = finalDumpUriOrPath,
                dumpDisplayPath = finalDumpDisplay,
                counts = summary.countsByCategory,
                ddsCount = summary.ddsReconstructedCount,
                audioCount = summary.audioConverted48kHzCount,
                manifestPath = finalManifestDisplay
            )
        } catch (e: Exception) {
            val errMsg = e.message ?: "Error desconocido"
            ForensicJobStateHolder.appendLog("[FATAL] $errMsg")
            ForensicJobStateHolder.finishWithError("Error durante la extracción", errMsg)
            runCatching { if (tempDir.exists()) tempDir.deleteRecursively() }
            runCatching { stagingOutputRoot?.deleteRecursively() }
        }
    }

    private fun runConversionPipeline(dumpUriOrPath: String) {
        val storageHelper = SafStorageHelper(applicationContext)
        var tempStageIn: File? = null
        var tempStageOut: File? = null

        try {
            fun mapStageToCategory(stage: String): String? = when {
                stage.startsWith("01/09") -> ForensicCategories.CAT_01_AUDIO
                stage.startsWith("02/09") -> ForensicCategories.CAT_02_VIDEOS
                stage.startsWith("03/09") -> ForensicCategories.CAT_03_TEXTURES
                stage.startsWith("04/09") -> ForensicCategories.CAT_04_MODELS
                stage.startsWith("05/09") -> ForensicCategories.CAT_05_SKELETONS
                stage.startsWith("06/09") -> ForensicCategories.CAT_06_PHYSICS
                stage.startsWith("07/09") -> ForensicCategories.CAT_07_ENTITIES
                stage.startsWith("08/09") -> ForensicCategories.CAT_08_TEXTS
                stage.startsWith("09/09") -> ForensicCategories.CAT_09_ENGINE
                else -> null
            }

            val isSafTree = dumpUriOrPath.startsWith("content://")
            val directDir = if (!isSafTree) File(dumpUriOrPath.removePrefix("file://")) else storageHelper.resolveDirectWritableDirOrNull(dumpUriOrPath)

            val localDumpDir: File
            val outputOverrideDir: File?
            if (directDir != null && directDir.exists()) {
                localDumpDir = directDir
                outputOverrideDir = null
            } else {
                ForensicJobStateHolder.appendLog("[CONV] Cargando carpeta WoS_Full_Port_Dump desde SAF...")
                tempStageIn = File(filesDir, "wos_conv_in_${System.currentTimeMillis()}")
                localDumpDir = storageHelper.stageSafTreeToLocal(Uri.parse(dumpUriOrPath), tempStageIn) {
                    ForensicJobStateHolder.appendLog(it)
                }
                tempStageOut = File(filesDir, "wos_conv_out_${System.currentTimeMillis()}").apply { mkdirs() }
                outputOverrideDir = tempStageOut
            }

            var lastItemSkipped = false
            val mediaTranscoder = MediaAudioTranscoder { ForensicJobStateHolder.appendLog(it) }
            val converter = PortBatchConverter(
                mediaTranscoder = mediaTranscoder,
                onLog = { msg ->
                    if (msg.contains("[CONV:SKIP]")) {
                        lastItemSkipped = true
                    }
                    ForensicJobStateHolder.appendLog(msg)
                },
                onProgress = { processed, total, stage ->
                    val progress = if (total > 0) processed.toFloat() / total.toFloat() else 1f
                    val category = mapStageToCategory(stage)
                    val convertedOk = !lastItemSkipped
                    lastItemSkipped = false

                    ForensicJobStateHolder.updateConversionProgress(
                        progress = progress,
                        stage = stage,
                        processed = processed,
                        total = total,
                        categoryKey = category,
                        convertedOk = convertedOk
                    )
                    val pct = (progress * 100f).roundToInt()
                    updateNotification(NOTIF_ID_CONVERT, "WoS Port Converter ($pct%)", "$stage ($processed/$total)")
                }
            )

            val summary = converter.convertDumpDirectory(localDumpDir, outputOverrideDir)

            var displayOutDir = summary.outputConvertedDir
            var displayManifest = summary.manifestPath

            if (isSafTree && outputOverrideDir != null) {
                ForensicJobStateHolder.appendLog("[CONV] Guardando WoS_Port_Ready_Converted en carpeta SAF...")
                val synced = storageHelper.syncLocalFolderToSafTree(
                    localRootDir = outputOverrideDir,
                    treeUri = Uri.parse(dumpUriOrPath),
                    targetFolderName = ForensicCategories.CONVERTED_FOLDER_NAME
                )
                displayOutDir = synced
                displayManifest = "$synced/MANIFIESTO_CONVERSION_PORT.json"
            }

            val convertedCounts = summary.statsByCategory.mapValues { it.value.converted }
            ForensicJobStateHolder.finishConversionSuccess(
                outputConvertedDisplay = displayOutDir,
                manifestPath = displayManifest,
                totalAnalyzed = summary.totalAnalyzed,
                totalConverted = summary.totalConverted,
                totalSkipped = summary.totalSkipped,
                convertedCountsByCategory = convertedCounts
            )
        } catch (e: Exception) {
            val errMsg = e.message ?: "Error desconocido"
            ForensicJobStateHolder.appendLog("[FATAL] $errMsg")
            ForensicJobStateHolder.finishWithError("Error durante la conversión para Port", errMsg)
        } finally {
            runCatching { tempStageIn?.deleteRecursively() }
            runCatching { tempStageOut?.deleteRecursively() }
        }
    }

    private fun startForegroundWithType(notificationId: Int, notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(notificationId, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(notificationId, notification)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_desc)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(title: String, text: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun updateNotification(notificationId: Int, title: String, text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(notificationId, buildNotification(title, text))
    }

    private fun acquireWakeLock() {
        if (wakeLock == null) {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "WoSForensicExtractor::JobWakeLock").apply {
                acquire(60 * 60 * 1000L)
            }
        }
    }

    private fun releaseWakeLock() {
        runCatching {
            if (wakeLock?.isHeld == true) wakeLock?.release()
        }
        wakeLock = null
    }
}
