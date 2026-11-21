package com.example.wos_forensic_extractor.model

object ForensicCategories {
    const val DUMP_FOLDER_NAME = "WoS_Full_Port_Dump"
    const val CONVERTED_FOLDER_NAME = "WoS_Port_Ready_Converted"

    const val CAT_01_AUDIO = "01_Audio_y_Voces"
    const val CAT_02_VIDEOS = "02_Videos_BIK"
    const val CAT_03_TEXTURES = "03_Texturas_e_Imagenes"
    const val CAT_04_MODELS = "04_Modelos_3D_Mallas"
    const val CAT_05_SKELETONS = "05_Esqueletos_y_Animaciones"
    const val CAT_06_PHYSICS = "06_Fisica_Colisiones_y_Niveles"
    const val CAT_07_ENTITIES = "07_Entidades_Combate_y_Scripts"
    const val CAT_08_TEXTS = "08_Textos_e_Idiomas"
    const val CAT_09_ENGINE = "09_Motor_Shaders_y_Binarios"

    val ALL_CATEGORIES: List<String> = listOf(
        CAT_01_AUDIO,
        CAT_02_VIDEOS,
        CAT_03_TEXTURES,
        CAT_04_MODELS,
        CAT_05_SKELETONS,
        CAT_06_PHYSICS,
        CAT_07_ENTITIES,
        CAT_08_TEXTS,
        CAT_09_ENGINE
    )

    fun emptyCountsMap(): Map<String, Int> = ALL_CATEGORIES.associateWith { 0 }
}

data class ClassificationSummary(
    val dumpRootDir: String,
    val manifestPath: String,
    val totalFiles: Int,
    val totalBytes: Long,
    val ddsReconstructedCount: Int,
    val audioConverted48kHzCount: Int,
    val countsByCategory: Map<String, Int>
)

class PortCategoryStats {
    var analyzed: Int = 0
    var converted: Int = 0
    var skipped: Int = 0
}

data class PortConversionSummary(
    val sourceDumpDir: String,
    val outputConvertedDir: String,
    val manifestPath: String,
    val totalAnalyzed: Int,
    val totalConverted: Int,
    val totalSkipped: Int,
    val statsByCategory: Map<String, PortCategoryStats>,
    val generatedPaths: List<String>
)

enum class ActiveMode {
    NONE,
    EXTRACT,
    CONVERT
}

data class ConversionCompletedInfo(
    val outputDir: String,
    val manifestPath: String,
    val totalAnalyzed: Int,
    val totalConverted: Int,
    val totalSkipped: Int
)

data class ForensicUiState(
    val selectedIsoUri: String? = null,
    val selectedIsoName: String? = null,
    val selectedIsoSizeGb: Double? = null,
    val selectedOutputDirUri: String? = null,
    val selectedOutputDirDisplay: String? = null,
    val selectedDumpDirUri: String? = null,
    val selectedDumpDirDisplay: String? = null,
    val convertedOutputDirBanner: String? = null,
    val convertedBannerTotal: Int = 0,
    val convertedBannerSkipped: Int = 0,
    val isRunning: Boolean = false,
    val activeMode: ActiveMode = ActiveMode.NONE,
    val globalProgress: Float = 0f,
    val currentStageLabel: String = "",
    val classifiedProcessed: Int = 0,
    val classifiedTotal: Int = 0,
    val ddsReconstructedCount: Int = 0,
    val audioConverted48kHzCount: Int = 0,
    val manifestResultPath: String? = null,
    val categoryCounts: Map<String, Int> = ForensicCategories.emptyCountsMap(),
    val logs: List<String> = emptyList(),
    val completionDialog: ConversionCompletedInfo? = null,
    val errorMessage: String? = null
)
