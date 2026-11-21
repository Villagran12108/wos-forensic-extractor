package com.example.wos_forensic_extractor.domain.converter

import com.example.wos_forensic_extractor.domain.extractor.MediaAudioTranscoder
import com.example.wos_forensic_extractor.model.ForensicCategories
import com.example.wos_forensic_extractor.model.PortCategoryStats
import com.example.wos_forensic_extractor.model.PortConversionSummary
import org.json.JSONObject
import java.io.BufferedWriter
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

class PortBatchConverter(
    private val mediaTranscoder: MediaAudioTranscoder,
    private val onLog: ((String) -> Unit)? = null,
    private val onProgress: ((processed: Int, total: Int, currentStage: String) -> Unit)? = null
) {
    private val chunkSize = 65536
    private val textureConverter = PortTextureConverter { log(it) }
    private val geometryConverter = PortGeometryConverter { log(it) }
    private val skeletonTextConverter = PortSkeletonTextConverter { log(it) }
    private val binaryAnalyzer = PortBinaryAnalyzer { log(it) }

    private fun log(msg: String) {
        onLog?.invoke(msg)
    }

    fun convertDumpDirectory(inputDumpDir: File, outputRootOverride: File? = null): PortConversionSummary {
        val resolvedDumpDir = resolveDumpRoot(inputDumpDir)
        val outputRoot = outputRootOverride
            ?: File(resolvedDumpDir.parentFile, ForensicCategories.CONVERTED_FOLDER_NAME)
        outputRoot.mkdirs()

        for (cat in ForensicCategories.ALL_CATEGORIES) {
            File(outputRoot, cat).mkdirs()
        }

        log("[CONV] Carpeta origen: ${resolvedDumpDir.absolutePath}")
        log("[CONV] Carpeta destino: ${outputRoot.absolutePath}")

        val filesByCategory = HashMap<String, List<File>>()
        var totalFiles = 0
        for (cat in ForensicCategories.ALL_CATEGORIES) {
            val catDir = File(resolvedDumpDir, cat)
            val list = if (catDir.exists() && catDir.isDirectory) {
                catDir.walkTopDown().filter { it.isFile }.toList()
            } else {
                emptyList()
            }
            filesByCategory[cat] = list
            totalFiles += list.size
        }

        val stats = ForensicCategories.ALL_CATEGORIES.associateWith { PortCategoryStats() }
        val generatedPaths = ArrayList<String>()

        val manifestFile = File(outputRoot, "MANIFIESTO_CONVERSION_PORT.json")
        val recordsTempFile = File(outputRoot, ".conv_records.tmp")

        var processedGlobal = 0
        var totalConverted = 0
        var totalSkipped = 0

        BufferedWriter(OutputStreamWriter(FileOutputStream(recordsTempFile), Charsets.UTF_8)).use { recWriter ->
            var firstRecord = true

            fun writeRecord(category: String, src: String, dst: String, converted: Boolean, detail: String) {
                val rec = JSONObject().apply {
                    put("categoria", category)
                    put("origen", src)
                    put("destino", dst)
                    put("estado", if (converted) "convertido" else "omitido_original_conservado")
                    put("detalle", detail)
                }
                if (!firstRecord) recWriter.write(",\n")
                firstRecord = false
                recWriter.write("    $rec")
            }

            // 1. 01_Audio_y_Voces -> WAV 48kHz PCM 16-bit
            processAudioCategory(
                sourceDir = File(resolvedDumpDir, ForensicCategories.CAT_01_AUDIO),
                destDir = File(outputRoot, ForensicCategories.CAT_01_AUDIO),
                files = filesByCategory[ForensicCategories.CAT_01_AUDIO].orEmpty(),
                stats = stats.getValue(ForensicCategories.CAT_01_AUDIO)
            ) { src, dst, converted, detail ->
                processedGlobal++
                if (converted) totalConverted++ else totalSkipped++
                generatedPaths.add(dst)
                writeRecord(ForensicCategories.CAT_01_AUDIO, src, dst, converted, detail)
                onProgress?.invoke(processedGlobal, totalFiles, "01/09 Audio -> WAV 48kHz")
            }

            // 2. 02_Videos_BIK -> MP4
            processVideoCategory(
                destDir = File(outputRoot, ForensicCategories.CAT_02_VIDEOS),
                files = filesByCategory[ForensicCategories.CAT_02_VIDEOS].orEmpty(),
                stats = stats.getValue(ForensicCategories.CAT_02_VIDEOS)
            ) { src, dst, converted, detail ->
                processedGlobal++
                if (converted) totalConverted++ else totalSkipped++
                generatedPaths.add(dst)
                writeRecord(ForensicCategories.CAT_02_VIDEOS, src, dst, converted, detail)
                onProgress?.invoke(processedGlobal, totalFiles, "02/09 Videos BIK -> MP4")
            }

            // 3. 03_Texturas_e_Imagenes -> DDS
            textureConverter.processTexturesCategory(
                destDir = File(outputRoot, ForensicCategories.CAT_03_TEXTURES),
                files = filesByCategory[ForensicCategories.CAT_03_TEXTURES].orEmpty(),
                stats = stats.getValue(ForensicCategories.CAT_03_TEXTURES)
            ) { src, dst, converted, detail ->
                processedGlobal++
                if (converted) totalConverted++ else totalSkipped++
                generatedPaths.add(dst)
                writeRecord(ForensicCategories.CAT_03_TEXTURES, src, dst, converted, detail)
                onProgress?.invoke(processedGlobal, totalFiles, "03/09 Texturas -> DDS")
            }

            // 4. 04_Modelos_3D_Mallas -> OBJ
            geometryConverter.processGeometryCategory(
                destDir = File(outputRoot, ForensicCategories.CAT_04_MODELS),
                files = filesByCategory[ForensicCategories.CAT_04_MODELS].orEmpty(),
                stats = stats.getValue(ForensicCategories.CAT_04_MODELS),
                stageLabel = "04/09 Modelos 3D -> OBJ"
            ) { src, dst, converted, detail ->
                processedGlobal++
                if (converted) totalConverted++ else totalSkipped++
                generatedPaths.add(dst)
                writeRecord(ForensicCategories.CAT_04_MODELS, src, dst, converted, detail)
                onProgress?.invoke(processedGlobal, totalFiles, "04/09 Modelos 3D -> OBJ")
            }

            // 5. 05_Esqueletos_y_Animaciones -> JSON
            skeletonTextConverter.processSkeletonsCategory(
                destDir = File(outputRoot, ForensicCategories.CAT_05_SKELETONS),
                files = filesByCategory[ForensicCategories.CAT_05_SKELETONS].orEmpty(),
                stats = stats.getValue(ForensicCategories.CAT_05_SKELETONS)
            ) { src, dst, converted, detail ->
                processedGlobal++
                if (converted) totalConverted++ else totalSkipped++
                generatedPaths.add(dst)
                writeRecord(ForensicCategories.CAT_05_SKELETONS, src, dst, converted, detail)
                onProgress?.invoke(processedGlobal, totalFiles, "05/09 Esqueletos -> JSON")
            }

            // 6. 06_Fisica_Colisiones_y_Niveles -> OBJ
            geometryConverter.processGeometryCategory(
                destDir = File(outputRoot, ForensicCategories.CAT_06_PHYSICS),
                files = filesByCategory[ForensicCategories.CAT_06_PHYSICS].orEmpty(),
                stats = stats.getValue(ForensicCategories.CAT_06_PHYSICS),
                stageLabel = "06/09 Colisiones y Niveles -> OBJ"
            ) { src, dst, converted, detail ->
                processedGlobal++
                if (converted) totalConverted++ else totalSkipped++
                generatedPaths.add(dst)
                writeRecord(ForensicCategories.CAT_06_PHYSICS, src, dst, converted, detail)
                onProgress?.invoke(processedGlobal, totalFiles, "06/09 Colisiones -> OBJ")
            }

            // 7. 07_Entidades_Combate_y_Scripts -> JSON + CSV
            skeletonTextConverter.processTextAndEntitiesCategory(
                categoryName = ForensicCategories.CAT_07_ENTITIES,
                destDir = File(outputRoot, ForensicCategories.CAT_07_ENTITIES),
                files = filesByCategory[ForensicCategories.CAT_07_ENTITIES].orEmpty(),
                stats = stats.getValue(ForensicCategories.CAT_07_ENTITIES)
            ) { src, dstList, converted, detail ->
                processedGlobal++
                if (converted) totalConverted++ else totalSkipped++
                generatedPaths.addAll(dstList)
                writeRecord(ForensicCategories.CAT_07_ENTITIES, src, dstList.joinToString(" | "), converted, detail)
                onProgress?.invoke(processedGlobal, totalFiles, "07/09 Entidades -> JSON/CSV")
            }

            // 8. 08_Textos_e_Idiomas -> JSON + CSV
            skeletonTextConverter.processTextAndEntitiesCategory(
                categoryName = ForensicCategories.CAT_08_TEXTS,
                destDir = File(outputRoot, ForensicCategories.CAT_08_TEXTS),
                files = filesByCategory[ForensicCategories.CAT_08_TEXTS].orEmpty(),
                stats = stats.getValue(ForensicCategories.CAT_08_TEXTS)
            ) { src, dstList, converted, detail ->
                processedGlobal++
                if (converted) totalConverted++ else totalSkipped++
                generatedPaths.addAll(dstList)
                writeRecord(ForensicCategories.CAT_08_TEXTS, src, dstList.joinToString(" | "), converted, detail)
                onProgress?.invoke(processedGlobal, totalFiles, "08/09 Textos/Idiomas -> JSON/CSV")
            }

            // 9. 09_Motor_Shaders_y_Binarios -> JSON + TXT
            binaryAnalyzer.processEngineBinariesCategory(
                destDir = File(outputRoot, ForensicCategories.CAT_09_ENGINE),
                files = filesByCategory[ForensicCategories.CAT_09_ENGINE].orEmpty(),
                stats = stats.getValue(ForensicCategories.CAT_09_ENGINE)
            ) { src, dstList, converted, detail ->
                processedGlobal++
                if (converted) totalConverted++ else totalSkipped++
                generatedPaths.addAll(dstList)
                writeRecord(ForensicCategories.CAT_09_ENGINE, src, dstList.joinToString(" | "), converted, detail)
                onProgress?.invoke(processedGlobal, totalFiles, "09/09 Binarios/Shaders -> JSON/TXT")
            }
        }

        val isoFormatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }

        BufferedWriter(OutputStreamWriter(FileOutputStream(manifestFile), Charsets.UTF_8)).use { writer ->
            writer.write("{\n")
            writer.write("  \"proyecto\": \"WoS Forensic Extractor - Conversor Port\",\n")
            writer.write("  \"fechaUtc\": ${JSONObject.quote(isoFormatter.format(Date()))},\n")
            writer.write("  \"carpetaOrigen\": ${JSONObject.quote(resolvedDumpDir.absolutePath)},\n")
            writer.write("  \"carpetaDestino\": ${JSONObject.quote(outputRoot.absolutePath)},\n")
            writer.write("  \"archivos\": [\n")
            if (recordsTempFile.exists()) {
                recordsTempFile.bufferedReader(Charsets.UTF_8).use { reader ->
                    val buf = CharArray(8192)
                    while (true) {
                        val r = reader.read(buf)
                        if (r <= 0) break
                        writer.write(buf, 0, r)
                    }
                }
                recordsTempFile.delete()
            }
            writer.write("\n  ],\n")
            writer.write("  \"resumen\": {\n")
            writer.write("    \"totalArchivosAnalizados\": $processedGlobal,\n")
            writer.write("    \"totalConvertidosExito\": $totalConverted,\n")
            writer.write("    \"totalOmitidosConservados\": $totalSkipped,\n")
            val statsObj = JSONObject()
            stats.forEach { (k, v) ->
                statsObj.put(
                    k,
                    JSONObject().apply {
                        put("analizados", v.analyzed)
                        put("convertidos", v.converted)
                        put("omitidos", v.skipped)
                    }
                )
            }
            writer.write("    \"porCategoria\": ${statsObj.toString(2).replace("\n", "\n    ")}\n")
            writer.write("  }\n")
            writer.write("}\n")
            writer.flush()
        }

        log("[CONV:FIN] Conversión completada. Analizados: $processedGlobal | Convertidos: $totalConverted | Omitidos (original conservado): $totalSkipped")
        log("[CONV:FIN] Manifiesto generado: ${manifestFile.absolutePath}")

        return PortConversionSummary(
            sourceDumpDir = resolvedDumpDir.absolutePath,
            outputConvertedDir = outputRoot.absolutePath,
            manifestPath = manifestFile.absolutePath,
            totalAnalyzed = processedGlobal,
            totalConverted = totalConverted,
            totalSkipped = totalSkipped,
            statsByCategory = stats,
            generatedPaths = generatedPaths
        )
    }

    private fun resolveDumpRoot(inputDir: File): File {
        val candidate = File(inputDir, ForensicCategories.DUMP_FOLDER_NAME)
        return if (candidate.exists() && candidate.isDirectory) candidate else inputDir
    }

    private fun processAudioCategory(
        sourceDir: File,
        destDir: File,
        files: List<File>,
        stats: PortCategoryStats,
        onItemDone: (src: String, dst: String, converted: Boolean, detail: String) -> Unit
    ) {
        val ps4ReadyDir = File(sourceDir, "WAV_48kHz_PS4_Ready")
        val validPreconvertedByBase = LinkedHashMap<String, File>()

        for (f in files) {
            val isInsidePs4 = f.absolutePath.startsWith(ps4ReadyDir.absolutePath)
            if (isInsidePs4 && f.extension.lowercase() == "wav" && mediaTranscoder.isValidWavFile(f)) {
                validPreconvertedByBase[f.nameWithoutExtension.lowercase()] = f
            }
        }

        val handledBases = HashSet<String>()
        for ((baseKey, wavSrc) in validPreconvertedByBase) {
            stats.analyzed++
            val dst = uniquePath(File(destDir, wavSrc.name))
            try {
                copyFileStreaming(wavSrc, dst)
                handledBases.add(baseKey)
                stats.converted++
                onItemDone(wavSrc.absolutePath, dst.absolutePath, true, "WAV 48kHz válido copiado sin recodificar")
            } catch (e: Exception) {
                stats.skipped++
                log("[CONV:SKIP] Error copiando WAV preconvertido ${wavSrc.name}: ${e.message}")
                onItemDone(wavSrc.absolutePath, wavSrc.absolutePath, false, "Error al copiar WAV: ${e.message}")
            }
        }

        for (file in files) {
            if (file.absolutePath.startsWith(ps4ReadyDir.absolutePath) &&
                validPreconvertedByBase.containsValue(file)
            ) {
                continue
            }

            val baseLower = file.nameWithoutExtension.lowercase()
            if (handledBases.contains(baseLower)) {
                stats.analyzed++
                stats.converted++
                val existingDst = File(destDir, "$baseLower.wav").absolutePath
                onItemDone(
                    file.absolutePath,
                    existingDst,
                    true,
                    "Ya cubierto por WAV_48kHz_PS4_Ready sin recodificación"
                )
                continue
            }

            stats.analyzed++
            val outWav = uniquePath(File(destDir, "${file.nameWithoutExtension}.wav"))
            val ok = mediaTranscoder.convertAudioToWav48kHz(file, outWav, forceStereo = true)
            if (ok) {
                stats.converted++
                log("[AUDIO] Convertido: ${outWav.name}")
                onItemDone(file.absolutePath, outWav.absolutePath, true, "Convertido a WAV PCM 48kHz 16-bit estéreo")
            } else {
                stats.skipped++
                log("[CONV:SKIP] Audio propietario no decodificable (${file.name})")
                val fallback = uniquePath(File(destDir, file.name))
                copyFileStreaming(file, fallback)
                onItemDone(
                    file.absolutePath,
                    fallback.absolutePath,
                    false,
                    "No decodificable por códec nativo; original conservado"
                )
            }
        }
    }

    private fun processVideoCategory(
        destDir: File,
        files: List<File>,
        stats: PortCategoryStats,
        onItemDone: (src: String, dst: String, converted: Boolean, detail: String) -> Unit
    ) {
        for (file in files) {
            stats.analyzed++
            val ext = ".${file.extension.lowercase()}"
            if (ext == ".mp4") {
                try {
                    val dst = uniquePath(File(destDir, file.name))
                    copyFileStreaming(file, dst)
                    stats.converted++
                    onItemDone(file.absolutePath, dst.absolutePath, true, "MP4 copiado directamente")
                } catch (e: Exception) {
                    stats.skipped++
                    log("[CONV:SKIP] Error copiando MP4 ${file.name}: ${e.message}")
                    onItemDone(file.absolutePath, file.absolutePath, false, "Error copiando MP4: ${e.message}")
                }
                continue
            }

            val outMp4 = uniquePath(File(destDir, "${file.nameWithoutExtension}.mp4"))
            try {
                mediaTranscoder.transcodeVideoToMp4OrThrow(file, outMp4)
                stats.converted++
                log("[VIDEO] Transcodificado: ${outMp4.name}")
                onItemDone(file.absolutePath, outMp4.absolutePath, true, "Transcodificado a MP4")
            } catch (e: Exception) {
                stats.skipped++
                log("[CONV:SKIP] Video no transcodificable (${file.name}): ${e.message}")
                val fallback = uniquePath(File(destDir, file.name))
                copyFileStreaming(file, fallback)
                onItemDone(
                    file.absolutePath,
                    fallback.absolutePath,
                    false,
                    "Códec propietario BIK/externo; original conservado"
                )
            }
        }
    }

    private fun copyFileStreaming(src: File, dst: File) {
        dst.parentFile?.mkdirs()
        FileInputStream(src).use { input ->
            FileOutputStream(dst).use { out ->
                val buf = ByteArray(chunkSize)
                while (true) {
                    val r = input.read(buf)
                    if (r <= 0) break
                    out.write(buf, 0, r)
                }
                out.flush()
            }
        }
    }

    private fun uniquePath(desired: File): File {
        if (!desired.exists()) return desired
        val parent = desired.parentFile
        val base = desired.nameWithoutExtension
        val ext = if (desired.extension.isNotEmpty()) ".${desired.extension}" else ""
        var idx = 1
        while (true) {
            val candidate = File(parent, "${base}_${idx.toString().padStart(3, '0')}$ext")
            if (!candidate.exists()) return candidate
            idx++
        }
    }
}
