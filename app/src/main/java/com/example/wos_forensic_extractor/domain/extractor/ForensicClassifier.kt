package com.example.wos_forensic_extractor.domain.extractor

import com.example.wos_forensic_extractor.model.ClassificationSummary
import com.example.wos_forensic_extractor.model.ForensicCategories
import org.json.JSONObject
import java.io.BufferedWriter
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

class ForensicClassifier(
    private val mediaTranscoder: MediaAudioTranscoder,
    private val onLog: ((String) -> Unit)? = null,
    private val onProgress: ((processed: Int, total: Int) -> Unit)? = null
) {
    private val chunkSize = 65536
    private val skipIntermediateContainers = setOf(
        ".iso", ".cab", ".hdr", ".msi", ".pack", ".pcpack", ".pcapk", ".apkf"
    )

    private data class TexDdsInfo(
        val fourCc: String,
        val width: Int,
        val height: Int,
        val mipCount: Int,
        val payloadOffset: Int
    )

    private fun log(msg: String) {
        onLog?.invoke(msg)
    }

    fun classifyAndFinalize(
        isoSourceName: String,
        tempDir: File,
        outputRootDir: File
    ): ClassificationSummary {
        val dumpRoot = File(outputRootDir, ForensicCategories.DUMP_FOLDER_NAME)
        dumpRoot.mkdirs()

        for (category in ForensicCategories.ALL_CATEGORIES) {
            File(dumpRoot, category).mkdirs()
        }
        val ps4AudioDir = File(dumpRoot, "${ForensicCategories.CAT_01_AUDIO}/WAV_48kHz_PS4_Ready")
        ps4AudioDir.mkdirs()

        val counts = ForensicCategories.ALL_CATEGORIES.associateWith { 0 }.toMutableMap()
        val allFiles = ArrayList<File>()
        if (tempDir.exists()) {
            tempDir.walkTopDown().forEach { entity ->
                if (entity.isFile) {
                    val ext = ".${entity.extension.lowercase()}"
                    if (ext !in skipIntermediateContainers) {
                        allFiles.add(entity)
                    }
                }
            }
        }

        val total = allFiles.size
        var processed = 0
        var totalBytes = 0L
        var ddsReconstructedCount = 0
        var audioConverted48kHzCount = 0

        val manifestFile = File(dumpRoot, "MANIFIESTO_EXTRACCION.json")
        val isoFormatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val recordsTempFile = File(dumpRoot, ".manifest_records.tmp")

        BufferedWriter(OutputStreamWriter(FileOutputStream(recordsTempFile), Charsets.UTF_8)).use { recWriter ->
            var firstEntry = true
            for (file in allFiles) {
                processed++
                onProgress?.invoke(processed, total)

                val fileSize = file.length()
                if (fileSize <= 0L) continue

                val head64 = readHeaderBytes(file, 64)
                val sig32 = if (head64.size > 32) head64.copyOfRange(0, 32) else head64
                val magicHex = toHex(sig32)
                val magicAscii = toPrintableAscii(sig32)

                val category = detectCategory(file.absolutePath, sig32)
                val desiredDest = File(File(dumpRoot, category), file.name)
                val finalDest = resolveNonCollidingPath(desiredDest)

                safeMoveStreaming(file, finalDest)
                counts[category] = (counts[category] ?: 0) + 1
                totalBytes += fileSize

                var reconstructedDdsPath: String? = null
                var convertedWav48kPath: String? = null

                if (category == ForensicCategories.CAT_03_TEXTURES &&
                    finalDest.extension.lowercase() == "tex" &&
                    !startsWithAscii(sig32, "DDS ")
                ) {
                    val texInfo = inspectRawDxtTex(head64, fileSize.toInt())
                    if (texInfo != null) {
                        val ddsDesired = File(
                            File(dumpRoot, ForensicCategories.CAT_03_TEXTURES),
                            "${finalDest.nameWithoutExtension}_reconstructed.dds"
                        )
                        val ddsDest = resolveNonCollidingPath(ddsDesired)
                        if (writeReconstructedDds(finalDest, ddsDest, texInfo)) {
                            reconstructedDdsPath = ddsDest.absolutePath
                            ddsReconstructedCount++
                        }
                    }
                }

                if (category == ForensicCategories.CAT_01_AUDIO) {
                    val wavDesired = File(ps4AudioDir, "${finalDest.nameWithoutExtension}.wav")
                    val wavDest = resolveNonCollidingPath(wavDesired)
                    if (mediaTranscoder.convertAudioToWav48kHz(finalDest, wavDest, forceStereo = false)) {
                        convertedWav48kPath = wavDest.absolutePath
                        audioConverted48kHzCount++
                    }
                }

                val record = JSONObject().apply {
                    put("categoria", category)
                    put("rutaOriginal", file.absolutePath)
                    put("rutaFinal", finalDest.absolutePath)
                    put("tamanoBytes", fileSize)
                    put("firmaHex", magicHex)
                    put("firmaAscii", magicAscii)
                    if (reconstructedDdsPath != null) put("ddsReconstruido", reconstructedDdsPath)
                    if (convertedWav48kPath != null) put("audio48kHzPs4", convertedWav48kPath)
                }

                if (!firstEntry) {
                    recWriter.write(",\n")
                }
                firstEntry = false
                recWriter.write("    ${record}")

                if (processed % 100 == 0 || processed == total) {
                    log("[CLASIFICADOR] $processed / $total archivos organizados...")
                }
            }
        }

        val totalClassified = counts.values.sum()
        BufferedWriter(OutputStreamWriter(FileOutputStream(manifestFile), Charsets.UTF_8)).use { writer ->
            writer.write("{\n")
            writer.write("  \"proyecto\": \"WoS Forensic Extractor\",\n")
            writer.write("  \"fechaUtc\": ${JSONObject.quote(isoFormatter.format(Date()))},\n")
            writer.write("  \"isoOrigen\": ${JSONObject.quote(isoSourceName)},\n")
            writer.write("  \"directorioVolcado\": ${JSONObject.quote(dumpRoot.absolutePath)},\n")
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
            writer.write("    \"totalArchivos\": $totalClassified,\n")
            writer.write("    \"totalBytes\": $totalBytes,\n")
            writer.write("    \"ddsCabecerasReconstruidas\": $ddsReconstructedCount,\n")
            writer.write("    \"audiosConvertidos48kHzPs4\": $audioConverted48kHzCount,\n")
            val countsJson = JSONObject()
            counts.forEach { (k, v) -> countsJson.put(k, v) }
            val formattedCounts = countsJson.toString(2).replace("\n", "\n    ")
            writer.write("    \"conteoPorCategoria\": $formattedCounts\n")
            writer.write("  }\n")
            writer.write("}\n")
            writer.flush()
        }

        runCatching {
            if (tempDir.exists()) {
                log("[LIMPIEZA] Eliminando carpeta temporal: ${tempDir.absolutePath}")
                tempDir.deleteRecursively()
            }
        }.onFailure { e ->
            log("[WARN] No se pudo borrar completamente la carpeta temporal: ${e.message}")
        }

        log("[FIN] Volcado forense completado en: ${dumpRoot.absolutePath}")
        return ClassificationSummary(
            dumpRootDir = dumpRoot.absolutePath,
            manifestPath = manifestFile.absolutePath,
            totalFiles = totalClassified,
            totalBytes = totalBytes,
            ddsReconstructedCount = ddsReconstructedCount,
            audioConverted48kHzCount = audioConverted48kHzCount,
            countsByCategory = counts
        )
    }

    private fun detectCategory(filePath: String, head: ByteArray): String {
        val f = File(filePath)
        val ext = if (f.extension.isNotEmpty()) ".${f.extension.lowercase()}" else ""
        val nameLower = f.name.lowercase()
        val ascii = toPrintableAscii(head)

        if (ext in setOf(".bik", ".bk2", ".smk", ".avi", ".wmv", ".mp4") ||
            startsWithAscii(head, "BIKi") || startsWithAscii(head, "BIKf") || startsWithAscii(head, "KB2")
        ) {
            return ForensicCategories.CAT_02_VIDEOS
        }

        if (ext in setOf(
                ".wav", ".ogg", ".mp3", ".wma", ".xma", ".fsb", ".xwb", ".xsb",
                ".bnk", ".wem", ".adpcm", ".snd", ".sfx", ".mus"
            ) ||
            startsWithAscii(head, "RIFF") || startsWithAscii(head, "OggS") ||
            startsWithAscii(head, "FSB") || startsWithAscii(head, "WBND") ||
            startsWithAscii(head, "BKHD") || startsWithAscii(head, "ID3")
        ) {
            return ForensicCategories.CAT_01_AUDIO
        }

        if (ext in setOf(".dds", ".tex", ".png", ".jpg", ".jpeg", ".tga", ".bmp", ".img", ".txd") ||
            startsWithAscii(head, "DDS ") || startsWithAscii(head, "IMG") || startsWithAscii(head, "TEX") ||
            (head.size >= 4 && head[0] == 0x89.toByte() && head[1] == 0x50.toByte() &&
                head[2] == 0x4E.toByte() && head[3] == 0x47.toByte()) ||
            (head.size >= 3 && head[0] == 0xFF.toByte() && head[1] == 0xD8.toByte() && head[2] == 0xFF.toByte())
        ) {
            return ForensicCategories.CAT_03_TEXTURES
        }

        if (ext in setOf(".mesh", ".pcgv", ".pcvx", ".cvxlo", ".mdl", ".obj", ".fbx", ".geo") ||
            startsWithAscii(head, "MESH") || startsWithAscii(head, "PCGV") ||
            startsWithAscii(head, "PCVX") || startsWithAscii(head, "CVXLO")
        ) {
            return ForensicCategories.CAT_04_MODELS
        }

        if (ext in setOf(".anim", ".skel", ".skelmap", ".anm", ".hkx", ".rig") ||
            startsWithAscii(head, "ANIM") || startsWithAscii(head, "SKELMAP") || startsWithAscii(head, "SKEL")
        ) {
            return ForensicCategories.CAT_05_SKELETONS
        }

        if (ext in setOf(".coll", ".phys", ".bsp", ".lvl", ".map", ".zone", ".nav", ".col") ||
            startsWithAscii(head, "COLL") || startsWithAscii(head, "PHYS")
        ) {
            return ForensicCategories.CAT_06_PHYSICS
        }

        if (ext in setOf(".ent", ".json", ".json_ise", ".lua", ".luac", ".py", ".scr", ".ai", ".cmb", ".xml", ".cfg", ".ini") ||
            startsWithAscii(head, "ENT") || startsWithAscii(head, "JSON_ISE") ||
            ascii.trimStart().startsWith("{") ||
            (head.size >= 4 && head[0] == 0x1B.toByte() && head[1] == 0x4C.toByte() &&
                head[2] == 0x75.toByte() && head[3] == 0x61.toByte())
        ) {
            return ForensicCategories.CAT_07_ENTITIES
        }

        if (ext in setOf(".loc", ".lng", ".str", ".txt", ".csv", ".sub", ".srt", ".ttf", ".otf", ".fnt", ".font") ||
            nameLower.contains("subtitle") || nameLower.contains("dialog") || nameLower.contains("font") ||
            nameLower.contains("english") || nameLower.contains("spanish") || nameLower.contains("french") ||
            nameLower.contains("german") || nameLower.contains("italian") ||
            Regex("(^|[_\\-.])(es|en|fr|de|it)([_\\-.]|$)").containsMatchIn(nameLower)
        ) {
            return ForensicCategories.CAT_08_TEXTS
        }

        if (ext in setOf(".pcvs", ".pcps", ".pcsv", ".pcsx", ".fx", ".fxo", ".cso", ".hlsl", ".exe", ".dll", ".xex", ".sys", ".idt", ".tbl") ||
            nameLower == "default.xex" || nameLower.startsWith("!") ||
            startsWithAscii(head, "PCVS") || startsWithAscii(head, "PCPS") ||
            startsWithAscii(head, "PCSV") || startsWithAscii(head, "PCSX") ||
            startsWithAscii(head, "XEX2") || startsWithAscii(head, "DXBC") ||
            (head.size >= 2 && head[0] == 0x4D.toByte() && head[1] == 0x5A.toByte())
        ) {
            return ForensicCategories.CAT_09_ENGINE
        }

        return ForensicCategories.CAT_09_ENGINE
    }

    private fun inspectRawDxtTex(head64: ByteArray, fileSize: Int): TexDdsInfo? {
        if (head64.size < 16 || fileSize < 128) return null
        val ascii = toPrintableAscii(head64)
        var fourCc: String? = null
        var fourCcOffset = -1
        val dxt1Idx = ascii.indexOf("DXT1")
        val dxt5Idx = ascii.indexOf("DXT5")
        if (dxt1Idx >= 0) {
            fourCc = "DXT1"
            fourCcOffset = dxt1Idx
        } else if (dxt5Idx >= 0) {
            fourCc = "DXT5"
            fourCcOffset = dxt5Idx
        }
        if (fourCc == null) return null

        val blockSize = if (fourCc == "DXT1") 8 else 16
        val bd = ByteBuffer.wrap(head64).order(ByteOrder.LITTLE_ENDIAN)
        var width = 0
        var height = 0
        var mipCount = 1
        var payloadOffset = 0

        var pos = 0
        while (pos + 8 <= head64.size && pos <= 48) {
            val w = bd.getInt(pos)
            val h = bd.getInt(pos + 4)
            if (isValidTexDim(w) && isValidTexDim(h)) {
                val baseLevelBytes = ((w + 3) / 4) * ((h + 3) / 4) * blockSize
                if (baseLevelBytes <= fileSize) {
                    width = w
                    height = h
                    if (pos + 12 <= head64.size) {
                        val mips = bd.getInt(pos + 8)
                        if (mips in 1..14) mipCount = mips
                    }
                    val headerEndGuess = maxOf(fourCcOffset + 4, pos + 12)
                    payloadOffset = ((headerEndGuess + 3) / 4) * 4
                    if (fileSize - payloadOffset < baseLevelBytes) payloadOffset = 0
                    break
                }
            }
            pos += 4
        }

        if (width == 0 || height == 0) {
            payloadOffset = if (fourCcOffset + 4 <= 32) ((fourCcOffset + 7) / 4) * 4 else 0
            val avail = fileSize - payloadOffset
            val inferred = inferDimensionsFromPayload(avail, blockSize)
            width = inferred[0]
            height = inferred[1]
            if (width == 0 || height == 0) return null
        }

        return TexDdsInfo(fourCc, width, height, mipCount, payloadOffset)
    }

    private fun writeReconstructedDds(sourceTexFile: File, destDdsFile: File, info: TexDdsInfo): Boolean {
        return try {
            val blockSize = if (info.fourCc == "DXT1") 8 else 16
            val linearSize = ((info.width + 3) / 4) * ((info.height + 3) / 4) * blockSize
            val hdr = ByteBuffer.allocate(128).order(ByteOrder.LITTLE_ENDIAN)
            hdr.putInt(0x00, 0x20534444)
            hdr.putInt(0x04, 124)
            val dwFlags = if (info.mipCount > 1) 0x000A1007 else 0x00081007
            hdr.putInt(0x08, dwFlags)
            hdr.putInt(0x0C, info.height)
            hdr.putInt(0x10, info.width)
            hdr.putInt(0x14, linearSize)
            hdr.putInt(0x18, 0)
            hdr.putInt(0x1C, info.mipCount)
            hdr.putInt(0x4C, 32)
            hdr.putInt(0x50, 0x00000004)
            val fourCcVal = if (info.fourCc == "DXT1") 0x31545844 else 0x35545844
            hdr.putInt(0x54, fourCcVal)
            val dwCaps = if (info.mipCount > 1) 0x00401008 else 0x00001000
            hdr.putInt(0x6C, dwCaps)

            RandomAccessFile(sourceTexFile, "r").use { raf ->
                val srcLen = raf.length()
                if (info.payloadOffset >= srcLen) return false
                FileOutputStream(destDdsFile).use { fos ->
                    fos.write(hdr.array())
                    raf.seek(info.payloadOffset.toLong())
                    val buf = ByteArray(chunkSize)
                    var remaining = srcLen - info.payloadOffset
                    while (remaining > 0L) {
                        val toRead = minOf(chunkSize.toLong(), remaining).toInt()
                        val r = raf.read(buf, 0, toRead)
                        if (r <= 0) break
                        fos.write(buf, 0, r)
                        remaining -= r
                    }
                    fos.flush()
                }
            }
            true
        } catch (e: Exception) {
            log("[DDS-ERR] No se pudo reconstruir DDS de ${sourceTexFile.name}: ${e.message}")
            false
        }
    }

    private fun safeMoveStreaming(src: File, dst: File) {
        dst.parentFile?.mkdirs()
        if (src.renameTo(dst)) return
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
        src.delete()
    }

    private fun resolveNonCollidingPath(desired: File): File {
        if (!desired.exists()) return desired
        val parent = desired.parentFile
        val base = desired.nameWithoutExtension
        val ext = if (desired.extension.isNotEmpty()) ".${desired.extension}" else ""
        var suffix = 1
        while (true) {
            val candidate = File(parent, "${base}_${suffix.toString().padStart(3, '0')}$ext")
            if (!candidate.exists()) return candidate
            suffix++
        }
    }

    private fun readHeaderBytes(file: File, maxBytes: Int): ByteArray {
        return runCatching {
            RandomAccessFile(file, "r").use { raf ->
                val toRead = minOf(maxBytes.toLong(), raf.length()).toInt()
                if (toRead <= 0) return ByteArray(0)
                ByteArray(toRead).also { raf.readFully(it) }
            }
        }.getOrElse { ByteArray(0) }
    }

    private fun startsWithAscii(bytes: ByteArray, prefix: String): Boolean {
        if (bytes.size < prefix.length) return false
        for (i in prefix.indices) {
            if ((bytes[i].toInt() and 0xFF) != prefix[i].code) return false
        }
        return true
    }

    private fun isValidTexDim(v: Int): Boolean = v in 16..4096 && (v and (v - 1)) == 0

    private fun inferDimensionsFromPayload(payloadBytes: Int, blockSize: Int): IntArray {
        val dims = intArrayOf(4096, 2048, 1024, 512, 256, 128, 64, 32, 16)
        for (w in dims) {
            for (h in dims) {
                val needed = ((w + 3) / 4) * ((h + 3) / 4) * blockSize
                if (needed == payloadBytes) return intArrayOf(w, h)
            }
        }
        for (w in dims) {
            val needed = ((w + 3) / 4) * ((w + 3) / 4) * blockSize
            if (needed <= payloadBytes) return intArrayOf(w, w)
        }
        return intArrayOf(0, 0)
    }

    private fun toHex(bytes: ByteArray): String =
        bytes.joinToString(" ") { (it.toInt() and 0xFF).toString(16).uppercase().padStart(2, '0') }

    private fun toPrintableAscii(bytes: ByteArray): String = buildString(bytes.size) {
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            append(if (v in 32..126) v.toChar() else '.')
        }
    }
}
