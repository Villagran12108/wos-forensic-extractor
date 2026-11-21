package com.example.wos_forensic_extractor.domain.converter

import com.example.wos_forensic_extractor.model.PortCategoryStats
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedWriter
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import kotlin.math.abs

internal class PortSkeletonTextConverter(
    private val onLog: (String) -> Unit
) {
    private val chunkSize = 65536

    private data class ExtractedStringEntry(
        val offset: Long,
        val encoding: String,
        val detectedLanguage: String,
        val text: String
    )

    fun processSkeletonsCategory(
        destDir: File,
        files: List<File>,
        stats: PortCategoryStats,
        onItemDone: (src: String, dst: String, converted: Boolean, detail: String) -> Unit
    ) {
        for (file in files) {
            stats.analyzed++
            val ext = ".${file.extension.lowercase()}"
            if (ext == ".json") {
                try {
                    val dst = uniquePath(File(destDir, file.name))
                    copyFileStreaming(file, dst)
                    stats.converted++
                    onItemDone(file.absolutePath, dst.absolutePath, true, "JSON de esqueleto copiado")
                } catch (e: Exception) {
                    stats.skipped++
                    onLog("[CONV:SKIP] Error copiando JSON ${file.name}: ${e.message}")
                    onItemDone(file.absolutePath, file.absolutePath, false, "Error copiando JSON: ${e.message}")
                }
                continue
            }

            try {
                val outJson = uniquePath(File(destDir, "${file.nameWithoutExtension}.json"))
                val detail = extractSkeletonOrAnimToJson(file, outJson)
                stats.converted++
                onLog("[RIG/ANIM] Exportado: ${outJson.name} ($detail)")
                onItemDone(file.absolutePath, outJson.absolutePath, true, detail)
            } catch (e: Exception) {
                stats.skipped++
                onLog("[CONV:SKIP] Esqueleto/Anim no parseable (${file.name}): ${e.message}")
                val fallback = uniquePath(File(destDir, file.name))
                copyFileStreaming(file, fallback)
                onItemDone(
                    file.absolutePath,
                    fallback.absolutePath,
                    false,
                    "Estructura ANIM/SKELMAP no detectada; original conservado"
                )
            }
        }
    }

    fun processTextAndEntitiesCategory(
        categoryName: String,
        destDir: File,
        files: List<File>,
        stats: PortCategoryStats,
        onItemDone: (src: String, dstList: List<String>, converted: Boolean, detail: String) -> Unit
    ) {
        for (file in files) {
            stats.analyzed++
            val ext = ".${file.extension.lowercase()}"
            if (ext == ".ttf" || ext == ".otf") {
                try {
                    val dst = uniquePath(File(destDir, file.name))
                    copyFileStreaming(file, dst)
                    stats.converted++
                    onItemDone(file.absolutePath, listOf(dst.absolutePath), true, "Fuente tipográfica copiada")
                } catch (e: Exception) {
                    stats.skipped++
                    onLog("[CONV:SKIP] Error copiando fuente ${file.name}: ${e.message}")
                    onItemDone(file.absolutePath, listOf(file.absolutePath), false, "Error copiando fuente: ${e.message}")
                }
                continue
            }

            try {
                val baseName = file.nameWithoutExtension
                val jsonOut = uniquePath(File(destDir, "$baseName.json"))
                val csvOut = uniquePath(File(destDir, "$baseName.csv"))
                val detail = extractStringsAndParamsToJsonCsv(file, jsonOut, csvOut)
                stats.converted++
                onLog("[$categoryName] Exportado JSON+CSV: $baseName ($detail)")
                onItemDone(file.absolutePath, listOf(jsonOut.absolutePath, csvOut.absolutePath), true, detail)
            } catch (e: Exception) {
                stats.skipped++
                onLog("[CONV:SKIP] Tabla/Entidad no extraíble (${file.name}): ${e.message}")
                val fallback = uniquePath(File(destDir, file.name))
                copyFileStreaming(file, fallback)
                onItemDone(
                    file.absolutePath,
                    listOf(fallback.absolutePath),
                    false,
                    "Sin cadenas válidas (${e.message}); original conservado"
                )
            }
        }
    }

    private fun extractSkeletonOrAnimToJson(sourceFile: File, destJsonFile: File): String {
        RandomAccessFile(sourceFile, "r").use { raf ->
            val fileLength = raf.length()
            if (fileLength < 16L) throw IllegalStateException("Archivo demasiado pequeño")

            raf.seek(0L)
            val headLen = minOf(64L, fileLength).toInt()
            val head = ByteArray(headLen)
            raf.readFully(head)
            val headBd = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN)
            val magic = printableAscii(head.copyOfRange(0, minOf(8, head.size)))

            var frameCountHint = 0
            if (head.size >= 16) {
                var off = 4
                while (off <= 28 && off + 4 <= head.size) {
                    val v = headBd.getInt(off)
                    if (v in 1..30000) {
                        frameCountHint = v
                        break
                    }
                    off += 4
                }
            }

            val bones = ArrayList<JSONObject>()
            val boneNames = ArrayList<String>()
            val seenBoneNames = HashSet<String>()
            val hierarchyParents = ArrayList<Int>()
            val keyframes = ArrayList<JSONObject>()

            val bonePattern = Regex("^(Bip\\d+|Pelvis|Spine\\d*|Neck|Head|Root|Bone\\d*|[LR]_[A-Za-z0-9_]+|[A-Za-z][A-Za-z0-9_]{2,47})$")
            val knownRigKeywords = Regex(
                "(bip|pelvis|spine|head|neck|clavicle|shoulder|arm|forearm|hand|finger|thumb|thigh|calf|shin|foot|toe|root|jaw|eye|tail|cape|web|camera|weapon)",
                RegexOption.IGNORE_CASE
            )

            var pos = 0L
            val overlap = 256
            while (pos < fileLength) {
                raf.seek(pos)
                val toRead = minOf(chunkSize.toLong(), fileLength - pos).toInt()
                val chunk = ByteArray(toRead)
                val read = raf.read(chunk)
                if (read <= 0) break

                var i = 0
                while (i < read) {
                    if (isAsciiIdentChar(chunk[i].toInt() and 0xFF)) {
                        val start = i
                        while (i < read && isAsciiIdentChar(chunk[i].toInt() and 0xFF) && (i - start) < 64) {
                            i++
                        }
                        if (i < read && chunk[i] == 0.toByte() && (i - start) >= 3) {
                            val candidate = String(chunk, start, i - start, Charsets.US_ASCII)
                            if (bonePattern.matches(candidate) &&
                                (knownRigKeywords.containsMatchIn(candidate) || candidate.contains('_')) &&
                                seenBoneNames.add(candidate)
                            ) {
                                val boneJson = JSONObject().apply {
                                    put("indice", bones.size)
                                    put("nombre", candidate)
                                    put("offset", "0x${(pos + start).toString(16).uppercase()}")
                                }
                                bones.add(boneJson)
                                boneNames.add(candidate)
                            }
                        }
                    }
                    i++
                }

                if (hierarchyParents.isEmpty() && bones.size >= 3) {
                    val bd = ByteBuffer.wrap(chunk, 0, read).order(ByteOrder.LITTLE_ENDIAN)
                    var off = 0
                    while (off + (bones.size * 2) <= read) {
                        var roots = 0
                        var valid = true
                        val tempParents = ArrayList<Int>(bones.size)
                        for (b in bones.indices) {
                            val parentIdx = bd.getShort(off + (b * 2)).toInt()
                            if (parentIdx < -1 || parentIdx >= bones.size || parentIdx == b) {
                                valid = false
                                break
                            }
                            if (parentIdx == -1) roots++
                            tempParents.add(parentIdx)
                        }
                        if (valid && roots in 1..maxOf(3, bones.size / 4)) {
                            hierarchyParents.addAll(tempParents)
                            break
                        }
                        off += 2
                    }
                }

                if (keyframes.size < 4096) {
                    val bd = ByteBuffer.wrap(chunk, 0, read).order(ByteOrder.LITTLE_ENDIAN)
                    var off = 0
                    while (off + 16 <= read && keyframes.size < 4096) {
                        val qx = bd.getFloat(off)
                        val qy = bd.getFloat(off + 4)
                        val qz = bd.getFloat(off + 8)
                        val qw = bd.getFloat(off + 12)
                        if (!qx.isNaN() && !qy.isNaN() && !qz.isNaN() && !qw.isNaN() &&
                            abs(qx) <= 1.05f && abs(qy) <= 1.05f && abs(qz) <= 1.05f && abs(qw) <= 1.05f
                        ) {
                            val normSq = (qx * qx) + (qy * qy) + (qz * qz) + (qw * qw)
                            if (normSq in 0.96f..1.04f) {
                                val trivialIdentity = qx == 0f && qy == 0f && qz == 0f && qw == 1f
                                if (!trivialIdentity || keyframes.isNotEmpty()) {
                                    val quatArr = JSONArray().apply {
                                        put(String.format(Locale.US, "%.6f", qx).toDouble())
                                        put(String.format(Locale.US, "%.6f", qy).toDouble())
                                        put(String.format(Locale.US, "%.6f", qz).toDouble())
                                        put(String.format(Locale.US, "%.6f", qw).toDouble())
                                    }
                                    keyframes.add(JSONObject().apply {
                                        put("offset", "0x${(pos + off).toString(16).uppercase()}")
                                        put("quaternion", quatArr)
                                    })
                                    off += 12
                                }
                            }
                        }
                        off += 4
                    }
                }

                if (pos + read >= fileLength) break
                pos += read - overlap
            }

            if (bones.isEmpty() && keyframes.isEmpty()) {
                throw IllegalStateException("Sin nombres de huesos ni cuaterniones normalizados")
            }

            val hierarchyArr = JSONArray()
            for (idx in bones.indices) {
                val parentIdx = if (idx < hierarchyParents.size) hierarchyParents[idx] else if (idx == 0) -1 else 0
                val hObj = JSONObject().apply {
                    put("boneIndex", idx)
                    put("boneName", boneNames[idx])
                    put("parentIndex", parentIdx)
                    if (parentIdx in boneNames.indices) {
                        put("parentName", boneNames[parentIdx])
                    }
                }
                hierarchyArr.put(hObj)
            }

            val doc = JSONObject().apply {
                put("archivoOrigen", sourceFile.name)
                put("firma", magic)
                put("tamanoBytes", fileLength)
                put("conteoFramesEstimado", frameCountHint)
                put("totalHuesos", bones.size)
                put("huesos", JSONArray(bones))
                put("jerarquia", hierarchyArr)
                put("totalKeyframesMuestreados", keyframes.size)
                put("keyframes", JSONArray(keyframes))
            }

            destJsonFile.parentFile?.mkdirs()
            destJsonFile.writeText(doc.toString(2), Charsets.UTF_8)
            return "${bones.size} huesos, ${keyframes.size} keyframes"
        }
    }

    private fun extractStringsAndParamsToJsonCsv(
        sourceFile: File,
        destJsonFile: File,
        destCsvFile: File
    ): String {
        RandomAccessFile(sourceFile, "r").use { raf ->
            val fileLength = raf.length()
            if (fileLength == 0L) throw IllegalStateException("Archivo vacío")

            val fileHintLang = inferLanguageFromFilename(sourceFile.name)
            val entries = ArrayList<ExtractedStringEntry>()
            val detectedParams = LinkedHashMap<String, String>()
            val seenOffsets = HashSet<String>()

            var pos = 0L
            val overlap = 512
            while (pos < fileLength) {
                raf.seek(pos)
                val toRead = minOf(chunkSize.toLong(), fileLength - pos).toInt()
                val chunk = ByteArray(toRead)
                val read = raf.read(chunk)
                if (read <= 0) break

                var i = 0
                while (i < read) {
                    if (isReadableTextByte(chunk[i].toInt() and 0xFF)) {
                        val start = i
                        while (i < read && isReadableTextByte(chunk[i].toInt() and 0xFF) && (i - start) < 2048) {
                            i++
                        }
                        if (i - start >= 3) {
                            val rawText = String(chunk, start, i - start, Charsets.UTF_8)
                            val clean = cleanControlChars(rawText)
                            if (clean.length >= 3 && hasMeaningfulLettersOrDigits(clean)) {
                                val absOffset = pos + start
                                if (seenOffsets.add("A:$absOffset")) {
                                    val lang = if (fileHintLang != "DESCONOCIDO") fileHintLang else detectTextLanguage(clean)
                                    entries.add(ExtractedStringEntry(absOffset, "ASCII/UTF-8", lang, clean))
                                    captureKeyValueParam(clean, detectedParams)
                                }
                            }
                        }
                    }
                    i++
                }

                var u = 0
                while (u + 5 < read) {
                    if (isUtf16LeCharAt(chunk, u)) {
                        val start = u
                        val sb = StringBuilder()
                        while (u + 1 < read && isUtf16LeCharAt(chunk, u) && sb.length < 1024) {
                            val codeUnit = (chunk[u].toInt() and 0xFF) or ((chunk[u + 1].toInt() and 0xFF) shl 8)
                            sb.append(codeUnit.toChar())
                            u += 2
                        }
                        if (sb.length >= 3) {
                            val clean = cleanControlChars(sb.toString())
                            if (clean.length >= 3 && hasMeaningfulLettersOrDigits(clean)) {
                                val absOffset = pos + start
                                if (seenOffsets.add("U:$absOffset")) {
                                    val lang = if (fileHintLang != "DESCONOCIDO") fileHintLang else detectTextLanguage(clean)
                                    entries.add(ExtractedStringEntry(absOffset, "UTF-16LE", lang, clean))
                                    captureKeyValueParam(clean, detectedParams)
                                }
                            }
                        }
                    } else {
                        u += 2
                    }
                }

                if (pos + read >= fileLength) break
                pos += read - overlap
            }

            if (entries.isEmpty()) {
                throw IllegalStateException("No se hallaron cadenas ASCII ni UTF-16LE legibles")
            }

            destCsvFile.parentFile?.mkdirs()
            BufferedWriter(OutputStreamWriter(FileOutputStream(destCsvFile), Charsets.UTF_8)).use { csv ->
                csv.write("ID_Offset,Idioma_Detectado,Texto_Limpio\n")
                for (entry in entries) {
                    val idOffset = "0x${entry.offset.toString(16).uppercase()}"
                    csv.write("${csvEscape(idOffset)},${csvEscape(entry.detectedLanguage)},${csvEscape(entry.text)}\n")
                }
                csv.flush()
            }

            destJsonFile.parentFile?.mkdirs()
            BufferedWriter(OutputStreamWriter(FileOutputStream(destJsonFile), Charsets.UTF_8)).use { json ->
                json.write("{\n")
                json.write("  \"archivoOrigen\": ${JSONObject.quote(sourceFile.name)},\n")
                json.write("  \"tamanoBytes\": $fileLength,\n")
                json.write("  \"totalCadenas\": ${entries.size},\n")
                val paramsJson = JSONObject()
                detectedParams.forEach { (k, v) -> paramsJson.put(k, v) }
                json.write("  \"parametrosDetectados\": ${paramsJson.toString(2).replace("\n", "\n  ")},\n")
                json.write("  \"entradas\": [\n")
                for (idx in entries.indices) {
                    val e = entries[idx]
                    val row = JSONObject().apply {
                        put("idOffset", "0x${e.offset.toString(16).uppercase()}")
                        put("idiomaDetectado", e.detectedLanguage)
                        put("codificacion", e.encoding)
                        put("textoLimpio", e.text)
                    }
                    val comma = if (idx < entries.size - 1) "," else ""
                    json.write("    $row$comma\n")
                }
                json.write("  ]\n")
                json.write("}\n")
                json.flush()
            }

            return "${entries.size} cadenas (${detectedParams.size} parámetros)"
        }
    }

    private fun isAsciiIdentChar(b: Int): Boolean =
        b in 48..57 || b in 65..90 || b in 97..122 || b == 95 || b == 46 || b == 45

    private fun isReadableTextByte(b: Int): Boolean =
        b in 32..126 || b == 9 || b == 10 || b == 13

    private fun isUtf16LeCharAt(buf: ByteArray, offset: Int): Boolean {
        if (offset + 1 >= buf.size) return false
        val lo = buf[offset].toInt() and 0xFF
        val hi = buf[offset + 1].toInt() and 0xFF
        if (hi == 0x00) return lo in 0x20..0x7E || lo in 0xA0..0xFF
        return hi == 0x01 && lo <= 0x7F
    }

    private fun cleanControlChars(raw: String): String =
        raw.replace(Regex("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]"), "")
            .replace(Regex("[\\r\\n\\t]+"), " ")
            .trim()

    private fun hasMeaningfulLettersOrDigits(s: String): Boolean =
        Regex("[A-Za-zÁÉÍÓÚÜÑáéíóúüñ0-9]{2,}").containsMatchIn(s)

    private fun inferLanguageFromFilename(filename: String): String {
        val lower = filename.lowercase()
        return when {
            lower.contains("spanish") || Regex("(^|[_\\-.])es([_\\-.]|$)").containsMatchIn(lower) -> "ES"
            lower.contains("english") || Regex("(^|[_\\-.])en([_\\-.]|$)").containsMatchIn(lower) -> "EN"
            lower.contains("french") || Regex("(^|[_\\-.])fr([_\\-.]|$)").containsMatchIn(lower) -> "FR"
            lower.contains("german") || Regex("(^|[_\\-.])de([_\\-.]|$)").containsMatchIn(lower) -> "DE"
            lower.contains("italian") || Regex("(^|[_\\-.])it([_\\-.]|$)").containsMatchIn(lower) -> "IT"
            else -> "DESCONOCIDO"
        }
    }

    private fun detectTextLanguage(text: String): String {
        val lower = " ${text.lowercase()} "
        return when {
            Regex("[áéíóúüñ¿¡]").containsMatchIn(lower) ||
                Regex(" (el|la|los|las|que|para|con|por|una|spider|ciudad|misión) ").containsMatchIn(lower) -> "ES"
            Regex(" (le|la|les|des|avec|pour|dans|vous|est) ").containsMatchIn(lower) -> "FR"
            Regex(" (der|die|das|und|mit|für|nicht|ist) ").containsMatchIn(lower) -> "DE"
            Regex(" (che|per|con|gli|una|questo|sono) ").containsMatchIn(lower) -> "IT"
            Regex(" (the|and|with|for|you|this|from|attack|mission|damage) ").containsMatchIn(lower) -> "EN"
            else -> "TECH/EN"
        }
    }

    private fun captureKeyValueParam(line: String, paramsOut: MutableMap<String, String>) {
        if (paramsOut.size >= 512) return
        val m = Regex("^([A-Za-z_][A-Za-z0-9_.\\-]{1,48})\\s*[:=]\\s*(.+)$").find(line)
        if (m != null) {
            paramsOut[m.groupValues[1]] = m.groupValues[2].trim()
        }
    }

    private fun csvEscape(value: String): String = "\"${value.replace("\"", "\"\"")}\""

    private fun printableAscii(bytes: ByteArray): String = buildString(bytes.size) {
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            append(if (v in 32..126) v.toChar() else '.')
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
