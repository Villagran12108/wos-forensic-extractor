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

internal class PortBinaryAnalyzer(
    private val onLog: (String) -> Unit
) {
    private val chunkSize = 65536

    private data class PeSection(
        val name: String,
        val virtualSize: Long,
        val virtualAddress: Long,
        val rawSize: Long,
        val rawAddress: Long,
        val characteristics: Long
    ) {
        fun toJson(): JSONObject = JSONObject().apply {
            put("nombre", name)
            put("virtualSize", virtualSize)
            put("virtualAddress", "0x${virtualAddress.toString(16).uppercase()}")
            put("rawSize", rawSize)
            put("rawOffset", "0x${rawAddress.toString(16).uppercase()}")
            put("characteristics", "0x${characteristics.toString(16).uppercase()}")
        }
    }

    fun processEngineBinariesCategory(
        destDir: File,
        files: List<File>,
        stats: PortCategoryStats,
        onItemDone: (src: String, dstList: List<String>, converted: Boolean, detail: String) -> Unit
    ) {
        for (file in files) {
            stats.analyzed++
            try {
                val baseName = file.nameWithoutExtension
                val jsonOut = uniquePath(File(destDir, "${baseName}_port_analysis.json"))
                val txtOut = uniquePath(File(destDir, "${baseName}_port_analysis.txt"))

                val detail = analyzeEngineBinaryOrShader(file, jsonOut, txtOut)
                stats.converted++
                onLog("[BIN/PORT] Analizado: ${file.name} ($detail)")
                onItemDone(file.absolutePath, listOf(jsonOut.absolutePath, txtOut.absolutePath), true, detail)
            } catch (e: Exception) {
                stats.skipped++
                onLog("[CONV:SKIP] Binario/shader no analizable (${file.name}): ${e.message}")
                val fallback = uniquePath(File(destDir, file.name))
                copyFileStreaming(file, fallback)
                onItemDone(
                    file.absolutePath,
                    listOf(fallback.absolutePath),
                    false,
                    "Error analizando binario (${e.message}); original conservado"
                )
            }
        }
    }

    private fun analyzeEngineBinaryOrShader(
        sourceFile: File,
        destJsonFile: File,
        destTxtFile: File
    ): String {
        RandomAccessFile(sourceFile, "r").use { raf ->
            val fileLength = raf.length()
            if (fileLength < 8L) throw IllegalStateException("Archivo binario demasiado pequeño")

            raf.seek(0L)
            val headLen = minOf(64L, fileLength).toInt()
            val head64 = ByteArray(headLen)
            raf.readFully(head64)
            val magicStr = printableAscii(head64.copyOfRange(0, minOf(8, head64.size)))

            val analysis = JSONObject().apply {
                put("archivoOrigen", sourceFile.name)
                put("tamanoBytes", fileLength)
                put("firma", magicStr)
            }

            val sections = ArrayList<PeSection>()
            val importedDlls = LinkedHashMap<String, MutableList<String>>()
            val exportedFunctions = ArrayList<String>()
            val shaderConstants = ArrayList<String>()

            if (head64.size >= 64 && head64[0] == 0x4D.toByte() && head64[1] == 0x5A.toByte()) {
                parsePeCoffBinary(raf, fileLength, head64, analysis, sections, importedDlls, exportedFunctions)
            } else if (magicStr.startsWith("XEX2")) {
                parseXex2Binary(raf, fileLength, analysis, importedDlls)
            } else if (magicStr.startsWith("PCVS") || magicStr.startsWith("PCPS") ||
                magicStr.startsWith("PCSV") || magicStr.startsWith("PCSX") ||
                magicStr.startsWith("DXBC") || sourceFile.extension.lowercase().contains("fx")
            ) {
                parseShaderBinary(raf, fileLength, magicStr, analysis, shaderConstants)
            } else {
                analysis.put("tipoFormato", "Binario / Tabla de motor / MSI")
            }

            val technicalStrings = scanTechnicalPortStrings(raf, fileLength)

            analysis.put("secciones", JSONArray(sections.map { it.toJson() }))
            val importsJson = JSONObject()
            importedDlls.forEach { (k, v) -> importsJson.put(k, JSONArray(v)) }
            analysis.put("libreriasImportadas", importsJson)
            analysis.put("funcionesExportadas", JSONArray(exportedFunctions))
            if (shaderConstants.isNotEmpty()) {
                analysis.put("constantesShader", JSONArray(shaderConstants))
            }
            analysis.put("cadenasTecnicasCount", technicalStrings.size)
            analysis.put("cadenasTecnicas", JSONArray(technicalStrings))

            destJsonFile.parentFile?.mkdirs()
            destJsonFile.writeText(analysis.toString(2), Charsets.UTF_8)

            destTxtFile.parentFile?.mkdirs()
            BufferedWriter(OutputStreamWriter(FileOutputStream(destTxtFile), Charsets.UTF_8)).use { txt ->
                txt.write("=== WoS C++ PORT ANALYSIS ===\n")
                txt.write("Archivo: ${sourceFile.name} ($fileLength bytes)\n")
                txt.write("Formato: ${analysis.optString("tipoFormato", magicStr)}\n")
                if (analysis.has("arquitectura")) {
                    txt.write("Arquitectura: ${analysis.getString("arquitectura")}\n")
                }
                if (analysis.has("entryPoint")) {
                    txt.write("EntryPoint: ${analysis.getString("entryPoint")}\n")
                }
                txt.write("\n--- SECCIONES (${sections.size}) ---\n")
                for (s in sections) {
                    txt.write(
                        "${s.name.padEnd(10)} VA=0x${s.virtualAddress.toString(16)} RawOff=0x${s.rawAddress.toString(16)} RawSize=${s.rawSize}\n"
                    )
                }
                txt.write("\n--- LIBRERÍAS IMPORTADAS (${importedDlls.size}) ---\n")
                for ((dll, fns) in importedDlls) {
                    txt.write("[$dll] (${fns.size} funciones): ${fns.take(25).joinToString(", ")}\n")
                }
                if (exportedFunctions.isNotEmpty()) {
                    txt.write("\n--- FUNCIONES EXPORTADAS (${exportedFunctions.size}) ---\n")
                    for (fn in exportedFunctions.take(200)) {
                        txt.write("  $fn\n")
                    }
                }
                if (shaderConstants.isNotEmpty()) {
                    txt.write("\n--- CONSTANTES DE SHADER (${shaderConstants.size}) ---\n")
                    for (c in shaderConstants) {
                        txt.write("  $c\n")
                    }
                }
                txt.write("\n--- CADENAS TÉCNICAS / RUTAS CPP (${technicalStrings.size}) ---\n")
                for (ts in technicalStrings) {
                    txt.write("  $ts\n")
                }
                txt.flush()
            }

            return "${sections.size} secciones, ${importedDlls.size} DLLs, ${technicalStrings.size} cadenas técnicas"
        }
    }

    private fun parsePeCoffBinary(
        raf: RandomAccessFile,
        fileLength: Long,
        head64: ByteArray,
        analysisOut: JSONObject,
        sectionsOut: MutableList<PeSection>,
        importsOut: MutableMap<String, MutableList<String>>,
        exportsOut: MutableList<String>
    ) {
        val dosBd = ByteBuffer.wrap(head64).order(ByteOrder.LITTLE_ENDIAN)
        val peOffset = dosBd.getInt(0x3C).toLong() and 0xFFFFFFFFL
        if (peOffset <= 0L || peOffset + 256L > fileLength) {
            analysisOut.put("tipoFormato", "DOS / MZ sin cabecera PE válida")
            return
        }

        raf.seek(peOffset)
        val peHdr = ByteArray(minOf(512L, fileLength - peOffset).toInt())
        raf.readFully(peHdr)
        if (peHdr.size < 24 || peHdr[0] != 0x50.toByte() || peHdr[1] != 0x45.toByte() ||
            peHdr[2] != 0.toByte() || peHdr[3] != 0.toByte()
        ) {
            analysisOut.put("tipoFormato", "MZ sin firma PE\\0\\0")
            return
        }

        val peBd = ByteBuffer.wrap(peHdr).order(ByteOrder.LITTLE_ENDIAN)
        val machine = peBd.getShort(4).toInt() and 0xFFFF
        val numSections = peBd.getShort(6).toInt() and 0xFFFF
        val timeStamp = peBd.getInt(8).toLong() and 0xFFFFFFFFL
        val optHeaderSize = peBd.getShort(20).toInt() and 0xFFFF
        val optMagic = if (peHdr.size >= 26) peBd.getShort(24).toInt() and 0xFFFF else 0
        val isPe64 = optMagic == 0x020B

        analysisOut.put("tipoFormato", if (isPe64) "PE32+ (64-bit)" else "PE32 (32-bit)")
        analysisOut.put(
            "arquitectura",
            when (machine) {
                0x014C -> "x86 (0x014C)"
                0x8664 -> "x86_64 (0x8664)"
                else -> "0x${machine.toString(16)}"
            }
        )
        analysisOut.put("timeDateStamp", timeStamp)

        if (peHdr.size >= 44) {
            val entryRva = peBd.getInt(40).toLong() and 0xFFFFFFFFL
            analysisOut.put("entryPoint", "0x${entryRva.toString(16).uppercase()}")
        }

        val sectionsTableOffset = peOffset + 24L + optHeaderSize.toLong()
        if (numSections in 1..96 && sectionsTableOffset + (numSections * 40L) <= fileLength) {
            raf.seek(sectionsTableOffset)
            val secBytes = ByteArray(numSections * 40)
            raf.readFully(secBytes)
            val secBd = ByteBuffer.wrap(secBytes).order(ByteOrder.LITTLE_ENDIAN)
            for (i in 0 until numSections) {
                val base = i * 40
                val secName = readNullPaddedAscii(secBytes.copyOfRange(base, base + 8))
                sectionsOut.add(
                    PeSection(
                        name = secName,
                        virtualSize = secBd.getInt(base + 8).toLong() and 0xFFFFFFFFL,
                        virtualAddress = secBd.getInt(base + 12).toLong() and 0xFFFFFFFFL,
                        rawSize = secBd.getInt(base + 16).toLong() and 0xFFFFFFFFL,
                        rawAddress = secBd.getInt(base + 20).toLong() and 0xFFFFFFFFL,
                        characteristics = secBd.getInt(base + 36).toLong() and 0xFFFFFFFFL
                    )
                )
            }
        }

        fun rvaToOffset(rva: Long): Long? {
            for (s in sectionsOut) {
                val span = maxOf(s.virtualSize, s.rawSize)
                if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
                    val off = s.rawAddress + (rva - s.virtualAddress)
                    if (off in 0L until fileLength) return off
                }
            }
            return null
        }

        val dataDirStart = if (isPe64) 24 + 112 else 24 + 96
        if (peHdr.size >= dataDirStart + 16) {
            val exportRva = peBd.getInt(dataDirStart).toLong() and 0xFFFFFFFFL
            val importRva = peBd.getInt(dataDirStart + 8).toLong() and 0xFFFFFFFFL

            if (importRva > 0L) {
                val impOff = rvaToOffset(importRva)
                if (impOff != null) {
                    val descBytes = ByteArray(20)
                    for (d in 0 until 256) {
                        val descPos = impOff + (d * 20L)
                        if (descPos + 20L > fileLength) break
                        raf.seek(descPos)
                        raf.readFully(descBytes)
                        val descBd = ByteBuffer.wrap(descBytes).order(ByteOrder.LITTLE_ENDIAN)
                        val origFirstThunk = descBd.getInt(0).toLong() and 0xFFFFFFFFL
                        val nameRva = descBd.getInt(12).toLong() and 0xFFFFFFFFL
                        val firstThunk = descBd.getInt(16).toLong() and 0xFFFFFFFFL
                        if (nameRva == 0L && firstThunk == 0L) break

                        val dllNameOff = rvaToOffset(nameRva) ?: continue
                        val dllName = readCStringAt(raf, dllNameOff, fileLength)
                        if (dllName.isEmpty()) continue

                        val funcs = ArrayList<String>()
                        val thunkRva = if (origFirstThunk != 0L) origFirstThunk else firstThunk
                        val thunkOff = rvaToOffset(thunkRva)
                        if (thunkOff != null) {
                            val entrySize = if (isPe64) 8 else 4
                            val tBytes = ByteArray(entrySize)
                            for (t in 0 until 1024) {
                                val tPos = thunkOff + (t.toLong() * entrySize)
                                if (tPos + entrySize > fileLength) break
                                raf.seek(tPos)
                                raf.readFully(tBytes)
                                val tBd = ByteBuffer.wrap(tBytes).order(ByteOrder.LITTLE_ENDIAN)
                                val value = if (isPe64) tBd.getLong(0) else (tBd.getInt(0).toLong() and 0xFFFFFFFFL)
                                if (value == 0L) break

                                val byOrdinal = if (isPe64) {
                                    (value and Long.MIN_VALUE) != 0L
                                } else {
                                    (value and 0x80000000L) != 0L
                                }
                                if (byOrdinal) {
                                    funcs.add("Ordinal_${value and 0xFFFFL}")
                                } else {
                                    val hintNameOff = rvaToOffset(value and 0x7FFFFFFFL)
                                    if (hintNameOff != null && hintNameOff + 2L < fileLength) {
                                        val fn = readCStringAt(raf, hintNameOff + 2L, fileLength)
                                        if (fn.isNotEmpty()) funcs.add(fn)
                                    }
                                }
                            }
                        }
                        importsOut[dllName] = funcs
                    }
                }
            }

            if (exportRva > 0L) {
                val expOff = rvaToOffset(exportRva)
                if (expOff != null && expOff + 40L <= fileLength) {
                    raf.seek(expOff)
                    val expBytes = ByteArray(40)
                    raf.readFully(expBytes)
                    val expBd = ByteBuffer.wrap(expBytes).order(ByteOrder.LITTLE_ENDIAN)
                    val numNames = expBd.getInt(24)
                    val addrOfNamesRva = expBd.getInt(32).toLong() and 0xFFFFFFFFL
                    val namesOff = rvaToOffset(addrOfNamesRva)
                    if (namesOff != null && numNames in 1..8192) {
                        raf.seek(namesOff)
                        val readLen = minOf(numNames.toLong() * 4L, fileLength - namesOff).toInt()
                        val namePtrs = ByteArray(readLen)
                        raf.readFully(namePtrs)
                        val ptrBd = ByteBuffer.wrap(namePtrs).order(ByteOrder.LITTLE_ENDIAN)
                        var n = 0
                        while (n + 4 <= namePtrs.size) {
                            val fnRva = ptrBd.getInt(n).toLong() and 0xFFFFFFFFL
                            val fnOff = rvaToOffset(fnRva)
                            if (fnOff != null) {
                                val fn = readCStringAt(raf, fnOff, fileLength)
                                if (fn.isNotEmpty()) exportsOut.add(fn)
                            }
                            n += 4
                        }
                    }
                }
            }
        }
    }

    private fun parseXex2Binary(
        raf: RandomAccessFile,
        fileLength: Long,
        analysisOut: JSONObject,
        importsOut: MutableMap<String, MutableList<String>>
    ) {
        analysisOut.put("tipoFormato", "Xbox 360 XEX2 Executable")
        analysisOut.put("arquitectura", "PowerPC Xenon (Big-Endian)")
        if (fileLength < 24L) return

        raf.seek(0L)
        val hdr = ByteArray(minOf(4096L, fileLength).toInt())
        raf.readFully(hdr)
        val bd = ByteBuffer.wrap(hdr).order(ByteOrder.BIG_ENDIAN)

        val moduleFlags = bd.getInt(4).toLong() and 0xFFFFFFFFL
        val peDataOffset = bd.getInt(8).toLong() and 0xFFFFFFFFL
        val headerCount = bd.getInt(16)

        analysisOut.put("moduleFlags", "0x${moduleFlags.toString(16).uppercase()}")
        analysisOut.put("peDataOffset", "0x${peDataOffset.toString(16).uppercase()}")
        analysisOut.put("optionalHeaderCount", headerCount)

        var cursor = 24
        for (i in 0 until headerCount) {
            if (cursor + 8 > hdr.size) break
            val key = bd.getInt(cursor)
            val valueOrOffset = bd.getInt(cursor + 4).toLong() and 0xFFFFFFFFL
            cursor += 8

            if (key == 0x00010100) {
                analysisOut.put("entryPoint", "0x${valueOrOffset.toString(16).uppercase()}")
            } else if (key == 0x000103FF && valueOrOffset > 0L && valueOrOffset + 16L < fileLength) {
                raf.seek(valueOrOffset)
                val impBlk = ByteArray(minOf(4096L, fileLength - valueOrOffset).toInt())
                raf.readFully(impBlk)
                if (impBlk.size >= 16) {
                    val impBd = ByteBuffer.wrap(impBlk).order(ByteOrder.BIG_ENDIAN)
                    val strTableSize = impBd.getInt(4)
                    val libCount = impBd.getInt(8)
                    if (strTableSize in 1..2047 && 12 + strTableSize <= impBlk.size) {
                        val strBytes = impBlk.copyOfRange(12, 12 + strTableSize)
                        var pStr = 0
                        for (l in 0 until libCount) {
                            if (pStr >= strBytes.size) break
                            var end = pStr
                            while (end < strBytes.size && strBytes[end] != 0.toByte()) end++
                            if (end <= pStr) break
                            val libName = String(strBytes, pStr, end - pStr, Charsets.US_ASCII)
                            if (libName.isNotEmpty()) importsOut[libName] = ArrayList()
                            pStr = end + 1
                            while (pStr < strBytes.size && strBytes[pStr] == 0.toByte()) pStr++
                        }
                    }
                }
            }
        }
    }

    private fun parseShaderBinary(
        raf: RandomAccessFile,
        fileLength: Long,
        magicStr: String,
        analysisOut: JSONObject,
        constantsOut: MutableList<String>
    ) {
        analysisOut.put("tipoFormato", "Shader / Bytecode Gráfico ($magicStr)")
        if (magicStr.contains("VS") || magicStr.contains("SV")) {
            analysisOut.put("shaderStage", "VertexShader")
        } else if (magicStr.contains("PS") || magicStr.contains("SX")) {
            analysisOut.put("shaderStage", "PixelShader")
        }

        val seen = HashSet<String>()
        val shaderHint = Regex(
            "^(vs_\\d_\\d|ps_\\d_\\d|[A-Za-z_][A-Za-z0-9_]*(Matrix|World|View|Proj|Light|Color|Texture|Sampler|Map|Pos|Normal|UV|Bone|Skin|Alpha|Specular|Fog)[A-Za-z0-9_]*)$",
            RegexOption.IGNORE_CASE
        )

        var pos = 0L
        while (pos < fileLength && constantsOut.size < 512) {
            raf.seek(pos)
            val toRead = minOf(chunkSize.toLong(), fileLength - pos).toInt()
            val chunk = ByteArray(toRead)
            val read = raf.read(chunk)
            if (read <= 0) break

            var i = 0
            while (i < read) {
                if (isAsciiIdentChar(chunk[i].toInt() and 0xFF)) {
                    val start = i
                    while (i < read && isAsciiIdentChar(chunk[i].toInt() and 0xFF) && (i - start) < 96) i++
                    if (i - start >= 4) {
                        val s = String(chunk, start, i - start, Charsets.US_ASCII)
                        if (shaderHint.matches(s) && seen.add(s)) {
                            constantsOut.add(s)
                        }
                    }
                }
                i++
            }
            if (pos + read >= fileLength) break
            pos += read - 128
        }
    }

    private fun scanTechnicalPortStrings(raf: RandomAccessFile, fileLength: Long): List<String> {
        val results = ArrayList<String>()
        val seen = HashSet<String>()
        val techRegex = Regex(
            "(\\.(cpp|hpp|h|c|fx|hlsl|dll|exe|xex|lib|pdb|bik|pcpack)\\b|::|^[A-Za-z]:\\\\|\\\\src\\\\|Treyarch|Shaba|Spider|WebOfShadows|D3D|Havok|Bink)",
            RegexOption.IGNORE_CASE
        )

        var pos = 0L
        val overlap = 256
        while (pos < fileLength && results.size < 1500) {
            raf.seek(pos)
            val toRead = minOf(chunkSize.toLong(), fileLength - pos).toInt()
            val chunk = ByteArray(toRead)
            val read = raf.read(chunk)
            if (read <= 0) break

            var i = 0
            while (i < read && results.size < 1500) {
                val b = chunk[i].toInt() and 0xFF
                if (b in 32..126) {
                    val start = i
                    while (i < read && (chunk[i].toInt() and 0xFF) in 32..126 && (i - start) < 300) i++
                    if (i - start >= 6) {
                        val s = String(chunk, start, i - start, Charsets.US_ASCII).trim()
                        if (techRegex.containsMatchIn(s) && seen.add(s)) {
                            results.add(s)
                        }
                    }
                }
                i++
            }
            if (pos + read >= fileLength) break
            pos += read - overlap
        }
        return results
    }

    private fun readCStringAt(raf: RandomAccessFile, offset: Long, fileLength: Long): String {
        if (offset < 0L || offset >= fileLength) return ""
        raf.seek(offset)
        val buf = ByteArray(minOf(260L, fileLength - offset).toInt())
        val read = raf.read(buf)
        val sb = StringBuilder()
        for (i in 0 until read) {
            val b = buf[i].toInt() and 0xFF
            if (b == 0) break
            if (b !in 32..126) return ""
            sb.append(b.toChar())
        }
        return sb.toString()
    }

    private fun readNullPaddedAscii(bytes: ByteArray): String = buildString {
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            if (v == 0) break
            if (v in 32..126) append(v.toChar())
        }
    }

    private fun isAsciiIdentChar(b: Int): Boolean =
        b in 48..57 || b in 65..90 || b in 97..122 || b == 95 || b == 46 || b == 45

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
