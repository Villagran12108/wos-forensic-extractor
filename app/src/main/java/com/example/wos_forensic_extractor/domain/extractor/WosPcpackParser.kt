package com.example.wos_forensic_extractor.domain.extractor

import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.Inflater

class WosPcpackParser(
    private val onLog: ((String) -> Unit)? = null
) {
    private val chunkSize = 65536
    private val containerExtensions = setOf(".pack", ".pcpack", ".pcapk", ".apkf")

    private data class PackEntry(
        val hash: Long,
        val offset: Long,
        val compressedSize: Long,
        val uncompressedSize: Long,
        val name: String?
    )

    private data class CandidateTableLayout(
        val tableOffset: Long,
        val entryCount: Int,
        val stride: Int,
        val entries: List<PackEntry>
    )

    private fun log(msg: String) {
        onLog?.invoke(msg)
    }

    fun unpackAllContainers(rootDir: File): Int {
        val processedContainers = HashSet<String>()
        var totalExtractedAssets = 0

        var foundNew = true
        while (foundNew) {
            foundNew = false
            if (!rootDir.exists()) break

            val candidates = ArrayList<File>()
            rootDir.walkTopDown().forEach { entity ->
                if (entity.isFile && !processedContainers.contains(entity.absolutePath)) {
                    if (isEngineContainer(entity)) {
                        candidates.add(entity)
                    }
                }
            }

            if (candidates.isNotEmpty()) {
                foundNew = true
            }

            for (container in candidates) {
                processedContainers.add(container.absolutePath)
                val outDir = File(container.parentFile, "${container.nameWithoutExtension}_unpacked")
                try {
                    val count = unpackSingleContainer(container, outDir)
                    totalExtractedAssets += count
                } catch (e: Exception) {
                    log("[PACK-ERR] Error procesando ${container.name}: ${e.message}")
                }
            }
        }
        return totalExtractedAssets
    }

    private fun isEngineContainer(file: File): Boolean {
        val ext = ".${file.extension.lowercase()}"
        return runCatching {
            val len = file.length()
            if (len < 16L) return false
            RandomAccessFile(file, "r").use { raf ->
                val header = ByteArray(8)
                val r = raf.read(header)
                if (r < 4) return false
                val ascii8 = String(header, 0, r, Charsets.ISO_8859_1)
                if (ascii8.contains("PCPACK") ||
                    ascii8.contains("KCAPCP") ||
                    ascii8.contains("APKF") ||
                    ascii8.contains("PCSTOC")
                ) {
                    return true
                }
                ext in containerExtensions
            }
        }.getOrDefault(false)
    }

    private fun unpackSingleContainer(containerFile: File, outputDir: File): Int {
        RandomAccessFile(containerFile, "r").use { raf ->
            val fileLength = raf.length()
            if (fileLength < 24L) return 0

            raf.seek(0L)
            val hdrLen = minOf(128L, fileLength).toInt()
            val headerBytes = ByteArray(hdrLen)
            raf.readFully(headerBytes)
            val headerData = ByteBuffer.wrap(headerBytes).order(ByteOrder.LITTLE_ENDIAN)

            val magicAscii = extractPrintableMagic(headerBytes, 8)
            log("[PACK] Analizando ${containerFile.name} ($fileLength bytes, firma=\"$magicAscii\")")

            val layout = detectTableLayout(raf, headerBytes, headerData, fileLength)
            if (layout == null || layout.entries.isEmpty()) {
                log("[PACK] Tabla estándar no detectada en ${containerFile.name}; ejecutando tallado por flujos zlib/magic...")
                return carveZlibStreamsFallback(
                    raf = raf,
                    fileLength = fileLength,
                    outputDir = outputDir,
                    containerName = containerFile.nameWithoutExtension
                )
            }

            if (!outputDir.exists()) outputDir.mkdirs()
            var extracted = 0

            for (i in layout.entries.indices) {
                val entry = layout.entries[i]
                val rawLen = if (entry.compressedSize > 0L) entry.compressedSize else entry.uncompressedSize
                if (rawLen <= 0L || entry.offset < 0L || entry.offset + rawLen > fileLength) {
                    continue
                }

                val hashHex = entry.hash.toString(16).uppercase().padStart(8, '0')
                val tempOutFile = File(outputDir, ".tmp_entry_${i}_$hashHex")

                val isCompressed = entry.compressedSize > 0L &&
                    entry.uncompressedSize > 0L &&
                    entry.compressedSize != entry.uncompressedSize

                var written = false
                if (isCompressed) {
                    written = decompressEntryStreaming(raf, entry.offset, entry.compressedSize, tempOutFile)
                    if (!written) {
                        copyRangeStreaming(raf, entry.offset, rawLen, tempOutFile)
                        written = true
                    }
                } else {
                    copyRangeStreaming(raf, entry.offset, rawLen, tempOutFile)
                    written = true
                }

                if (!written || !tempOutFile.exists()) continue

                val finalName = if (!entry.name.isNullOrBlank()) {
                    val sanitized = sanitizeRelativeName(entry.name)
                    if (sanitized.isNotEmpty()) sanitized else "$hashHex${detectExtensionFromMagic(tempOutFile)}"
                } else {
                    val ext = detectExtensionFromMagic(tempOutFile)
                    "$hashHex$ext"
                }

                val finalFile = uniquePath(File(outputDir, finalName))
                finalFile.parentFile?.mkdirs()
                if (!tempOutFile.renameTo(finalFile)) {
                    tempOutFile.copyTo(finalFile, overwrite = true)
                    tempOutFile.delete()
                }
                extracted++
            }

            log("[PACK] Extraídos $extracted sub-archivos de ${containerFile.name}.")
            return extracted
        }
    }

    private fun detectTableLayout(
        raf: RandomAccessFile,
        headerBytes: ByteArray,
        headerData: ByteBuffer,
        fileLength: Long
    ): CandidateTableLayout? {
        val candidateTableOffsets = LinkedHashSet<Long>()
        val candidateCounts = LinkedHashSet<Int>()

        var pos = 4
        while (pos + 4 <= headerBytes.size && pos <= 44) {
            val value = headerData.getInt(pos).toLong() and 0xFFFFFFFFL
            if (value in 1L..200000L) candidateCounts.add(value.toInt())
            if (value in 12L until (fileLength - 16L)) candidateTableOffsets.add(value)
            pos += 4
        }
        candidateTableOffsets.addAll(listOf(16L, 20L, 24L, 28L, 32L, 36L, 40L, 48L, 64L))

        var nameResolver: ((Int) -> String?)? = null
        var namePos = 12
        while (namePos + 8 <= headerBytes.size && namePos <= 40) {
            val nOff = headerData.getInt(namePos).toLong() and 0xFFFFFFFFL
            val nSize = headerData.getInt(namePos + 4).toLong() and 0xFFFFFFFFL
            if (nOff > 32L && nSize > 4L && nOff + nSize <= fileLength && nSize <= 16L * 1024L * 1024L) {
                if (looksLikeStringTable(raf, nOff, nSize.toInt())) {
                    raf.seek(nOff)
                    val nameBlob = ByteArray(nSize.toInt())
                    raf.readFully(nameBlob)
                    nameResolver = { relOffset -> readCString(nameBlob, relOffset) }
                    break
                }
            }
            namePos += 4
        }

        val candidateStrides = listOf(16, 20, 24, 28, 32, 40, 48, 64)
        for (tableOff in candidateTableOffsets) {
            for (count in candidateCounts) {
                for (stride in candidateStrides) {
                    val tableEnd = tableOff + (count.toLong() * stride.toLong())
                    if (tableEnd > fileLength || tableEnd <= tableOff) continue
                    val parsed = tryParseEntryTable(raf, tableOff, count, stride, fileLength, nameResolver)
                    if (parsed != null) {
                        return CandidateTableLayout(tableOff, count, stride, parsed)
                    }
                }
            }
        }
        return null
    }

    private fun tryParseEntryTable(
        raf: RandomAccessFile,
        tableOffset: Long,
        count: Int,
        stride: Int,
        fileLength: Long,
        nameResolver: ((Int) -> String?)?
    ): List<PackEntry>? {
        val sampleCount = minOf(count, 8)
        raf.seek(tableOffset)
        val sampleBytes = ByteArray(sampleCount * stride)
        val r = raf.read(sampleBytes)
        if (r < sampleCount * stride) return null

        val fieldSchemas = buildList {
            if (stride >= 16) {
                add(intArrayOf(0, 1, 2, 3, -1))
                add(intArrayOf(0, 1, 3, 2, -1))
                add(intArrayOf(3, 0, 1, 2, -1))
            }
            if (stride >= 20) {
                add(intArrayOf(0, 1, 2, 3, 4))
                add(intArrayOf(0, 2, 3, 4, 1))
            }
            if (stride >= 24) {
                add(intArrayOf(0, 1, 2, 3, 4))
                add(intArrayOf(0, 2, 4, 5, 1))
            }
            if (stride >= 32) {
                add(intArrayOf(0, 1, 2, 3, 4))
            }
        }

        var matchedSchema: IntArray? = null
        for (schema in fieldSchemas) {
            var allValid = true
            var validDataEntries = 0
            for (i in 0 until sampleCount) {
                val row = ByteBuffer.wrap(sampleBytes, i * stride, stride).order(ByteOrder.LITTLE_ENDIAN)
                val offset = row.getInt(schema[1] * 4).toLong() and 0xFFFFFFFFL
                val uSize = row.getInt(schema[2] * 4).toLong() and 0xFFFFFFFFL
                val cSize = row.getInt(schema[3] * 4).toLong() and 0xFFFFFFFFL
                val diskSize = if (cSize > 0L) cSize else uSize
                if (diskSize == 0L && offset == 0L) continue
                if (offset < tableOffset + (count.toLong() * stride.toLong()) ||
                    diskSize <= 0L ||
                    offset + diskSize > fileLength ||
                    uSize > 512L * 1024L * 1024L
                ) {
                    allValid = false
                    break
                }
                validDataEntries++
            }
            if (allValid && validDataEntries > 0) {
                matchedSchema = schema
                break
            }
        }

        if (matchedSchema == null) return null

        val tableBytesLen = count * stride
        raf.seek(tableOffset)
        val fullTable = ByteArray(tableBytesLen)
        val readFull = raf.read(fullTable)
        if (readFull < tableBytesLen) return null

        val entries = ArrayList<PackEntry>(count)
        for (i in 0 until count) {
            val rowBase = i * stride
            val row = ByteBuffer.wrap(fullTable, rowBase, stride).order(ByteOrder.LITTLE_ENDIAN)
            val hash = row.getInt(matchedSchema[0] * 4).toLong() and 0xFFFFFFFFL
            val offset = row.getInt(matchedSchema[1] * 4).toLong() and 0xFFFFFFFFL
            val uSize = row.getInt(matchedSchema[2] * 4).toLong() and 0xFFFFFFFFL
            val cSize = row.getInt(matchedSchema[3] * 4).toLong() and 0xFFFFFFFFL

            val diskSize = if (cSize > 0L) cSize else uSize
            if (diskSize <= 0L || offset + diskSize > fileLength) continue

            var entryName: String? = null
            if (matchedSchema[4] >= 0 && nameResolver != null) {
                val nameOff = row.getInt(matchedSchema[4] * 4)
                entryName = nameResolver(nameOff)
            } else if (stride >= 48) {
                val inline = readCString(fullTable.copyOfRange(rowBase + 16, rowBase + stride), 0)
                if (inline != null && inline.contains('.')) {
                    entryName = inline
                }
            }

            entries.add(PackEntry(hash, offset, cSize, uSize, entryName))
        }
        return if (entries.isEmpty()) null else entries
    }

    private fun decompressEntryStreaming(
        raf: RandomAccessFile,
        offset: Long,
        compressedLength: Long,
        outFile: File
    ): Boolean {
        if (tryZlibStream(raf, offset, compressedLength, outFile, raw = false)) return true
        return tryZlibStream(raf, offset, compressedLength, outFile, raw = true)
    }

    private fun tryZlibStream(
        raf: RandomAccessFile,
        offset: Long,
        compressedLength: Long,
        outFile: File,
        raw: Boolean
    ): Boolean {
        val inflater = Inflater(raw)
        return try {
            raf.seek(offset)
            val inBuf = ByteArray(chunkSize)
            val outBuf = ByteArray(chunkSize)
            var remaining = compressedLength
            var totalOut = 0L

            FileOutputStream(outFile).use { fos ->
                while (remaining > 0L && !inflater.finished()) {
                    val toRead = minOf(chunkSize.toLong(), remaining).toInt()
                    val r = raf.read(inBuf, 0, toRead)
                    if (r <= 0) break
                    remaining -= r
                    inflater.setInput(inBuf, 0, r)
                    while (!inflater.needsInput() && !inflater.finished()) {
                        val written = inflater.inflate(outBuf)
                        if (written > 0) {
                            fos.write(outBuf, 0, written)
                            totalOut += written
                        } else if (inflater.needsDictionary()) {
                            return false
                        } else {
                            break
                        }
                    }
                }
                fos.flush()
            }
            totalOut > 0L && outFile.exists() && outFile.length() > 0L
        } catch (_: Exception) {
            runCatching { if (outFile.exists()) outFile.delete() }
            false
        } finally {
            inflater.end()
        }
    }

    private fun copyRangeStreaming(
        raf: RandomAccessFile,
        offset: Long,
        length: Long,
        outFile: File
    ) {
        val buf = ByteArray(chunkSize)
        raf.seek(offset)
        FileOutputStream(outFile).use { fos ->
            var remaining = length
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

    private fun carveZlibStreamsFallback(
        raf: RandomAccessFile,
        fileLength: Long,
        outputDir: File,
        containerName: String
    ): Int {
        if (!outputDir.exists()) outputDir.mkdirs()
        var carvedCount = 0
        var pos = 0L
        val window = ByteArray(chunkSize)

        while (pos < fileLength - 16L) {
            raf.seek(pos)
            val windowLen = minOf(chunkSize.toLong(), fileLength - pos).toInt()
            val read = raf.read(window, 0, windowLen)
            if (read < 4) break

            var foundOffset = -1L
            for (i in 0 until read - 2) {
                if (window[i] == 0x78.toByte() &&
                    (window[i + 1] == 0x9C.toByte() ||
                        window[i + 1] == 0xDA.toByte() ||
                        window[i + 1] == 0x01.toByte() ||
                        window[i + 1] == 0x5E.toByte())
                ) {
                    foundOffset = pos + i
                    break
                }
            }

            if (foundOffset < 0L) {
                pos += read - 2
                continue
            }

            val maxTryLen = minOf(16L * 1024L * 1024L, fileLength - foundOffset)
            val tmpFile = File(outputDir, ".carve_$carvedCount")
            val ok = tryZlibStream(raf, foundOffset, maxTryLen, tmpFile, raw = false)

            if (ok) {
                val ext = detectExtensionFromMagic(tmpFile)
                val hashTag = foundOffset.toString(16).uppercase().padStart(8, '0')
                val finalFile = uniquePath(File(outputDir, "${containerName}_$hashTag$ext"))
                if (!tmpFile.renameTo(finalFile)) {
                    tmpFile.copyTo(finalFile, overwrite = true)
                    tmpFile.delete()
                }
                carvedCount++
                pos = foundOffset + 64L
            } else {
                if (tmpFile.exists()) tmpFile.delete()
                pos = foundOffset + 2L
            }
        }
        return carvedCount
    }

    private fun detectExtensionFromMagic(file: File): String {
        return runCatching {
            RandomAccessFile(file, "r").use { raf ->
                val len = minOf(16L, raf.length()).toInt()
                if (len <= 0) return ".bin"
                val magic = ByteArray(len)
                raf.readFully(magic)
                val ascii = String(magic, Charsets.ISO_8859_1)

                when {
                    ascii.startsWith("DDS ") -> ".dds"
                    ascii.startsWith("BIKi") || ascii.startsWith("BIKf") || ascii.startsWith("KB2") -> ".bik"
                    ascii.startsWith("RIFF") -> ".wav"
                    ascii.startsWith("OggS") -> ".ogg"
                    ascii.startsWith("MESH") || ascii.startsWith("PCGV") ||
                        ascii.startsWith("PCVX") || ascii.startsWith("CVXLO") -> ".mesh"
                    ascii.startsWith("ANIM") -> ".anim"
                    ascii.startsWith("SKEL") -> ".skel"
                    ascii.startsWith("TEX") || ascii.startsWith("IMG") -> ".tex"
                    ascii.startsWith("ENT") -> ".ent"
                    ascii.startsWith("COLL") -> ".coll"
                    ascii.startsWith("PHYS") -> ".phys"
                    ascii.startsWith("PCVS") || ascii.startsWith("PCSV") -> ".pcvs"
                    ascii.startsWith("PCPS") || ascii.startsWith("PCSX") -> ".pcps"
                    magic.size >= 4 && magic[0] == 0x89.toByte() && magic[1] == 0x50.toByte() &&
                        magic[2] == 0x4E.toByte() && magic[3] == 0x47.toByte() -> ".png"
                    magic.size >= 3 && magic[0] == 0xFF.toByte() && magic[1] == 0xD8.toByte() &&
                        magic[2] == 0xFF.toByte() -> ".jpg"
                    ascii.trimStart().startsWith("{") || ascii.trimStart().startsWith("[") -> ".json"
                    else -> ".bin"
                }
            }
        }.getOrDefault(".bin")
    }

    private fun looksLikeStringTable(raf: RandomAccessFile, offset: Long, size: Int): Boolean {
        raf.seek(offset)
        val sampleLen = minOf(size, 256)
        val bytes = ByteArray(sampleLen)
        val read = raf.read(bytes)
        if (read <= 0) return false
        var printable = 0
        var nulls = 0
        for (i in 0 until read) {
            val b = bytes[i].toInt() and 0xFF
            if (b == 0) nulls++ else if (b in 32..126) printable++
        }
        return nulls > 0 && (printable + nulls) > (read * 0.85)
    }

    private fun readCString(blob: ByteArray, offset: Int): String? {
        if (offset < 0 || offset >= blob.size) return null
        val sb = StringBuilder()
        for (i in offset until blob.size) {
            val b = blob[i].toInt() and 0xFF
            if (b == 0) break
            if (b !in 32..126) return null
            sb.append(b.toChar())
            if (sb.length > 260) return null
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    private fun sanitizeRelativeName(raw: String): String {
        val normalized = raw.replace('\\', '/').replace("..", "_")
        val parts = normalized.split('/')
            .map { it.replace(Regex("[<>:\"|?*\\x00-\\x1F]"), "_").trim() }
            .filter { it.isNotEmpty() }
        return if (parts.isEmpty()) "" else parts.joinToString(File.separator)
    }

    private fun extractPrintableMagic(bytes: ByteArray, len: Int): String {
        val end = minOf(bytes.size, len)
        return buildString(end) {
            for (i in 0 until end) {
                val b = bytes[i].toInt() and 0xFF
                append(if (b in 32..126) b.toChar() else '.')
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
