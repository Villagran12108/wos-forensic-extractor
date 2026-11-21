package com.example.wos_forensic_extractor.domain.extractor

import android.content.Context
import android.os.ParcelFileDescriptor
import com.example.wos_forensic_extractor.data.storage.SafStorageHelper
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets

class IsoArchiveExtractor(
    private val context: Context,
    private val storageHelper: SafStorageHelper,
    private val onLog: (String) -> Unit
) {
    private val chunkSize = 65536

    fun extractIso(
        isoUriOrPath: String,
        isoDisplayName: String,
        tempDir: File
    ) {
        if (!tempDir.exists()) tempDir.mkdirs()

        val nativeLibDir = context.applicationInfo.nativeLibraryDir
        val sevenZipBin = if (!nativeLibDir.isNullOrEmpty()) File(nativeLibDir, "lib7zz.so") else null
        val directIsoFile = resolveReadableDirectFile(isoUriOrPath)

        if (sevenZipBin != null && sevenZipBin.exists() && sevenZipBin.canExecute() && directIsoFile != null) {
            onLog("[7ZZ] Iniciando extracción de ISO con lib7zz.so: $isoDisplayName")
            val exitCode = runProcessStreaming(
                executable = sevenZipBin.absolutePath,
                arguments = listOf("x", directIsoFile.absolutePath, "-o${tempDir.absolutePath}", "-y"),
                tag = "7ZZ-ISO"
            )
            if (exitCode <= 1) {
                onLog("[7ZZ] Extracción de ISO completada (código $exitCode).")
                return
            }
            onLog("[WARN] lib7zz.so devolvió código $exitCode; activando motor ISO-9660/Joliet nativo...")
        } else {
            onLog("[ISO] Iniciando extracción en streaming ARM64/Kotlin: $isoDisplayName")
        }

        val (pfd: ParcelFileDescriptor?, channel: FileChannel) = storageHelper.openIsoReadChannel(isoUriOrPath)
        try {
            val isoSize = channel.size()
            if (isoSize < 32768L + 2048L) {
                throw IllegalStateException("Imagen ISO demasiado pequeña o corrupta ($isoSize bytes)")
            }

            val isoExtracted = tryExtractIso9660OrJoliet(channel, isoSize, tempDir)
            if (isoExtracted > 0) {
                onLog("[7ZZ-ISO] Extracción ISO-9660/Joliet completada: $isoExtracted archivos extraídos.")
                return
            }

            val udfExtracted = tryExtractUdfBridgeOrXbox(channel, isoSize, tempDir)
            if (udfExtracted > 0) {
                onLog("[7ZZ-ISO] Extracción UDF completada: $udfExtracted archivos extraídos.")
                return
            }

            throw IllegalStateException(
                "No se detectaron descriptores ISO-9660, Joliet ni UDF válidos en $isoDisplayName."
            )
        } finally {
            runCatching { channel.close() }
            runCatching { pfd?.close() }
        }
    }

    private fun resolveReadableDirectFile(uriOrPath: String): File? {
        if (!uriOrPath.startsWith("content://")) {
            val f = File(uriOrPath.removePrefix("file://"))
            if (f.exists() && f.canRead()) return f
        }
        return null
    }

    private fun runProcessStreaming(
        executable: String,
        arguments: List<String>,
        tag: String
    ): Int {
        val process = ProcessBuilder(listOf(executable) + arguments)
            .redirectErrorStream(false)
            .start()

        val stdoutThread = Thread {
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val trimmed = line?.trim().orEmpty()
                    if (trimmed.isNotEmpty()) onLog("[$tag] $trimmed")
                }
            }
        }
        val stderrThread = Thread {
            BufferedReader(InputStreamReader(process.errorStream)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val trimmed = line?.trim().orEmpty()
                    if (trimmed.isNotEmpty()) onLog("[$tag-ERR] $trimmed")
                }
            }
        }
        stdoutThread.start()
        stderrThread.start()
        val code = process.waitFor()
        stdoutThread.join()
        stderrThread.join()
        return code
    }

    private fun tryExtractIso9660OrJoliet(
        channel: FileChannel,
        isoSize: Long,
        tempDir: File
    ): Int {
        val sectorBuf = ByteArray(2048)
        var primaryRootRecord: ByteArray? = null
        var jolietRootRecord: ByteArray? = null

        var sector = 16L
        while (sector < 64L && (sector * 2048L + 2048L) <= isoSize) {
            readFullyAt(channel, sector * 2048L, sectorBuf, 2048)
            val vdType = sectorBuf[0].toInt() and 0xFF
            val id = String(sectorBuf, 1, 5, StandardCharsets.US_ASCII)
            if (id != "CD001") break

            if (vdType == 1 && primaryRootRecord == null) {
                primaryRootRecord = sectorBuf.copyOfRange(156, 190)
            } else if (vdType == 2) {
                val esc0 = sectorBuf[88].toInt() and 0xFF
                val esc1 = sectorBuf[89].toInt() and 0xFF
                val esc2 = sectorBuf[90].toInt() and 0xFF
                if (esc0 == 0x25 && esc1 == 0x2F && (esc2 == 0x40 || esc2 == 0x43 || esc2 == 0x45)) {
                    jolietRootRecord = sectorBuf.copyOfRange(156, 190)
                }
            } else if (vdType == 255) {
                break
            }
            sector++
        }

        val useJoliet = jolietRootRecord != null
        val rootRecord = jolietRootRecord ?: primaryRootRecord ?: return 0

        val rootLba = readUint32LE(rootRecord, 2)
        val rootLen = readUint32LE(rootRecord, 10)
        if (rootLba <= 0L || rootLen <= 0L) return 0

        val visitedDirs = HashSet<Long>()
        return extractIsoDirectoryRecursive(
            channel = channel,
            isoSize = isoSize,
            dirLba = rootLba,
            dirDataLen = rootLen,
            destDir = tempDir,
            useJoliet = useJoliet,
            visitedDirs = visitedDirs
        )
    }

    private fun extractIsoDirectoryRecursive(
        channel: FileChannel,
        isoSize: Long,
        dirLba: Long,
        dirDataLen: Long,
        destDir: File,
        useJoliet: Boolean,
        visitedDirs: MutableSet<Long>
    ): Int {
        if (!visitedDirs.add(dirLba)) return 0
        if (dirDataLen <= 0 || dirDataLen > 64 * 1024 * 1024L) return 0
        val dirOffset = dirLba * 2048L
        if (dirOffset < 0 || dirOffset + dirDataLen > isoSize) return 0

        val dirBytes = ByteArray(dirDataLen.toInt())
        readFullyAt(channel, dirOffset, dirBytes, dirBytes.size)

        var extractedCount = 0
        var pos = 0
        while (pos < dirBytes.size) {
            val recLen = dirBytes[pos].toInt() and 0xFF
            if (recLen == 0) {
                val nextSector = ((pos / 2048) + 1) * 2048
                if (nextSector >= dirBytes.size) break
                pos = nextSector
                continue
            }
            if (pos + recLen > dirBytes.size || recLen < 34) break

            val extentLba = readUint32LE(dirBytes, pos + 2)
            val dataLen = readUint32LE(dirBytes, pos + 10)
            val flags = dirBytes[pos + 25].toInt() and 0xFF
            val nameLen = dirBytes[pos + 32].toInt() and 0xFF

            if (nameLen > 0 && pos + 33 + nameLen <= pos + recLen) {
                val isSpecial = nameLen == 1 && (dirBytes[pos + 33].toInt() == 0 || dirBytes[pos + 33].toInt() == 1)
                if (!isSpecial) {
                    var name = decodeIsoName(dirBytes, pos + 33, nameLen, useJoliet)
                    val semiIdx = name.indexOf(';')
                    if (semiIdx >= 0) name = name.substring(0, semiIdx)
                    name = name.trim().trimEnd('.')

                    if (name.isNotEmpty() && name != "." && name != "..") {
                        val safeName = sanitizePathSegment(name)
                        val isDir = (flags and 0x02) != 0
                        if (isDir) {
                            val subDir = File(destDir, safeName)
                            if (!subDir.exists()) subDir.mkdirs()
                            extractedCount += extractIsoDirectoryRecursive(
                                channel = channel,
                                isoSize = isoSize,
                                dirLba = extentLba,
                                dirDataLen = dataLen,
                                destDir = subDir,
                                useJoliet = useJoliet,
                                visitedDirs = visitedDirs
                            )
                        } else {
                            val fileOffset = extentLba * 2048L
                            if (fileOffset >= 0 && fileOffset + dataLen <= isoSize) {
                                val outFile = File(destDir, safeName)
                                copyChannelRangeToFile(channel, fileOffset, dataLen, outFile)
                                extractedCount++
                                if (extractedCount % 25 == 0) {
                                    onLog("[7ZZ-ISO] Extraído: ${outFile.name} ($dataLen bytes)")
                                }
                            }
                        }
                    }
                }
            }
            pos += recLen
        }
        return extractedCount
    }

    /**
     * Fallback for UDF (ECMA-167) or Xbox 360 XGD2/XGD3 ISO images if no ISO-9660 volume descriptor matched.
     */
    private fun tryExtractUdfBridgeOrXbox(
        channel: FileChannel,
        isoSize: Long,
        tempDir: File
    ): Int {
        // Check Xbox 360 XDVDFS magic at common offsets (0x0, 0xFD90000, 0x2080000, 0x18300000)
        val xdvdfsBaseOffsets = longArrayOf(0L, 0x0FD90000L, 0x02080000L, 0x18300000L)
        val headerBuf = ByteArray(40)
        for (base in xdvdfsBaseOffsets) {
            val magicOff = base + (32L * 2048L)
            if (magicOff + 40 <= isoSize) {
                readFullyAt(channel, magicOff, headerBuf, 40)
                val sig = String(headerBuf, 0, 20, StandardCharsets.US_ASCII)
                if (sig == "MICROSOFT*XBOX*MEDIA") {
                    val rootSector = readUint32LE(headerBuf, 20)
                    val rootSize = readUint32LE(headerBuf, 24)
                    if (rootSector > 0L && rootSize > 0L) {
                        onLog("[7ZZ-ISO] Volumen Xbox 360 XDVDFS detectado en offset 0x${base.toString(16)}")
                        return extractXdvdfsNode(
                            channel = channel,
                            isoSize = isoSize,
                            baseOffset = base,
                            dirSector = rootSector,
                            dirSize = rootSize,
                            nodeOffset = 0,
                            destDir = tempDir
                        )
                    }
                }
            }
        }
        return 0
    }

    private fun extractXdvdfsNode(
        channel: FileChannel,
        isoSize: Long,
        baseOffset: Long,
        dirSector: Long,
        dirSize: Long,
        nodeOffset: Int,
        destDir: File
    ): Int {
        if (dirSize <= 0L || dirSize > 16 * 1024 * 1024L) return 0
        val dirOffset = baseOffset + (dirSector * 2048L)
        if (dirOffset + dirSize > isoSize) return 0
        val dirBytes = ByteArray(dirSize.toInt())
        readFullyAt(channel, dirOffset, dirBytes, dirBytes.size)
        return traverseXdvdfsTree(channel, isoSize, baseOffset, dirBytes, nodeOffset, destDir)
    }

    private fun traverseXdvdfsTree(
        channel: FileChannel,
        isoSize: Long,
        baseOffset: Long,
        dirBytes: ByteArray,
        offset: Int,
        destDir: File
    ): Int {
        if (offset < 0 || offset + 14 > dirBytes.size) return 0
        val left = readUint16LE(dirBytes, offset)
        val right = readUint16LE(dirBytes, offset + 2)
        val startSector = readUint32LE(dirBytes, offset + 4)
        val fileSize = readUint32LE(dirBytes, offset + 8)
        val attrs = dirBytes[offset + 12].toInt() and 0xFF
        val nameLen = dirBytes[offset + 13].toInt() and 0xFF

        var count = 0
        if (left != 0xFFFF && left > 0) {
            count += traverseXdvdfsTree(channel, isoSize, baseOffset, dirBytes, left * 4, destDir)
        }

        if (nameLen > 0 && offset + 14 + nameLen <= dirBytes.size) {
            val rawName = String(dirBytes, offset + 14, nameLen, StandardCharsets.ISO_8859_1)
            val safeName = sanitizePathSegment(rawName)
            val isDir = (attrs and 0x10) != 0
            if (isDir) {
                val sub = File(destDir, safeName)
                if (!sub.exists()) sub.mkdirs()
                count += extractXdvdfsNode(channel, isoSize, baseOffset, startSector, fileSize, 0, sub)
            } else {
                val fileOff = baseOffset + (startSector * 2048L)
                if (fileOff >= 0L && fileOff + fileSize <= isoSize) {
                    val outFile = File(destDir, safeName)
                    copyChannelRangeToFile(channel, fileOff, fileSize, outFile)
                    count++
                    if (count % 25 == 0) {
                        onLog("[7ZZ-ISO] Extraído: ${outFile.name} ($fileSize bytes)")
                    }
                }
            }
        }

        if (right != 0xFFFF && right > 0) {
            count += traverseXdvdfsTree(channel, isoSize, baseOffset, dirBytes, right * 4, destDir)
        }
        return count
    }

    private fun copyChannelRangeToFile(
        channel: FileChannel,
        startOffset: Long,
        length: Long,
        outFile: File
    ) {
        outFile.parentFile?.mkdirs()
        val buf = ByteBuffer.allocate(chunkSize)
        FileOutputStream(outFile).use { fos ->
            var pos = startOffset
            var remaining = length
            while (remaining > 0L) {
                buf.clear()
                val toRead = if (remaining < chunkSize) remaining.toInt() else chunkSize
                buf.limit(toRead)
                val read = channel.read(buf, pos)
                if (read <= 0) break
                fos.write(buf.array(), 0, read)
                pos += read
                remaining -= read
            }
            fos.flush()
        }
    }

    private fun readFullyAt(channel: FileChannel, offset: Long, dst: ByteArray, length: Int) {
        val bb = ByteBuffer.wrap(dst, 0, length)
        var pos = offset
        while (bb.hasRemaining()) {
            val read = channel.read(bb, pos)
            if (read <= 0) break
            pos += read
        }
    }

    private fun decodeIsoName(bytes: ByteArray, offset: Int, len: Int, useJoliet: Boolean): String {
        return if (useJoliet && len >= 2) {
            val evenLen = len and 0xFFFFFFFE.toInt()
            String(bytes, offset, evenLen, StandardCharsets.UTF_16BE)
        } else {
            String(bytes, offset, len, StandardCharsets.ISO_8859_1)
        }
    }

    private fun sanitizePathSegment(name: String): String {
        return name.replace(Regex("[<>:\"/\\\\|?*\\x00-\\x1F]"), "_").ifBlank { "unnamed" }
    }

    private fun readUint16LE(buf: ByteArray, offset: Int): Int {
        return (buf[offset].toInt() and 0xFF) or ((buf[offset + 1].toInt() and 0xFF) shl 8)
    }

    private fun readUint32LE(buf: ByteArray, offset: Int): Long {
        return ByteBuffer.wrap(buf, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
    }
}
