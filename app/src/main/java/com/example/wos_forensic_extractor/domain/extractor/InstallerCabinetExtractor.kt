package com.example.wos_forensic_extractor.domain.extractor

import android.content.Context
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.Inflater

class InstallerCabinetExtractor(
    private val context: Context,
    private val onLog: (String) -> Unit
) {
    private val chunkSize = 65536

    fun extractInstallersAndCabinets(rootDir: File) {
        val nativeLibDir = context.applicationInfo.nativeLibraryDir
        val sevenZipBin = if (!nativeLibDir.isNullOrEmpty()) File(nativeLibDir, "lib7zz.so") else null
        val unshieldBin = if (!nativeLibDir.isNullOrEmpty()) File(nativeLibDir, "libunshield.so") else null

        val has7zz = sevenZipBin != null && sevenZipBin.exists() && sevenZipBin.canExecute()
        val hasUnshield = unshieldBin != null && unshieldBin.exists() && unshieldBin.canExecute()

        // 2A. Extract .msi files first (may contain embedded .cab files)
        val msiFiles = findFilesByExtension(rootDir, setOf(".msi"))
        for (msi in msiFiles) {
            val outSubDir = File(msi.parentFile, "${msi.nameWithoutExtension}_msi_extracted")
            outSubDir.mkdirs()
            onLog("[7ZZ] Extrayendo paquete MSI: ${msi.name}")
            if (has7zz) {
                val code = runProcessStreaming(
                    sevenZipBin!!.absolutePath,
                    listOf("x", msi.absolutePath, "-o${outSubDir.absolutePath}", "-y"),
                    "7ZZ-MSI"
                )
                if (code > 1) {
                    onLog("[WARN] lib7zz.so devolvió código $code para ${msi.name}, aplicando escáner MSI/CAB nativo.")
                    carveEmbeddedCabinetsFromMsi(msi, outSubDir)
                }
            } else {
                carveEmbeddedCabinetsFromMsi(msi, outSubDir)
            }
        }

        // 2B. Detect .hdr and .cab (including those extracted from .msi)
        val hdrFiles = findFilesByExtension(rootDir, setOf(".hdr"))
        val cabFiles = findFilesByExtension(rootDir, setOf(".cab")).sortedBy { it.absolutePath.lowercase() }

        val processedGroups = HashSet<String>()
        val handledCabs = HashSet<String>()

        for (hdr in hdrFiles) {
            val dirPath = hdr.parentFile?.absolutePath ?: continue
            val hdrBase = hdr.nameWithoutExtension.lowercase()
            val groupPrefix = hdrBase.replace(Regex("\\d+$"), "")
            val groupKey = "$dirPath::$groupPrefix"
            if (!processedGroups.add(groupKey)) continue

            val siblingCabs = cabFiles.filter { c ->
                c.parentFile?.absolutePath == dirPath &&
                    (c.nameWithoutExtension.lowercase().replace(Regex("\\d+$"), "") == groupPrefix ||
                        c.nameWithoutExtension.lowercase() == hdrBase)
            }
            siblingCabs.forEach { handledCabs.add(it.absolutePath) }

            val targetVolume = siblingCabs.firstOrNull() ?: hdr
            val outSubDir = File(hdr.parentFile, "${groupPrefix}_unshield_extracted")
            outSubDir.mkdirs()

            onLog("[UNSHIELD] Extrayendo grupo InstallShield ($groupPrefix): ${targetVolume.name}")
            if (hasUnshield) {
                val code = runProcessStreaming(
                    unshieldBin!!.absolutePath,
                    listOf("-d", outSubDir.absolutePath, "x", targetVolume.absolutePath),
                    "UNSHIELD"
                )
                if (code != 0) {
                    onLog("[WARN] libunshield.so finalizó con código $code en ${targetVolume.name}.")
                }
            } else {
                var carved = 0
                for (vol in siblingCabs.ifEmpty { listOf(targetVolume) }) {
                    carved += carveZlibStreams(vol, outSubDir, vol.nameWithoutExtension)
                }
                onLog("[UNSHIELD] Flujos InstallShield tallados en Kotlin: $carved elementos de $groupPrefix")
            }
        }

        for (cab in cabFiles) {
            if (handledCabs.contains(cab.absolutePath)) continue
            val magic = readFirstBytes(cab, 4)
            val isInstallShield = magic.size >= 4 &&
                magic[0] == 0x49.toByte() &&
                magic[1] == 0x53.toByte() &&
                magic[2] == 0x63.toByte() &&
                magic[3] == 0x28.toByte()

            val dirPath = cab.parentFile?.absolutePath ?: ""
            val cabBase = cab.nameWithoutExtension.lowercase()
            val groupPrefix = cabBase.replace(Regex("\\d+$"), "")

            if (isInstallShield) {
                val groupKey = "$dirPath::$groupPrefix"
                if (!processedGroups.add(groupKey)) continue
                val outSubDir = File(cab.parentFile, "${groupPrefix}_unshield_extracted")
                outSubDir.mkdirs()
                onLog("[UNSHIELD] CAB InstallShield detectado por firma ISc(: ${cab.name}")
                if (hasUnshield) {
                    val code = runProcessStreaming(
                        unshieldBin!!.absolutePath,
                        listOf("-d", outSubDir.absolutePath, "x", cab.absolutePath),
                        "UNSHIELD"
                    )
                    if (code != 0) {
                        onLog("[WARN] libunshield.so devolvió código $code en ${cab.name}.")
                    }
                } else {
                    val carved = carveZlibStreams(cab, outSubDir, cab.nameWithoutExtension)
                    onLog("[UNSHIELD] Flujos InstallShield extraídos: $carved elementos de ${cab.name}")
                }
            } else {
                val outSubDir = File(cab.parentFile, "${cab.nameWithoutExtension}_cab_extracted")
                outSubDir.mkdirs()
                onLog("[7ZZ] Extrayendo CAB estándar: ${cab.name}")
                if (has7zz) {
                    val code = runProcessStreaming(
                        sevenZipBin!!.absolutePath,
                        listOf("x", cab.absolutePath, "-o${outSubDir.absolutePath}", "-y"),
                        "7ZZ-CAB"
                    )
                    if (code > 1) {
                        onLog("[WARN] lib7zz.so devolvió código $code en ${cab.name}.")
                    }
                } else {
                    val count = extractMscfCab(cab, outSubDir)
                    onLog("[7ZZ-CAB] Extraídos $count archivos de ${cab.name}")
                }
            }
        }
    }

    private fun carveEmbeddedCabinetsFromMsi(msiFile: File, outDir: File) {
        val len = msiFile.length()
        if (len < 64L) return
        var cabIndex = 0
        RandomAccessFile(msiFile, "r").use { raf ->
            val buf = ByteArray(chunkSize)
            var pos = 0L
            while (pos < len - 36L) {
                raf.seek(pos)
                val toRead = minOf(chunkSize.toLong(), len - pos).toInt()
                val read = raf.read(buf, 0, toRead)
                if (read < 36) break
                var i = 0
                while (i + 36 <= read) {
                    if (buf[i] == 0x4D.toByte() && buf[i + 1] == 0x53.toByte() &&
                        buf[i + 2] == 0x43.toByte() && buf[i + 3] == 0x46.toByte()
                    ) {
                        val cabSize = ByteBuffer.wrap(buf, i + 8, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                        val absOff = pos + i
                        if (cabSize in 64L..(len - absOff)) {
                            val cabTmp = File(outDir, "embedded_${cabIndex++}.cab")
                            copyRange(raf, absOff, cabSize, cabTmp)
                            onLog("[7ZZ-MSI] CAB embebido detectado en MSI (${cabTmp.name}, $cabSize bytes)")
                            i += 36
                            continue
                        }
                    }
                    i++
                }
                if (pos + read >= len) break
                pos += read - 36
            }
        }
    }

    /**
     * Pure-Kotlin MSCF Cabinet extractor supporting uncompressed (type 0) and MSZIP deflate (type 1) folders.
     */
    private fun extractMscfCab(cabFile: File, outDir: File): Int {
        RandomAccessFile(cabFile, "r").use { raf ->
            val len = raf.length()
            if (len < 36L) return 0
            val hdr = ByteArray(36)
            raf.seek(0L)
            raf.readFully(hdr)
            if (hdr[0] != 0x4D.toByte() || hdr[1] != 0x53.toByte() ||
                hdr[2] != 0x43.toByte() || hdr[3] != 0x46.toByte()
            ) {
                return 0
            }

            val bd = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN)
            val offsetFiles = bd.getInt(16).toLong() and 0xFFFFFFFFL
            val flags = bd.getShort(24).toInt() and 0xFFFF
            val numFolders = bd.getShort(26).toInt() and 0xFFFF
            val numFiles = bd.getShort(28).toInt() and 0xFFFF

            var cursor = 36L
            if ((flags and 0x0004) != 0) {
                raf.seek(cursor)
                val extHdr = ByteArray(4)
                raf.readFully(extHdr)
                val cbCFHeader = ByteBuffer.wrap(extHdr, 0, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
                cursor += 4L + cbCFHeader
            }

            data class CabFolder(val dataOffset: Long, val numBlocks: Int, val compType: Int)
            val folders = ArrayList<CabFolder>(numFolders)
            val folderBuf = ByteArray(8)
            for (f in 0 until numFolders) {
                raf.seek(cursor)
                raf.readFully(folderBuf)
                val fbd = ByteBuffer.wrap(folderBuf).order(ByteOrder.LITTLE_ENDIAN)
                val dataOff = fbd.getInt(0).toLong() and 0xFFFFFFFFL
                val cBlocks = fbd.getShort(4).toInt() and 0xFFFF
                val typeCompress = fbd.getShort(6).toInt() and 0x000F
                folders.add(CabFolder(dataOff, cBlocks, typeCompress))
                cursor += 8L
            }

            data class CabFileEntry(
                val size: Int,
                val folderOffset: Int,
                val folderIndex: Int,
                val name: String
            )
            val entries = ArrayList<CabFileEntry>(numFiles)
            raf.seek(offsetFiles)
            val fileHeaderBuf = ByteArray(16)
            for (i in 0 until numFiles) {
                if (raf.filePointer + 16 > len) break
                raf.readFully(fileHeaderBuf)
                val ebd = ByteBuffer.wrap(fileHeaderBuf).order(ByteOrder.LITTLE_ENDIAN)
                val cbFile = ebd.getInt(0)
                val uoffFolderStart = ebd.getInt(4)
                val iFolder = ebd.getShort(8).toInt() and 0xFFFF
                val nameBytes = ByteArrayOutputStream()
                while (raf.filePointer < len) {
                    val b = raf.read()
                    if (b <= 0) break
                    nameBytes.write(b)
                }
                val rawName = nameBytes.toString("UTF-8").replace('\\', '/')
                entries.add(CabFileEntry(cbFile, uoffFolderStart, iFolder, rawName))
            }

            var extracted = 0
            for ((folderIdx, folder) in folders.withIndex()) {
                val folderEntries = entries.filter { it.folderIndex == folderIdx }.sortedBy { it.folderOffset }
                if (folderEntries.isEmpty()) continue
                if (folder.compType != 0 && folder.compType != 1) {
                    onLog("[WARN] Compresión CAB tipo ${folder.compType} (LZX/Quantum) no soportada sin lib7zz.so en ${cabFile.name}")
                    continue
                }

                // Stream folder data blocks sequentially
                val blockHdr = ByteArray(8)
                var dataPos = folder.dataOffset
                val folderOut = ByteArrayOutputStream()
                for (b in 0 until folder.numBlocks) {
                    if (dataPos + 8 > len) break
                    raf.seek(dataPos)
                    raf.readFully(blockHdr)
                    val bbd = ByteBuffer.wrap(blockHdr).order(ByteOrder.LITTLE_ENDIAN)
                    val cbData = bbd.getShort(4).toInt() and 0xFFFF
                    val cbUncomp = bbd.getShort(6).toInt() and 0xFFFF
                    dataPos += 8L
                    if (dataPos + cbData > len) break
                    val compBytes = ByteArray(cbData)
                    raf.seek(dataPos)
                    raf.readFully(compBytes)
                    dataPos += cbData

                    if (folder.compType == 0) {
                        folderOut.write(compBytes)
                    } else if (folder.compType == 1 && cbData >= 2) {
                        // MSZIP starts with "CK" (0x43 0x4B) before raw deflate stream
                        val startIdx = if (compBytes[0] == 0x43.toByte() && compBytes[1] == 0x4B.toByte()) 2 else 0
                        val inflater = Inflater(true)
                        try {
                            inflater.setInput(compBytes, startIdx, cbData - startIdx)
                            val outBuf = ByteArray(maxOf(cbUncomp, 32768))
                            val inflated = inflater.inflate(outBuf)
                            folderOut.write(outBuf, 0, inflated)
                        } catch (_: Exception) {
                        } finally {
                            inflater.end()
                        }
                    }
                }

                val uncompressedData = folderOut.toByteArray()
                for (entry in folderEntries) {
                    if (entry.folderOffset >= 0 && entry.folderOffset + entry.size <= uncompressedData.size) {
                        val safeRel = entry.name.split('/').filter { it.isNotBlank() && it != ".." }.joinToString("/")
                        if (safeRel.isEmpty()) continue
                        val outFile = File(outDir, safeRel)
                        outFile.parentFile?.mkdirs()
                        FileOutputStream(outFile).use { fos ->
                            fos.write(uncompressedData, entry.folderOffset, entry.size)
                        }
                        extracted++
                    }
                }
            }
            return extracted
        }
    }

    private fun carveZlibStreams(file: File, outDir: File, baseName: String): Int {
        var carved = 0
        RandomAccessFile(file, "r").use { raf ->
            val fileLength = raf.length()
            var pos = 0L
            val window = ByteArray(chunkSize)
            while (pos < fileLength - 16L) {
                raf.seek(pos)
                val winLen = minOf(chunkSize.toLong(), fileLength - pos).toInt()
                val read = raf.read(window, 0, winLen)
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

                val maxTry = minOf(16L * 1024L * 1024L, fileLength - foundOffset).toInt()
                val tmpOut = File(outDir, ".tmp_carve_$carved")
                val ok = tryInflateAt(raf, foundOffset, maxTry, tmpOut)
                if (ok) {
                    val tag = foundOffset.toString(16).uppercase().padStart(8, '0')
                    val dst = File(outDir, "${baseName}_$tag.bin")
                    tmpOut.renameTo(dst)
                    carved++
                    pos = foundOffset + 64L
                } else {
                    if (tmpOut.exists()) tmpOut.delete()
                    pos = foundOffset + 2L
                }
            }
        }
        return carved
    }

    private fun tryInflateAt(raf: RandomAccessFile, offset: Long, maxLen: Int, outFile: File): Boolean {
        val inflater = Inflater(false)
        return try {
            raf.seek(offset)
            val inBuf = ByteArray(chunkSize)
            val outBuf = ByteArray(chunkSize)
            var remaining = maxLen
            var totalOut = 0L
            FileOutputStream(outFile).use { fos ->
                while (remaining > 0 && !inflater.finished()) {
                    val toRead = minOf(chunkSize, remaining)
                    val r = raf.read(inBuf, 0, toRead)
                    if (r <= 0) break
                    remaining -= r
                    inflater.setInput(inBuf, 0, r)
                    while (!inflater.needsInput() && !inflater.finished()) {
                        val count = inflater.inflate(outBuf)
                        if (count > 0) {
                            fos.write(outBuf, 0, count)
                            totalOut += count
                        } else if (inflater.needsDictionary()) {
                            return false
                        } else {
                            break
                        }
                    }
                }
                fos.flush()
            }
            totalOut > 0L && inflater.finished()
        } catch (_: Exception) {
            false
        } finally {
            inflater.end()
        }
    }

    private fun copyRange(raf: RandomAccessFile, offset: Long, length: Long, dst: File) {
        val buf = ByteArray(chunkSize)
        raf.seek(offset)
        FileOutputStream(dst).use { fos ->
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

    private fun runProcessStreaming(executable: String, arguments: List<String>, tag: String): Int {
        val process = ProcessBuilder(listOf(executable) + arguments).start()
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

    private fun findFilesByExtension(rootDir: File, extensions: Set<String>): List<File> {
        if (!rootDir.exists()) return emptyList()
        return rootDir.walkTopDown()
            .filter { it.isFile && ".${it.extension.lowercase()}" in extensions }
            .toList()
    }

    private fun readFirstBytes(file: File, count: Int): ByteArray {
        return runCatching {
            RandomAccessFile(file, "r").use { raf ->
                val toRead = minOf(count.toLong(), raf.length()).toInt()
                if (toRead <= 0) return ByteArray(0)
                ByteArray(toRead).also { raf.readFully(it) }
            }
        }.getOrElse { ByteArray(0) }
    }
}
