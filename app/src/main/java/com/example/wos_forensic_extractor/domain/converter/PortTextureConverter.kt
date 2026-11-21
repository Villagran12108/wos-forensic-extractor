package com.example.wos_forensic_extractor.domain.converter

import com.example.wos_forensic_extractor.model.PortCategoryStats
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal class PortTextureConverter(
    private val onLog: (String) -> Unit
) {
    private val chunkSize = 65536

    private data class TexHeaderMatch(
        val format: String,
        val width: Int,
        val height: Int,
        val mipCount: Int,
        val payloadOffset: Int
    )

    fun processTexturesCategory(
        destDir: File,
        files: List<File>,
        stats: PortCategoryStats,
        onItemDone: (src: String, dst: String, converted: Boolean, detail: String) -> Unit
    ) {
        for (file in files) {
            stats.analyzed++
            val ext = ".${file.extension.lowercase()}"
            try {
                val head128 = readHeader(file, 128)
                val isAlreadyDds = head128.size >= 4 &&
                    String(head128, 0, 4, Charsets.US_ASCII) == "DDS "

                if ((ext == ".dds" && isAlreadyDds) || ext in setOf(".png", ".jpg", ".jpeg")) {
                    val dst = uniquePath(File(destDir, file.name))
                    copyFileStreaming(file, dst)
                    stats.converted++
                    onItemDone(file.absolutePath, dst.absolutePath, true, "Imagen/DDS estándar copiada limpia")
                    continue
                }

                val fileLen = file.length()
                val match = parseProprietaryTextureHeader(head128, fileLen)
                    ?: throw IllegalStateException("No se detectó firma DXT1/DXT3/DXT5/ATI2/RGBA ni dimensiones válidas")

                val ddsOut = uniquePath(File(destDir, "${file.nameWithoutExtension}.dds"))
                writeStandardDdsFromTex(file, ddsOut, match)

                stats.converted++
                onLog("[TEX->DDS] Reconstruido ${ddsOut.name} (${match.width}x${match.height} ${match.format})")
                onItemDone(
                    file.absolutePath,
                    ddsOut.absolutePath,
                    true,
                    "Cabecera DDS 128B reconstruida (${match.width}x${match.height}, ${match.format})"
                )
            } catch (e: Exception) {
                stats.skipped++
                onLog("[CONV:SKIP] Textura no convertible (${file.name}): ${e.message}")
                val fallback = uniquePath(File(destDir, file.name))
                copyFileStreaming(file, fallback)
                onItemDone(
                    file.absolutePath,
                    fallback.absolutePath,
                    false,
                    "Formato propietario no reconocido; original conservado"
                )
            }
        }
    }

    private fun parseProprietaryTextureHeader(head128: ByteArray, fileSize: Long): TexHeaderMatch? {
        if (head128.size < 16 || fileSize < 64L) return null
        val ascii = buildString(head128.size) {
            for (b in head128) {
                val v = b.toInt() and 0xFF
                append(if (v in 32..126) v.toChar() else '.')
            }
        }

        var format: String? = null
        var formatPos = -1
        for (candidate in listOf("DXT1", "DXT3", "DXT5", "ATI2", "RGBA")) {
            val idx = ascii.indexOf(candidate)
            if (idx >= 0) {
                format = candidate
                formatPos = idx
                break
            }
        }
        if (format == null) return null

        val bd = ByteBuffer.wrap(head128).order(ByteOrder.LITTLE_ENDIAN)
        var width = 0
        var height = 0
        var mipCount = 1
        var payloadOffset = 0
        val minBlockBytes = when (format) {
            "RGBA" -> 4
            "DXT1" -> 8
            else -> 16
        }

        var pos = 0
        while (pos + 8 <= head128.size) {
            val w = bd.getInt(pos)
            val h = bd.getInt(pos + 4)
            if (isPowerOfTwoDim(w) && isPowerOfTwoDim(h)) {
                val expectedLevel0 = if (format == "RGBA") {
                    w.toLong() * h.toLong() * 4L
                } else {
                    (((w + 3) / 4).toLong() * ((h + 3) / 4).toLong() * minBlockBytes.toLong())
                }
                if (expectedLevel0 <= fileSize) {
                    width = w
                    height = h
                    if (pos + 12 <= head128.size) {
                        val m = bd.getInt(pos + 8)
                        if (m in 1..14) mipCount = m
                    }
                    val endMark = maxOf(formatPos + 4, pos + 8)
                    payloadOffset = ((endMark + 3) / 4) * 4
                    if (fileSize - payloadOffset < expectedLevel0) payloadOffset = 0
                    break
                }
            }
            pos += 4
        }

        if (width == 0 || height == 0) {
            payloadOffset = if (formatPos + 4 <= 64) ((formatPos + 7) / 4) * 4 else 0
            val avail = (fileSize - payloadOffset).toInt()
            val dims = inferTextureDims(avail, format)
            width = dims[0]
            height = dims[1]
            if (width == 0 || height == 0) return null
        }

        return TexHeaderMatch(format, width, height, mipCount, payloadOffset)
    }

    private fun writeStandardDdsFromTex(sourceFile: File, destFile: File, match: TexHeaderMatch) {
        val ddsHeader = ByteBuffer.allocate(128).order(ByteOrder.LITTLE_ENDIAN)
        ddsHeader.putInt(0x00, 0x20534444)
        ddsHeader.putInt(0x04, 124)

        val isRgba = match.format == "RGBA"
        val blockSize = if (match.format == "DXT1") 8 else 16
        val pitchOrLinearSize = if (isRgba) {
            match.width * 4
        } else {
            ((match.width + 3) / 4) * ((match.height + 3) / 4) * blockSize
        }

        val dwFlags = if (isRgba) 0x000A100F else 0x000A1007
        ddsHeader.putInt(0x08, dwFlags)
        ddsHeader.putInt(0x0C, match.height)
        ddsHeader.putInt(0x10, match.width)
        ddsHeader.putInt(0x14, pitchOrLinearSize)
        ddsHeader.putInt(0x18, 0)
        ddsHeader.putInt(0x1C, match.mipCount)

        ddsHeader.putInt(0x4C, 32)
        if (isRgba) {
            ddsHeader.putInt(0x50, 0x00000041)
            ddsHeader.putInt(0x54, 0)
            ddsHeader.putInt(0x58, 32)
            ddsHeader.putInt(0x5C, 0x00FF0000)
            ddsHeader.putInt(0x60, 0x0000FF00)
            ddsHeader.putInt(0x64, 0x000000FF)
            ddsHeader.putInt(0x68, 0xFF000000.toInt())
        } else {
            ddsHeader.putInt(0x50, 0x00000004)
            ddsHeader.putInt(0x54, fourCcToInt32(match.format))
        }

        val dwCaps = if (match.mipCount > 1) 0x00401008 else 0x00001000
        ddsHeader.putInt(0x6C, dwCaps)

        RandomAccessFile(sourceFile, "r").use { raf ->
            val srcLen = raf.length()
            if (match.payloadOffset >= srcLen) {
                throw IllegalStateException("Offset de payload fuera de rango")
            }
            destFile.parentFile?.mkdirs()
            FileOutputStream(destFile).use { fos ->
                fos.write(ddsHeader.array())
                raf.seek(match.payloadOffset.toLong())
                val buf = ByteArray(chunkSize)
                var remaining = srcLen - match.payloadOffset
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
    }

    private fun isPowerOfTwoDim(v: Int): Boolean = v in 16..4096 && (v and (v - 1)) == 0

    private fun inferTextureDims(payloadBytes: Int, format: String): IntArray {
        val blockSize = if (format == "DXT1") 8 else 16
        val dims = intArrayOf(4096, 2048, 1024, 512, 256, 128, 64, 32, 16)
        for (w in dims) {
            for (h in dims) {
                val needed = if (format == "RGBA") w * h * 4 else ((w + 3) / 4) * ((h + 3) / 4) * blockSize
                if (needed == payloadBytes) return intArrayOf(w, h)
            }
        }
        for (w in dims) {
            val needed = if (format == "RGBA") w * w * 4 else ((w + 3) / 4) * ((w + 3) / 4) * blockSize
            if (needed <= payloadBytes) return intArrayOf(w, w)
        }
        return intArrayOf(0, 0)
    }

    private fun fourCcToInt32(fourCc: String): Int {
        return fourCc[0].code or (fourCc[1].code shl 8) or (fourCc[2].code shl 16) or (fourCc[3].code shl 24)
    }

    private fun readHeader(file: File, maxBytes: Int): ByteArray {
        RandomAccessFile(file, "r").use { raf ->
            val toRead = minOf(maxBytes.toLong(), raf.length()).toInt()
            if (toRead <= 0) return ByteArray(0)
            return ByteArray(toRead).also { raf.readFully(it) }
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
