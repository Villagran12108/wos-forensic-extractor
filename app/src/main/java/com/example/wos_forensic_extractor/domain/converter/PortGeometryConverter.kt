package com.example.wos_forensic_extractor.domain.converter

import com.example.wos_forensic_extractor.model.PortCategoryStats
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

internal class PortGeometryConverter(
    private val onLog: (String) -> Unit
) {
    private val chunkSize = 65536

    private data class VertexBufferCandidate(
        val offset: Long,
        val stride: Int,
        val vertexCount: Int,
        val uvRelOffset: Int,
        val score: Double
    )

    private data class IndexBufferCandidate(
        val offset: Long,
        val indexCount: Int,
        val triangleCount: Int
    )

    fun processGeometryCategory(
        destDir: File,
        files: List<File>,
        stats: PortCategoryStats,
        stageLabel: String,
        onItemDone: (src: String, dst: String, converted: Boolean, detail: String) -> Unit
    ) {
        for (file in files) {
            stats.analyzed++
            val ext = ".${file.extension.lowercase()}"
            if (ext == ".obj") {
                try {
                    val dst = uniquePath(File(destDir, file.name))
                    copyFileStreaming(file, dst)
                    stats.converted++
                    onItemDone(file.absolutePath, dst.absolutePath, true, "Wavefront OBJ copiado")
                } catch (e: Exception) {
                    stats.skipped++
                    onLog("[CONV:SKIP] Error copiando OBJ ${file.name}: ${e.message}")
                    onItemDone(file.absolutePath, file.absolutePath, false, "Error copiando OBJ: ${e.message}")
                }
                continue
            }

            try {
                val objOut = uniquePath(File(destDir, "${file.nameWithoutExtension}.obj"))
                val detail = extractBinaryGeometryToObj(file, objOut)
                stats.converted++
                onLog("[$stageLabel] Exportado: ${objOut.name} ($detail)")
                onItemDone(file.absolutePath, objOut.absolutePath, true, detail)
            } catch (e: Exception) {
                stats.skipped++
                onLog("[CONV:SKIP] Malla/colisión no extraíble (${file.name}): ${e.message}")
                val fallback = uniquePath(File(destDir, file.name))
                copyFileStreaming(file, fallback)
                onItemDone(
                    file.absolutePath,
                    fallback.absolutePath,
                    false,
                    "Geometría no detectada (${e.message}); original conservado"
                )
            }
        }
    }

    private fun extractBinaryGeometryToObj(sourceFile: File, destObjFile: File): String {
        RandomAccessFile(sourceFile, "r").use { raf ->
            val fileLength = raf.length()
            if (fileLength < 64L) {
                throw IllegalStateException("Archivo demasiado pequeño ($fileLength bytes)")
            }

            val bestVb = scanBestVertexBuffer(raf, fileLength)
                ?: throw IllegalStateException("No se halló un arreglo contiguo válido de vértices float32")
            if (bestVb.vertexCount < 3) {
                throw IllegalStateException("No se halló un arreglo contiguo válido de vértices float32")
            }

            val vbEnd = bestVb.offset + (bestVb.vertexCount.toLong() * bestVb.stride.toLong())
            val bestIb = scanBestIndexBuffer(raf, fileLength, bestVb.vertexCount, bestVb.offset, vbEnd)

            destObjFile.parentFile?.mkdirs()
            try {
                BufferedWriter(OutputStreamWriter(FileOutputStream(destObjFile), Charsets.UTF_8)).use { sink ->
                    sink.write("# WoS Forensic Mesh\n")
                    sink.write("# Source: ${sourceFile.name}\n")
                    sink.write("# VertexOffset: 0x${bestVb.offset.toString(16).uppercase()} Stride: ${bestVb.stride} Count: ${bestVb.vertexCount}\n")
                    if (bestIb != null) {
                        sink.write("# IndexOffset: 0x${bestIb.offset.toString(16).uppercase()} Triangles: ${bestIb.triangleCount}\n")
                    }
                    sink.write("o ${sourceFile.nameWithoutExtension.replace(' ', '_')}\n")

                    val hasUvs = bestVb.uvRelOffset >= 0
                    val batchVertices = 2048
                    var writtenVerts = 0
                    while (writtenVerts < bestVb.vertexCount) {
                        val countNow = minOf(batchVertices, bestVb.vertexCount - writtenVerts)
                        raf.seek(bestVb.offset + (writtenVerts.toLong() * bestVb.stride.toLong()))
                        val vBytes = ByteArray(countNow * bestVb.stride)
                        val r = raf.read(vBytes)
                        if (r <= 0) break
                        val bd = ByteBuffer.wrap(vBytes, 0, r).order(ByteOrder.LITTLE_ENDIAN)

                        for (i in 0 until countNow) {
                            val base = i * bestVb.stride
                            if (base + 12 > r) break
                            val x = bd.getFloat(base)
                            val y = bd.getFloat(base + 4)
                            val z = bd.getFloat(base + 8)
                            sink.write(String.format(Locale.US, "v %.6f %.6f %.6f\n", x, y, z))

                            if (hasUvs && base + bestVb.uvRelOffset + 8 <= r) {
                                val u = bd.getFloat(base + bestVb.uvRelOffset)
                                val v = bd.getFloat(base + bestVb.uvRelOffset + 4)
                                sink.write(String.format(Locale.US, "vt %.6f %.6f\n", u, v))
                            }
                        }
                        writtenVerts += countNow
                    }

                    var exportedTriangles = 0
                    if (bestIb != null && bestIb.triangleCount > 0) {
                        val batchTriangles = 4096
                        var processedTris = 0
                        while (processedTris < bestIb.triangleCount) {
                            val trisNow = minOf(batchTriangles, bestIb.triangleCount - processedTris)
                            raf.seek(bestIb.offset + (processedTris.toLong() * 6L))
                            val iBytes = ByteArray(trisNow * 6)
                            val r = raf.read(iBytes)
                            if (r <= 0) break
                            val bd = ByteBuffer.wrap(iBytes, 0, r).order(ByteOrder.LITTLE_ENDIAN)

                            for (t in 0 until trisNow) {
                                val base = t * 6
                                if (base + 6 > r) break
                                val a = bd.getShort(base).toInt() and 0xFFFF
                                val b = bd.getShort(base + 2).toInt() and 0xFFFF
                                val c = bd.getShort(base + 4).toInt() and 0xFFFF
                                if (a < bestVb.vertexCount && b < bestVb.vertexCount && c < bestVb.vertexCount &&
                                    a != b && b != c && a != c
                                ) {
                                    val ia = a + 1
                                    val ib = b + 1
                                    val ic = c + 1
                                    if (hasUvs) {
                                        sink.write("f $ia/$ia $ib/$ib $ic/$ic\n")
                                    } else {
                                        sink.write("f $ia $ib $ic\n")
                                    }
                                    exportedTriangles++
                                }
                            }
                            processedTris += trisNow
                        }
                    } else if (bestVb.vertexCount >= 3) {
                        val triCount = bestVb.vertexCount / 3
                        for (t in 0 until triCount) {
                            val i1 = (t * 3) + 1
                            val i2 = i1 + 1
                            val i3 = i1 + 2
                            if (hasUvs) {
                                sink.write("f $i1/$i1 $i2/$i2 $i3/$i3\n")
                            } else {
                                sink.write("f $i1 $i2 $i3\n")
                            }
                            exportedTriangles++
                        }
                    }
                    sink.flush()
                    return "${bestVb.vertexCount} vértices (stride ${bestVb.stride}B), $exportedTriangles triángulos"
                }
            } catch (e: Exception) {
                if (destObjFile.exists()) destObjFile.delete()
                throw e
            }
        }
    }

    private fun scanBestVertexBuffer(raf: RandomAccessFile, fileLength: Long): VertexBufferCandidate? {
        val strides = intArrayOf(12, 24, 32, 36, 40, 48)
        val windowSize = 262144
        val overlap = 4096
        var best: VertexBufferCandidate? = null

        for (stride in strides) {
            var filePos = 0L
            while (filePos + (stride * 6L) <= fileLength) {
                raf.seek(filePos)
                val toRead = minOf(windowSize.toLong(), fileLength - filePos).toInt()
                val buf = ByteArray(toRead)
                val read = raf.read(buf)
                if (read < stride * 6) break
                val bd = ByteBuffer.wrap(buf, 0, read).order(ByteOrder.LITTLE_ENDIAN)

                var localOff = 0
                while (localOff + (stride * 6) <= read) {
                    if (isPlausibleVertex(bd, localOff)) {
                        var runCount = 0
                        var nonZeroCount = 0
                        var probeOff = localOff
                        while (probeOff + 12 <= read && isPlausibleVertex(bd, probeOff)) {
                            val x = bd.getFloat(probeOff)
                            val y = bd.getFloat(probeOff + 4)
                            val z = bd.getFloat(probeOff + 8)
                            if (abs(x) + abs(y) + abs(z) > 1e-4f) nonZeroCount++
                            runCount++
                            probeOff += stride
                        }

                        val absStart = filePos + localOff
                        if (probeOff + stride > read && absStart + (runCount.toLong() * stride.toLong()) < fileLength) {
                            runCount = extendVertexRunFromFile(raf, absStart, stride, runCount, fileLength)
                        }

                        if (runCount >= 8 && nonZeroCount >= 4) {
                            val uvRel = detectUvOffsetInStride(
                                bd, localOff, stride, minOf(runCount, (read - localOff) / stride)
                            )
                            val score = runCount.toDouble() + if (uvRel >= 0) 50.0 else 0.0
                            if (best == null || score > best.score) {
                                best = VertexBufferCandidate(absStart, stride, runCount, uvRel, score)
                            }
                        }
                        localOff += maxOf(stride, runCount * stride)
                    } else {
                        localOff += 4
                    }
                }

                if (filePos + read >= fileLength) break
                filePos += read - overlap
            }
        }
        return best
    }

    private fun extendVertexRunFromFile(
        raf: RandomAccessFile,
        startOffset: Long,
        stride: Int,
        initialCount: Int,
        fileLength: Long
    ): Int {
        var count = initialCount
        var nextPos = startOffset + (count.toLong() * stride.toLong())
        while (nextPos + 12L <= fileLength) {
            raf.seek(nextPos)
            val toRead = minOf((chunkSize - (chunkSize % stride)).toLong(), fileLength - nextPos).toInt()
            if (toRead < stride) break
            val chunk = ByteArray(toRead)
            val read = raf.read(chunk)
            if (read < stride) break
            val bd = ByteBuffer.wrap(chunk, 0, read).order(ByteOrder.LITTLE_ENDIAN)
            var pos = 0
            var broke = false
            while (pos + 12 <= read) {
                if (!isPlausibleVertex(bd, pos)) {
                    broke = true
                    break
                }
                count++
                pos += stride
            }
            nextPos += pos
            if (broke || read < toRead) break
        }
        return count
    }

    private fun isPlausibleVertex(bd: ByteBuffer, offset: Int): Boolean {
        val x = bd.getFloat(offset)
        val y = bd.getFloat(offset + 4)
        val z = bd.getFloat(offset + 8)
        if (x.isNaN() || x.isInfinite() || y.isNaN() || y.isInfinite() || z.isNaN() || z.isInfinite()) {
            return false
        }
        if (x < -50000f || x > 50000f || y < -50000f || y > 50000f || z < -50000f || z > 50000f) {
            return false
        }
        fun validCoord(v: Float): Boolean = v == 0f || (abs(v) in 1e-4f..50000f)
        if (!validCoord(x) || !validCoord(y) || !validCoord(z)) return false
        return x != 0f || y != 0f || z != 0f
    }

    private fun detectUvOffsetInStride(
        bd: ByteBuffer,
        startLocal: Int,
        stride: Int,
        sampleVerts: Int
    ): Int {
        if (stride < 20 || sampleVerts < 4) return -1
        val checkCount = minOf(sampleVerts, 16)
        var rel = 12
        while (rel + 8 <= stride) {
            var allValid = true
            var nonZeroUvs = 0
            for (i in 0 until checkCount) {
                val pos = startLocal + (i * stride) + rel
                val u = bd.getFloat(pos)
                val v = bd.getFloat(pos + 4)
                if (u.isNaN() || u.isInfinite() || v.isNaN() || v.isInfinite() ||
                    u < -16f || u > 16f || v < -16f || v > 16f
                ) {
                    allValid = false
                    break
                }
                if ((u != 0f && abs(u) < 1e-5f) || (v != 0f && abs(v) < 1e-5f)) {
                    allValid = false
                    break
                }
                if (u != 0f || v != 0f) nonZeroUvs++
            }
            if (allValid && nonZeroUvs >= 2) return rel
            rel += 4
        }
        return -1
    }

    private fun scanBestIndexBuffer(
        raf: RandomAccessFile,
        fileLength: Long,
        vertexCount: Int,
        vbStart: Long,
        vbEnd: Long
    ): IndexBufferCandidate? {
        val windowSize = 262144
        val overlap = 1024
        var best: IndexBufferCandidate? = null
        var filePos = 0L

        while (filePos + 24L <= fileLength) {
            raf.seek(filePos)
            val toRead = minOf(windowSize.toLong(), fileLength - filePos).toInt()
            val buf = ByteArray(toRead)
            val read = raf.read(buf)
            if (read < 24) break
            val bd = ByteBuffer.wrap(buf, 0, read).order(ByteOrder.LITTLE_ENDIAN)

            var localOff = 0
            while (localOff + 24 <= read) {
                val absOff = filePos + localOff
                if (absOff in vbStart until vbEnd) {
                    val jump = (vbEnd - filePos).toInt()
                    localOff = if (jump < 0) read else jump
                    continue
                }

                var validTris = 0
                var probe = localOff
                while (probe + 6 <= read) {
                    val absProbe = filePos + probe
                    if (absProbe in vbStart until vbEnd) break
                    val a = bd.getShort(probe).toInt() and 0xFFFF
                    val b = bd.getShort(probe + 2).toInt() and 0xFFFF
                    val c = bd.getShort(probe + 4).toInt() and 0xFFFF
                    if (a < vertexCount && b < vertexCount && c < vertexCount &&
                        a != b && b != c && a != c
                    ) {
                        validTris++
                        probe += 6
                    } else {
                        break
                    }
                }

                if (validTris >= 4) {
                    var totalTris = validTris
                    if (probe + 6 > read) {
                        totalTris = extendIndexRunFromFile(
                            raf, absOff, validTris, vertexCount, vbStart, vbEnd, fileLength
                        )
                    }
                    if (best == null || totalTris > best.triangleCount) {
                        best = IndexBufferCandidate(absOff, totalTris * 3, totalTris)
                    }
                    localOff += maxOf(6, validTris * 6)
                } else {
                    localOff += 2
                }
            }

            if (filePos + read >= fileLength) break
            filePos += read - overlap
        }
        return best
    }

    private fun extendIndexRunFromFile(
        raf: RandomAccessFile,
        startOffset: Long,
        initialTris: Int,
        vertexCount: Int,
        vbStart: Long,
        vbEnd: Long,
        fileLength: Long
    ): Int {
        var tris = initialTris
        var nextPos = startOffset + (tris.toLong() * 6L)
        while (nextPos + 6L <= fileLength) {
            if (nextPos in vbStart until vbEnd) break
            raf.seek(nextPos)
            val toRead = minOf(65532L, fileLength - nextPos).toInt()
            if (toRead < 6) break
            val chunk = ByteArray(toRead)
            val read = raf.read(chunk)
            if (read < 6) break
            val bd = ByteBuffer.wrap(chunk, 0, read).order(ByteOrder.LITTLE_ENDIAN)
            var pos = 0
            var broke = false
            while (pos + 6 <= read) {
                val absPos = nextPos + pos
                if (absPos in vbStart until vbEnd) {
                    broke = true
                    break
                }
                val a = bd.getShort(pos).toInt() and 0xFFFF
                val b = bd.getShort(pos + 2).toInt() and 0xFFFF
                val c = bd.getShort(pos + 4).toInt() and 0xFFFF
                if (a >= vertexCount || b >= vertexCount || c >= vertexCount || a == b || b == c || a == c) {
                    broke = true
                    break
                }
                tris++
                pos += 6
            }
            nextPos += pos
            if (broke || read < toRead) break
        }
        return tris
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
