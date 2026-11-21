package com.example.wos_forensic_extractor.domain.extractor

import android.media.AudioFormat
import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMuxer
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MediaAudioTranscoder(
    private val onLog: ((String) -> Unit)? = null
) {
    /**
     * Decodes Android-compatible audio files (.wav, .ogg, .mp3, .aac, .flac, etc.)
     * using native MediaExtractor + MediaCodec and resamples to 48000 Hz 16-bit stereo PCM WAV.
     * Returns false gracefully for proprietary game codecs (XMA, FSB, WEM, BNK, etc.).
     */
    fun convertAudioToWav48kHz(
        inputFile: File,
        outputWavFile: File,
        forceStereo: Boolean = false
    ): Boolean {
        outputWavFile.parentFile?.mkdirs()
        var extractor: MediaExtractor? = null
        var codec: MediaCodec? = null
        var pcmTempFile: File? = null

        return try {
            extractor = MediaExtractor()
            extractor.setDataSource(inputFile.absolutePath)

            var audioTrackIndex = -1
            var inputFormat: MediaFormat? = null
            for (i in 0 until extractor.trackCount) {
                val fmt = extractor.getTrackFormat(i)
                val mime = fmt.getString(MediaFormat.KEY_MIME) ?: ""
                if (mime.startsWith("audio/")) {
                    audioTrackIndex = i
                    inputFormat = fmt
                    break
                }
            }

            if (audioTrackIndex < 0 || inputFormat == null) {
                return false
            }

            extractor.selectTrack(audioTrackIndex)
            val mime = inputFormat.getString(MediaFormat.KEY_MIME) ?: return false
            var sampleRate = if (inputFormat.containsKey(MediaFormat.KEY_SAMPLE_RATE)) {
                inputFormat.getInteger(MediaFormat.KEY_SAMPLE_RATE)
            } else 48000
            var channelCount = if (inputFormat.containsKey(MediaFormat.KEY_CHANNEL_COUNT)) {
                inputFormat.getInteger(MediaFormat.KEY_CHANNEL_COUNT)
            } else 2

            codec = MediaCodec.createDecoderByType(mime)
            codec.configure(inputFormat, null, null, 0)
            codec.start()

            pcmTempFile = File(outputWavFile.parentFile, ".tmp_pcm_${System.nanoTime()}.raw")
            val bufferInfo = MediaCodec.BufferInfo()
            var sawInputEOS = false
            var sawOutputEOS = false

            FileOutputStream(pcmTempFile).use { rawOut ->
                while (!sawOutputEOS) {
                    if (!sawInputEOS) {
                        val inIdx = codec.dequeueInputBuffer(10_000L)
                        if (inIdx >= 0) {
                            val inBuf = codec.getInputBuffer(inIdx)
                            if (inBuf != null) {
                                val sampleSize = extractor.readSampleData(inBuf, 0)
                                if (sampleSize < 0) {
                                    codec.queueInputBuffer(inIdx, 0, 0, 0L, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                                    sawInputEOS = true
                                } else {
                                    codec.queueInputBuffer(inIdx, 0, sampleSize, extractor.sampleTime, 0)
                                    extractor.advance()
                                }
                            }
                        }
                    }

                    val outIdx = codec.dequeueOutputBuffer(bufferInfo, 10_000L)
                    when {
                        outIdx >= 0 -> {
                            val outBuf = codec.getOutputBuffer(outIdx)
                            if (outBuf != null && bufferInfo.size > 0) {
                                val chunk = ByteArray(bufferInfo.size)
                                outBuf.position(bufferInfo.offset)
                                outBuf.get(chunk)
                                rawOut.write(chunk)
                            }
                            codec.releaseOutputBuffer(outIdx, false)
                            if ((bufferInfo.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) {
                                sawOutputEOS = true
                            }
                        }
                        outIdx == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                            val outFmt = codec.outputFormat
                            if (outFmt.containsKey(MediaFormat.KEY_SAMPLE_RATE)) {
                                sampleRate = outFmt.getInteger(MediaFormat.KEY_SAMPLE_RATE)
                            }
                            if (outFmt.containsKey(MediaFormat.KEY_CHANNEL_COUNT)) {
                                channelCount = outFmt.getInteger(MediaFormat.KEY_CHANNEL_COUNT)
                            }
                            if (outFmt.containsKey(MediaFormat.KEY_PCM_ENCODING)) {
                                val enc = outFmt.getInteger(MediaFormat.KEY_PCM_ENCODING)
                                if (enc != AudioFormat.ENCODING_PCM_16BIT && enc != AudioFormat.ENCODING_INVALID) {
                                    // Still write raw PCM; most Android decoders default to 16-bit
                                }
                            }
                        }
                    }
                }
                rawOut.flush()
            }

            if (!pcmTempFile.exists() || pcmTempFile.length() <= 0L) {
                return false
            }

            val targetChannels = if (forceStereo) 2 else channelCount.coerceIn(1, 2)
            writeResampledWav48kHz(
                rawPcmFile = pcmTempFile,
                srcRate = sampleRate,
                srcChannels = channelCount.coerceAtLeast(1),
                dstRate = 48000,
                dstChannels = targetChannels,
                destWavFile = outputWavFile
            )

            outputWavFile.exists() && outputWavFile.length() > 44L
        } catch (e: Exception) {
            onLog?.invoke("[FFMPEG-SKIP] Audio no decodificable (${inputFile.name}): ${e.message}")
            runCatching { if (outputWavFile.exists()) outputWavFile.delete() }
            false
        } finally {
            runCatching { codec?.stop() }
            runCatching { codec?.release() }
            runCatching { extractor?.release() }
            runCatching { pcmTempFile?.delete() }
        }
    }

    fun isValidWavFile(file: File): Boolean {
        return runCatching {
            if (file.length() <= 44L) return false
            RandomAccessFile(file, "r").use { raf ->
                val hdr = ByteArray(12)
                raf.readFully(hdr)
                val riff = String(hdr, 0, 4, Charsets.US_ASCII)
                val wave = String(hdr, 8, 4, Charsets.US_ASCII)
                riff == "RIFF" && wave == "WAVE"
            }
        }.getOrDefault(false)
    }

    /**
     * Attempts remuxing/transcoding standard containers (.avi/.wmv/.mp4) to MP4 using MediaExtractor+MediaMuxer.
     * Returns false for proprietary Bink (.bik/.bk2) so the original file is preserved cleanly.
     */
    fun transcodeVideoToMp4OrThrow(inputFile: File, outMp4File: File) {
        val ext = inputFile.extension.lowercase()
        if (ext == "bik" || ext == "bk2" || ext == "smk") {
            throw IllegalStateException("Códec propietario Bink Video ($ext) requiere FFmpeg Bink demuxer; original conservado")
        }
        var extractor: MediaExtractor? = null
        var muxer: MediaMuxer? = null
        try {
            extractor = MediaExtractor()
            extractor.setDataSource(inputFile.absolutePath)
            if (extractor.trackCount == 0) {
                throw IllegalStateException("Sin pistas multimedia reconocidas")
            }
            muxer = MediaMuxer(outMp4File.absolutePath, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
            val trackMap = HashMap<Int, Int>()
            for (i in 0 until extractor.trackCount) {
                val fmt = extractor.getTrackFormat(i)
                val mime = fmt.getString(MediaFormat.KEY_MIME) ?: ""
                if (mime.startsWith("video/") || mime.startsWith("audio/")) {
                    extractor.selectTrack(i)
                    trackMap[i] = muxer.addTrack(fmt)
                }
            }
            if (trackMap.isEmpty()) {
                throw IllegalStateException("Ninguna pista compatible con contenedor MP4")
            }
            muxer.start()
            val buf = ByteBuffer.allocate(262144)
            val info = MediaCodec.BufferInfo()
            while (true) {
                val trackIdx = extractor.sampleTrackIndex
                if (trackIdx < 0) break
                val size = extractor.readSampleData(buf, 0)
                if (size < 0) break
                info.offset = 0
                info.size = size
                info.presentationTimeUs = extractor.sampleTime
                info.flags = extractor.sampleFlags
                val dstTrack = trackMap[trackIdx]
                if (dstTrack != null) {
                    muxer.writeSampleData(dstTrack, buf, info)
                }
                extractor.advance()
            }
            muxer.stop()
        } catch (e: Exception) {
            runCatching { if (outMp4File.exists()) outMp4File.delete() }
            throw e
        } finally {
            runCatching { muxer?.release() }
            runCatching { extractor?.release() }
        }
    }

    private fun writeResampledWav48kHz(
        rawPcmFile: File,
        srcRate: Int,
        srcChannels: Int,
        dstRate: Int,
        dstChannels: Int,
        destWavFile: File
    ) {
        val rawBytes = rawPcmFile.readBytes()
        val srcSamplesTotal = rawBytes.size / (2 * srcChannels)
        if (srcSamplesTotal <= 0) return

        val srcShorts = ShortArray(srcSamplesTotal * srcChannels)
        ByteBuffer.wrap(rawBytes).order(ByteOrder.LITTLE_ENDIAN).asShortBuffer().get(srcShorts)

        val dstFrames = ((srcSamplesTotal.toLong() * dstRate.toLong()) / srcRate.toLong()).toInt().coerceAtLeast(1)
        val dstDataSize = dstFrames * dstChannels * 2

        FileOutputStream(destWavFile).use { fos ->
            val hdr = ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN)
            hdr.put("RIFF".toByteArray(Charsets.US_ASCII))
            hdr.putInt(36 + dstDataSize)
            hdr.put("WAVE".toByteArray(Charsets.US_ASCII))
            hdr.put("fmt ".toByteArray(Charsets.US_ASCII))
            hdr.putInt(16) // PCM fmt chunk size
            hdr.putShort(1) // PCM format
            hdr.putShort(dstChannels.toShort())
            hdr.putInt(dstRate)
            hdr.putInt(dstRate * dstChannels * 2)
            hdr.putShort((dstChannels * 2).toShort())
            hdr.putShort(16)
            hdr.put("data".toByteArray(Charsets.US_ASCII))
            hdr.putInt(dstDataSize)
            fos.write(hdr.array())

            val outChunk = ByteBuffer.allocate(16384 * dstChannels * 2).order(ByteOrder.LITTLE_ENDIAN)
            val ratio = srcRate.toDouble() / dstRate.toDouble()

            for (frame in 0 until dstFrames) {
                val srcPos = frame * ratio
                val idx0 = srcPos.toInt().coerceIn(0, srcSamplesTotal - 1)
                val idx1 = (idx0 + 1).coerceIn(0, srcSamplesTotal - 1)
                val frac = srcPos - idx0

                for (ch in 0 until dstChannels) {
                    val sCh = if (srcChannels == 1) 0 else ch.coerceAtMost(srcChannels - 1)
                    val s0 = srcShorts[idx0 * srcChannels + sCh].toDouble()
                    val s1 = srcShorts[idx1 * srcChannels + sCh].toDouble()
                    val sample = (s0 + (s1 - s0) * frac).toInt().coerceIn(-32768, 32767).toShort()
                    outChunk.putShort(sample)
                }
                if (outChunk.remaining() < dstChannels * 2) {
                    fos.write(outChunk.array(), 0, outChunk.position())
                    outChunk.clear()
                }
            }
            if (outChunk.position() > 0) {
                fos.write(outChunk.array(), 0, outChunk.position())
            }
            fos.flush()
        }
    }
}
