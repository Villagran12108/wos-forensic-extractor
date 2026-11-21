import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:ffmpeg_kit_flutter_new/ffmpeg_kit.dart';
import 'package:ffmpeg_kit_flutter_new/return_code.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;

typedef PortLogCallback = void Function(String message);
typedef PortProgressCallback = void Function(
  int processed,
  int total,
  String currentStage,
);

class PortCategoryStats {
  int analyzed = 0;
  int converted = 0;
  int skipped = 0;

  Map<String, int> toJson() => <String, int>{
        'analizados': analyzed,
        'convertidos': converted,
        'omitidos': skipped,
      };
}

class PortConversionSummary {
  final String sourceDumpDir;
  final String outputConvertedDir;
  final String manifestPath;
  final int totalAnalyzed;
  final int totalConverted;
  final int totalSkipped;
  final Map<String, PortCategoryStats> statsByCategory;
  final List<String> generatedPaths;

  const PortConversionSummary({
    required this.sourceDumpDir,
    required this.outputConvertedDir,
    required this.manifestPath,
    required this.totalAnalyzed,
    required this.totalConverted,
    required this.totalSkipped,
    required this.statsByCategory,
    required this.generatedPaths,
  });
}

class _VertexBufferCandidate {
  final int offset;
  final int stride;
  final int vertexCount;
  final int uvRelOffset;
  final double score;

  const _VertexBufferCandidate({
    required this.offset,
    required this.stride,
    required this.vertexCount,
    required this.uvRelOffset,
    required this.score,
  });
}

class _IndexBufferCandidate {
  final int offset;
  final int indexCount;
  final int triangleCount;

  const _IndexBufferCandidate({
    required this.offset,
    required this.indexCount,
    required this.triangleCount,
  });
}

class _PeSection {
  final String name;
  final int virtualSize;
  final int virtualAddress;
  final int rawSize;
  final int rawAddress;
  final int characteristics;

  const _PeSection({
    required this.name,
    required this.virtualSize,
    required this.virtualAddress,
    required this.rawSize,
    required this.rawAddress,
    required this.characteristics,
  });

  Map<String, Object> toJson() => <String, Object>{
        'nombre': name,
        'virtualSize': virtualSize,
        'virtualAddress': '0x${virtualAddress.toRadixString(16).toUpperCase()}',
        'rawSize': rawSize,
        'rawOffset': '0x${rawAddress.toRadixString(16).toUpperCase()}',
        'characteristics': '0x${characteristics.toRadixString(16).toUpperCase()}',
      };
}

class _ExtractedStringEntry {
  final int offset;
  final String encoding;
  final String detectedLanguage;
  final String text;

  const _ExtractedStringEntry({
    required this.offset,
    required this.encoding,
    required this.detectedLanguage,
    required this.text,
  });
}

class _TexHeaderMatch {
  final String format;
  final int width;
  final int height;
  final int mipCount;
  final int payloadOffset;

  const _TexHeaderMatch({
    required this.format,
    required this.width,
    required this.height,
    required this.mipCount,
    required this.payloadOffset,
  });
}

class PortBatchConverter {
  static const int _chunkSize = 65536; // 64 KB
  static const String outputFolderName = 'WoS_Port_Ready_Converted';

  static const String cat01Audio = '01_Audio_y_Voces';
  static const String cat02Videos = '02_Videos_BIK';
  static const String cat03Textures = '03_Texturas_e_Imagenes';
  static const String cat04Models = '04_Modelos_3D_Mallas';
  static const String cat05Skeletons = '05_Esqueletos_y_Animaciones';
  static const String cat06Physics = '06_Fisica_Colisiones_y_Niveles';
  static const String cat07Entities = '07_Entidades_Combate_y_Scripts';
  static const String cat08Texts = '08_Textos_e_Idiomas';
  static const String cat09Engine = '09_Motor_Shaders_y_Binarios';

  static const List<String> allCategories = <String>[
    cat01Audio,
    cat02Videos,
    cat03Textures,
    cat04Models,
    cat05Skeletons,
    cat06Physics,
    cat07Entities,
    cat08Texts,
    cat09Engine,
  ];

  final PortLogCallback? onLog;
  final PortProgressCallback? onProgress;

  PortBatchConverter({
    this.onLog,
    this.onProgress,
  });

  void _log(String msg) {
    onLog?.call(msg);
  }

  /// Ejecuta la conversión completa de WoS_Full_Port_Dump hacia la carpeta hermana WoS_Port_Ready_Converted.
  Future<PortConversionSummary> convertDumpDirectory({
    required String inputDumpDir,
    RootIsolateToken? rootIsolateToken,
  }) async {
    if (rootIsolateToken != null) {
      BackgroundIsolateBinaryMessenger.ensureInitialized(rootIsolateToken);
    }

    final String resolvedDumpDir = await _resolveDumpRoot(inputDumpDir);
    final String outputRoot = p.join(p.dirname(resolvedDumpDir), outputFolderName);
    await Directory(outputRoot).create(recursive: true);

    for (final cat in allCategories) {
      await Directory(p.join(outputRoot, cat)).create(recursive: true);
    }

    _log('[CONV] Carpeta origen: $resolvedDumpDir');
    _log('[CONV] Carpeta destino: $outputRoot');

    final Map<String, List<File>> filesByCategory = <String, List<File>>{};
    int totalFiles = 0;
    for (final cat in allCategories) {
      final catDir = Directory(p.join(resolvedDumpDir, cat));
      final List<File> list = <File>[];
      if (await catDir.exists()) {
        await for (final entity in catDir.list(recursive: true, followLinks: false)) {
          if (entity is File) {
            list.add(entity);
          }
        }
      }
      filesByCategory[cat] = list;
      totalFiles += list.length;
    }

    final Map<String, PortCategoryStats> stats = <String, PortCategoryStats>{
      for (final cat in allCategories) cat: PortCategoryStats(),
    };
    final List<String> generatedPaths = <String>[];

    final String manifestPath = p.join(outputRoot, 'MANIFIESTO_CONVERSION_PORT.json');
    final File manifestFile = File(manifestPath);
    final IOSink manifestSink = manifestFile.openWrite(encoding: utf8);

    manifestSink.writeln('{');
    manifestSink.writeln('  "proyecto": "WoS Forensic Extractor - Conversor Port",');
    manifestSink.writeln('  "fechaUtc": ${jsonEncode(DateTime.now().toUtc().toIso8601String())},');
    manifestSink.writeln('  "carpetaOrigen": ${jsonEncode(resolvedDumpDir)},');
    manifestSink.writeln('  "carpetaDestino": ${jsonEncode(outputRoot)},');
    manifestSink.writeln('  "archivos": [');

    bool firstRecord = true;
    int processedGlobal = 0;
    int totalConverted = 0;
    int totalSkipped = 0;

    void writeManifestRecord({
      required String category,
      required String sourcePath,
      required String destPath,
      required String status,
      required String detail,
    }) {
      final Map<String, Object> rec = <String, Object>{
        'categoria': category,
        'origen': sourcePath,
        'destino': destPath,
        'estado': status,
        'detalle': detail,
      };
      if (!firstRecord) {
        manifestSink.writeln(',');
      }
      firstRecord = false;
      manifestSink.write('    ${jsonEncode(rec)}');
    }

    try {
      await _processAudioCategory(
        sourceDirPath: p.join(resolvedDumpDir, cat01Audio),
        destDirPath: p.join(outputRoot, cat01Audio),
        files: filesByCategory[cat01Audio]!,
        stats: stats[cat01Audio]!,
        onItemDone: (src, dst, converted, detail) {
          processedGlobal++;
          if (converted) {
            totalConverted++;
          } else {
            totalSkipped++;
          }
          generatedPaths.add(dst);
          writeManifestRecord(
            category: cat01Audio,
            sourcePath: src,
            destPath: dst,
            status: converted ? 'convertido' : 'omitido_original_conservado',
            detail: detail,
          );
          onProgress?.call(processedGlobal, totalFiles, '01/09 Audio -> WAV 48kHz');
        },
      );

      await _processVideoCategory(
        destDirPath: p.join(outputRoot, cat02Videos),
        files: filesByCategory[cat02Videos]!,
        stats: stats[cat02Videos]!,
        onItemDone: (src, dst, converted, detail) {
          processedGlobal++;
          if (converted) {
            totalConverted++;
          } else {
            totalSkipped++;
          }
          generatedPaths.add(dst);
          writeManifestRecord(
            category: cat02Videos,
            sourcePath: src,
            destPath: dst,
            status: converted ? 'convertido' : 'omitido_original_conservado',
            detail: detail,
          );
          onProgress?.call(processedGlobal, totalFiles, '02/09 Videos BIK -> MP4');
        },
      );

      await _processTexturesCategory(
        destDirPath: p.join(outputRoot, cat03Textures),
        files: filesByCategory[cat03Textures]!,
        stats: stats[cat03Textures]!,
        onItemDone: (src, dst, converted, detail) {
          processedGlobal++;
          if (converted) {
            totalConverted++;
          } else {
            totalSkipped++;
          }
          generatedPaths.add(dst);
          writeManifestRecord(
            category: cat03Textures,
            sourcePath: src,
            destPath: dst,
            status: converted ? 'convertido' : 'omitido_original_conservado',
            detail: detail,
          );
          onProgress?.call(processedGlobal, totalFiles, '03/09 Texturas -> DDS');
        },
      );

      await _processGeometryCategory(
        categoryName: cat04Models,
        destDirPath: p.join(outputRoot, cat04Models),
        files: filesByCategory[cat04Models]!,
        stats: stats[cat04Models]!,
        stageLabel: '04/09 Modelos 3D -> OBJ',
        onItemDone: (src, dst, converted, detail) {
          processedGlobal++;
          if (converted) {
            totalConverted++;
          } else {
            totalSkipped++;
          }
          generatedPaths.add(dst);
          writeManifestRecord(
            category: cat04Models,
            sourcePath: src,
            destPath: dst,
            status: converted ? 'convertido' : 'omitido_original_conservado',
            detail: detail,
          );
          onProgress?.call(processedGlobal, totalFiles, '04/09 Modelos 3D -> OBJ');
        },
      );

      await _processSkeletonsCategory(
        destDirPath: p.join(outputRoot, cat05Skeletons),
        files: filesByCategory[cat05Skeletons]!,
        stats: stats[cat05Skeletons]!,
        onItemDone: (src, dst, converted, detail) {
          processedGlobal++;
          if (converted) {
            totalConverted++;
          } else {
            totalSkipped++;
          }
          generatedPaths.add(dst);
          writeManifestRecord(
            category: cat05Skeletons,
            sourcePath: src,
            destPath: dst,
            status: converted ? 'convertido' : 'omitido_original_conservado',
            detail: detail,
          );
          onProgress?.call(processedGlobal, totalFiles, '05/09 Esqueletos -> JSON');
        },
      );

      await _processGeometryCategory(
        categoryName: cat06Physics,
        destDirPath: p.join(outputRoot, cat06Physics),
        files: filesByCategory[cat06Physics]!,
        stats: stats[cat06Physics]!,
        stageLabel: '06/09 Colisiones y Niveles -> OBJ',
        onItemDone: (src, dst, converted, detail) {
          processedGlobal++;
          if (converted) {
            totalConverted++;
          } else {
            totalSkipped++;
          }
          generatedPaths.add(dst);
          writeManifestRecord(
            category: cat06Physics,
            sourcePath: src,
            destPath: dst,
            status: converted ? 'convertido' : 'omitido_original_conservado',
            detail: detail,
          );
          onProgress?.call(processedGlobal, totalFiles, '06/09 Colisiones -> OBJ');
        },
      );

      await _processTextAndEntitiesCategory(
        categoryName: cat07Entities,
        destDirPath: p.join(outputRoot, cat07Entities),
        files: filesByCategory[cat07Entities]!,
        stats: stats[cat07Entities]!,
        onItemDone: (src, dstList, converted, detail) {
          processedGlobal++;
          if (converted) {
            totalConverted++;
          } else {
            totalSkipped++;
          }
          for (final d in dstList) {
            generatedPaths.add(d);
          }
          writeManifestRecord(
            category: cat07Entities,
            sourcePath: src,
            destPath: dstList.join(' | '),
            status: converted ? 'convertido' : 'omitido_original_conservado',
            detail: detail,
          );
          onProgress?.call(processedGlobal, totalFiles, '07/09 Entidades -> JSON/CSV');
        },
      );

      await _processTextAndEntitiesCategory(
        categoryName: cat08Texts,
        destDirPath: p.join(outputRoot, cat08Texts),
        files: filesByCategory[cat08Texts]!,
        stats: stats[cat08Texts]!,
        onItemDone: (src, dstList, converted, detail) {
          processedGlobal++;
          if (converted) {
            totalConverted++;
          } else {
            totalSkipped++;
          }
          for (final d in dstList) {
            generatedPaths.add(d);
          }
          writeManifestRecord(
            category: cat08Texts,
            sourcePath: src,
            destPath: dstList.join(' | '),
            status: converted ? 'convertido' : 'omitido_original_conservado',
            detail: detail,
          );
          onProgress?.call(processedGlobal, totalFiles, '08/09 Textos/Idiomas -> JSON/CSV');
        },
      );

      await _processEngineBinariesCategory(
        destDirPath: p.join(outputRoot, cat09Engine),
        files: filesByCategory[cat09Engine]!,
        stats: stats[cat09Engine]!,
        onItemDone: (src, dstList, converted, detail) {
          processedGlobal++;
          if (converted) {
            totalConverted++;
          } else {
            totalSkipped++;
          }
          for (final d in dstList) {
            generatedPaths.add(d);
          }
          writeManifestRecord(
            category: cat09Engine,
            sourcePath: src,
            destPath: dstList.join(' | '),
            status: converted ? 'convertido' : 'omitido_original_conservado',
            detail: detail,
          );
          onProgress?.call(processedGlobal, totalFiles, '09/09 Binarios/Shaders -> JSON/TXT');
        },
      );

      manifestSink.writeln('');
      manifestSink.writeln('  ],');
      manifestSink.writeln('  "resumen": {');
      manifestSink.writeln('    "totalArchivosAnalizados": $processedGlobal,');
      manifestSink.writeln('    "totalConvertidosExito": $totalConverted,');
      manifestSink.writeln('    "totalOmitidosConservados": $totalSkipped,');

      final Map<String, Map<String, int>> statsMap = <String, Map<String, int>>{
        for (final entry in stats.entries) entry.key: entry.value.toJson(),
      };
      final String formattedStats =
          const JsonEncoder.withIndent('      ').convert(statsMap).replaceAll('\n', '\n    ');
      manifestSink.writeln('    "porCategoria": $formattedStats');
      manifestSink.writeln('  }');
      manifestSink.writeln('}');
      await manifestSink.flush();
    } finally {
      await manifestSink.close();
    }

    _log(
      '[CONV:FIN] Conversión completada. Analizados: $processedGlobal | Convertidos: $totalConverted | Omitidos (original conservado): $totalSkipped',
    );
    _log('[CONV:FIN] Manifiesto generado: $manifestPath');

    return PortConversionSummary(
      sourceDumpDir: resolvedDumpDir,
      outputConvertedDir: outputRoot,
      manifestPath: manifestPath,
      totalAnalyzed: processedGlobal,
      totalConverted: totalConverted,
      totalSkipped: totalSkipped,
      statsByCategory: stats,
      generatedPaths: generatedPaths,
    );
  }

  Future<String> _resolveDumpRoot(String inputDir) async {
    final String candidateSub = p.join(inputDir, 'WoS_Full_Port_Dump');
    if (await Directory(candidateSub).exists()) {
      return candidateSub;
    }
    return inputDir;
  }

  Future<void> _processAudioCategory({
    required String sourceDirPath,
    required String destDirPath,
    required List<File> files,
    required PortCategoryStats stats,
    required void Function(String src, String dst, bool converted, String detail) onItemDone,
  }) async {
    final String ps4ReadySubdir = p.join(sourceDirPath, 'WAV_48kHz_PS4_Ready');
    final Map<String, File> validPreconvertedByBase = <String, File>{};

    for (final f in files) {
      if (p.isWithin(ps4ReadySubdir, f.path) &&
          p.extension(f.path).toLowerCase() == '.wav') {
        if (await _isValidWavFile(f)) {
          validPreconvertedByBase[p.basenameWithoutExtension(f.path).toLowerCase()] = f;
        }
      }
    }

    final Set<String> handledBases = <String>{};

    for (final entry in validPreconvertedByBase.entries) {
      stats.analyzed++;
      final File wavSrc = entry.value;
      final String dstPath = await _uniquePath(p.join(destDirPath, p.basename(wavSrc.path)));
      try {
        await _copyFileStreaming(wavSrc, File(dstPath));
        handledBases.add(entry.key);
        stats.converted++;
        onItemDone(wavSrc.path, dstPath, true, 'WAV 48kHz válido copiado sin recodificar');
      } catch (e) {
        stats.skipped++;
        _log('[CONV:SKIP] Error copiando WAV preconvertido ${p.basename(wavSrc.path)}: $e');
        onItemDone(wavSrc.path, wavSrc.path, false, 'Error al copiar WAV: $e');
      }
    }

    for (final file in files) {
      if (p.isWithin(ps4ReadySubdir, file.path)) {
        if (validPreconvertedByBase.containsValue(file)) continue;
      }

      final String baseLower = p.basenameWithoutExtension(file.path).toLowerCase();
      if (handledBases.contains(baseLower)) {
        stats.analyzed++;
        stats.converted++;
        final String existingDst = p.join(destDirPath, '$baseLower.wav');
        onItemDone(
          file.path,
          existingDst,
          true,
          'Ya cubierto por WAV_48kHz_PS4_Ready sin recodificación',
        );
        continue;
      }

      stats.analyzed++;
      final String outWavPath = await _uniquePath(
        p.join(destDirPath, '${p.basenameWithoutExtension(file.path)}.wav'),
      );

      try {
        final session = await FFmpegKit.executeWithArguments([
          '-y',
          '-hide_banner',
          '-loglevel',
          'error',
          '-i',
          file.path,
          '-ar',
          '48000',
          '-ac',
          '2',
          '-c:a',
          'pcm_s16le',
          outWavPath,
        ]);

        final ReturnCode? rc = await session.getReturnCode();
        final File outFile = File(outWavPath);
        if (ReturnCode.isSuccess(rc) && await outFile.exists() && await outFile.length() > 44) {
          stats.converted++;
          _log('[AUDIO] Convertido: ${p.basename(outWavPath)}');
          onItemDone(file.path, outWavPath, true, 'Convertido a WAV PCM 48kHz 16-bit estéreo');
        } else {
          if (await outFile.exists()) await outFile.delete();
          throw StateError('FFmpeg devolvió código ${rc?.getValue()}');
        }
      } catch (e) {
        stats.skipped++;
        _log('[CONV:SKIP] Audio propietario no decodificable (${p.basename(file.path)}): $e');
        final String fallbackPath = await _uniquePath(
          p.join(destDirPath, p.basename(file.path)),
        );
        await _copyFileStreaming(file, File(fallbackPath));
        onItemDone(file.path, fallbackPath, false, 'No decodificable por FFmpeg; original conservado');
      }
    }
  }

  Future<bool> _isValidWavFile(File file) async {
    RandomAccessFile? raf;
    try {
      final int len = await file.length();
      if (len <= 44) return false;
      raf = await file.open(mode: FileMode.read);
      final Uint8List hdr = await raf.read(12);
      if (hdr.length < 12) return false;
      final String riff = String.fromCharCodes(hdr.sublist(0, 4));
      final String wave = String.fromCharCodes(hdr.sublist(8, 12));
      return riff == 'RIFF' && wave == 'WAVE';
    } catch (_) {
      return false;
    } finally {
      await raf?.close();
    }
  }

  Future<void> _processVideoCategory({
    required String destDirPath,
    required List<File> files,
    required PortCategoryStats stats,
    required void Function(String src, String dst, bool converted, String detail) onItemDone,
  }) async {
    for (final file in files) {
      stats.analyzed++;
      final String ext = p.extension(file.path).toLowerCase();

      if (ext == '.mp4') {
        try {
          final String dst = await _uniquePath(p.join(destDirPath, p.basename(file.path)));
          await _copyFileStreaming(file, File(dst));
          stats.converted++;
          onItemDone(file.path, dst, true, 'MP4 copiado directamente');
        } catch (e) {
          stats.skipped++;
          _log('[CONV:SKIP] Error copiando MP4 ${p.basename(file.path)}: $e');
          onItemDone(file.path, file.path, false, 'Error copiando MP4: $e');
        }
        continue;
      }

      final String outMp4Path = await _uniquePath(
        p.join(destDirPath, '${p.basenameWithoutExtension(file.path)}.mp4'),
      );

      try {
        final session = await FFmpegKit.executeWithArguments([
          '-y',
          '-hide_banner',
          '-loglevel',
          'error',
          '-i',
          file.path,
          '-c:v',
          'libx264',
          '-preset',
          'veryfast',
          '-crf',
          '18',
          '-pix_fmt',
          'yuv420p',
          '-c:a',
          'aac',
          '-ar',
          '48000',
          '-b:a',
          '192k',
          outMp4Path,
        ]);

        final ReturnCode? rc = await session.getReturnCode();
        final File outFile = File(outMp4Path);
        if (ReturnCode.isSuccess(rc) && await outFile.exists() && await outFile.length() > 0) {
          stats.converted++;
          _log('[VIDEO] Transcodificado: ${p.basename(outMp4Path)}');
          onItemDone(file.path, outMp4Path, true, 'Transcodificado BIK -> MP4 H.264 + AAC 48kHz');
        } else {
          if (await outFile.exists()) await outFile.delete();
          throw StateError('FFmpeg falló en BIK (código ${rc?.getValue()})');
        }
      } catch (e) {
        stats.skipped++;
        _log('[CONV:SKIP] Video no transcodificable (${p.basename(file.path)}): $e');
        final String fallbackPath = await _uniquePath(
          p.join(destDirPath, p.basename(file.path)),
        );
        await _copyFileStreaming(file, File(fallbackPath));
        onItemDone(file.path, fallbackPath, false, 'Error FFmpeg H.264/BIK; original conservado');
      }
    }
  }

  Future<void> _processTexturesCategory({
    required String destDirPath,
    required List<File> files,
    required PortCategoryStats stats,
    required void Function(String src, String dst, bool converted, String detail) onItemDone,
  }) async {
    for (final file in files) {
      stats.analyzed++;
      final String ext = p.extension(file.path).toLowerCase();

      try {
        final Uint8List head128 = await _readHeader(file, 128);
        final bool isAlreadyDds = head128.length >= 4 &&
            String.fromCharCodes(head128.sublist(0, 4)) == 'DDS ';

        if (ext == '.dds' && isAlreadyDds || ext == '.png' || ext == '.jpg' || ext == '.jpeg') {
          final String dst = await _uniquePath(p.join(destDirPath, p.basename(file.path)));
          await _copyFileStreaming(file, File(dst));
          stats.converted++;
          onItemDone(file.path, dst, true, 'Imagen/DDS estándar copiada limpia');
          continue;
        }

        final int fileLen = await file.length();
        final _TexHeaderMatch? match = _parseProprietaryTextureHeader(head128, fileLen);
        if (match == null) {
          throw StateError('No se detectó firma DXT1/DXT3/DXT5/ATI2/RGBA ni dimensiones válidas');
        }

        final String ddsOutPath = await _uniquePath(
          p.join(destDirPath, '${p.basenameWithoutExtension(file.path)}.dds'),
        );

        await _writeStandardDdsFromTex(
          sourceFile: file,
          destFile: File(ddsOutPath),
          match: match,
        );

        stats.converted++;
        _log('[TEX->DDS] Reconstruido ${p.basename(ddsOutPath)} (${match.width}x${match.height} ${match.format})');
        onItemDone(
          file.path,
          ddsOutPath,
          true,
          'Cabecera DDS 128B reconstruida (${match.width}x${match.height}, ${match.format})',
        );
      } catch (e) {
        stats.skipped++;
        _log('[CONV:SKIP] Textura no convertible (${p.basename(file.path)}): $e');
        final String fallbackPath = await _uniquePath(
          p.join(destDirPath, p.basename(file.path)),
        );
        await _copyFileStreaming(file, File(fallbackPath));
        onItemDone(file.path, fallbackPath, false, 'Formato propietario no reconocido; original conservado');
      }
    }
  }

  _TexHeaderMatch? _parseProprietaryTextureHeader(Uint8List head128, int fileSize) {
    if (head128.length < 16 || fileSize < 64) return null;

    final String ascii = String.fromCharCodes(
      head128.map((b) => (b >= 32 && b <= 126) ? b : 46),
    );

    String? format;
    int formatPos = -1;
    for (final candidate in const ['DXT1', 'DXT3', 'DXT5', 'ATI2', 'RGBA']) {
      final int idx = ascii.indexOf(candidate);
      if (idx >= 0) {
        format = candidate;
        formatPos = idx;
        break;
      }
    }

    if (format == null) return null;

    final ByteData bd = ByteData.sublistView(head128);
    int width = 0;
    int height = 0;
    int mipCount = 1;
    int payloadOffset = 0;

    final int minBlockBytes = format == 'RGBA'
        ? 4
        : (format == 'DXT1' ? 8 : 16);

    for (int pos = 0; pos + 8 <= head128.length; pos += 4) {
      final int w = bd.getUint32(pos, Endian.little);
      final int h = bd.getUint32(pos + 4, Endian.little);
      if (_isPowerOfTwoDim(w) && _isPowerOfTwoDim(h)) {
        final int expectedLevel0 = format == 'RGBA'
            ? (w * h * 4)
            : (((w + 3) ~/ 4) * ((h + 3) ~/ 4) * minBlockBytes);
        if (expectedLevel0 <= fileSize) {
          width = w;
          height = h;
          if (pos + 12 <= head128.length) {
            final int m = bd.getUint32(pos + 8, Endian.little);
            if (m >= 1 && m <= 14) {
              mipCount = m;
            }
          }
          final int endMark = math.max(formatPos + 4, pos + 8);
          payloadOffset = ((endMark + 3) ~/ 4) * 4;
          if (fileSize - payloadOffset < expectedLevel0) {
            payloadOffset = 0;
          }
          break;
        }
      }
    }

    if (width == 0 || height == 0) {
      payloadOffset = (formatPos + 4 <= 64) ? ((formatPos + 4 + 3) ~/ 4) * 4 : 0;
      final int avail = fileSize - payloadOffset;
      final List<int> dims = _inferTextureDims(avail, format);
      width = dims[0];
      height = dims[1];
      if (width == 0 || height == 0) return null;
    }

    return _TexHeaderMatch(
      format: format,
      width: width,
      height: height,
      mipCount: mipCount,
      payloadOffset: payloadOffset,
    );
  }

  Future<void> _writeStandardDdsFromTex({
    required File sourceFile,
    required File destFile,
    required _TexHeaderMatch match,
  }) async {
    final ByteData ddsHeader = ByteData(128);
    ddsHeader.setUint32(0x00, 0x20534444, Endian.little);
    ddsHeader.setUint32(0x04, 124, Endian.little);

    final bool isRgba = match.format == 'RGBA';
    final int blockSize = match.format == 'DXT1' ? 8 : 16;
    final int pitchOrLinearSize = isRgba
        ? (match.width * 4)
        : (((match.width + 3) ~/ 4) * ((match.height + 3) ~/ 4) * blockSize);

    final int dwFlags = isRgba ? 0x000A100F : 0x000A1007;
    ddsHeader.setUint32(0x08, dwFlags, Endian.little);
    ddsHeader.setUint32(0x0C, match.height, Endian.little);
    ddsHeader.setUint32(0x10, match.width, Endian.little);
    ddsHeader.setUint32(0x14, pitchOrLinearSize, Endian.little);
    ddsHeader.setUint32(0x18, 0, Endian.little);
    ddsHeader.setUint32(0x1C, match.mipCount, Endian.little);

    ddsHeader.setUint32(0x4C, 32, Endian.little);
    if (isRgba) {
      ddsHeader.setUint32(0x50, 0x00000041, Endian.little);
      ddsHeader.setUint32(0x54, 0, Endian.little);
      ddsHeader.setUint32(0x58, 32, Endian.little);
      ddsHeader.setUint32(0x5C, 0x00FF0000, Endian.little);
      ddsHeader.setUint32(0x60, 0x0000FF00, Endian.little);
      ddsHeader.setUint32(0x64, 0x000000FF, Endian.little);
      ddsHeader.setUint32(0x68, 0xFF000000, Endian.little);
    } else {
      ddsHeader.setUint32(0x50, 0x00000004, Endian.little);
      ddsHeader.setUint32(0x54, _fourCcToUint32(match.format), Endian.little);
    }

    final int dwCaps = match.mipCount > 1 ? 0x00401008 : 0x00001000;
    ddsHeader.setUint32(0x6C, dwCaps, Endian.little);

    RandomAccessFile? raf;
    IOSink? sink;
    try {
      raf = await sourceFile.open(mode: FileMode.read);
      final int srcLen = await raf.length();
      if (match.payloadOffset >= srcLen) {
        throw StateError('Offset de payload fuera de rango');
      }

      sink = destFile.openWrite();
      sink.add(ddsHeader.buffer.asUint8List());

      await raf.setPosition(match.payloadOffset);
      int remaining = srcLen - match.payloadOffset;
      while (remaining > 0) {
        final int toRead = remaining > _chunkSize ? _chunkSize : remaining;
        final Uint8List chunk = await raf.read(toRead);
        if (chunk.isEmpty) break;
        sink.add(chunk);
        remaining -= chunk.length;
      }

      await sink.flush();
      await sink.close();
      sink = null;
    } finally {
      try {
        await sink?.close();
      } catch (_) {}
      await raf?.close();
    }
  }

  Future<void> _processGeometryCategory({
    required String categoryName,
    required String destDirPath,
    required List<File> files,
    required PortCategoryStats stats,
    required String stageLabel,
    required void Function(String src, String dst, bool converted, String detail) onItemDone,
  }) async {
    for (final file in files) {
      stats.analyzed++;
      final String ext = p.extension(file.path).toLowerCase();

      if (ext == '.obj') {
        try {
          final String dst = await _uniquePath(p.join(destDirPath, p.basename(file.path)));
          await _copyFileStreaming(file, File(dst));
          stats.converted++;
          onItemDone(file.path, dst, true, 'Wavefront OBJ copiado');
        } catch (e) {
          stats.skipped++;
          _log('[CONV:SKIP] Error copiando OBJ ${p.basename(file.path)}: $e');
          onItemDone(file.path, file.path, false, 'Error copiando OBJ: $e');
        }
        continue;
      }

      try {
        final String objPath = await _uniquePath(
          p.join(destDirPath, '${p.basenameWithoutExtension(file.path)}.obj'),
        );
        final String detail = await _extractBinaryGeometryToObj(
          sourceFile: file,
          destObjFile: File(objPath),
        );
        stats.converted++;
        _log('[$stageLabel] Exportado: ${p.basename(objPath)} ($detail)');
        onItemDone(file.path, objPath, true, detail);
      } catch (e) {
        stats.skipped++;
        _log('[CONV:SKIP] Malla/colisión no extraíble (${p.basename(file.path)}): $e');
        final String fallbackPath = await _uniquePath(
          p.join(destDirPath, p.basename(file.path)),
        );
        await _copyFileStreaming(file, File(fallbackPath));
        onItemDone(file.path, fallbackPath, false, 'Geometría no detectada ($e); original conservado');
      }
    }
  }

  Future<String> _extractBinaryGeometryToObj({
    required File sourceFile,
    required File destObjFile,
  }) async {
    final RandomAccessFile raf = await sourceFile.open(mode: FileMode.read);
    try {
      final int fileLength = await raf.length();
      if (fileLength < 64) {
        throw StateError('Archivo demasiado pequeño ($fileLength bytes)');
      }

      final _VertexBufferCandidate? bestVb = await _scanBestVertexBuffer(
        raf: raf,
        fileLength: fileLength,
      );
      if (bestVb == null || bestVb.vertexCount < 3) {
        throw StateError('No se halló un arreglo contiguo válido de vértices float32');
      }

      final _IndexBufferCandidate? bestIb = await _scanBestIndexBuffer(
        raf: raf,
        fileLength: fileLength,
        vertexCount: bestVb.vertexCount,
        vbStart: bestVb.offset,
        vbEnd: bestVb.offset + (bestVb.vertexCount * bestVb.stride),
      );

      final IOSink sink = destObjFile.openWrite(encoding: utf8);
      try {
        sink.writeln('# WoS Forensic Mesh');
        sink.writeln('# Source: ${p.basename(sourceFile.path)}');
        sink.writeln('# VertexOffset: 0x${bestVb.offset.toRadixString(16).toUpperCase()} Stride: ${bestVb.stride} Count: ${bestVb.vertexCount}');
        if (bestIb != null) {
          sink.writeln('# IndexOffset: 0x${bestIb.offset.toRadixString(16).toUpperCase()} Triangles: ${bestIb.triangleCount}');
        }
        sink.writeln('o ${p.basenameWithoutExtension(sourceFile.path).replaceAll(' ', '_')}');

        final bool hasUvs = bestVb.uvRelOffset >= 0;
        const int batchVertices = 2048;
        int writtenVerts = 0;
        while (writtenVerts < bestVb.vertexCount) {
          final int countNow = math.min(batchVertices, bestVb.vertexCount - writtenVerts);
          await raf.setPosition(bestVb.offset + (writtenVerts * bestVb.stride));
          final Uint8List vBytes = await raf.read(countNow * bestVb.stride);
          final ByteData bd = ByteData.sublistView(vBytes);

          for (int i = 0; i < countNow; i++) {
            final int base = i * bestVb.stride;
            if (base + 12 > vBytes.length) break;
            final double x = bd.getFloat32(base, Endian.little);
            final double y = bd.getFloat32(base + 4, Endian.little);
            final double z = bd.getFloat32(base + 8, Endian.little);
            sink.writeln('v ${x.toStringAsFixed(6)} ${y.toStringAsFixed(6)} ${z.toStringAsFixed(6)}');

            if (hasUvs && base + bestVb.uvRelOffset + 8 <= vBytes.length) {
              final double u = bd.getFloat32(base + bestVb.uvRelOffset, Endian.little);
              final double v = bd.getFloat32(base + bestVb.uvRelOffset + 4, Endian.little);
              sink.writeln('vt ${u.toStringAsFixed(6)} ${v.toStringAsFixed(6)}');
            }
          }
          writtenVerts += countNow;
        }

        int exportedTriangles = 0;
        if (bestIb != null && bestIb.triangleCount > 0) {
          const int batchTriangles = 4096;
          int processedTris = 0;
          while (processedTris < bestIb.triangleCount) {
            final int trisNow = math.min(batchTriangles, bestIb.triangleCount - processedTris);
            await raf.setPosition(bestIb.offset + (processedTris * 6));
            final Uint8List iBytes = await raf.read(trisNow * 6);
            final ByteData bd = ByteData.sublistView(iBytes);

            for (int t = 0; t < trisNow; t++) {
              final int base = t * 6;
              if (base + 6 > iBytes.length) break;
              final int a = bd.getUint16(base, Endian.little);
              final int b = bd.getUint16(base + 2, Endian.little);
              final int c = bd.getUint16(base + 4, Endian.little);
              if (a < bestVb.vertexCount &&
                  b < bestVb.vertexCount &&
                  c < bestVb.vertexCount &&
                  a != b &&
                  b != c &&
                  a != c) {
                final int ia = a + 1;
                final int ib = b + 1;
                final int ic = c + 1;
                if (hasUvs) {
                  sink.writeln('f $ia/$ia $ib/$ib $ic/$ic');
                } else {
                  sink.writeln('f $ia $ib $ic');
                }
                exportedTriangles++;
              }
            }
            processedTris += trisNow;
          }
        } else if (bestVb.vertexCount >= 3) {
          final int triCount = bestVb.vertexCount ~/ 3;
          for (int t = 0; t < triCount; t++) {
            final int i1 = (t * 3) + 1;
            final int i2 = i1 + 1;
            final int i3 = i1 + 2;
            if (hasUvs) {
              sink.writeln('f $i1/$i1 $i2/$i2 $i3/$i3');
            } else {
              sink.writeln('f $i1 $i2 $i3');
            }
            exportedTriangles++;
          }
        }

        await sink.flush();
        await sink.close();

        return '${bestVb.vertexCount} vértices (stride ${bestVb.stride}B), $exportedTriangles triángulos';
      } catch (e) {
        await sink.close();
        if (await destObjFile.exists()) {
          await destObjFile.delete();
        }
        rethrow;
      }
    } finally {
      await raf.close();
    }
  }

  Future<_VertexBufferCandidate?> _scanBestVertexBuffer({
    required RandomAccessFile raf,
    required int fileLength,
  }) async {
    const List<int> strides = <int>[12, 24, 32, 36, 40, 48];
    const int windowSize = 262144;
    const int overlap = 4096;

    _VertexBufferCandidate? best;

    for (final stride in strides) {
      int filePos = 0;
      while (filePos + (stride * 6) <= fileLength) {
        await raf.setPosition(filePos);
        final int toRead = math.min(windowSize, fileLength - filePos);
        final Uint8List buf = await raf.read(toRead);
        if (buf.length < stride * 6) break;
        final ByteData bd = ByteData.sublistView(buf);

        int localOff = 0;
        while (localOff + (stride * 6) <= buf.length) {
          if (_isPlausibleVertex(bd, localOff)) {
            int runCount = 0;
            int nonZeroCount = 0;
            int probeOff = localOff;

            while (probeOff + 12 <= buf.length && _isPlausibleVertex(bd, probeOff)) {
              final double x = bd.getFloat32(probeOff, Endian.little);
              final double y = bd.getFloat32(probeOff + 4, Endian.little);
              final double z = bd.getFloat32(probeOff + 8, Endian.little);
              if (x.abs() + y.abs() + z.abs() > 1e-4) {
                nonZeroCount++;
              }
              runCount++;
              probeOff += stride;
            }

            final int absStart = filePos + localOff;
            if (probeOff + stride > buf.length && absStart + (runCount * stride) < fileLength) {
              runCount = await _extendVertexRunFromFile(
                raf: raf,
                startOffset: absStart,
                stride: stride,
                initialCount: runCount,
                fileLength: fileLength,
              );
            }

            if (runCount >= 8 && nonZeroCount >= 4) {
              final int uvRel = _detectUvOffsetInStride(
                bd: bd,
                startLocal: localOff,
                stride: stride,
                sampleVerts: math.min(runCount, (buf.length - localOff) ~/ stride),
              );
              final double score = runCount.toDouble() + (uvRel >= 0 ? 50.0 : 0.0);
              if (best == null || score > best.score) {
                best = _VertexBufferCandidate(
                  offset: absStart,
                  stride: stride,
                  vertexCount: runCount,
                  uvRelOffset: uvRel,
                  score: score,
                );
              }
            }

            localOff += math.max(stride, runCount * stride);
          } else {
            localOff += 4;
          }
        }

        if (filePos + toRead >= fileLength) break;
        filePos += toRead - overlap;
      }
    }

    return best;
  }

  Future<int> _extendVertexRunFromFile({
    required RandomAccessFile raf,
    required int startOffset,
    required int stride,
    required int initialCount,
    required int fileLength,
  }) async {
    int count = initialCount;
    int nextPos = startOffset + (count * stride);
    while (nextPos + 12 <= fileLength) {
      await raf.setPosition(nextPos);
      final int toRead = math.min(_chunkSize - (_chunkSize % stride), fileLength - nextPos);
      if (toRead < stride) break;
      final Uint8List chunk = await raf.read(toRead);
      final ByteData bd = ByteData.sublistView(chunk);
      int pos = 0;
      bool broke = false;
      while (pos + 12 <= chunk.length) {
        if (!_isPlausibleVertex(bd, pos)) {
          broke = true;
          break;
        }
        count++;
        pos += stride;
      }
      nextPos += pos;
      if (broke || chunk.length < toRead) break;
    }
    return count;
  }

  bool _isPlausibleVertex(ByteData bd, int offset) {
    final double x = bd.getFloat32(offset, Endian.little);
    final double y = bd.getFloat32(offset + 4, Endian.little);
    final double z = bd.getFloat32(offset + 8, Endian.little);

    if (x.isNaN || x.isInfinite || y.isNaN || y.isInfinite || z.isNaN || z.isInfinite) {
      return false;
    }
    if (x < -50000.0 || x > 50000.0 || y < -50000.0 || y > 50000.0 || z < -50000.0 || z > 50000.0) {
      return false;
    }

    bool validCoord(double v) => v == 0.0 || (v.abs() >= 1e-4 && v.abs() <= 50000.0);
    if (!validCoord(x) || !validCoord(y) || !validCoord(z)) {
      return false;
    }

    return (x != 0.0 || y != 0.0 || z != 0.0);
  }

  int _detectUvOffsetInStride({
    required ByteData bd,
    required int startLocal,
    required int stride,
    required int sampleVerts,
  }) {
    if (stride < 20 || sampleVerts < 4) return -1;
    final int checkCount = math.min(sampleVerts, 16);

    for (int rel = 12; rel + 8 <= stride; rel += 4) {
      bool allValid = true;
      int nonZeroUvs = 0;
      for (int i = 0; i < checkCount; i++) {
        final int pos = startLocal + (i * stride) + rel;
        final double u = bd.getFloat32(pos, Endian.little);
        final double v = bd.getFloat32(pos + 4, Endian.little);
        if (u.isNaN ||
            u.isInfinite ||
            v.isNaN ||
            v.isInfinite ||
            u < -16.0 ||
            u > 16.0 ||
            v < -16.0 ||
            v > 16.0) {
          allValid = false;
          break;
        }
        if ((u != 0.0 && u.abs() < 1e-5) || (v != 0.0 && v.abs() < 1e-5)) {
          allValid = false;
          break;
        }
        if (u != 0.0 || v != 0.0) nonZeroUvs++;
      }
      if (allValid && nonZeroUvs >= 2) {
        return rel;
      }
    }
    return -1;
  }

  Future<_IndexBufferCandidate?> _scanBestIndexBuffer({
    required RandomAccessFile raf,
    required int fileLength,
    required int vertexCount,
    required int vbStart,
    required int vbEnd,
  }) async {
    const int windowSize = 262144;
    const int overlap = 1024;
    _IndexBufferCandidate? best;

    int filePos = 0;
    while (filePos + 24 <= fileLength) {
      await raf.setPosition(filePos);
      final int toRead = math.min(windowSize, fileLength - filePos);
      final Uint8List buf = await raf.read(toRead);
      if (buf.length < 24) break;
      final ByteData bd = ByteData.sublistView(buf);

      int localOff = 0;
      while (localOff + 24 <= buf.length) {
        final int absOff = filePos + localOff;
        if (absOff >= vbStart && absOff < vbEnd) {
          localOff = (vbEnd - filePos);
          if (localOff < 0) localOff = buf.length;
          continue;
        }

        int validTris = 0;
        int probe = localOff;
        while (probe + 6 <= buf.length) {
          final int absProbe = filePos + probe;
          if (absProbe >= vbStart && absProbe < vbEnd) break;

          final int a = bd.getUint16(probe, Endian.little);
          final int b = bd.getUint16(probe + 2, Endian.little);
          final int c = bd.getUint16(probe + 4, Endian.little);
          if (a < vertexCount &&
              b < vertexCount &&
              c < vertexCount &&
              a != b &&
              b != c &&
              a != c) {
            validTris++;
            probe += 6;
          } else {
            break;
          }
        }

        if (validTris >= 4) {
          int totalTris = validTris;
          if (probe + 6 > buf.length) {
            totalTris = await _extendIndexRunFromFile(
              raf: raf,
              startOffset: absOff,
              initialTris: validTris,
              vertexCount: vertexCount,
              vbStart: vbStart,
              vbEnd: vbEnd,
              fileLength: fileLength,
            );
          }

          if (best == null || totalTris > best.triangleCount) {
            best = _IndexBufferCandidate(
              offset: absOff,
              indexCount: totalTris * 3,
              triangleCount: totalTris,
            );
          }
          localOff += math.max(6, validTris * 6);
        } else {
          localOff += 2;
        }
      }

      if (filePos + toRead >= fileLength) break;
      filePos += toRead - overlap;
    }

    return best;
  }

  Future<int> _extendIndexRunFromFile({
    required RandomAccessFile raf,
    required int startOffset,
    required int initialTris,
    required int vertexCount,
    required int vbStart,
    required int vbEnd,
    required int fileLength,
  }) async {
    int tris = initialTris;
    int nextPos = startOffset + (tris * 6);
    while (nextPos + 6 <= fileLength) {
      if (nextPos >= vbStart && nextPos < vbEnd) break;
      await raf.setPosition(nextPos);
      final int toRead = math.min(65532, fileLength - nextPos);
      if (toRead < 6) break;
      final Uint8List chunk = await raf.read(toRead);
      final ByteData bd = ByteData.sublistView(chunk);
      int pos = 0;
      bool broke = false;
      while (pos + 6 <= chunk.length) {
        final int absPos = nextPos + pos;
        if (absPos >= vbStart && absPos < vbEnd) {
          broke = true;
          break;
        }
        final int a = bd.getUint16(pos, Endian.little);
        final int b = bd.getUint16(pos + 2, Endian.little);
        final int c = bd.getUint16(pos + 4, Endian.little);
        if (a >= vertexCount || b >= vertexCount || c >= vertexCount || a == b || b == c || a == c) {
          broke = true;
          break;
        }
        tris++;
        pos += 6;
      }
      nextPos += pos;
      if (broke || chunk.length < toRead) break;
    }
    return tris;
  }

  Future<void> _processSkeletonsCategory({
    required String destDirPath,
    required List<File> files,
    required PortCategoryStats stats,
    required void Function(String src, String dst, bool converted, String detail) onItemDone,
  }) async {
    for (final file in files) {
      stats.analyzed++;
      final String ext = p.extension(file.path).toLowerCase();

      if (ext == '.json') {
        try {
          final String dst = await _uniquePath(p.join(destDirPath, p.basename(file.path)));
          await _copyFileStreaming(file, File(dst));
          stats.converted++;
          onItemDone(file.path, dst, true, 'JSON de esqueleto copiado');
        } catch (e) {
          stats.skipped++;
          _log('[CONV:SKIP] Error copiando JSON ${p.basename(file.path)}: $e');
          onItemDone(file.path, file.path, false, 'Error copiando JSON: $e');
        }
        continue;
      }

      try {
        final String outJsonPath = await _uniquePath(
          p.join(destDirPath, '${p.basenameWithoutExtension(file.path)}.json'),
        );
        final String detail = await _extractSkeletonOrAnimToJson(
          sourceFile: file,
          destJsonFile: File(outJsonPath),
        );
        stats.converted++;
        _log('[RIG/ANIM] Exportado: ${p.basename(outJsonPath)} ($detail)');
        onItemDone(file.path, outJsonPath, true, detail);
      } catch (e) {
        stats.skipped++;
        _log('[CONV:SKIP] Esqueleto/Anim no parseable (${p.basename(file.path)}): $e');
        final String fallbackPath = await _uniquePath(
          p.join(destDirPath, p.basename(file.path)),
        );
        await _copyFileStreaming(file, File(fallbackPath));
        onItemDone(file.path, fallbackPath, false, 'Estructura ANIM/SKELMAP no detectada; original conservado');
      }
    }
  }

  Future<String> _extractSkeletonOrAnimToJson({
    required File sourceFile,
    required File destJsonFile,
  }) async {
    final RandomAccessFile raf = await sourceFile.open(mode: FileMode.read);
    try {
      final int fileLength = await raf.length();
      if (fileLength < 16) {
        throw StateError('Archivo demasiado pequeño');
      }

      await raf.setPosition(0);
      final Uint8List head = await raf.read(math.min(64, fileLength));
      final ByteData headBd = ByteData.sublistView(head);
      final String magic = _printableAscii(head.sublist(0, math.min(8, head.length)));

      int frameCountHint = 0;
      if (head.length >= 16) {
        for (int off = 4; off <= 28 && off + 4 <= head.length; off += 4) {
          final int val = headBd.getUint32(off, Endian.little);
          if (val >= 1 && val <= 30000) {
            frameCountHint = val;
            break;
          }
        }
      }

      final List<Map<String, Object>> bones = <Map<String, Object>>[];
      final Set<String> seenBoneNames = <String>{};
      final List<int> hierarchyParents = <int>[];
      final List<Map<String, Object>> keyframes = <Map<String, Object>>[];

      final RegExp bonePattern = RegExp(
        r'^(Bip\d+|Pelvis|Spine\d*|Neck|Head|Root|Bone\d*|[LR]_[A-Za-z0-9_]+|[A-Za-z][A-Za-z0-9_]{2,47})$',
      );
      final RegExp knownRigKeywords = RegExp(
        r'(bip|pelvis|spine|head|neck|clavicle|shoulder|arm|forearm|hand|finger|thumb|thigh|calf|shin|foot|toe|root|jaw|eye|tail|cape|web|camera|weapon)',
        caseSensitive: false,
      );

      int pos = 0;
      const int overlap = 256;
      while (pos < fileLength) {
        await raf.setPosition(pos);
        final int toRead = math.min(_chunkSize, fileLength - pos);
        final Uint8List chunk = await raf.read(toRead);
        if (chunk.isEmpty) break;

        int i = 0;
        while (i < chunk.length) {
          if (_isAsciiIdentChar(chunk[i])) {
            final int start = i;
            while (i < chunk.length && _isAsciiIdentChar(chunk[i]) && (i - start) < 64) {
              i++;
            }
            if (i < chunk.length && chunk[i] == 0 && (i - start) >= 3) {
              final String candidate = String.fromCharCodes(chunk.sublist(start, i));
              if (bonePattern.hasMatch(candidate) &&
                  (knownRigKeywords.hasMatch(candidate) || candidate.contains('_')) &&
                  seenBoneNames.add(candidate)) {
                bones.add(<String, Object>{
                  'indice': bones.length,
                  'nombre': candidate,
                  'offset': '0x${(pos + start).toRadixString(16).toUpperCase()}',
                });
              }
            }
          }
          i++;
        }

        if (hierarchyParents.isEmpty && bones.length >= 3) {
          final ByteData bd = ByteData.sublistView(chunk);
          for (int off = 0; off + (bones.length * 2) <= chunk.length; off += 2) {
            int roots = 0;
            bool valid = true;
            final List<int> tempParents = <int>[];
            for (int b = 0; b < bones.length; b++) {
              final int parentIdx = bd.getInt16(off + (b * 2), Endian.little);
              if (parentIdx < -1 || parentIdx >= bones.length || parentIdx == b) {
                valid = false;
                break;
              }
              if (parentIdx == -1) roots++;
              tempParents.add(parentIdx);
            }
            if (valid && roots >= 1 && roots <= math.max(3, bones.length ~/ 4)) {
              hierarchyParents.addAll(tempParents);
              break;
            }
          }
        }

        if (keyframes.length < 4096) {
          final ByteData bd = ByteData.sublistView(chunk);
          for (int off = 0; off + 16 <= chunk.length && keyframes.length < 4096; off += 4) {
            final double qx = bd.getFloat32(off, Endian.little);
            final double qy = bd.getFloat32(off + 4, Endian.little);
            final double qz = bd.getFloat32(off + 8, Endian.little);
            final double qw = bd.getFloat32(off + 12, Endian.little);
            if (qx.isNaN || qy.isNaN || qz.isNaN || qw.isNaN) continue;
            if (qx.abs() > 1.05 || qy.abs() > 1.05 || qz.abs() > 1.05 || qw.abs() > 1.05) {
              continue;
            }
            final double normSq = (qx * qx) + (qy * qy) + (qz * qz) + (qw * qw);
            if (normSq >= 0.96 && normSq <= 1.04) {
              final bool trivialIdentity = qx == 0.0 && qy == 0.0 && qz == 0.0 && qw == 1.0;
              if (!trivialIdentity || keyframes.isNotEmpty) {
                keyframes.add(<String, Object>{
                  'offset': '0x${(pos + off).toRadixString(16).toUpperCase()}',
                  'quaternion': <double>[
                    double.parse(qx.toStringAsFixed(6)),
                    double.parse(qy.toStringAsFixed(6)),
                    double.parse(qz.toStringAsFixed(6)),
                    double.parse(qw.toStringAsFixed(6)),
                  ],
                });
                off += 12;
              }
            }
          }
        }

        if (pos + toRead >= fileLength) break;
        pos += toRead - overlap;
      }

      if (bones.isEmpty && keyframes.isEmpty) {
        throw StateError('Sin nombres de huesos ni cuaterniones normalizados');
      }

      final List<Map<String, Object>> hierarchy = <Map<String, Object>>[];
      for (int idx = 0; idx < bones.length; idx++) {
        final int parentIdx = idx < hierarchyParents.length ? hierarchyParents[idx] : (idx == 0 ? -1 : 0);
        hierarchy.add(<String, Object>{
          'boneIndex': idx,
          'boneName': bones[idx]['nombre']!,
          'parentIndex': parentIdx,
          if (parentIdx >= 0 && parentIdx < bones.length)
            'parentName': bones[parentIdx]['nombre']!,
        });
      }

      final IOSink sink = destJsonFile.openWrite(encoding: utf8);
      try {
        final Map<String, Object> doc = <String, Object>{
          'archivoOrigen': p.basename(sourceFile.path),
          'firma': magic,
          'tamanoBytes': fileLength,
          'conteoFramesEstimado': frameCountHint,
          'totalHuesos': bones.length,
          'huesos': bones,
          'jerarquia': hierarchy,
          'totalKeyframesMuestreados': keyframes.length,
          'keyframes': keyframes,
        };
        sink.write(const JsonEncoder.withIndent('  ').convert(doc));
        await sink.flush();
      } finally {
        await sink.close();
      }

      return '${bones.length} huesos, ${keyframes.length} keyframes';
    } finally {
      await raf.close();
    }
  }

  Future<void> _processTextAndEntitiesCategory({
    required String categoryName,
    required String destDirPath,
    required List<File> files,
    required PortCategoryStats stats,
    required void Function(String src, List<String> dstList, bool converted, String detail) onItemDone,
  }) async {
    for (final file in files) {
      stats.analyzed++;
      final String ext = p.extension(file.path).toLowerCase();

      if (ext == '.ttf' || ext == '.otf') {
        try {
          final String dst = await _uniquePath(p.join(destDirPath, p.basename(file.path)));
          await _copyFileStreaming(file, File(dst));
          stats.converted++;
          onItemDone(file.path, <String>[dst], true, 'Fuente tipográfica copiada');
        } catch (e) {
          stats.skipped++;
          _log('[CONV:SKIP] Error copiando fuente ${p.basename(file.path)}: $e');
          onItemDone(file.path, <String>[file.path], false, 'Error copiando fuente: $e');
        }
        continue;
      }

      try {
        final String baseName = p.basenameWithoutExtension(file.path);
        final String jsonOutPath = await _uniquePath(p.join(destDirPath, '$baseName.json'));
        final String csvOutPath = await _uniquePath(p.join(destDirPath, '$baseName.csv'));

        final String detail = await _extractStringsAndParamsToJsonCsv(
          sourceFile: file,
          destJsonFile: File(jsonOutPath),
          destCsvFile: File(csvOutPath),
        );

        stats.converted++;
        _log('[$categoryName] Exportado JSON+CSV: $baseName ($detail)');
        onItemDone(file.path, <String>[jsonOutPath, csvOutPath], true, detail);
      } catch (e) {
        stats.skipped++;
        _log('[CONV:SKIP] Tabla/Entidad no extraíble (${p.basename(file.path)}): $e');
        final String fallbackPath = await _uniquePath(
          p.join(destDirPath, p.basename(file.path)),
        );
        await _copyFileStreaming(file, File(fallbackPath));
        onItemDone(file.path, <String>[fallbackPath], false, 'Sin cadenas válidas ($e); original conservado');
      }
    }
  }

  Future<String> _extractStringsAndParamsToJsonCsv({
    required File sourceFile,
    required File destJsonFile,
    required File destCsvFile,
  }) async {
    final RandomAccessFile raf = await sourceFile.open(mode: FileMode.read);
    try {
      final int fileLength = await raf.length();
      if (fileLength == 0) {
        throw StateError('Archivo vacío');
      }

      final String fileHintLang = _inferLanguageFromFilename(p.basename(sourceFile.path));
      final List<_ExtractedStringEntry> entries = <_ExtractedStringEntry>[];
      final Map<String, String> detectedParams = <String, String>{};
      final Set<String> seenOffsets = <String>{};

      int pos = 0;
      const int overlap = 512;

      while (pos < fileLength) {
        await raf.setPosition(pos);
        final int toRead = math.min(_chunkSize, fileLength - pos);
        final Uint8List chunk = await raf.read(toRead);
        if (chunk.isEmpty) break;

        int i = 0;
        while (i < chunk.length) {
          if (_isReadableTextByte(chunk[i])) {
            final int start = i;
            while (i < chunk.length && _isReadableTextByte(chunk[i]) && (i - start) < 2048) {
              i++;
            }
            final int strLen = i - start;
            if (strLen >= 3) {
              final String rawText = utf8.decode(chunk.sublist(start, i), allowMalformed: true);
              final String clean = _cleanControlChars(rawText);
              if (clean.length >= 3 && _hasMeaningfulLettersOrDigits(clean)) {
                final int absOffset = pos + start;
                final String key = 'A:$absOffset';
                if (seenOffsets.add(key)) {
                  final String lang = fileHintLang != 'DESCONOCIDO'
                      ? fileHintLang
                      : _detectTextLanguage(clean);
                  entries.add(_ExtractedStringEntry(
                    offset: absOffset,
                    encoding: 'ASCII/UTF-8',
                    detectedLanguage: lang,
                    text: clean,
                  ));
                  _captureKeyValueParam(clean, detectedParams);
                }
              }
            }
          }
          i++;
        }

        int u = 0;
        while (u + 5 < chunk.length) {
          if (_isUtf16LeCharAt(chunk, u)) {
            final int start = u;
            final List<int> codeUnits = <int>[];
            while (u + 1 < chunk.length && _isUtf16LeCharAt(chunk, u) && codeUnits.length < 1024) {
              codeUnits.add(chunk[u] | (chunk[u + 1] << 8));
              u += 2;
            }
            if (codeUnits.length >= 3) {
              final String clean = _cleanControlChars(String.fromCharCodes(codeUnits));
              if (clean.length >= 3 && _hasMeaningfulLettersOrDigits(clean)) {
                final int absOffset = pos + start;
                final String key = 'U:$absOffset';
                if (seenOffsets.add(key)) {
                  final String lang = fileHintLang != 'DESCONOCIDO'
                      ? fileHintLang
                      : _detectTextLanguage(clean);
                  entries.add(_ExtractedStringEntry(
                    offset: absOffset,
                    encoding: 'UTF-16LE',
                    detectedLanguage: lang,
                    text: clean,
                  ));
                  _captureKeyValueParam(clean, detectedParams);
                }
              }
            }
          } else {
            u += 2;
          }
        }

        if (pos + toRead >= fileLength) break;
        pos += toRead - overlap;
      }

      if (entries.isEmpty) {
        throw StateError('No se hallaron cadenas ASCII ni UTF-16LE legibles');
      }

      final IOSink csvSink = destCsvFile.openWrite(encoding: utf8);
      try {
        csvSink.writeln('ID_Offset,Idioma_Detectado,Texto_Limpio');
        for (final entry in entries) {
          final String idOffset = '0x${entry.offset.toRadixString(16).toUpperCase()}';
          csvSink.writeln(
            '${_csvEscape(idOffset)},${_csvEscape(entry.detectedLanguage)},${_csvEscape(entry.text)}',
          );
        }
        await csvSink.flush();
      } finally {
        await csvSink.close();
      }

      final IOSink jsonSink = destJsonFile.openWrite(encoding: utf8);
      try {
        jsonSink.writeln('{');
        jsonSink.writeln('  "archivoOrigen": ${jsonEncode(p.basename(sourceFile.path))},');
        jsonSink.writeln('  "tamanoBytes": $fileLength,');
        jsonSink.writeln('  "totalCadenas": ${entries.length},');
        jsonSink.writeln('  "parametrosDetectados": ${const JsonEncoder.withIndent('    ').convert(detectedParams).replaceAll('\n', '\n  ')},');
        jsonSink.writeln('  "entradas": [');
        for (int idx = 0; idx < entries.length; idx++) {
          final e = entries[idx];
          final String rowJson = jsonEncode(<String, Object>{
            'idOffset': '0x${e.offset.toRadixString(16).toUpperCase()}',
            'idiomaDetectado': e.detectedLanguage,
            'codificacion': e.encoding,
            'textoLimpio': e.text,
          });
          final String comma = idx < entries.length - 1 ? ',' : '';
          jsonSink.writeln('    $rowJson$comma');
        }
        jsonSink.writeln('  ]');
        jsonSink.writeln('}');
        await jsonSink.flush();
      } finally {
        await jsonSink.close();
      }

      return '${entries.length} cadenas (${detectedParams.length} parámetros)';
    } finally {
      await raf.close();
    }
  }

  Future<void> _processEngineBinariesCategory({
    required String destDirPath,
    required List<File> files,
    required PortCategoryStats stats,
    required void Function(String src, List<String> dstList, bool converted, String detail) onItemDone,
  }) async {
    for (final file in files) {
      stats.analyzed++;
      try {
        final String baseName = p.basenameWithoutExtension(file.path);
        final String jsonOutPath = await _uniquePath(
          p.join(destDirPath, '${baseName}_port_analysis.json'),
        );
        final String txtOutPath = await _uniquePath(
          p.join(destDirPath, '${baseName}_port_analysis.txt'),
        );

        final String detail = await _analyzeEngineBinaryOrShader(
          sourceFile: file,
          destJsonFile: File(jsonOutPath),
          destTxtFile: File(txtOutPath),
        );

        stats.converted++;
        _log('[BIN/PORT] Analizado: ${p.basename(file.path)} ($detail)');
        onItemDone(file.path, <String>[jsonOutPath, txtOutPath], true, detail);
      } catch (e) {
        stats.skipped++;
        _log('[CONV:SKIP] Binario/shader no analizable (${p.basename(file.path)}): $e');
        final String fallbackPath = await _uniquePath(
          p.join(destDirPath, p.basename(file.path)),
        );
        await _copyFileStreaming(file, File(fallbackPath));
        onItemDone(file.path, <String>[fallbackPath], false, 'Error analizando binario ($e); original conservado');
      }
    }
  }

  Future<String> _analyzeEngineBinaryOrShader({
    required File sourceFile,
    required File destJsonFile,
    required File destTxtFile,
  }) async {
    final RandomAccessFile raf = await sourceFile.open(mode: FileMode.read);
    try {
      final int fileLength = await raf.length();
      if (fileLength < 8) {
        throw StateError('Archivo binario demasiado pequeño');
      }

      await raf.setPosition(0);
      final Uint8List head64 = await raf.read(math.min(64, fileLength));
      final String magicStr = _printableAscii(head64.sublist(0, math.min(8, head64.length)));

      final Map<String, Object?> analysis = <String, Object?>{
        'archivoOrigen': p.basename(sourceFile.path),
        'tamanoBytes': fileLength,
        'firma': magicStr,
      };

      final List<_PeSection> sections = <_PeSection>[];
      final Map<String, List<String>> importedDlls = <String, List<String>>{};
      final List<String> exportedFunctions = <String>[];
      final List<String> shaderConstants = <String>[];

      if (head64.length >= 64 && head64[0] == 0x4D && head64[1] == 0x5A) {
        await _parsePeCoffBinary(
          raf: raf,
          fileLength: fileLength,
          head64: head64,
          analysisOut: analysis,
          sectionsOut: sections,
          importsOut: importedDlls,
          exportsOut: exportedFunctions,
        );
      } else if (magicStr.startsWith('XEX2')) {
        await _parseXex2Binary(
          raf: raf,
          fileLength: fileLength,
          analysisOut: analysis,
          importsOut: importedDlls,
        );
      } else if (magicStr.startsWith('PCVS') ||
          magicStr.startsWith('PCPS') ||
          magicStr.startsWith('PCSV') ||
          magicStr.startsWith('PCSX') ||
          magicStr.startsWith('DXBC') ||
          p.extension(sourceFile.path).toLowerCase().contains('fx')) {
        await _parseShaderBinary(
          raf: raf,
          fileLength: fileLength,
          magicStr: magicStr,
          analysisOut: analysis,
          constantsOut: shaderConstants,
        );
      } else {
        analysis['tipoFormato'] = 'Binario / Tabla de motor / MSI';
      }

      final List<String> technicalStrings = await _scanTechnicalPortStrings(
        raf: raf,
        fileLength: fileLength,
      );

      analysis['secciones'] = sections.map((s) => s.toJson()).toList();
      analysis['libreriasImportadas'] = importedDlls;
      analysis['funcionesExportadas'] = exportedFunctions;
      if (shaderConstants.isNotEmpty) {
        analysis['constantesShader'] = shaderConstants;
      }
      analysis['cadenasTecnicasCount'] = technicalStrings.length;
      analysis['cadenasTecnicas'] = technicalStrings;

      final IOSink jsonSink = destJsonFile.openWrite(encoding: utf8);
      try {
        jsonSink.write(const JsonEncoder.withIndent('  ').convert(analysis));
        await jsonSink.flush();
      } finally {
        await jsonSink.close();
      }

      final IOSink txtSink = destTxtFile.openWrite(encoding: utf8);
      try {
        txtSink.writeln('=== WoS C++ PORT ANALYSIS ===');
        txtSink.writeln('Archivo: ${p.basename(sourceFile.path)} ($fileLength bytes)');
        txtSink.writeln('Formato: ${analysis['tipoFormato'] ?? magicStr}');
        if (analysis.containsKey('arquitectura')) {
          txtSink.writeln('Arquitectura: ${analysis['arquitectura']}');
        }
        if (analysis.containsKey('entryPoint')) {
          txtSink.writeln('EntryPoint: ${analysis['entryPoint']}');
        }
        txtSink.writeln('\n--- SECCIONES (${sections.length}) ---');
        for (final s in sections) {
          txtSink.writeln(
            '${s.name.padRight(10)} VA=0x${s.virtualAddress.toRadixString(16)} RawOff=0x${s.rawAddress.toRadixString(16)} RawSize=${s.rawSize}',
          );
        }
        txtSink.writeln('\n--- LIBRERÍAS IMPORTADAS (${importedDlls.length}) ---');
        for (final e in importedDlls.entries) {
          txtSink.writeln('[${e.key}] (${e.value.length} funciones): ${e.value.take(25).join(', ')}');
        }
        if (exportedFunctions.isNotEmpty) {
          txtSink.writeln('\n--- FUNCIONES EXPORTADAS (${exportedFunctions.length}) ---');
          for (final fn in exportedFunctions.take(200)) {
            txtSink.writeln('  $fn');
          }
        }
        if (shaderConstants.isNotEmpty) {
          txtSink.writeln('\n--- CONSTANTES DE SHADER (${shaderConstants.length}) ---');
          for (final c in shaderConstants) {
            txtSink.writeln('  $c');
          }
        }
        txtSink.writeln('\n--- CADENAS TÉCNICAS / RUTAS CPP (${technicalStrings.length}) ---');
        for (final ts in technicalStrings) {
          txtSink.writeln('  $ts');
        }
        await txtSink.flush();
      } finally {
        await txtSink.close();
      }

      return '${sections.length} secciones, ${importedDlls.length} DLLs, ${technicalStrings.length} cadenas técnicas';
    } finally {
      await raf.close();
    }
  }

  Future<void> _parsePeCoffBinary({
    required RandomAccessFile raf,
    required int fileLength,
    required Uint8List head64,
    required Map<String, Object?> analysisOut,
    required List<_PeSection> sectionsOut,
    required Map<String, List<String>> importsOut,
    required List<String> exportsOut,
  }) async {
    final ByteData dosBd = ByteData.sublistView(head64);
    final int peOffset = dosBd.getUint32(0x3C, Endian.little);
    if (peOffset <= 0 || peOffset + 256 > fileLength) {
      analysisOut['tipoFormato'] = 'DOS / MZ sin cabecera PE válida';
      return;
    }

    await raf.setPosition(peOffset);
    final Uint8List peHdr = await raf.read(math.min(512, fileLength - peOffset));
    if (peHdr.length < 24 ||
        peHdr[0] != 0x50 ||
        peHdr[1] != 0x45 ||
        peHdr[2] != 0 ||
        peHdr[3] != 0) {
      analysisOut['tipoFormato'] = 'MZ sin firma PE\\0\\0';
      return;
    }

    final ByteData peBd = ByteData.sublistView(peHdr);
    final int machine = peBd.getUint16(4, Endian.little);
    final int numSections = peBd.getUint16(6, Endian.little);
    final int timeStamp = peBd.getUint32(8, Endian.little);
    final int optHeaderSize = peBd.getUint16(20, Endian.little);
    final int optMagic = peHdr.length >= 26 ? peBd.getUint16(24, Endian.little) : 0;
    final bool isPe64 = optMagic == 0x020B;

    analysisOut['tipoFormato'] = isPe64 ? 'PE32+ (64-bit)' : 'PE32 (32-bit)';
    analysisOut['arquitectura'] = machine == 0x014C
        ? 'x86 (0x014C)'
        : (machine == 0x8664 ? 'x86_64 (0x8664)' : '0x${machine.toRadixString(16)}');
    analysisOut['timeDateStamp'] = timeStamp;

    if (peHdr.length >= 44) {
      final int entryRva = peBd.getUint32(40, Endian.little);
      analysisOut['entryPoint'] = '0x${entryRva.toRadixString(16).toUpperCase()}';
    }

    final int sectionsTableOffset = peOffset + 24 + optHeaderSize;
    if (numSections > 0 &&
        numSections <= 96 &&
        sectionsTableOffset + (numSections * 40) <= fileLength) {
      await raf.setPosition(sectionsTableOffset);
      final Uint8List secBytes = await raf.read(numSections * 40);
      final ByteData secBd = ByteData.sublistView(secBytes);
      for (int i = 0; i < numSections; i++) {
        final int base = i * 40;
        final String secName = _readNullPaddedAscii(secBytes.sublist(base, base + 8));
        sectionsOut.add(_PeSection(
          name: secName,
          virtualSize: secBd.getUint32(base + 8, Endian.little),
          virtualAddress: secBd.getUint32(base + 12, Endian.little),
          rawSize: secBd.getUint32(base + 16, Endian.little),
          rawAddress: secBd.getUint32(base + 20, Endian.little),
          characteristics: secBd.getUint32(base + 36, Endian.little),
        ));
      }
    }

    int? rvaToOffset(int rva) {
      for (final s in sectionsOut) {
        final int span = math.max(s.virtualSize, s.rawSize);
        if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
          final int off = s.rawAddress + (rva - s.virtualAddress);
          if (off >= 0 && off < fileLength) return off;
        }
      }
      return null;
    }

    final int dataDirStart = isPe64 ? 24 + 112 : 24 + 96;
    if (peHdr.length >= dataDirStart + 16) {
      final int exportRva = peBd.getUint32(dataDirStart, Endian.little);
      final int importRva = peBd.getUint32(dataDirStart + 8, Endian.little);

      if (importRva > 0) {
        final int? impOff = rvaToOffset(importRva);
        if (impOff != null) {
          for (int d = 0; d < 256; d++) {
            final int descPos = impOff + (d * 20);
            if (descPos + 20 > fileLength) break;
            await raf.setPosition(descPos);
            final Uint8List descBytes = await raf.read(20);
            final ByteData descBd = ByteData.sublistView(descBytes);

            final int origFirstThunk = descBd.getUint32(0, Endian.little);
            final int nameRva = descBd.getUint32(12, Endian.little);
            final int firstThunk = descBd.getUint32(16, Endian.little);
            if (nameRva == 0 && firstThunk == 0) break;

            final int? dllNameOff = rvaToOffset(nameRva);
            if (dllNameOff == null) continue;
            final String dllName = await _readCStringAt(raf, dllNameOff, fileLength);
            if (dllName.isEmpty) continue;

            final List<String> funcs = <String>[];
            final int thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
            final int? thunkOff = rvaToOffset(thunkRva);
            if (thunkOff != null) {
              final int entrySize = isPe64 ? 8 : 4;
              for (int t = 0; t < 1024; t++) {
                final int tPos = thunkOff + (t * entrySize);
                if (tPos + entrySize > fileLength) break;
                await raf.setPosition(tPos);
                final Uint8List tBytes = await raf.read(entrySize);
                final ByteData tBd = ByteData.sublistView(tBytes);
                final int val = isPe64
                    ? tBd.getUint64(0, Endian.little)
                    : tBd.getUint32(0, Endian.little);
                if (val == 0) break;

                final bool byOrdinal = isPe64
                    ? (val & 0x8000000000000000) != 0
                    : (val & 0x80000000) != 0;
                if (byOrdinal) {
                  funcs.add('Ordinal_${val & 0xFFFF}');
                } else {
                  final int? hintNameOff = rvaToOffset(val & 0x7FFFFFFF);
                  if (hintNameOff != null && hintNameOff + 2 < fileLength) {
                    final String fn = await _readCStringAt(raf, hintNameOff + 2, fileLength);
                    if (fn.isNotEmpty) funcs.add(fn);
                  }
                }
              }
            }
            importsOut[dllName] = funcs;
          }
        }
      }

      if (exportRva > 0) {
        final int? expOff = rvaToOffset(exportRva);
        if (expOff != null && expOff + 40 <= fileLength) {
          await raf.setPosition(expOff);
          final Uint8List expBytes = await raf.read(40);
          final ByteData expBd = ByteData.sublistView(expBytes);
          final int numNames = expBd.getUint32(24, Endian.little);
          final int addrOfNamesRva = expBd.getUint32(32, Endian.little);
          final int? namesOff = rvaToOffset(addrOfNamesRva);
          if (namesOff != null && numNames > 0 && numNames <= 8192) {
            await raf.setPosition(namesOff);
            final int readLen = math.min(numNames * 4, fileLength - namesOff);
            final Uint8List namePtrs = await raf.read(readLen);
            final ByteData ptrBd = ByteData.sublistView(namePtrs);
            for (int n = 0; n + 4 <= namePtrs.length; n += 4) {
              final int fnRva = ptrBd.getUint32(n, Endian.little);
              final int? fnOff = rvaToOffset(fnRva);
              if (fnOff != null) {
                final String fn = await _readCStringAt(raf, fnOff, fileLength);
                if (fn.isNotEmpty) exportsOut.add(fn);
              }
            }
          }
        }
      }
    }
  }

  Future<void> _parseXex2Binary({
    required RandomAccessFile raf,
    required int fileLength,
    required Map<String, Object?> analysisOut,
    required Map<String, List<String>> importsOut,
  }) async {
    analysisOut['tipoFormato'] = 'Xbox 360 XEX2 Executable';
    analysisOut['arquitectura'] = 'PowerPC Xenon (Big-Endian)';
    if (fileLength < 24) return;

    await raf.setPosition(0);
    final Uint8List hdr = await raf.read(math.min(4096, fileLength));
    final ByteData bd = ByteData.sublistView(hdr);

    final int moduleFlags = bd.getUint32(4, Endian.big);
    final int peDataOffset = bd.getUint32(8, Endian.big);
    final int headerCount = bd.getUint32(16, Endian.big);

    analysisOut['moduleFlags'] = '0x${moduleFlags.toRadixString(16).toUpperCase()}';
    analysisOut['peDataOffset'] = '0x${peDataOffset.toRadixString(16).toUpperCase()}';
    analysisOut['optionalHeaderCount'] = headerCount;

    int cursor = 24;
    for (int i = 0; i < headerCount && cursor + 8 <= hdr.length; i++) {
      final int key = bd.getUint32(cursor, Endian.big);
      final int valueOrOffset = bd.getUint32(cursor + 4, Endian.big);
      cursor += 8;

      if (key == 0x00010100) {
        analysisOut['entryPoint'] = '0x${valueOrOffset.toRadixString(16).toUpperCase()}';
      } else if (key == 0x000103FF && valueOrOffset > 0 && valueOrOffset + 16 < fileLength) {
        await raf.setPosition(valueOrOffset);
        final Uint8List impBlk = await raf.read(math.min(4096, fileLength - valueOrOffset));
        if (impBlk.length >= 16) {
          final ByteData impBd = ByteData.sublistView(impBlk);
          final int strTableSize = impBd.getUint32(4, Endian.big);
          final int libCount = impBd.getUint32(8, Endian.big);
          if (strTableSize > 0 && strTableSize < 2048 && 12 + strTableSize <= impBlk.length) {
            final Uint8List strBytes = impBlk.sublist(12, 12 + strTableSize);
            int pStr = 0;
            for (int l = 0; l < libCount && pStr < strBytes.length; l++) {
              final int end = strBytes.indexOf(0, pStr);
              if (end <= pStr) break;
              final String libName = String.fromCharCodes(strBytes.sublist(pStr, end));
              if (libName.isNotEmpty) {
                importsOut[libName] = <String>[];
              }
              pStr = end + 1;
              while (pStr < strBytes.length && strBytes[pStr] == 0) {
                pStr++;
              }
            }
          }
        }
      }
    }
  }

  Future<void> _parseShaderBinary({
    required RandomAccessFile raf,
    required int fileLength,
    required String magicStr,
    required Map<String, Object?> analysisOut,
    required List<String> constantsOut,
  }) async {
    analysisOut['tipoFormato'] = 'Shader / Bytecode Gráfico ($magicStr)';
    if (magicStr.contains('VS') || magicStr.contains('SV')) {
      analysisOut['shaderStage'] = 'VertexShader';
    } else if (magicStr.contains('PS') || magicStr.contains('SX')) {
      analysisOut['shaderStage'] = 'PixelShader';
    }

    final Set<String> seen = <String>{};
    final RegExp shaderHint = RegExp(
      r'^(vs_\d_\d|ps_\d_\d|[A-Za-z_][A-Za-z0-9_]*(Matrix|World|View|Proj|Light|Color|Texture|Sampler|Map|Pos|Normal|UV|Bone|Skin|Alpha|Specular|Fog)[A-Za-z0-9_]*)$',
      caseSensitive: false,
    );

    int pos = 0;
    while (pos < fileLength && constantsOut.length < 512) {
      await raf.setPosition(pos);
      final int toRead = math.min(_chunkSize, fileLength - pos);
      final Uint8List chunk = await raf.read(toRead);
      if (chunk.isEmpty) break;

      int i = 0;
      while (i < chunk.length) {
        if (_isAsciiIdentChar(chunk[i])) {
          final int start = i;
          while (i < chunk.length && _isAsciiIdentChar(chunk[i]) && (i - start) < 96) {
            i++;
          }
          if (i - start >= 4) {
            final String s = String.fromCharCodes(chunk.sublist(start, i));
            if (shaderHint.hasMatch(s) && seen.add(s)) {
              constantsOut.add(s);
            }
          }
        }
        i++;
      }

      if (pos + toRead >= fileLength) break;
      pos += toRead - 128;
    }
  }

  Future<List<String>> _scanTechnicalPortStrings({
    required RandomAccessFile raf,
    required int fileLength,
  }) async {
    final List<String> results = <String>[];
    final Set<String> seen = <String>{};
    final RegExp techRegex = RegExp(
      r'(\.(cpp|hpp|h|c|fx|hlsl|dll|exe|xex|lib|pdb|bik|pcpack)\b|::|^[A-Za-z]:\\|\\src\\|Treyarch|Shaba|Spider|WebOfShadows|D3D|Havok|Bink)',
      caseSensitive: false,
    );

    int pos = 0;
    const int overlap = 256;
    while (pos < fileLength && results.length < 1500) {
      await raf.setPosition(pos);
      final int toRead = math.min(_chunkSize, fileLength - pos);
      final Uint8List chunk = await raf.read(toRead);
      if (chunk.isEmpty) break;

      int i = 0;
      while (i < chunk.length && results.length < 1500) {
        if (chunk[i] >= 32 && chunk[i] <= 126) {
          final int start = i;
          while (i < chunk.length && chunk[i] >= 32 && chunk[i] <= 126 && (i - start) < 300) {
            i++;
          }
          if (i - start >= 6) {
            final String s = String.fromCharCodes(chunk.sublist(start, i)).trim();
            if (techRegex.hasMatch(s) && seen.add(s)) {
              results.add(s);
            }
          }
        }
        i++;
      }

      if (pos + toRead >= fileLength) break;
      pos += toRead - overlap;
    }

    return results;
  }

  Future<void> _copyFileStreaming(File src, File dst) async {
    await Directory(p.dirname(dst.path)).create(recursive: true);
    RandomAccessFile? raf;
    IOSink? sink;
    try {
      raf = await src.open(mode: FileMode.read);
      final int total = await raf.length();
      sink = dst.openWrite();

      int remaining = total;
      while (remaining > 0) {
        final int toRead = remaining > _chunkSize ? _chunkSize : remaining;
        final Uint8List chunk = await raf.read(toRead);
        if (chunk.isEmpty) break;
        sink.add(chunk);
        remaining -= chunk.length;
      }
      await sink.flush();
      await sink.close();
      sink = null;
    } finally {
      try {
        await sink?.close();
      } catch (_) {}
      await raf?.close();
    }
  }

  Future<Uint8List> _readHeader(File file, int maxBytes) async {
    RandomAccessFile? raf;
    try {
      raf = await file.open(mode: FileMode.read);
      final int len = await raf.length();
      final int toRead = len < maxBytes ? len : maxBytes;
      if (toRead <= 0) return Uint8List(0);
      return await raf.read(toRead);
    } finally {
      await raf?.close();
    }
  }

  Future<String> _readCStringAt(RandomAccessFile raf, int offset, int fileLength) async {
    if (offset < 0 || offset >= fileLength) return '';
    await raf.setPosition(offset);
    final Uint8List buf = await raf.read(math.min(260, fileLength - offset));
    final List<int> chars = <int>[];
    for (final b in buf) {
      if (b == 0) break;
      if (b < 32 || b > 126) return '';
      chars.add(b);
    }
    return String.fromCharCodes(chars);
  }

  String _readNullPaddedAscii(Uint8List bytes) {
    final List<int> chars = <int>[];
    for (final b in bytes) {
      if (b == 0) break;
      if (b >= 32 && b <= 126) chars.add(b);
    }
    return String.fromCharCodes(chars);
  }

  Future<String> _uniquePath(String desiredPath) async {
    if (!await File(desiredPath).exists()) return desiredPath;
    final String dir = p.dirname(desiredPath);
    final String base = p.basenameWithoutExtension(desiredPath);
    final String ext = p.extension(desiredPath);
    int idx = 1;
    while (true) {
      final String candidate = p.join(dir, '${base}_${idx.toString().padLeft(3, '0')}$ext');
      if (!await File(candidate).exists()) return candidate;
      idx++;
    }
  }

  bool _isPowerOfTwoDim(int v) => v >= 16 && v <= 4096 && (v & (v - 1)) == 0;

  List<int> _inferTextureDims(int payloadBytes, String format) {
    final int blockSize = format == 'DXT1' ? 8 : 16;
    const List<int> dims = <int>[4096, 2048, 1024, 512, 256, 128, 64, 32, 16];
    for (final w in dims) {
      for (final h in dims) {
        final int needed = format == 'RGBA'
            ? (w * h * 4)
            : (((w + 3) ~/ 4) * ((h + 3) ~/ 4) * blockSize);
        if (needed == payloadBytes) return <int>[w, h];
      }
    }
    for (final w in dims) {
      final int needed = format == 'RGBA'
          ? (w * w * 4)
          : (((w + 3) ~/ 4) * ((w + 3) ~/ 4) * blockSize);
      if (needed <= payloadBytes) return <int>[w, w];
    }
    return const <int>[0, 0];
  }

  int _fourCcToUint32(String fourCc) {
    final List<int> u = fourCc.codeUnits;
    return u[0] | (u[1] << 8) | (u[2] << 16) | (u[3] << 24);
  }

  bool _isAsciiIdentChar(int b) {
    return (b >= 48 && b <= 57) ||
        (b >= 65 && b <= 90) ||
        (b >= 97 && b <= 122) ||
        b == 95 ||
        b == 46 ||
        b == 45;
  }

  bool _isReadableTextByte(int b) {
    return (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13;
  }

  bool _isUtf16LeCharAt(Uint8List buf, int offset) {
    if (offset + 1 >= buf.length) return false;
    final int lo = buf[offset];
    final int hi = buf[offset + 1];
    if (hi == 0x00) {
      return (lo >= 0x20 && lo <= 0x7E) || (lo >= 0xA0 && lo <= 0xFF);
    }
    return hi == 0x01 && lo <= 0x7F;
  }

  String _cleanControlChars(String raw) {
    return raw
        .replaceAll(RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]'), '')
        .replaceAll(RegExp(r'[\r\n\t]+'), ' ')
        .trim();
  }

  bool _hasMeaningfulLettersOrDigits(String s) {
    return RegExp(r'[A-Za-zÁÉÍÓÚÜÑáéíóúüñ0-9]{2,}').hasMatch(s);
  }

  String _inferLanguageFromFilename(String filename) {
    final String lower = filename.toLowerCase();
    if (lower.contains('spanish') || RegExp(r'(^|[_\-.])es([_\-.]|$)').hasMatch(lower)) {
      return 'ES';
    }
    if (lower.contains('english') || RegExp(r'(^|[_\-.])en([_\-.]|$)').hasMatch(lower)) {
      return 'EN';
    }
    if (lower.contains('french') || RegExp(r'(^|[_\-.])fr([_\-.]|$)').hasMatch(lower)) {
      return 'FR';
    }
    if (lower.contains('german') || RegExp(r'(^|[_\-.])de([_\-.]|$)').hasMatch(lower)) {
      return 'DE';
    }
    if (lower.contains('italian') || RegExp(r'(^|[_\-.])it([_\-.]|$)').hasMatch(lower)) {
      return 'IT';
    }
    return 'DESCONOCIDO';
  }

  String _detectTextLanguage(String text) {
    final String lower = ' ${text.toLowerCase()} ';
    if (RegExp(r'[áéíóúüñ¿¡]').hasMatch(lower) ||
        RegExp(r' (el|la|los|las|que|para|con|por|una|spider|ciudad|misión) ').hasMatch(lower)) {
      return 'ES';
    }
    if (RegExp(r' (le|la|les|des|avec|pour|dans|vous|est) ').hasMatch(lower)) {
      return 'FR';
    }
    if (RegExp(r' (der|die|das|und|mit|für|nicht|ist) ').hasMatch(lower)) {
      return 'DE';
    }
    if (RegExp(r' (che|per|con|gli|una|questo|sono) ').hasMatch(lower)) {
      return 'IT';
    }
    if (RegExp(r' (the|and|with|for|you|this|from|attack|mission|damage) ').hasMatch(lower)) {
      return 'EN';
    }
    return 'TECH/EN';
  }

  void _captureKeyValueParam(String line, Map<String, String> paramsOut) {
    if (paramsOut.length >= 512) return;
    final Match? m = RegExp(r'^([A-Za-z_][A-Za-z0-9_.\-]{1,48})\s*[:=]\s*(.+)$').firstMatch(line);
    if (m != null) {
      paramsOut[m.group(1)!] = m.group(2)!.trim();
    }
  }

  String _csvEscape(String value) {
    final String escaped = value.replaceAll('"', '""');
    return '"$escaped"';
  }

  String _printableAscii(Uint8List bytes) {
    return String.fromCharCodes(
      bytes.map((b) => (b >= 32 && b <= 126) ? b : 46),
    );
  }
}
