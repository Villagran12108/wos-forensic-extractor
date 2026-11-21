import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;

import 'binary_tools_service.dart';

typedef ClassifierLogCallback = void Function(String message);
typedef ClassifierProgressCallback = void Function(int processed, int total);

class ClassificationSummary {
  final String dumpRootDir;
  final String manifestPath;
  final int totalFiles;
  final int totalBytes;
  final int ddsReconstructedCount;
  final int audioConverted48kHzCount;
  final Map<String, int> countsByCategory;

  const ClassificationSummary({
    required this.dumpRootDir,
    required this.manifestPath,
    required this.totalFiles,
    required this.totalBytes,
    required this.ddsReconstructedCount,
    required this.audioConverted48kHzCount,
    required this.countsByCategory,
  });
}

class _TexDdsInfo {
  final String fourCc;
  final int width;
  final int height;
  final int mipCount;
  final int payloadOffset;

  const _TexDdsInfo({
    required this.fourCc,
    required this.width,
    required this.height,
    required this.mipCount,
    required this.payloadOffset,
  });
}

class ForensicClassifier {
  static const int _chunkSize = 65536; // 64 KB
  static const String dumpFolderName = 'WoS_Full_Port_Dump';

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

  static const Set<String> _skipIntermediateContainers = <String>{
    '.iso',
    '.cab',
    '.hdr',
    '.msi',
    '.pack',
    '.pcpack',
    '.pcapk',
    '.apkf',
  };

  final BinaryToolsService binaryTools;
  final ClassifierLogCallback? onLog;
  final ClassifierProgressCallback? onProgress;

  ForensicClassifier({
    required this.binaryTools,
    this.onLog,
    this.onProgress,
  });

  void _log(String msg) {
    onLog?.call(msg);
  }

  /// Paso 4 y 5: Clasifica por Magic Bytes + extensión en las 9 carpetas de WoS_Full_Port_Dump,
  /// reconstruye cabeceras DDS de 128 bytes para DXT1/DXT5 crudos, convierte audios a 48kHz,
  /// escribe MANIFIESTO_EXTRACCION.json por flujo y elimina tempDir al finalizar.
  Future<ClassificationSummary> classifyAndFinalize({
    required String isoSourcePath,
    required String tempDir,
    required String outputDir,
  }) async {
    final String dumpRoot = p.join(outputDir, dumpFolderName);
    await Directory(dumpRoot).create(recursive: true);

    for (final category in allCategories) {
      await Directory(p.join(dumpRoot, category)).create(recursive: true);
    }
    final String ps4AudioDir = p.join(dumpRoot, cat01Audio, 'WAV_48kHz_PS4_Ready');
    await Directory(ps4AudioDir).create(recursive: true);

    final Map<String, int> counts = <String, int>{
      for (final c in allCategories) c: 0,
    };

    final List<File> allFiles = <File>[];
    final tempDirectory = Directory(tempDir);
    if (await tempDirectory.exists()) {
      await for (final entity in tempDirectory.list(recursive: true, followLinks: false)) {
        if (entity is File) {
          final ext = p.extension(entity.path).toLowerCase();
          if (_skipIntermediateContainers.contains(ext)) {
            continue;
          }
          allFiles.add(entity);
        }
      }
    }

    final int total = allFiles.length;
    int processed = 0;
    int totalBytes = 0;
    int ddsReconstructedCount = 0;
    int audioConverted48kHzCount = 0;

    final String manifestPath = p.join(dumpRoot, 'MANIFIESTO_EXTRACCION.json');
    final File manifestFile = File(manifestPath);
    final IOSink manifestSink = manifestFile.openWrite(encoding: utf8);

    manifestSink.writeln('{');
    manifestSink.writeln('  "proyecto": "WoS Forensic Extractor",');
    manifestSink.writeln('  "fechaUtc": ${jsonEncode(DateTime.now().toUtc().toIso8601String())},');
    manifestSink.writeln('  "isoOrigen": ${jsonEncode(isoSourcePath)},');
    manifestSink.writeln('  "directorioVolcado": ${jsonEncode(dumpRoot)},');
    manifestSink.writeln('  "archivos": [');

    bool firstManifestEntry = true;

    try {
      for (final file in allFiles) {
        processed++;
        onProgress?.call(processed, total);

        final int fileSize = await file.length();
        if (fileSize <= 0) continue;

        final Uint8List head64 = await _readHeaderBytes(file, 64);
        final Uint8List sig32 = head64.length > 32 ? head64.sublist(0, 32) : head64;
        final String magicHex = _toHex(sig32);
        final String magicAscii = _toPrintableAscii(sig32);

        final String category = _detectCategory(
          filePath: file.path,
          head: sig32,
        );

        final String baseFileName = p.basename(file.path);
        final String desiredDest = p.join(dumpRoot, category, baseFileName);
        final String finalDest = await _resolveNonCollidingPath(desiredDest);

        await _safeMoveStreaming(file, File(finalDest));
        counts[category] = (counts[category] ?? 0) + 1;
        totalBytes += fileSize;

        String? reconstructedDdsPath;
        String? convertedWav48kPath;

        if (category == cat03Textures &&
            p.extension(finalDest).toLowerCase() == '.tex' &&
            !_startsWithAscii(sig32, 'DDS ')) {
          final _TexDdsInfo? texInfo = _inspectRawDxtTex(
            head64: head64,
            fileSize: fileSize,
          );
          if (texInfo != null) {
            final String ddsDesired = p.join(
              dumpRoot,
              cat03Textures,
              '${p.basenameWithoutExtension(finalDest)}_reconstructed.dds',
            );
            final String ddsDest = await _resolveNonCollidingPath(ddsDesired);
            final bool ok = await _writeReconstructedDds(
              sourceTexFile: File(finalDest),
              destDdsFile: File(ddsDest),
              info: texInfo,
            );
            if (ok) {
              reconstructedDdsPath = ddsDest;
              ddsReconstructedCount++;
            }
          }
        }

        if (category == cat01Audio) {
          final String wavDesired = p.join(
            ps4AudioDir,
            '${p.basenameWithoutExtension(finalDest)}.wav',
          );
          final String wavDest = await _resolveNonCollidingPath(wavDesired);
          final bool converted = await binaryTools.convertAudioToWav48kHz(
            inputPath: finalDest,
            outputWavPath: wavDest,
          );
          if (converted) {
            convertedWav48kPath = wavDest;
            audioConverted48kHzCount++;
          }
        }

        final Map<String, Object?> record = <String, Object?>{
          'categoria': category,
          'rutaOriginal': file.path,
          'rutaFinal': finalDest,
          'tamanoBytes': fileSize,
          'firmaHex': magicHex,
          'firmaAscii': magicAscii,
          if (reconstructedDdsPath != null) 'ddsReconstruido': reconstructedDdsPath,
          if (convertedWav48kPath != null) 'audio48kHzPs4': convertedWav48kPath,
        };

        if (!firstManifestEntry) {
          manifestSink.writeln(',');
        }
        firstManifestEntry = false;
        manifestSink.write('    ${jsonEncode(record)}');

        if (processed % 100 == 0 || processed == total) {
          _log('[CLASIFICADOR] $processed / $total archivos organizados...');
        }
      }

      manifestSink.writeln('');
      manifestSink.writeln('  ],');
      manifestSink.writeln('  "resumen": {');
    } finally {
      await manifestSink.flush();
      await manifestSink.close();
    }

    await _finalizeManifestJson(
      manifestFile: manifestFile,
      totalFiles: counts.values.fold<int>(0, (a, b) => a + b),
      totalBytes: totalBytes,
      ddsReconstructedCount: ddsReconstructedCount,
      audioConverted48kHzCount: audioConverted48kHzCount,
      counts: counts,
    );

    try {
      if (await tempDirectory.exists()) {
        _log('[LIMPIEZA] Eliminando carpeta temporal: $tempDir');
        await tempDirectory.delete(recursive: true);
      }
    } catch (e) {
      _log('[WARN] No se pudo borrar completamente la carpeta temporal: $e');
    }

    _log('[FIN] Volcado forense completado en: $dumpRoot');
    return ClassificationSummary(
      dumpRootDir: dumpRoot,
      manifestPath: manifestPath,
      totalFiles: counts.values.fold<int>(0, (a, b) => a + b),
      totalBytes: totalBytes,
      ddsReconstructedCount: ddsReconstructedCount,
      audioConverted48kHzCount: audioConverted48kHzCount,
      countsByCategory: counts,
    );
  }

  Future<void> _finalizeManifestJson({
    required File manifestFile,
    required int totalFiles,
    required int totalBytes,
    required int ddsReconstructedCount,
    required int audioConverted48kHzCount,
    required Map<String, int> counts,
  }) async {
    final String contentTailMarker = '  ],\n  "resumen": {';
    final int len = await manifestFile.length();
    final int tailReadLen = len < 512 ? len : 512;
    int truncatePos = len;

    final readRaf = await manifestFile.open(mode: FileMode.read);
    try {
      await readRaf.setPosition(len - tailReadLen);
      final tailBytes = await readRaf.read(tailReadLen);
      final tailStr = utf8.decode(tailBytes, allowMalformed: true);
      final idx = tailStr.lastIndexOf(contentTailMarker);
      if (idx >= 0) {
        truncatePos = (len - tailReadLen) + utf8.encode(tailStr.substring(0, idx)).length;
      }
    } finally {
      await readRaf.close();
    }

    final writeRaf = await manifestFile.open(mode: FileMode.writeOnlyAppend);
    try {
      await writeRaf.truncate(truncatePos);
      await writeRaf.setPosition(truncatePos);
      final StringBuffer summaryBuf = StringBuffer();
      summaryBuf.writeln('  ],');
      summaryBuf.writeln('  "resumen": {');
      summaryBuf.writeln('    "totalArchivos": $totalFiles,');
      summaryBuf.writeln('    "totalBytes": $totalBytes,');
      summaryBuf.writeln('    "ddsCabecerasReconstruidas": $ddsReconstructedCount,');
      summaryBuf.writeln('    "audiosConvertidos48kHzPs4": $audioConverted48kHzCount,');
      summaryBuf.writeln('    "conteoPorCategoria": ${const JsonEncoder.withIndent('      ').convert(counts).replaceAll('\n', '\n    ')}');
      summaryBuf.writeln('  }');
      summaryBuf.writeln('}');
      await writeRaf.writeString(summaryBuf.toString(), encoding: utf8);
      await writeRaf.flush();
    } finally {
      await writeRaf.close();
    }
  }

  String _detectCategory({
    required String filePath,
    required Uint8List head,
  }) {
    final String ext = p.extension(filePath).toLowerCase();
    final String nameLower = p.basename(filePath).toLowerCase();
    final String ascii = _toPrintableAscii(head);

    if (ext == '.bik' ||
        ext == '.bk2' ||
        ext == '.smk' ||
        ext == '.avi' ||
        ext == '.wmv' ||
        ext == '.mp4' ||
        _startsWithAscii(head, 'BIKi') ||
        _startsWithAscii(head, 'BIKf') ||
        _startsWithAscii(head, 'KB2')) {
      return cat02Videos;
    }

    if (ext == '.wav' ||
        ext == '.ogg' ||
        ext == '.mp3' ||
        ext == '.wma' ||
        ext == '.xma' ||
        ext == '.fsb' ||
        ext == '.xwb' ||
        ext == '.xsb' ||
        ext == '.bnk' ||
        ext == '.wem' ||
        ext == '.adpcm' ||
        ext == '.snd' ||
        ext == '.sfx' ||
        ext == '.mus' ||
        _startsWithAscii(head, 'RIFF') ||
        _startsWithAscii(head, 'OggS') ||
        _startsWithAscii(head, 'FSB') ||
        _startsWithAscii(head, 'WBND') ||
        _startsWithAscii(head, 'BKHD') ||
        _startsWithAscii(head, 'ID3')) {
      return cat01Audio;
    }

    if (ext == '.dds' ||
        ext == '.tex' ||
        ext == '.png' ||
        ext == '.jpg' ||
        ext == '.jpeg' ||
        ext == '.tga' ||
        ext == '.bmp' ||
        ext == '.img' ||
        ext == '.txd' ||
        _startsWithAscii(head, 'DDS ') ||
        _startsWithAscii(head, 'IMG') ||
        _startsWithAscii(head, 'TEX') ||
        (head.length >= 4 &&
            head[0] == 0x89 &&
            head[1] == 0x50 &&
            head[2] == 0x4E &&
            head[3] == 0x47) ||
        (head.length >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF)) {
      return cat03Textures;
    }

    if (ext == '.mesh' ||
        ext == '.pcgv' ||
        ext == '.pcvx' ||
        ext == '.cvxlo' ||
        ext == '.mdl' ||
        ext == '.obj' ||
        ext == '.fbx' ||
        ext == '.geo' ||
        _startsWithAscii(head, 'MESH') ||
        _startsWithAscii(head, 'PCGV') ||
        _startsWithAscii(head, 'PCVX') ||
        _startsWithAscii(head, 'CVXLO')) {
      return cat04Models;
    }

    if (ext == '.anim' ||
        ext == '.skel' ||
        ext == '.skelmap' ||
        ext == '.anm' ||
        ext == '.hkx' ||
        ext == '.rig' ||
        _startsWithAscii(head, 'ANIM') ||
        _startsWithAscii(head, 'SKELMAP') ||
        _startsWithAscii(head, 'SKEL')) {
      return cat05Skeletons;
    }

    if (ext == '.coll' ||
        ext == '.phys' ||
        ext == '.bsp' ||
        ext == '.lvl' ||
        ext == '.map' ||
        ext == '.zone' ||
        ext == '.nav' ||
        ext == '.col' ||
        _startsWithAscii(head, 'COLL') ||
        _startsWithAscii(head, 'PHYS')) {
      return cat06Physics;
    }

    if (ext == '.ent' ||
        ext == '.json' ||
        ext == '.json_ise' ||
        ext == '.lua' ||
        ext == '.luac' ||
        ext == '.py' ||
        ext == '.scr' ||
        ext == '.ai' ||
        ext == '.cmb' ||
        ext == '.xml' ||
        ext == '.cfg' ||
        ext == '.ini' ||
        _startsWithAscii(head, 'ENT') ||
        _startsWithAscii(head, 'JSON_ISE') ||
        ascii.trimLeft().startsWith('{') ||
        (head.length >= 4 &&
            head[0] == 0x1B &&
            head[1] == 0x4C &&
            head[2] == 0x75 &&
            head[3] == 0x61)) {
      return cat07Entities;
    }

    if (ext == '.loc' ||
        ext == '.lng' ||
        ext == '.str' ||
        ext == '.txt' ||
        ext == '.csv' ||
        ext == '.sub' ||
        ext == '.srt' ||
        ext == '.ttf' ||
        ext == '.otf' ||
        ext == '.fnt' ||
        ext == '.font' ||
        nameLower.contains('subtitle') ||
        nameLower.contains('dialog') ||
        nameLower.contains('font') ||
        nameLower.contains('english') ||
        nameLower.contains('spanish') ||
        nameLower.contains('french') ||
        nameLower.contains('german') ||
        nameLower.contains('italian') ||
        RegExp(r'(^|[_\-.])(es|en|fr|de|it)([_\-.]|$)').hasMatch(nameLower)) {
      return cat08Texts;
    }

    if (ext == '.pcvs' ||
        ext == '.pcps' ||
        ext == '.pcsv' ||
        ext == '.pcsx' ||
        ext == '.fx' ||
        ext == '.fxo' ||
        ext == '.cso' ||
        ext == '.hlsl' ||
        ext == '.exe' ||
        ext == '.dll' ||
        ext == '.xex' ||
        ext == '.sys' ||
        ext == '.idt' ||
        ext == '.tbl' ||
        nameLower == 'default.xex' ||
        nameLower.startsWith('!') ||
        _startsWithAscii(head, 'PCVS') ||
        _startsWithAscii(head, 'PCPS') ||
        _startsWithAscii(head, 'PCSV') ||
        _startsWithAscii(head, 'PCSX') ||
        _startsWithAscii(head, 'XEX2') ||
        _startsWithAscii(head, 'DXBC') ||
        (head.length >= 2 && head[0] == 0x4D && head[1] == 0x5A)) {
      return cat09Engine;
    }

    return cat09Engine;
  }

  _TexDdsInfo? _inspectRawDxtTex({
    required Uint8List head64,
    required int fileSize,
  }) {
    if (head64.length < 16 || fileSize < 128) return null;

    final String ascii = _toPrintableAscii(head64);
    String? fourCc;
    int fourCcOffset = -1;

    final int dxt1Idx = ascii.indexOf('DXT1');
    final int dxt5Idx = ascii.indexOf('DXT5');
    if (dxt1Idx >= 0) {
      fourCc = 'DXT1';
      fourCcOffset = dxt1Idx;
    } else if (dxt5Idx >= 0) {
      fourCc = 'DXT5';
      fourCcOffset = dxt5Idx;
    }

    if (fourCc == null) return null;

    final int blockSize = fourCc == 'DXT1' ? 8 : 16;
    final ByteData bd = ByteData.sublistView(head64);

    int width = 0;
    int height = 0;
    int mipCount = 1;
    int payloadOffset = 0;

    for (int pos = 0; pos + 8 <= head64.length && pos <= 48; pos += 4) {
      final int w = bd.getUint32(pos, Endian.little);
      final int h = bd.getUint32(pos + 4, Endian.little);
      if (_isValidTexDim(w) && _isValidTexDim(h)) {
        final int baseLevelBytes = ((w + 3) ~/ 4) * ((h + 3) ~/ 4) * blockSize;
        if (baseLevelBytes <= fileSize) {
          width = w;
          height = h;
          if (pos + 12 <= head64.length) {
            final int mips = bd.getUint32(pos + 8, Endian.little);
            if (mips >= 1 && mips <= 14) {
              mipCount = mips;
            }
          }
          final int headerEndGuess = (fourCcOffset + 4 > pos + 12) ? fourCcOffset + 4 : pos + 12;
          payloadOffset = ((headerEndGuess + 3) ~/ 4) * 4;
          if (fileSize - payloadOffset < baseLevelBytes) {
            payloadOffset = 0;
          }
          break;
        }
      }
    }

    if (width == 0 || height == 0) {
      payloadOffset = (fourCcOffset + 4 <= 32) ? ((fourCcOffset + 4 + 3) ~/ 4) * 4 : 0;
      final int avail = fileSize - payloadOffset;
      final List<int> inferred = _inferDimensionsFromPayload(avail, blockSize);
      width = inferred[0];
      height = inferred[1];
      if (width == 0 || height == 0) return null;
    }

    return _TexDdsInfo(
      fourCc: fourCc,
      width: width,
      height: height,
      mipCount: mipCount,
      payloadOffset: payloadOffset,
    );
  }

  Future<bool> _writeReconstructedDds({
    required File sourceTexFile,
    required File destDdsFile,
    required _TexDdsInfo info,
  }) async {
    RandomAccessFile? raf;
    IOSink? sink;
    try {
      final int blockSize = info.fourCc == 'DXT1' ? 8 : 16;
      final int linearSize = ((info.width + 3) ~/ 4) * ((info.height + 3) ~/ 4) * blockSize;

      final ByteData hdr = ByteData(128);
      hdr.setUint32(0x00, 0x20534444, Endian.little);
      hdr.setUint32(0x04, 124, Endian.little);
      final int dwFlags = info.mipCount > 1 ? 0x000A1007 : 0x00081007;
      hdr.setUint32(0x08, dwFlags, Endian.little);
      hdr.setUint32(0x0C, info.height, Endian.little);
      hdr.setUint32(0x10, info.width, Endian.little);
      hdr.setUint32(0x14, linearSize, Endian.little);
      hdr.setUint32(0x18, 0, Endian.little);
      hdr.setUint32(0x1C, info.mipCount, Endian.little);
      hdr.setUint32(0x4C, 32, Endian.little);
      hdr.setUint32(0x50, 0x00000004, Endian.little);
      final int fourCcVal = info.fourCc == 'DXT1' ? 0x31545844 : 0x35545844;
      hdr.setUint32(0x54, fourCcVal, Endian.little);
      final int dwCaps = info.mipCount > 1 ? 0x00401008 : 0x00001000;
      hdr.setUint32(0x6C, dwCaps, Endian.little);

      raf = await sourceTexFile.open(mode: FileMode.read);
      final int srcLen = await raf.length();
      if (info.payloadOffset >= srcLen) return false;

      sink = destDdsFile.openWrite();
      sink.add(hdr.buffer.asUint8List());

      await raf.setPosition(info.payloadOffset);
      int remaining = srcLen - info.payloadOffset;
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
      return true;
    } catch (e) {
      _log('[DDS-ERR] No se pudo reconstruir DDS de ${p.basename(sourceTexFile.path)}: $e');
      try {
        await sink?.close();
      } catch (_) {}
      return false;
    } finally {
      await raf?.close();
    }
  }

  Future<void> _safeMoveStreaming(File src, File dst) async {
    await Directory(p.dirname(dst.path)).create(recursive: true);
    try {
      await src.rename(dst.path);
    } on FileSystemException {
      RandomAccessFile? raf;
      IOSink? sink;
      try {
        raf = await src.open(mode: FileMode.read);
        final int totalLen = await raf.length();
        sink = dst.openWrite();

        int remaining = totalLen;
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
      if (await src.exists()) {
        await src.delete();
      }
    }
  }

  Future<String> _resolveNonCollidingPath(String desiredPath) async {
    if (!await File(desiredPath).exists()) return desiredPath;

    final String dir = p.dirname(desiredPath);
    final String base = p.basenameWithoutExtension(desiredPath);
    final String ext = p.extension(desiredPath);

    int suffix = 1;
    while (true) {
      final String candidate = p.join(
        dir,
        '${base}_${suffix.toString().padLeft(3, '0')}$ext',
      );
      if (!await File(candidate).exists()) {
        return candidate;
      }
      suffix++;
    }
  }

  Future<Uint8List> _readHeaderBytes(File file, int maxBytes) async {
    RandomAccessFile? raf;
    try {
      raf = await file.open(mode: FileMode.read);
      final int len = await raf.length();
      final int toRead = len < maxBytes ? len : maxBytes;
      if (toRead <= 0) return Uint8List(0);
      return await raf.read(toRead);
    } catch (_) {
      return Uint8List(0);
    } finally {
      await raf?.close();
    }
  }

  bool _startsWithAscii(Uint8List bytes, String prefix) {
    if (bytes.length < prefix.length) return false;
    for (int i = 0; i < prefix.length; i++) {
      if (bytes[i] != prefix.codeUnitAt(i)) return false;
    }
    return true;
  }

  bool _isValidTexDim(int v) {
    return v >= 16 && v <= 4096 && (v & (v - 1)) == 0;
  }

  List<int> _inferDimensionsFromPayload(int payloadBytes, int blockSize) {
    const List<int> dims = <int>[4096, 2048, 1024, 512, 256, 128, 64, 32, 16];
    for (final w in dims) {
      for (final h in dims) {
        final int needed = ((w + 3) ~/ 4) * ((h + 3) ~/ 4) * blockSize;
        if (needed == payloadBytes) {
          return <int>[w, h];
        }
      }
    }
    for (final w in dims) {
      final int needed = ((w + 3) ~/ 4) * ((w + 3) ~/ 4) * blockSize;
      if (needed <= payloadBytes) {
        return <int>[w, w];
      }
    }
    return const <int>[0, 0];
  }

  String _toHex(Uint8List bytes) {
    final StringBuffer sb = StringBuffer();
    for (int i = 0; i < bytes.length; i++) {
      if (i > 0) sb.write(' ');
      sb.write(bytes[i].toRadixString(16).padLeft(2, '0').toUpperCase());
    }
    return sb.toString();
  }

  String _toPrintableAscii(Uint8List bytes) {
    return String.fromCharCodes(
      bytes.map((b) => (b >= 32 && b <= 126) ? b : 46),
    );
  }
}
