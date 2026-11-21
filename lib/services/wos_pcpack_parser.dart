import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;

typedef ParserLogCallback = void Function(String message);

class _PackEntry {
  final int hash;
  final int offset;
  final int compressedSize;
  final int uncompressedSize;
  final String? name;

  const _PackEntry({
    required this.hash,
    required this.offset,
    required this.compressedSize,
    required this.uncompressedSize,
    this.name,
  });
}

class _CandidateTableLayout {
  final int tableOffset;
  final int entryCount;
  final int stride;
  final List<_PackEntry> entries;

  const _CandidateTableLayout({
    required this.tableOffset,
    required this.entryCount,
    required this.stride,
    required this.entries,
  });
}

class WosPcpackParser {
  static const int _chunkSize = 65536; // 64 KB
  static const Set<String> _containerExtensions = <String>{
    '.pack',
    '.pcpack',
    '.pcapk',
    '.apkf',
  };

  final ParserLogCallback? onLog;

  WosPcpackParser({this.onLog});

  void _log(String msg) {
    onLog?.call(msg);
  }

  /// Paso 3: Escanea recursivamente todos los archivos buscando contenedores del motor
  /// (.pack, .pcpack, .pcapk, .apkf o firmas PCPACK, KCAPCP, APKF, PCSTOC) y los desempaqueta.
  Future<int> unpackAllContainers({
    required String rootDir,
  }) async {
    final Set<String> processedContainers = <String>{};
    int totalExtractedAssets = 0;

    bool foundNewContainers = true;
    while (foundNewContainers) {
      foundNewContainers = false;
      final dir = Directory(rootDir);
      if (!await dir.exists()) break;

      final List<File> candidates = <File>[];
      await for (final entity in dir.list(recursive: true, followLinks: false)) {
        if (entity is File && !processedContainers.contains(entity.path)) {
          if (await _isEngineContainer(entity)) {
            candidates.add(entity);
          }
        }
      }

      if (candidates.isNotEmpty) {
        foundNewContainers = true;
      }

      for (final container in candidates) {
        processedContainers.add(container.path);
        final outDir = p.join(
          p.dirname(container.path),
          '${p.basenameWithoutExtension(container.path)}_unpacked',
        );
        try {
          final count = await unpackSingleContainer(
            containerFile: container,
            outputDir: outDir,
          );
          totalExtractedAssets += count;
        } catch (e) {
          _log('[PACK-ERR] Error procesando ${p.basename(container.path)}: $e');
        }
      }
    }

    return totalExtractedAssets;
  }

  Future<bool> _isEngineContainer(File file) async {
    final ext = p.extension(file.path).toLowerCase();
    RandomAccessFile? raf;
    try {
      final length = await file.length();
      if (length < 16) return false;

      raf = await file.open(mode: FileMode.read);
      final header = await raf.read(8);
      if (header.length < 4) return false;

      final ascii8 = String.fromCharCodes(header);
      if (ascii8.contains('PCPACK') ||
          ascii8.contains('KCAPCP') ||
          ascii8.contains('APKF') ||
          ascii8.contains('PCSTOC')) {
        return true;
      }

      return _containerExtensions.contains(ext);
    } catch (_) {
      return false;
    } finally {
      await raf?.close();
    }
  }

  Future<int> unpackSingleContainer({
    required File containerFile,
    required String outputDir,
  }) async {
    final raf = await containerFile.open(mode: FileMode.read);
    try {
      final int fileLength = await raf.length();
      if (fileLength < 24) return 0;

      await raf.setPosition(0);
      final Uint8List headerBytes = await raf.read(fileLength < 128 ? fileLength : 128);
      final ByteData headerData = ByteData.sublistView(headerBytes);

      final String magicAscii = _extractPrintableMagic(headerBytes, 8);
      _log('[PACK] Analizando ${p.basename(containerFile.path)} ($fileLength bytes, firma="$magicAscii")');

      final _CandidateTableLayout? layout = await _detectTableLayout(
        raf: raf,
        headerBytes: headerBytes,
        headerData: headerData,
        fileLength: fileLength,
      );

      if (layout == null || layout.entries.isEmpty) {
        _log('[PACK] Tabla estándar no detectada en ${p.basename(containerFile.path)}; ejecutando tallado por flujos zlib/magic...');
        return await _carveZlibStreamsFallback(
          raf: raf,
          fileLength: fileLength,
          outputDir: outputDir,
          containerName: p.basenameWithoutExtension(containerFile.path),
        );
      }

      await Directory(outputDir).create(recursive: true);
      int extracted = 0;

      for (int i = 0; i < layout.entries.length; i++) {
        final entry = layout.entries[i];
        final int rawLen = entry.compressedSize > 0
            ? entry.compressedSize
            : entry.uncompressedSize;

        if (rawLen <= 0 || entry.offset < 0 || entry.offset + rawLen > fileLength) {
          continue;
        }

        final String tempOutPath = p.join(
          outputDir,
          '.tmp_entry_${i}_${entry.hash.toRadixString(16).padLeft(8, '0').toUpperCase()}',
        );

        final bool isCompressed = entry.compressedSize > 0 &&
            entry.uncompressedSize > 0 &&
            entry.compressedSize != entry.uncompressedSize;

        bool written = false;
        if (isCompressed) {
          written = await _decompressEntryStreaming(
            raf: raf,
            offset: entry.offset,
            compressedLength: entry.compressedSize,
            outputPath: tempOutPath,
          );
          if (!written) {
            await _copyRangeStreaming(
              raf: raf,
              offset: entry.offset,
              length: rawLen,
              outputPath: tempOutPath,
            );
            written = true;
          }
        } else {
          await _copyRangeStreaming(
            raf: raf,
            offset: entry.offset,
            length: rawLen,
            outputPath: tempOutPath,
          );
          written = true;
        }

        if (!written) continue;

        final tempFile = File(tempOutPath);
        if (!await tempFile.exists()) continue;

        final String finalName;
        if (entry.name != null && entry.name!.trim().isNotEmpty) {
          final sanitized = _sanitizeRelativeName(entry.name!);
          finalName = sanitized.isNotEmpty
              ? sanitized
              : '${entry.hash.toRadixString(16).padLeft(8, '0').toUpperCase()}${await _detectExtensionFromMagic(tempFile)}';
        } else {
          final ext = await _detectExtensionFromMagic(tempFile);
          final hashHex = entry.hash.toRadixString(16).padLeft(8, '0').toUpperCase();
          finalName = '$hashHex$ext';
        }

        final String finalPath = await _uniquePath(p.join(outputDir, finalName));
        await Directory(p.dirname(finalPath)).create(recursive: true);
        await tempFile.rename(finalPath);
        extracted++;
      }

      _log('[PACK] Extraídos $extracted sub-archivos de ${p.basename(containerFile.path)}.');
      return extracted;
    } finally {
      await raf.close();
    }
  }

  Future<_CandidateTableLayout?> _detectTableLayout({
    required RandomAccessFile raf,
    required Uint8List headerBytes,
    required ByteData headerData,
    required int fileLength,
  }) async {
    final Set<int> candidateTableOffsets = <int>{};
    final Set<int> candidateCounts = <int>{};

    for (int pos = 4; pos + 4 <= headerBytes.length && pos <= 44; pos += 4) {
      final val = headerData.getUint32(pos, Endian.little);
      if (val > 0 && val <= 200000) {
        candidateCounts.add(val);
      }
      if (val >= 12 && val < fileLength - 16) {
        candidateTableOffsets.add(val);
      }
    }

    candidateTableOffsets.addAll(const [16, 20, 24, 28, 32, 36, 40, 48, 64]);

    String? Function(int nameOffset)? nameResolver;
    for (int pos = 12; pos + 8 <= headerBytes.length && pos <= 40; pos += 4) {
      final nOff = headerData.getUint32(pos, Endian.little);
      final nSize = headerData.getUint32(pos + 4, Endian.little);
      if (nOff > 32 && nSize > 4 && nOff + nSize <= fileLength && nSize <= 16 * 1024 * 1024) {
        final bool looksAscii = await _looksLikeStringTable(raf, nOff, nSize);
        if (looksAscii) {
          await raf.setPosition(nOff);
          final Uint8List nameBlob = await raf.read(nSize);
          nameResolver = (int relOffset) => _readCString(nameBlob, relOffset);
          break;
        }
      }
    }

    const List<int> candidateStrides = <int>[16, 20, 24, 28, 32, 40, 48, 64];

    for (final tableOff in candidateTableOffsets) {
      for (final count in candidateCounts) {
        for (final stride in candidateStrides) {
          final int tableEnd = tableOff + (count * stride);
          if (tableEnd > fileLength || tableEnd <= tableOff) continue;

          final parsed = await _tryParseEntryTable(
            raf: raf,
            tableOffset: tableOff,
            count: count,
            stride: stride,
            fileLength: fileLength,
            nameResolver: nameResolver,
          );
          if (parsed != null) {
            return _CandidateTableLayout(
              tableOffset: tableOff,
              entryCount: count,
              stride: stride,
              entries: parsed,
            );
          }
        }
      }
    }

    return null;
  }

  Future<List<_PackEntry>?> _tryParseEntryTable({
    required RandomAccessFile raf,
    required int tableOffset,
    required int count,
    required int stride,
    required int fileLength,
    required String? Function(int nameOffset)? nameResolver,
  }) async {
    final int sampleCount = count < 8 ? count : 8;
    await raf.setPosition(tableOffset);
    final Uint8List sampleBytes = await raf.read(sampleCount * stride);
    if (sampleBytes.length < sampleCount * stride) return null;

    final List<List<int>> fieldSchemas = <List<int>>[
      if (stride >= 16) [0, 1, 2, 3, -1],
      if (stride >= 16) [0, 1, 3, 2, -1],
      if (stride >= 16) [3, 0, 1, 2, -1],
      if (stride >= 20) [0, 1, 2, 3, 4],
      if (stride >= 20) [0, 2, 3, 4, 1],
      if (stride >= 24) [0, 1, 2, 3, 4],
      if (stride >= 24) [0, 2, 4, 5, 1],
      if (stride >= 32) [0, 1, 2, 3, 4],
    ];

    List<int>? matchedSchema;
    for (final schema in fieldSchemas) {
      bool allValid = true;
      int validDataEntries = 0;

      for (int i = 0; i < sampleCount; i++) {
        final ByteData row = ByteData.sublistView(
          sampleBytes,
          i * stride,
          (i + 1) * stride,
        );
        final int offset = row.getUint32(schema[1] * 4, Endian.little);
        final int uSize = row.getUint32(schema[2] * 4, Endian.little);
        final int cSize = row.getUint32(schema[3] * 4, Endian.little);

        final int diskSize = cSize > 0 ? cSize : uSize;
        if (diskSize == 0 && offset == 0) continue;

        if (offset < tableOffset + (count * stride) ||
            diskSize <= 0 ||
            offset + diskSize > fileLength ||
            uSize > 512 * 1024 * 1024) {
          allValid = false;
          break;
        }
        validDataEntries++;
      }

      if (allValid && validDataEntries > 0) {
        matchedSchema = schema;
        break;
      }
    }

    if (matchedSchema == null) return null;

    final List<_PackEntry> entries = <_PackEntry>[];
    final int tableBytesLen = count * stride;
    await raf.setPosition(tableOffset);
    final Uint8List fullTable = await raf.read(tableBytesLen);
    if (fullTable.length < tableBytesLen) return null;

    for (int i = 0; i < count; i++) {
      final int rowBase = i * stride;
      final ByteData row = ByteData.sublistView(fullTable, rowBase, rowBase + stride);

      final int hash = row.getUint32(matchedSchema[0] * 4, Endian.little);
      final int offset = row.getUint32(matchedSchema[1] * 4, Endian.little);
      final int uSize = row.getUint32(matchedSchema[2] * 4, Endian.little);
      final int cSize = row.getUint32(matchedSchema[3] * 4, Endian.little);

      final int diskSize = cSize > 0 ? cSize : uSize;
      if (diskSize <= 0 || offset + diskSize > fileLength) {
        continue;
      }

      String? entryName;
      if (matchedSchema[4] >= 0 && nameResolver != null) {
        final int nameOff = row.getUint32(matchedSchema[4] * 4, Endian.little);
        entryName = nameResolver(nameOff);
      } else if (stride >= 48) {
        final inline = _readCString(fullTable.sublist(rowBase + 16, rowBase + stride), 0);
        if (inline != null && inline.contains('.')) {
          entryName = inline;
        }
      }

      entries.add(_PackEntry(
        hash: hash,
        offset: offset,
        compressedSize: cSize,
        uncompressedSize: uSize,
        name: entryName,
      ));
    }

    return entries.isEmpty ? null : entries;
  }

  /// Descompresión en streaming de 64 KB usando ZLibDecoder (y fallback raw deflate).
  Future<bool> _decompressEntryStreaming({
    required RandomAccessFile raf,
    required int offset,
    required int compressedLength,
    required String outputPath,
  }) async {
    final bool okStandard = await _tryZlibStream(
      raf: raf,
      offset: offset,
      compressedLength: compressedLength,
      outputPath: outputPath,
      raw: false,
    );
    if (okStandard) return true;

    return await _tryZlibStream(
      raf: raf,
      offset: offset,
      compressedLength: compressedLength,
      outputPath: outputPath,
      raw: true,
    );
  }

  Future<bool> _tryZlibStream({
    required RandomAccessFile raf,
    required int offset,
    required int compressedLength,
    required String outputPath,
    required bool raw,
  }) async {
    final outFile = File(outputPath);
    IOSink? sink;
    try {
      sink = outFile.openWrite();
      final ZLibDecoder decoder = ZLibDecoder(raw: raw);
      final _SinkByteConsumer consumer = _SinkByteConsumer(sink);
      final ByteConversionSink convSink = decoder.startChunkedConversion(consumer);

      await raf.setPosition(offset);
      int remaining = compressedLength;
      while (remaining > 0) {
        final int toRead = remaining > _chunkSize ? _chunkSize : remaining;
        final Uint8List chunk = await raf.read(toRead);
        if (chunk.isEmpty) break;
        convSink.add(chunk);
        remaining -= chunk.length;
      }
      convSink.close();
      await sink.flush();
      await sink.close();
      sink = null;

      return await outFile.exists() && await outFile.length() > 0;
    } catch (_) {
      try {
        await sink?.close();
      } catch (_) {}
      try {
        if (await outFile.exists()) {
          await outFile.delete();
        }
      } catch (_) {}
      return false;
    }
  }

  Future<void> _copyRangeStreaming({
    required RandomAccessFile raf,
    required int offset,
    required int length,
    required String outputPath,
  }) async {
    final outFile = File(outputPath);
    final IOSink sink = outFile.openWrite();
    try {
      await raf.setPosition(offset);
      int remaining = length;
      while (remaining > 0) {
        final int toRead = remaining > _chunkSize ? _chunkSize : remaining;
        final Uint8List chunk = await raf.read(toRead);
        if (chunk.isEmpty) break;
        sink.add(chunk);
        remaining -= chunk.length;
      }
      await sink.flush();
    } finally {
      await sink.close();
    }
  }

  /// Fallback forense por bloques de 64 KB si un contenedor propietario no expone TOC estándar.
  Future<int> _carveZlibStreamsFallback({
    required RandomAccessFile raf,
    required int fileLength,
    required String outputDir,
    required String containerName,
  }) async {
    await Directory(outputDir).create(recursive: true);
    int carvedCount = 0;
    int pos = 0;

    while (pos < fileLength - 16) {
      await raf.setPosition(pos);
      final int windowLen = (fileLength - pos) < _chunkSize ? (fileLength - pos) : _chunkSize;
      final Uint8List window = await raf.read(windowLen);
      if (window.length < 4) break;

      int foundOffset = -1;
      for (int i = 0; i < window.length - 2; i++) {
        if (window[i] == 0x78 &&
            (window[i + 1] == 0x9C ||
                window[i + 1] == 0xDA ||
                window[i + 1] == 0x01 ||
                window[i + 1] == 0x5E)) {
          foundOffset = pos + i;
          break;
        }
      }

      if (foundOffset < 0) {
        pos += window.length - 2;
        continue;
      }

      final int maxTryLen = (fileLength - foundOffset) < (16 * 1024 * 1024)
          ? (fileLength - foundOffset)
          : (16 * 1024 * 1024);

      final String tmpPath = p.join(outputDir, '.carve_$carvedCount');
      final bool ok = await _tryZlibStream(
        raf: raf,
        offset: foundOffset,
        compressedLength: maxTryLen,
        outputPath: tmpPath,
        raw: false,
      );

      if (ok) {
        final tmpFile = File(tmpPath);
        final ext = await _detectExtensionFromMagic(tmpFile);
        final hashTag = foundOffset.toRadixString(16).padLeft(8, '0').toUpperCase();
        final finalPath = await _uniquePath(p.join(outputDir, '${containerName}_$hashTag$ext'));
        await tmpFile.rename(finalPath);
        carvedCount++;
        pos = foundOffset + 64;
      } else {
        pos = foundOffset + 2;
      }
    }

    return carvedCount;
  }

  Future<String> _detectExtensionFromMagic(File file) async {
    RandomAccessFile? raf;
    try {
      raf = await file.open(mode: FileMode.read);
      final int len = await raf.length();
      final Uint8List magic = await raf.read(len < 16 ? len : 16);
      if (magic.isEmpty) return '.bin';

      final String ascii = String.fromCharCodes(magic);

      if (ascii.startsWith('DDS ')) return '.dds';
      if (ascii.startsWith('BIKi') || ascii.startsWith('BIKf') || ascii.startsWith('KB2')) {
        return '.bik';
      }
      if (ascii.startsWith('RIFF')) return '.wav';
      if (ascii.startsWith('OggS')) return '.ogg';
      if (ascii.startsWith('MESH') ||
          ascii.startsWith('PCGV') ||
          ascii.startsWith('PCVX') ||
          ascii.startsWith('CVXLO')) {
        return '.mesh';
      }
      if (ascii.startsWith('ANIM')) return '.anim';
      if (ascii.startsWith('SKEL')) return '.skel';
      if (ascii.startsWith('TEX') || ascii.startsWith('IMG')) return '.tex';
      if (ascii.startsWith('ENT')) return '.ent';
      if (ascii.startsWith('COLL')) return '.coll';
      if (ascii.startsWith('PHYS')) return '.phys';
      if (ascii.startsWith('PCVS') || ascii.startsWith('PCSV')) return '.pcvs';
      if (ascii.startsWith('PCPS') || ascii.startsWith('PCSX')) return '.pcps';
      if (magic.length >= 4 &&
          magic[0] == 0x89 &&
          magic[1] == 0x50 &&
          magic[2] == 0x4E &&
          magic[3] == 0x47) {
        return '.png';
      }
      if (magic.length >= 3 && magic[0] == 0xFF && magic[1] == 0xD8 && magic[2] == 0xFF) {
        return '.jpg';
      }

      final trimmed = ascii.trimLeft();
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        return '.json';
      }

      return '.bin';
    } catch (_) {
      return '.bin';
    } finally {
      await raf?.close();
    }
  }

  Future<bool> _looksLikeStringTable(RandomAccessFile raf, int offset, int size) async {
    await raf.setPosition(offset);
    final sampleLen = size < 256 ? size : 256;
    final bytes = await raf.read(sampleLen);
    if (bytes.isEmpty) return false;

    int printable = 0;
    int nulls = 0;
    for (final b in bytes) {
      if (b == 0) {
        nulls++;
      } else if (b >= 32 && b <= 126) {
        printable++;
      }
    }
    return nulls > 0 && (printable + nulls) > (bytes.length * 0.85);
  }

  String? _readCString(Uint8List blob, int offset) {
    if (offset < 0 || offset >= blob.length) return null;
    final List<int> chars = <int>[];
    for (int i = offset; i < blob.length; i++) {
      final b = blob[i];
      if (b == 0) break;
      if (b < 32 || b > 126) return null;
      chars.add(b);
      if (chars.length > 260) return null;
    }
    if (chars.isEmpty) return null;
    return String.fromCharCodes(chars);
  }

  String _sanitizeRelativeName(String raw) {
    final normalized = raw.replaceAll('\\', '/').replaceAll('..', '_');
    final parts = normalized
        .split('/')
        .map((s) => s.replaceAll(RegExp(r'[<>:"|?*\x00-\x1F]'), '_').trim())
        .where((s) => s.isNotEmpty)
        .toList();
    return parts.isEmpty ? '' : p.joinAll(parts);
  }

  String _extractPrintableMagic(Uint8List bytes, int len) {
    final end = bytes.length < len ? bytes.length : len;
    return String.fromCharCodes(
      bytes.sublist(0, end).map((b) => (b >= 32 && b <= 126) ? b : 46),
    );
  }

  Future<String> _uniquePath(String desiredPath) async {
    if (!await File(desiredPath).exists()) return desiredPath;
    final dir = p.dirname(desiredPath);
    final base = p.basenameWithoutExtension(desiredPath);
    final ext = p.extension(desiredPath);
    int idx = 1;
    while (true) {
      final candidate = p.join(dir, '${base}_${idx.toString().padLeft(3, '0')}$ext');
      if (!await File(candidate).exists()) return candidate;
      idx++;
    }
  }
}

class _SinkByteConsumer implements Sink<List<int>> {
  final IOSink _ioSink;

  _SinkByteConsumer(this._ioSink);

  @override
  void add(List<int> data) {
    _ioSink.add(data);
  }

  @override
  void close() {}
}
