import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:ffmpeg_kit_flutter_new/ffmpeg_kit.dart';
import 'package:ffmpeg_kit_flutter_new/return_code.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;

typedef ForensicLogCallback = void Function(String message);

class BinaryToolsService {
  static const MethodChannel _channel = MethodChannel('wos_forensic/native');

  final String nativeLibDir;
  final ForensicLogCallback? onLog;

  BinaryToolsService({
    required this.nativeLibDir,
    this.onLog,
  });

  /// Debe llamarse desde el Isolate principal antes de iniciar el Isolate de extracción.
  static Future<String> getNativeLibDir() async {
    final String? dir = await _channel.invokeMethod<String>('getNativeLibDir');
    if (dir == null || dir.isEmpty) {
      throw StateError('No se pudo resolver nativeLibraryDir desde Android.');
    }
    return dir;
  }

  String get sevenZipBinaryPath => p.join(nativeLibDir, 'lib7zz.so');
  String get unshieldBinaryPath => p.join(nativeLibDir, 'libunshield.so');

  void _log(String msg) {
    onLog?.call(msg);
  }

  Future<void> verifyNativeBinaries() async {
    final sevenZip = File(sevenZipBinaryPath);
    final unshield = File(unshieldBinaryPath);

    if (!await sevenZip.exists()) {
      throw FileSystemException(
        'Binario nativo lib7zz.so no encontrado en nativeLibraryDir.',
        sevenZipBinaryPath,
      );
    }
    if (!await unshield.exists()) {
      throw FileSystemException(
        'Binario nativo libunshield.so no encontrado en nativeLibraryDir.',
        unshieldBinaryPath,
      );
    }
  }

  /// Paso 1: Extrae el archivo .ISO completo usando lib7zz.so en streaming de logs.
  Future<void> extractIso({
    required String isoPath,
    required String tempDir,
  }) async {
    await verifyNativeBinaries();
    final outDir = Directory(tempDir);
    if (!await outDir.exists()) {
      await outDir.create(recursive: true);
    }

    _log('[7ZZ] Iniciando extracción de ISO: ${p.basename(isoPath)}');
    final exitCode = await _runProcessStreaming(
      executable: sevenZipBinaryPath,
      arguments: ['x', isoPath, '-o$tempDir', '-y'],
      tag: '7ZZ-ISO',
    );

    if (exitCode > 1) {
      throw ProcessException(
        sevenZipBinaryPath,
        ['x', isoPath, '-o$tempDir', '-y'],
        'lib7zz.so falló extrayendo la ISO con código de salida $exitCode',
        exitCode,
      );
    }
    _log('[7ZZ] Extracción de ISO completada (código $exitCode).');
  }

  /// Paso 2: Extrae archivos .msi y .cab (InstallShield con libunshield.so y estándar con lib7zz.so).
  Future<void> extractInstallersAndCabinets({
    required String rootDir,
  }) async {
    await verifyNativeBinaries();

    // 2A. Extraer archivos .msi primero (pueden contener .cab embebidos en su interior).
    final msiFiles = await _findFilesByExtension(rootDir, const {'.msi'});
    for (final msi in msiFiles) {
      final outSubDir = p.join(
        p.dirname(msi.path),
        '${p.basenameWithoutExtension(msi.path)}_msi_extracted',
      );
      await Directory(outSubDir).create(recursive: true);
      _log('[7ZZ] Extrayendo paquete MSI: ${p.basename(msi.path)}');

      final code = await _runProcessStreaming(
        executable: sevenZipBinaryPath,
        arguments: ['x', msi.path, '-o$outSubDir', '-y'],
        tag: '7ZZ-MSI',
      );
      if (code > 1) {
        _log('[WARN] lib7zz.so devolvió código $code para ${p.basename(msi.path)}, continuando.');
      }
    }

    // 2B. Detectar todos los .hdr y .cab (incluyendo los recién extraídos de los .msi).
    final hdrFiles = await _findFilesByExtension(rootDir, const {'.hdr'});
    final cabFiles = await _findFilesByExtension(rootDir, const {'.cab'});

    // Mapear directorios que contienen grupos InstallShield (.hdr + .cab divididos).
    final Set<String> processedInstallShieldGroups = <String>{};
    final Set<String> installShieldHandledCabs = <String>{};

    // Procesar primero por detección de archivos .hdr.
    for (final hdr in hdrFiles) {
      final dirPath = p.dirname(hdr.path);
      final hdrBase = p.basenameWithoutExtension(hdr.path).toLowerCase();
      final groupPrefix = _stripTrailingDigits(hdrBase);
      final groupKey = '$dirPath::$groupPrefix';

      if (processedInstallShieldGroups.contains(groupKey)) {
        continue;
      }

      // Buscar el primer volumen del grupo (data1.cab o data1.hdr).
      final siblingCabs = cabFiles.where((c) {
        if (p.dirname(c.path) != dirPath) return false;
        final cBase = p.basenameWithoutExtension(c.path).toLowerCase();
        return _stripTrailingDigits(cBase) == groupPrefix || cBase == hdrBase;
      }).toList()
        ..sort((a, b) => a.path.toLowerCase().compareTo(b.path.toLowerCase()));

      for (final c in siblingCabs) {
        installShieldHandledCabs.add(c.path);
      }

      final String targetVolume = siblingCabs.isNotEmpty ? siblingCabs.first.path : hdr.path;
      processedInstallShieldGroups.add(groupKey);

      final outSubDir = p.join(dirPath, '${groupPrefix}_unshield_extracted');
      await Directory(outSubDir).create(recursive: true);

      _log('[UNSHIELD] Extrayendo grupo InstallShield ($groupPrefix): ${p.basename(targetVolume)}');
      final code = await _runProcessStreaming(
        executable: unshieldBinaryPath,
        arguments: ['-d', outSubDir, 'x', targetVolume],
        tag: 'UNSHIELD',
      );
      if (code != 0) {
        _log('[WARN] libunshield.so finalizó con código $code en ${p.basename(targetVolume)}.');
      }
    }

    // Procesar .cab restantes: revisar firma mágica ('ISc(' vs 'MSCF') por si algún InstallShield no tenía .hdr obvio.
    cabFiles.sort((a, b) => a.path.toLowerCase().compareTo(b.path.toLowerCase()));
    for (final cab in cabFiles) {
      if (installShieldHandledCabs.contains(cab.path)) {
        continue;
      }

      final magic = await _readFirstBytes(cab, 4);
      final isInstallShieldMagic = magic.length >= 4 &&
          magic[0] == 0x49 && // I
          magic[1] == 0x53 && // S
          magic[2] == 0x63 && // c
          magic[3] == 0x28;   // (

      final dirPath = p.dirname(cab.path);
      final cabBase = p.basenameWithoutExtension(cab.path).toLowerCase();
      final groupPrefix = _stripTrailingDigits(cabBase);

      if (isInstallShieldMagic) {
        final groupKey = '$dirPath::$groupPrefix';
        if (processedInstallShieldGroups.contains(groupKey)) {
          continue;
        }
        processedInstallShieldGroups.add(groupKey);

        final outSubDir = p.join(dirPath, '${groupPrefix}_unshield_extracted');
        await Directory(outSubDir).create(recursive: true);
        _log('[UNSHIELD] CAB InstallShield detectado por firma ISc(: ${p.basename(cab.path)}');

        final code = await _runProcessStreaming(
          executable: unshieldBinaryPath,
          arguments: ['-d', outSubDir, 'x', cab.path],
          tag: 'UNSHIELD',
        );
        if (code != 0) {
          _log('[WARN] libunshield.so devolvió código $code en ${p.basename(cab.path)}.');
        }
      } else {
        final outSubDir = p.join(
          dirPath,
          '${p.basenameWithoutExtension(cab.path)}_cab_extracted',
        );
        await Directory(outSubDir).create(recursive: true);
        _log('[7ZZ] Extrayendo CAB estándar: ${p.basename(cab.path)}');

        final code = await _runProcessStreaming(
          executable: sevenZipBinaryPath,
          arguments: ['x', cab.path, '-o$outSubDir', '-y'],
          tag: '7ZZ-CAB',
        );
        if (code > 1) {
          _log('[WARN] lib7zz.so devolvió código $code en ${p.basename(cab.path)}.');
        }
      }
    }
  }

  /// Convierte audios compatibles a WAV PCM 48000 Hz 16-bit usando ffmpeg_kit_flutter_new.
  /// Devuelve true si se convirtió correctamente; false si el formato es propietario no decodificable.
  Future<bool> convertAudioToWav48kHz({
    required String inputPath,
    required String outputWavPath,
  }) async {
    try {
      final outParent = Directory(p.dirname(outputWavPath));
      if (!await outParent.exists()) {
        await outParent.create(recursive: true);
      }

      final session = await FFmpegKit.executeWithArguments([
        '-y',
        '-v',
        'error',
        '-i',
        inputPath,
        '-ar',
        '48000',
        '-acodec',
        'pcm_s16le',
        outputWavPath,
      ]);

      final returnCode = await session.getReturnCode();
      if (ReturnCode.isSuccess(returnCode)) {
        final outFile = File(outputWavPath);
        if (await outFile.exists() && await outFile.length() > 44) {
          return true;
        }
      }

      final outFile = File(outputWavPath);
      if (await outFile.exists()) {
        await outFile.delete();
      }
      return false;
    } catch (e) {
      _log('[FFMPEG-SKIP] Audio no decodificable (${p.basename(inputPath)}): $e');
      try {
        final outFile = File(outputWavPath);
        if (await outFile.exists()) {
          await outFile.delete();
        }
      } catch (_) {}
      return false;
    }
  }

  Future<int> _runProcessStreaming({
    required String executable,
    required List<String> arguments,
    required String tag,
  }) async {
    final process = await Process.start(executable, arguments);
    const decoder = Utf8Decoder(allowMalformed: true);

    final stdoutSub = process.stdout
        .transform(decoder)
        .transform(const LineSplitter())
        .listen((line) {
      final trimmed = line.trim();
      if (trimmed.isNotEmpty) {
        _log('[$tag] $trimmed');
      }
    });

    final stderrSub = process.stderr
        .transform(decoder)
        .transform(const LineSplitter())
        .listen((line) {
      final trimmed = line.trim();
      if (trimmed.isNotEmpty) {
        _log('[$tag-ERR] $trimmed');
      }
    });

    final exitCode = await process.exitCode;
    await stdoutSub.cancel();
    await stderrSub.cancel();
    return exitCode;
  }

  Future<List<File>> _findFilesByExtension(
    String rootDir,
    Set<String> extensions,
  ) async {
    final List<File> results = <File>[];
    final dir = Directory(rootDir);
    if (!await dir.exists()) return results;

    await for (final entity in dir.list(recursive: true, followLinks: false)) {
      if (entity is File) {
        final ext = p.extension(entity.path).toLowerCase();
        if (extensions.contains(ext)) {
          results.add(entity);
        }
      }
    }
    return results;
  }

  Future<Uint8List> _readFirstBytes(File file, int count) async {
    RandomAccessFile? raf;
    try {
      raf = await file.open(mode: FileMode.read);
      final len = await raf.length();
      final toRead = len < count ? len : count;
      if (toRead <= 0) return Uint8List(0);
      return await raf.read(toRead);
    } catch (_) {
      return Uint8List(0);
    } finally {
      await raf?.close();
    }
  }

  String _stripTrailingDigits(String value) {
    return value.replaceFirst(RegExp(r'\d+$'), '');
  }
}
