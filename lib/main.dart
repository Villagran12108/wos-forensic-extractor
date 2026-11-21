import 'dart:async';
import 'dart:collection';
import 'dart:io';
import 'dart:isolate';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_foreground_task/flutter_foreground_task.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';

import 'services/binary_tools_service.dart';
import 'services/forensic_classifier.dart';
import 'services/port_batch_converter.dart';
import 'services/wos_pcpack_parser.dart';

@pragma('vm:entry-point')
void startCallback() {
  FlutterForegroundTask.setTaskHandler(_ForensicForegroundHandler());
}

class _ForensicForegroundHandler extends TaskHandler {
  @override
  Future<void> onStart(DateTime timestamp, TaskStarter starter) async {}

  @override
  void onRepeatEvent(DateTime timestamp) {}

  @override
  Future<void> onDestroy(DateTime timestamp) async {}
}

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  FlutterForegroundTask.initCommunicationPort();
  runApp(const WosForensicExtractorApp());
}

class WosForensicExtractorApp extends StatelessWidget {
  const WosForensicExtractorApp({super.key});

  @override
  Widget build(BuildContext context) {
    final ColorScheme darkScheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFFD32F2F),
      brightness: Brightness.dark,
    );

    return MaterialApp(
      title: 'WoS Forensic Extractor',
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.dark,
      darkTheme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorScheme: darkScheme,
        scaffoldBackgroundColor: const Color(0xFF0E1014),
        cardTheme: CardThemeData(
          color: const Color(0xFF171A21),
          elevation: 0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(14),
            side: BorderSide(color: Colors.white.withOpacity(0.08)),
          ),
        ),
      ),
      home: const WithForegroundTask(
        child: ExtractorHomeScreen(),
      ),
    );
  }
}

class ExtractorHomeScreen extends StatefulWidget {
  const ExtractorHomeScreen({super.key});

  @override
  State<ExtractorHomeScreen> createState() => _ExtractorHomeScreenState();
}

class _ExtractorHomeScreenState extends State<ExtractorHomeScreen> {
  static const int _maxUiLogLines = 1500;

  final ScrollController _logScrollController = ScrollController();
  final ListQueue<String> _logs = ListQueue<String>();

  // Estado Tarjeta 1: Extracción ISO
  String? _selectedIsoPath;
  String? _selectedIsoName;
  double? _selectedIsoSizeGb;
  String? _selectedOutputDir;

  // Estado Tarjeta 2: Conversión de carpeta extraída para Port
  String? _selectedDumpDirForConversion;
  String? _convertedOutputDirBanner;
  int _convertedBannerTotal = 0;
  int _convertedBannerSkipped = 0;

  // Estado global de ejecución, progreso y contadores
  bool _isRunning = false;
  String _activeMode = ''; // 'extract' o 'convert'
  double _globalProgress = 0.0;
  String _currentStageLabel = 'Listo para iniciar extracción o conversión forense';
  int _classifiedProcessed = 0;
  int _classifiedTotal = 0;
  int _ddsReconstructedCount = 0;
  int _audioConverted48kHzCount = 0;
  String? _manifestResultPath;

  final Map<String, int> _categoryCounts = <String, int>{
    for (final cat in ForensicClassifier.allCategories) cat: 0,
  };

  ReceivePort? _isolateReceivePort;
  Isolate? _workerIsolate;

  @override
  void initState() {
    super.initState();
    _initForegroundTask();
    _appendLog('[SISTEMA] WoS Forensic Extractor inicializado (ARM64 Streaming Mode).');
  }

  @override
  void dispose() {
    _logScrollController.dispose();
    _isolateReceivePort?.close();
    _workerIsolate?.kill(priority: Isolate.immediate);
    super.dispose();
  }

  void _initForegroundTask() {
    FlutterForegroundTask.init(
      androidNotificationOptions: AndroidNotificationOptions(
        channelId: 'wos_forensic_channel',
        channelName: 'WoS Forensic Extraction',
        channelDescription:
            'Mantiene activa la extracción y conversión forense de ISOs de 8+ GB en segundo plano.',
        channelImportance: NotificationChannelImportance.LOW,
        priority: NotificationPriority.LOW,
      ),
      iosNotificationOptions: const IOSNotificationOptions(
        showNotification: false,
        playSound: false,
      ),
      foregroundTaskOptions: ForegroundTaskOptions(
        eventAction: ForegroundTaskEventAction.nothing(),
        autoRunOnBoot: false,
        autoRunOnMyPackageReplaced: false,
        allowWakeLock: true,
        allowWifiLock: false,
      ),
    );
  }

  Future<bool> _ensureRequiredPermissions() async {
    _appendLog('[PERMISOS] Verificando almacenamiento total y notificaciones...');

    final PermissionStatus notifStatus = await Permission.notification.request();
    if (!notifStatus.isGranted) {
      _appendLog('[WARN] Permiso de notificaciones denegado; la notificación del servicio puede ocultarse.');
    }

    PermissionStatus manageStatus = await Permission.manageExternalStorage.status;
    if (!manageStatus.isGranted) {
      manageStatus = await Permission.manageExternalStorage.request();
    }

    if (manageStatus.isGranted) {
      _appendLog('[PERMISOS] MANAGE_EXTERNAL_STORAGE concedido.');
      return true;
    }

    final PermissionStatus legacyStorage = await Permission.storage.request();
    if (legacyStorage.isGranted) {
      _appendLog('[PERMISOS] Permiso de almacenamiento legacy concedido.');
      return true;
    }

    _appendLog('[ERROR] Permiso de almacenamiento total requerido para leer la ISO y escribir el volcado.');
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'Debes conceder "Acceso a todos los archivos" para procesar ISOs y carpetas de 8+ GB.',
          ),
        ),
      );
    }
    return false;
  }

  // ---------------------------------------------------------------------------
  // TARJETA 1: EXTRAER ISO COMPLETO
  // ---------------------------------------------------------------------------
  Future<void> _pickIsoFile() async {
    if (_isRunning) return;
    final bool hasPerms = await _ensureRequiredPermissions();
    if (!hasPerms) return;

    final FilePickerResult? result = await FilePicker.platform.pickFiles(
      type: FileType.any,
      allowMultiple: false,
      withData: false,
      withReadStream: false,
    );

    if (result == null || result.files.isEmpty) return;
    final PlatformFile picked = result.files.single;
    final String? path = picked.path;

    if (path == null || path.isEmpty) {
      _appendLog('[ERROR] No se pudo obtener una ruta de archivo real para la ISO.');
      return;
    }

    final File isoFile = File(path);
    if (!await isoFile.exists()) {
      _appendLog('[ERROR] El archivo seleccionado no existe en disco: $path');
      return;
    }

    final int byteLength = await isoFile.length();
    final double sizeGb = byteLength / (1024 * 1024 * 1024);

    if (!path.toLowerCase().endsWith('.iso')) {
      _appendLog('[WARN] El archivo elegido no tiene extensión .iso (${p.basename(path)}).');
    }

    setState(() {
      _selectedIsoPath = path;
      _selectedIsoName = p.basename(path);
      _selectedIsoSizeGb = sizeGb;
    });

    _appendLog(
      '[ISO] Seleccionada: $_selectedIsoName (${sizeGb.toStringAsFixed(2)} GB)',
    );
  }

  Future<void> _pickOutputDirectory() async {
    if (_isRunning) return;
    final bool hasPerms = await _ensureRequiredPermissions();
    if (!hasPerms) return;

    final String? dirPath = await FilePicker.platform.getDirectoryPath(
      dialogTitle: 'Elige la carpeta de destino para WoS_Full_Port_Dump',
    );

    if (dirPath == null || dirPath.isEmpty) return;

    setState(() {
      _selectedOutputDir = dirPath;
    });
    _appendLog('[DESTINO] Carpeta seleccionada: $dirPath');
  }

  Future<void> _startFullExtraction() async {
    if (_isRunning) return;

    if (_selectedIsoPath == null || _selectedOutputDir == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Selecciona primero el archivo .ISO y la carpeta de destino.'),
        ),
      );
      return;
    }

    final bool hasPerms = await _ensureRequiredPermissions();
    if (!hasPerms) return;

    late final String nativeLibDir;
    try {
      nativeLibDir = await BinaryToolsService.getNativeLibDir();
    } catch (e) {
      _appendLog('[ERROR] No se pudo obtener nativeLibraryDir: $e');
      return;
    }

    final RootIsolateToken? rootIsolateToken = RootIsolateToken.instance;
    if (rootIsolateToken == null) {
      _appendLog('[ERROR] RootIsolateToken no disponible en el Isolate principal.');
      return;
    }

    final Directory appSupportDir = await getApplicationSupportDirectory();
    final String tempDir = p.join(
      appSupportDir.path,
      'wos_temp_${DateTime.now().millisecondsSinceEpoch}',
    );

    setState(() {
      _isRunning = true;
      _activeMode = 'extract';
      _globalProgress = 0.01;
      _currentStageLabel = 'Iniciando Foreground Service y preparando entorno...';
      _classifiedProcessed = 0;
      _classifiedTotal = 0;
      _ddsReconstructedCount = 0;
      _audioConverted48kHzCount = 0;
      _manifestResultPath = null;
      _convertedOutputDirBanner = null;
      for (final key in _categoryCounts.keys) {
        _categoryCounts[key] = 0;
      }
    });

    await FlutterForegroundTask.startService(
      serviceId: 4040,
      notificationTitle: 'WoS Forensic Extractor',
      notificationText: 'Extrayendo recursos de $_selectedIsoName...',
      callback: startCallback,
    );

    _isolateReceivePort?.close();
    _isolateReceivePort = ReceivePort();

    _isolateReceivePort!.listen((dynamic message) async {
      if (message is! Map<String, dynamic>) return;
      final String type = message['type'] as String? ?? '';

      switch (type) {
        case 'log':
          final String text = message['message'] as String? ?? '';
          _appendLog(text);
          break;

        case 'progress':
          final double progress = (message['value'] as num?)?.toDouble() ?? _globalProgress;
          final String stage = message['stage'] as String? ?? _currentStageLabel;
          final int? proc = message['processed'] as int?;
          final int? tot = message['total'] as int?;

          if (mounted) {
            setState(() {
              _globalProgress = progress.clamp(0.0, 1.0);
              _currentStageLabel = stage;
              if (proc != null) _classifiedProcessed = proc;
              if (tot != null) _classifiedTotal = tot;
            });
          }

          await FlutterForegroundTask.updateService(
            notificationTitle: 'WoS Forensic Extractor (${(_globalProgress * 100).toStringAsFixed(0)}%)',
            notificationText: stage,
          );
          break;

        case 'done':
          final Map<dynamic, dynamic>? rawCounts =
              message['counts'] as Map<dynamic, dynamic>?;
          final int ddsCount = message['ddsCount'] as int? ?? 0;
          final int audioCount = message['audioCount'] as int? ?? 0;
          final String? manifestPath = message['manifestPath'] as String?;
          final String? dumpRootDir = message['dumpRootDir'] as String?;

          if (mounted) {
            setState(() {
              _isRunning = false;
              _activeMode = '';
              _globalProgress = 1.0;
              _currentStageLabel = 'Extracción forense completada al 100%';
              _ddsReconstructedCount = ddsCount;
              _audioConverted48kHzCount = audioCount;
              _manifestResultPath = manifestPath;
              if (dumpRootDir != null && dumpRootDir.isNotEmpty) {
                _selectedDumpDirForConversion = dumpRootDir;
              }
              if (rawCounts != null) {
                for (final entry in rawCounts.entries) {
                  final k = entry.key.toString();
                  final v = (entry.value as num).toInt();
                  if (_categoryCounts.containsKey(k)) {
                    _categoryCounts[k] = v;
                  }
                }
              }
            });
          }

          if (dumpRootDir != null && dumpRootDir.isNotEmpty) {
            _appendLog('[TARJETA-2] Carpeta asignada automáticamente para conversión Port: $dumpRootDir');
          }

          await FlutterForegroundTask.stopService();
          _isolateReceivePort?.close();
          _isolateReceivePort = null;
          _workerIsolate = null;
          break;

        case 'error':
          final String err = message['error'] as String? ?? 'Error desconocido';
          _appendLog('[FATAL] $err');
          if (mounted) {
            setState(() {
              _isRunning = false;
              _activeMode = '';
              _currentStageLabel = 'Error durante la extracción';
            });
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text('Error en la extracción: $err')),
            );
          }

          await FlutterForegroundTask.stopService();
          _isolateReceivePort?.close();
          _isolateReceivePort = null;
          _workerIsolate = null;
          break;
      }
    });

    _appendLog('[ISOLATE] Lanzando pipeline de extracción en segundo plano...');
    _workerIsolate = await Isolate.spawn<Map<String, dynamic>>(
      _extractionIsolateEntry,
      <String, dynamic>{
        'sendPort': _isolateReceivePort!.sendPort,
        'rootIsolateToken': rootIsolateToken,
        'nativeLibDir': nativeLibDir,
        'isoPath': _selectedIsoPath!,
        'outputDir': _selectedOutputDir!,
        'tempDir': tempDir,
      },
      errorsAreFatal: true,
    );
  }

  // ---------------------------------------------------------------------------
  // TARJETA 2: CONVERTIR CARPETA EXTRAÍDA PARA PORT
  // ---------------------------------------------------------------------------
  Future<void> _pickDumpFolderForConversion() async {
    if (_isRunning) return;
    final bool hasPerms = await _ensureRequiredPermissions();
    if (!hasPerms) return;

    final String? dirPath = await FilePicker.platform.getDirectoryPath(
      dialogTitle: 'Elige la carpeta WoS_Full_Port_Dump extraída',
    );

    if (dirPath == null || dirPath.isEmpty) return;

    setState(() {
      _selectedDumpDirForConversion = dirPath;
      _convertedOutputDirBanner = null;
    });
    _appendLog('[PORT-INPUT] Carpeta WoS_Full_Port_Dump seleccionada: $dirPath');
  }

  Future<void> _startPortBatchConversion() async {
    if (_isRunning) return;

    final String? dumpPath = _selectedDumpDirForConversion;
    if (dumpPath == null || dumpPath.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Selecciona primero una carpeta WoS_Full_Port_Dump válida.'),
        ),
      );
      return;
    }

    if (!await Directory(dumpPath).exists()) {
      _appendLog('[ERROR] La carpeta seleccionada no existe: $dumpPath');
      return;
    }

    final bool hasPerms = await _ensureRequiredPermissions();
    if (!hasPerms) return;

    final RootIsolateToken? rootIsolateToken = RootIsolateToken.instance;
    if (rootIsolateToken == null) {
      _appendLog('[ERROR] RootIsolateToken no disponible en el Isolate principal.');
      return;
    }

    setState(() {
      _isRunning = true;
      _activeMode = 'convert';
      _globalProgress = 0.01;
      _currentStageLabel = 'Iniciando conversión por lotes para Port...';
      _classifiedProcessed = 0;
      _classifiedTotal = 0;
      _manifestResultPath = null;
      _convertedOutputDirBanner = null;
      _convertedBannerTotal = 0;
      _convertedBannerSkipped = 0;
      for (final key in _categoryCounts.keys) {
        _categoryCounts[key] = 0;
      }
    });

    await FlutterForegroundTask.startService(
      serviceId: 4041,
      notificationTitle: 'WoS Port Batch Converter',
      notificationText: 'Convirtiendo recursos de ${p.basename(dumpPath)}...',
      callback: startCallback,
    );

    _isolateReceivePort?.close();
    _isolateReceivePort = ReceivePort();

    _isolateReceivePort!.listen((dynamic message) async {
      if (message is! Map<String, dynamic>) return;
      final String type = message['type'] as String? ?? '';

      switch (type) {
        case 'log':
          final String text = message['message'] as String? ?? '';
          _appendLog(text);
          break;

        case 'conv_progress':
          final double progress = (message['value'] as num?)?.toDouble() ?? _globalProgress;
          final String stage = message['stage'] as String? ?? _currentStageLabel;
          final int proc = message['processed'] as int? ?? 0;
          final int tot = message['total'] as int? ?? 0;
          final String? catKey = message['category'] as String?;
          final bool convertedOk = message['convertedOk'] as bool? ?? false;

          if (mounted) {
            setState(() {
              _globalProgress = progress.clamp(0.0, 1.0);
              _currentStageLabel = stage;
              _classifiedProcessed = proc;
              _classifiedTotal = tot;
              if (catKey != null && convertedOk && _categoryCounts.containsKey(catKey)) {
                _categoryCounts[catKey] = (_categoryCounts[catKey] ?? 0) + 1;
              }
            });
          }

          await FlutterForegroundTask.updateService(
            notificationTitle: 'WoS Port Converter (${(_globalProgress * 100).toStringAsFixed(0)}%)',
            notificationText: '$stage ($proc/$tot)',
          );
          break;

        case 'conv_done':
          final String outDir = message['outputConvertedDir'] as String? ?? '';
          final String manifestPath = message['manifestPath'] as String? ?? '';
          final int totalAnalyzed = message['totalAnalyzed'] as int? ?? 0;
          final int totalConverted = message['totalConverted'] as int? ?? 0;
          final int totalSkipped = message['totalSkipped'] as int? ?? 0;
          final Map<dynamic, dynamic>? rawCounts =
              message['counts'] as Map<dynamic, dynamic>?;

          if (mounted) {
            setState(() {
              _isRunning = false;
              _activeMode = '';
              _globalProgress = 1.0;
              _currentStageLabel = 'Conversión para Port completada al 100%';
              _manifestResultPath = manifestPath;
              _convertedOutputDirBanner = outDir;
              _convertedBannerTotal = totalConverted;
              _convertedBannerSkipped = totalSkipped;
              if (rawCounts != null) {
                for (final entry in rawCounts.entries) {
                  final String k = entry.key.toString();
                  final int v = (entry.value as num).toInt();
                  if (_categoryCounts.containsKey(k)) {
                    _categoryCounts[k] = v;
                  }
                }
              }
            });
          }

          await FlutterForegroundTask.stopService();
          _isolateReceivePort?.close();
          _isolateReceivePort = null;
          _workerIsolate = null;

          if (mounted) {
            _showConversionCompletedDialog(
              outputDir: outDir,
              manifestPath: manifestPath,
              totalAnalyzed: totalAnalyzed,
              totalConverted: totalConverted,
              totalSkipped: totalSkipped,
            );
          }
          break;

        case 'error':
          final String err = message['error'] as String? ?? 'Error desconocido';
          _appendLog('[FATAL] $err');
          if (mounted) {
            setState(() {
              _isRunning = false;
              _activeMode = '';
              _currentStageLabel = 'Error durante la conversión para Port';
            });
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text('Error en conversión Port: $err')),
            );
          }

          await FlutterForegroundTask.stopService();
          _isolateReceivePort?.close();
          _isolateReceivePort = null;
          _workerIsolate = null;
          break;
      }
    });

    _appendLog('[ISOLATE] Lanzando PortBatchConverter en segundo plano...');
    _workerIsolate = await Isolate.spawn<Map<String, dynamic>>(
      _conversionIsolateEntry,
      <String, dynamic>{
        'sendPort': _isolateReceivePort!.sendPort,
        'rootIsolateToken': rootIsolateToken,
        'dumpDir': dumpPath,
      },
      errorsAreFatal: true,
    );
  }

  Future<void> _showConversionCompletedDialog({
    required String outputDir,
    required String manifestPath,
    required int totalAnalyzed,
    required int totalConverted,
    required int totalSkipped,
  }) async {
    await showDialog<void>(
      context: context,
      builder: (BuildContext ctx) {
        return AlertDialog(
          title: const Row(
            children: [
              Icon(Icons.check_circle_rounded, color: Color(0xFF06D6A0)),
              SizedBox(width: 8),
              Expanded(child: Text('Conversión Port Completada')),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Archivos analizados: $totalAnalyzed'),
              Text('Convertidos con éxito: $totalConverted'),
              Text('Omitidos (original conservado): $totalSkipped'),
              const SizedBox(height: 12),
              const Text(
                'Carpeta WoS_Port_Ready_Converted:',
                style: TextStyle(fontWeight: FontWeight.w700, fontSize: 12.5),
              ),
              const SizedBox(height: 4),
              SelectableText(
                outputDir,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 11.5,
                  color: Color(0xFF06D6A0),
                ),
              ),
              const SizedBox(height: 10),
              const Text(
                'Manifiesto:',
                style: TextStyle(fontWeight: FontWeight.w700, fontSize: 12.5),
              ),
              const SizedBox(height: 4),
              SelectableText(
                manifestPath,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
              ),
            ],
          ),
          actions: [
            FilledButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Entendido'),
            ),
          ],
        );
      },
    );
  }

  void _appendLog(String line) {
    if (!mounted) return;
    setState(() {
      if (_logs.length >= _maxUiLogLines) {
        _logs.removeFirst();
      }
      _logs.addLast(line);
    });

    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_logScrollController.hasClients) {
        _logScrollController.jumpTo(
          _logScrollController.position.maxScrollExtent,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final ColorScheme cs = Theme.of(context).colorScheme;
    final int percent = (_globalProgress * 100).round();

    return Scaffold(
      appBar: AppBar(
        title: const Text(
          'WoS Forensic Extractor',
          style: TextStyle(fontWeight: FontWeight.w700),
        ),
        centerTitle: false,
        actions: [
          if (_isRunning)
            Padding(
              padding: const EdgeInsets.only(right: 16),
              child: Center(
                child: SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2.2,
                    color: cs.primary,
                  ),
                ),
              ),
            ),
        ],
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Row(
                        children: [
                          Icon(Icons.album_rounded, size: 18, color: cs.primary),
                          const SizedBox(width: 8),
                          const Expanded(
                            child: Text(
                              '1. EXTRAER ISO COMPLETO',
                              style: TextStyle(
                                fontSize: 13.5,
                                fontWeight: FontWeight.w800,
                                letterSpacing: 0.5,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 10),
                      Row(
                        children: [
                          Expanded(
                            child: FilledButton.tonalIcon(
                              onPressed: _isRunning ? null : _pickIsoFile,
                              icon: const Icon(Icons.disc_full_outlined),
                              label: const Text('Elegir archivo .ISO'),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: FilledButton.tonalIcon(
                              onPressed: _isRunning ? null : _pickOutputDirectory,
                              icon: const Icon(Icons.folder_open_outlined),
                              label: const Text('Elegir carpeta de destino'),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 10),
                      _InfoRow(
                        icon: Icons.album,
                        label: 'ISO:',
                        value: _selectedIsoName != null
                            ? '$_selectedIsoName (${_selectedIsoSizeGb!.toStringAsFixed(2)} GB)'
                            : 'Ninguna seleccionada',
                      ),
                      const SizedBox(height: 4),
                      _InfoRow(
                        icon: Icons.drive_file_move_outline,
                        label: 'Salida:',
                        value: _selectedOutputDir ?? 'Ninguna seleccionada',
                      ),
                      const SizedBox(height: 12),
                      SizedBox(
                        height: 48,
                        child: FilledButton.icon(
                          onPressed: _isRunning ? null : _startFullExtraction,
                          style: FilledButton.styleFrom(
                            backgroundColor: cs.primary,
                            foregroundColor: cs.onPrimary,
                            textStyle: const TextStyle(
                              fontSize: 14.5,
                              fontWeight: FontWeight.w800,
                              letterSpacing: 0.6,
                            ),
                          ),
                          icon: const Icon(Icons.rocket_launch_rounded),
                          label: Text(
                            _isRunning && _activeMode == 'extract'
                                ? 'EXTRAYENDO ISO EN SEGUNDO PLANO...'
                                : 'EXTRAER TODO PARA PORT',
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 10),

              Card(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Row(
                        children: [
                          Icon(Icons.transform_rounded, size: 18, color: cs.tertiary),
                          const SizedBox(width: 8),
                          const Expanded(
                            child: Text(
                              '2. CONVERTIR CARPETA EXTRAÍDA PARA PORT',
                              style: TextStyle(
                                fontSize: 13.5,
                                fontWeight: FontWeight.w800,
                                letterSpacing: 0.5,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 10),
                      FilledButton.tonalIcon(
                        onPressed: _isRunning ? null : _pickDumpFolderForConversion,
                        icon: const Icon(Icons.folder_special_outlined),
                        label: const Text('Elegir carpeta WoS_Full_Port_Dump'),
                      ),
                      const SizedBox(height: 10),
                      _InfoRow(
                        icon: Icons.folder_copy_outlined,
                        label: 'Origen:',
                        value: _selectedDumpDirForConversion ??
                            'Ninguna seleccionada (se auto-asigna tras extraer ISO)',
                      ),
                      const SizedBox(height: 12),
                      SizedBox(
                        height: 48,
                        child: FilledButton.icon(
                          onPressed: (_isRunning || _selectedDumpDirForConversion == null)
                              ? null
                              : _startPortBatchConversion,
                          style: FilledButton.styleFrom(
                            backgroundColor: cs.tertiaryContainer,
                            foregroundColor: cs.onTertiaryContainer,
                            textStyle: const TextStyle(
                              fontSize: 14.5,
                              fontWeight: FontWeight.w800,
                              letterSpacing: 0.6,
                            ),
                          ),
                          icon: const Icon(Icons.auto_fix_high_rounded),
                          label: Text(
                            _isRunning && _activeMode == 'convert'
                                ? 'CONVIRTIENDO RECURSOS PARA PORT...'
                                : '2. CONVERTIR TODO PARA PORT',
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 10),

              if (_convertedOutputDirBanner != null) ...[
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: const Color(0xFF06D6A0).withOpacity(0.12),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: const Color(0xFF06D6A0).withOpacity(0.55),
                    ),
                  ),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Icon(
                        Icons.verified_rounded,
                        color: Color(0xFF06D6A0),
                        size: 20,
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Conversión lista: $_convertedBannerTotal convertidos ($_convertedBannerSkipped conservados en original)',
                              style: const TextStyle(
                                fontWeight: FontWeight.w700,
                                fontSize: 12.5,
                                color: Color(0xFF06D6A0),
                              ),
                            ),
                            const SizedBox(height: 4),
                            SelectableText(
                              _convertedOutputDirBanner!,
                              style: const TextStyle(
                                fontFamily: 'monospace',
                                fontSize: 11.5,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 10),
              ],

              Card(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Expanded(
                            child: Text(
                              _currentStageLabel,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          Text(
                            '$percent%',
                            style: TextStyle(
                              fontSize: 14,
                              fontWeight: FontWeight.w800,
                              color: cs.primary,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      ClipRRect(
                        borderRadius: BorderRadius.circular(8),
                        child: LinearProgressIndicator(
                          value: _globalProgress,
                          minHeight: 10,
                        ),
                      ),
                      if (_classifiedTotal > 0 || _manifestResultPath != null) ...[
                        const SizedBox(height: 6),
                        Text(
                          _manifestResultPath != null
                              ? 'Manifiesto: $_manifestResultPath'
                              : 'Progreso de archivos: $_classifiedProcessed / $_classifiedTotal',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            fontSize: 11.5,
                            color: Colors.white.withOpacity(0.72),
                          ),
                        ),
                        if (_activeMode == '' &&
                            (_ddsReconstructedCount > 0 || _audioConverted48kHzCount > 0))
                          Text(
                            'DDS reconstruidos: $_ddsReconstructedCount  |  WAV 48kHz: $_audioConverted48kHzCount',
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              fontSize: 11,
                              color: Colors.white.withOpacity(0.65),
                            ),
                          ),
                      ],
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 10),

              SizedBox(
                height: 114,
                child: ListView.separated(
                  scrollDirection: Axis.horizontal,
                  itemCount: ForensicClassifier.allCategories.length,
                  separatorBuilder: (_, __) => const SizedBox(width: 8),
                  itemBuilder: (context, index) {
                    final String category = ForensicClassifier.allCategories[index];
                    final int count = _categoryCounts[category] ?? 0;
                    return _CategoryCounterCard(
                      category: category,
                      count: count,
                    );
                  },
                ),
              ),
              const SizedBox(height: 10),

              SizedBox(
                height: 260,
                child: Container(
                  decoration: BoxDecoration(
                    color: const Color(0xFF07090C),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: Colors.white.withOpacity(0.10)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 12,
                          vertical: 8,
                        ),
                        decoration: BoxDecoration(
                          color: const Color(0xFF12161E),
                          borderRadius: const BorderRadius.vertical(
                            top: Radius.circular(12),
                          ),
                          border: Border(
                            bottom: BorderSide(
                              color: Colors.white.withOpacity(0.08),
                            ),
                          ),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Text(
                              'CONSOLA FORENSE EN TIEMPO REAL',
                              style: TextStyle(
                                fontSize: 11.5,
                                fontWeight: FontWeight.w700,
                                letterSpacing: 0.8,
                              ),
                            ),
                            Text(
                              '${_logs.length} líneas',
                              style: TextStyle(
                                fontSize: 11,
                                color: Colors.white.withOpacity(0.55),
                              ),
                            ),
                          ],
                        ),
                      ),
                      Expanded(
                        child: ListView.builder(
                          controller: _logScrollController,
                          padding: const EdgeInsets.all(10),
                          itemCount: _logs.length,
                          itemBuilder: (context, idx) {
                            final String line = _logs.elementAt(idx);
                            final Color lineColor = line.contains('[ERROR]') ||
                                    line.contains('[FATAL]') ||
                                    line.contains('-ERR]')
                                ? const Color(0xFFFF6B6B)
                                : line.contains('[WARN]') ||
                                        line.contains('[FFMPEG-SKIP]') ||
                                        line.contains('[CONV:SKIP]')
                                    ? const Color(0xFFFFD166)
                                    : line.contains('[FIN]') || line.contains('[CONV:FIN]')
                                        ? const Color(0xFF06D6A0)
                                        : const Color(0xFFD5DCE6);
                            return Text(
                              line,
                              style: TextStyle(
                                fontFamily: 'monospace',
                                fontSize: 11.5,
                                height: 1.35,
                                color: lineColor,
                              ),
                            );
                          },
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _InfoRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;

  const _InfoRow({
    required this.icon,
    required this.label,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Icon(icon, size: 16, color: Colors.white70),
        const SizedBox(width: 6),
        Text(
          label,
          style: const TextStyle(
            fontSize: 12.5,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(width: 6),
        Expanded(
          child: Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 12.5,
              color: Colors.white.withOpacity(0.82),
            ),
          ),
        ),
      ],
    );
  }
}

class _CategoryCounterCard extends StatelessWidget {
  final String category;
  final int count;

  const _CategoryCounterCard({
    required this.category,
    required this.count,
  });

  @override
  Widget build(BuildContext context) {
    final ColorScheme cs = Theme.of(context).colorScheme;
    final String shortTitle = category.substring(3).replaceAll('_', ' ');
    final String indexBadge = category.substring(0, 2);

    return Container(
      width: 146,
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: const Color(0xFF171A21),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(
          color: count > 0
              ? cs.primary.withOpacity(0.45)
              : Colors.white.withOpacity(0.08),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: cs.primary.withOpacity(0.18),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  indexBadge,
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w800,
                    color: cs.primary,
                  ),
                ),
              ),
              Icon(_iconForCategory(category), size: 18, color: Colors.white70),
            ],
          ),
          Text(
            count.toString(),
            style: const TextStyle(
              fontSize: 22,
              fontWeight: FontWeight.w800,
            ),
          ),
          Text(
            shortTitle,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 11,
              height: 1.15,
              color: Colors.white.withOpacity(0.75),
            ),
          ),
        ],
      ),
    );
  }

  IconData _iconForCategory(String cat) {
    switch (cat) {
      case ForensicClassifier.cat01Audio:
        return Icons.audiotrack_rounded;
      case ForensicClassifier.cat02Videos:
        return Icons.movie_creation_outlined;
      case ForensicClassifier.cat03Textures:
        return Icons.texture_rounded;
      case ForensicClassifier.cat04Models:
        return Icons.view_in_ar_rounded;
      case ForensicClassifier.cat05Skeletons:
        return Icons.accessibility_new_rounded;
      case ForensicClassifier.cat06Physics:
        return Icons.terrain_rounded;
      case ForensicClassifier.cat07Entities:
        return Icons.code_rounded;
      case ForensicClassifier.cat08Texts:
        return Icons.translate_rounded;
      case ForensicClassifier.cat09Engine:
      default:
        return Icons.memory_rounded;
    }
  }
}

/// Isolate secundario para Botón 1 (Extracción completa desde .ISO).
@pragma('vm:entry-point')
Future<void> _extractionIsolateEntry(Map<String, dynamic> args) async {
  final SendPort sendPort = args['sendPort'] as SendPort;
  final RootIsolateToken? rootToken = args['rootIsolateToken'] as RootIsolateToken?;
  final String nativeLibDir = args['nativeLibDir'] as String;
  final String isoPath = args['isoPath'] as String;
  final String outputDir = args['outputDir'] as String;
  final String tempDir = args['tempDir'] as String;

  if (rootToken != null) {
    BackgroundIsolateBinaryMessenger.ensureInitialized(rootToken);
  }

  void sendLog(String msg) {
    sendPort.send(<String, dynamic>{
      'type': 'log',
      'message': msg,
    });
  }

  void sendProgress(
    double value,
    String stage, {
    int? processed,
    int? total,
  }) {
    sendPort.send(<String, dynamic>{
      'type': 'progress',
      'value': value,
      'stage': stage,
      'processed': processed,
      'total': total,
    });
  }

  try {
    double isoProgress = 0.02;
    double cabProgress = 0.30;
    double packProgress = 0.50;

    final BinaryToolsService binaryTools = BinaryToolsService(
      nativeLibDir: nativeLibDir,
      onLog: (msg) {
        sendLog(msg);
        if (msg.startsWith('[7ZZ-ISO]') && isoProgress < 0.28) {
          isoProgress += 0.002;
          sendProgress(isoProgress, 'Paso 1/4: Extrayendo imagen .ISO con lib7zz.so...');
        } else if ((msg.startsWith('[UNSHIELD]') ||
                msg.startsWith('[7ZZ-MSI]') ||
                msg.startsWith('[7ZZ-CAB]')) &&
            cabProgress < 0.48) {
          cabProgress += 0.004;
          sendProgress(cabProgress, 'Paso 2/4: Extrayendo MSI / InstallShield CAB...');
        }
      },
    );

    sendProgress(0.02, 'Paso 1/4: Extrayendo imagen .ISO con lib7zz.so...');
    await binaryTools.extractIso(
      isoPath: isoPath,
      tempDir: tempDir,
    );
    sendProgress(0.30, 'Paso 1/4 completado. Analizando .msi y .cab...');

    sendProgress(0.30, 'Paso 2/4: Extrayendo MSI / InstallShield CAB...');
    await binaryTools.extractInstallersAndCabinets(
      rootDir: tempDir,
    );
    sendProgress(0.50, 'Paso 2/4 completado. Escaneando contenedores PCPACK...');

    final WosPcpackParser parser = WosPcpackParser(
      onLog: (msg) {
        sendLog(msg);
        if (msg.startsWith('[PACK]') && packProgress < 0.74) {
          packProgress += 0.005;
          sendProgress(packProgress, 'Paso 3/4: Desempaquetando contenedores PCPACK/APKF...');
        }
      },
    );
    final int unpackedCount = await parser.unpackAllContainers(
      rootDir: tempDir,
    );
    sendLog('[PACK] Total de sub-archivos desempaquetados: $unpackedCount');
    sendProgress(0.75, 'Paso 3/4 completado. Clasificando y convirtiendo assets...');

    final ForensicClassifier classifier = ForensicClassifier(
      binaryTools: binaryTools,
      onLog: (msg) {
        sendLog(msg);
      },
      onProgress: (processed, total) {
        final double ratio = total > 0 ? (processed / total) : 1.0;
        final double overall = 0.75 + (0.24 * ratio);
        sendProgress(
          overall,
          'Paso 4/4: Clasificando y transcodificando ($processed/$total)...',
          processed: processed,
          total: total,
        );
      },
    );

    final ClassificationSummary summary = await classifier.classifyAndFinalize(
      isoSourcePath: isoPath,
      tempDir: tempDir,
      outputDir: outputDir,
    );

    sendPort.send(<String, dynamic>{
      'type': 'done',
      'dumpRootDir': summary.dumpRootDir,
      'counts': summary.countsByCategory,
      'ddsCount': summary.ddsReconstructedCount,
      'audioCount': summary.audioConverted48kHzCount,
      'manifestPath': summary.manifestPath,
    });
  } catch (e, st) {
    sendLog('[ERROR] $e\n$st');
    sendPort.send(<String, dynamic>{
      'type': 'error',
      'error': e.toString(),
    });
  }
}

/// Isolate secundario para Botón 2 (Conversión por lotes a formatos Port).
@pragma('vm:entry-point')
Future<void> _conversionIsolateEntry(Map<String, dynamic> args) async {
  final SendPort sendPort = args['sendPort'] as SendPort;
  final RootIsolateToken? rootToken = args['rootIsolateToken'] as RootIsolateToken?;
  final String dumpDir = args['dumpDir'] as String;

  if (rootToken != null) {
    BackgroundIsolateBinaryMessenger.ensureInitialized(rootToken);
  }

  bool lastItemSkipped = false;

  String? mapStageToCategory(String stage) {
    if (stage.startsWith('01/09')) return PortBatchConverter.cat01Audio;
    if (stage.startsWith('02/09')) return PortBatchConverter.cat02Videos;
    if (stage.startsWith('03/09')) return PortBatchConverter.cat03Textures;
    if (stage.startsWith('04/09')) return PortBatchConverter.cat04Models;
    if (stage.startsWith('05/09')) return PortBatchConverter.cat05Skeletons;
    if (stage.startsWith('06/09')) return PortBatchConverter.cat06Physics;
    if (stage.startsWith('07/09')) return PortBatchConverter.cat07Entities;
    if (stage.startsWith('08/09')) return PortBatchConverter.cat08Texts;
    if (stage.startsWith('09/09')) return PortBatchConverter.cat09Engine;
    return null;
  }

  try {
    final PortBatchConverter converter = PortBatchConverter(
      onLog: (String msg) {
        if (msg.contains('[CONV:SKIP]')) {
          lastItemSkipped = true;
        }
        sendPort.send(<String, dynamic>{
          'type': 'log',
          'message': msg,
        });
      },
      onProgress: (int processed, int total, String stage) {
        final double progress = total > 0 ? (processed / total) : 1.0;
        final String? category = mapStageToCategory(stage);
        final bool convertedOk = !lastItemSkipped;
        lastItemSkipped = false;

        sendPort.send(<String, dynamic>{
          'type': 'conv_progress',
          'value': progress,
          'stage': stage,
          'processed': processed,
          'total': total,
          'category': category,
          'convertedOk': convertedOk,
        });
      },
    );

    final PortConversionSummary summary = await converter.convertDumpDirectory(
      inputDumpDir: dumpDir,
      rootIsolateToken: rootToken,
    );

    final Map<String, int> convertedCountsByCategory = <String, int>{
      for (final entry in summary.statsByCategory.entries)
        entry.key: entry.value.converted,
    };

    sendPort.send(<String, dynamic>{
      'type': 'conv_done',
      'outputConvertedDir': summary.outputConvertedDir,
      'manifestPath': summary.manifestPath,
      'totalAnalyzed': summary.totalAnalyzed,
      'totalConverted': summary.totalConverted,
      'totalSkipped': summary.totalSkipped,
      'counts': convertedCountsByCategory,
    });
  } catch (e, st) {
    sendPort.send(<String, dynamic>{
      'type': 'log',
      'message': '[ERROR] $e\n$st',
    });
    sendPort.send(<String, dynamic>{
      'type': 'error',
      'error': e.toString(),
    });
  }
}
