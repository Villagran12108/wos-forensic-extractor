package com.example.wos_forensic_extractor

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    companion object {
        private const val CHANNEL = "wos_forensic/native"
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "getNativeLibDir" -> {
                        val libDir = applicationInfo.nativeLibraryDir
                        if (libDir.isNullOrEmpty()) {
                            result.error(
                                "NATIVE_LIB_DIR_UNAVAILABLE",
                                "No se pudo obtener applicationInfo.nativeLibraryDir",
                                null
                            )
                        } else {
                            result.success(libDir)
                        }
                    }
                    else -> result.notImplemented()
                }
            }
    }
}
