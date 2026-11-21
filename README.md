# WoS Forensic Extractor (Android / Kotlin + Jetpack Compose)

Aplicación nativa Android en **Kotlin** y **Jetpack Compose (Material 3)** reescrita desde el proyecto original en Flutter (`Villagran12108/wos-forensic-extractor`).

## Funcionalidades portadas

1. **Extracción forense completa desde `.ISO` (Streaming 64-bit / SAF)**:
   - Lectura directa mediante Storage Access Framework (`OpenDocument` / `OpenDocumentTree`) y `FileChannel` sin requerir permisos amplios de almacenamiento.
   - Soporte para `lib7zz.so` / `libunshield.so` si están presentes en `nativeLibraryDir`, con motor nativo en Kotlin para **ISO-9660 / Joliet**, **Xbox 360 XDVDFS**, **MSI / CAB (MSCF + MSZIP)** e **InstallShield (`ISc(`)**.
   - Desempaquetado recursivo de contenedores `PCPACK` / `KCAPCP` / `APKF` / `PCSTOC` (tabla TOC + descompresión `zlib`/deflate en streaming de 64 KB + tallado de flujos `zlib`).
   - Clasificación automática por Magic Bytes y extensión en las 9 categorías de `WoS_Full_Port_Dump` + generación de `MANIFIESTO_EXTRACCION.json`.
   - Reconstrucción de cabeceras DDS de 128 bytes para texturas `.tex` (`DXT1`/`DXT5`) y conversión de audio decodificable a WAV PCM 48kHz (`WAV_48kHz_PS4_Ready`) mediante `MediaExtractor` y `MediaCodec`.

2. **Conversión por lotes para Port (`WoS_Port_Ready_Converted`)**:
   - **01 Audio**: Copia de WAV 48kHz válidos y conversión de audios compatibles a WAV PCM 48kHz 16-bit estéreo.
   - **02 Videos**: Copia de MP4 y remuxing compatible (conservando `.bik` propietario cuando no es decodificable por `MediaExtractor`).
   - **03 Texturas**: Reconstrucción de cabeceras DDS (`DXT1`, `DXT3`, `DXT5`, `ATI2`, `RGBA`).
   - **04 Modelos 3D y 06 Física/Niveles**: Escáner binario de vertex buffers (`float32`, strides 12–48B, UVs) e index buffers (`uint16`) hacia Wavefront `.obj`.
   - **05 Esqueletos y Animaciones**: Extracción de huesos, jerarquía `int16` y cuaterniones normalizados a `.json`.
   - **07 Entidades y 08 Textos/Idiomas**: Extracción de cadenas ASCII/UTF-8 y UTF-16LE con detección de idioma y parámetros clave-valor a `.json` y `.csv`.
   - **09 Motor, Shaders y Binarios**: Análisis de cabeceras PE32/PE32+ (`.exe`/`.dll`), Xbox 360 `XEX2`, shaders (`PCVS`/`PCPS`/`DXBC`) y cadenas técnicas a `_port_analysis.json` y `_port_analysis.txt`.

3. **Servicio en primer plano y consola en tiempo real**:
   - `ForensicForegroundService` (`foregroundServiceType="dataSync"`) con `WakeLock` y notificaciones de progreso.
   - Consola forense en tiempo real con desplazamiento automático y tarjetas adaptativas para móviles y pantallas grandes.
