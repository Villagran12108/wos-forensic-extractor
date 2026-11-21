package com.example.wos_forensic_extractor.data.storage

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.channels.FileChannel

data class PickedIsoInfo(
    val uriString: String,
    val displayName: String,
    val sizeBytes: Long
) {
    val sizeGb: Double get() = sizeBytes.toDouble() / (1024.0 * 1024.0 * 1024.0)
}

data class PickedTreeInfo(
    val uriString: String,
    val displayPath: String
)

class SafStorageHelper(private val context: Context) {
    private val resolver: ContentResolver = context.contentResolver

    fun queryIsoInfo(uri: Uri): PickedIsoInfo? {
        if (uri.scheme == "file") {
            val path = uri.path ?: return null
            val f = File(path)
            if (!f.exists()) return null
            return PickedIsoInfo(uri.toString(), f.name, f.length())
        }

        var displayName = "archivo.iso"
        var sizeBytes = -1L

        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (nameIdx >= 0 && !cursor.isNull(nameIdx)) {
                    displayName = cursor.getString(nameIdx)
                }
                if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) {
                    sizeBytes = cursor.getLong(sizeIdx)
                }
            }
        }

        if (sizeBytes < 0L) {
            resolver.openFileDescriptor(uri, "r")?.use { pfd ->
                sizeBytes = pfd.statSize
            }
        }

        if (sizeBytes <= 0L) return null
        return PickedIsoInfo(
            uriString = uri.toString(),
            displayName = displayName,
            sizeBytes = sizeBytes
        )
    }

    fun describeTreeUri(uri: Uri): PickedTreeInfo {
        if (uri.scheme == "file") {
            val path = uri.path ?: uri.toString()
            return PickedTreeInfo(uri.toString(), path)
        }
        val docId = runCatching { DocumentsContract.getTreeDocumentId(uri) }.getOrNull()
        val display = if (docId != null) {
            if (docId.startsWith("primary:")) {
                val rel = docId.removePrefix("primary:").trimStart('/')
                if (rel.isEmpty()) {
                    Environment.getExternalStorageDirectory().absolutePath
                } else {
                    "${Environment.getExternalStorageDirectory().absolutePath}/$rel"
                }
            } else {
                docId
            }
        } else {
            uri.lastPathSegment ?: uri.toString()
        }
        return PickedTreeInfo(uriString = uri.toString(), displayPath = display)
    }

    fun openIsoReadChannel(uriOrPath: String): Pair<ParcelFileDescriptor?, FileChannel> {
        val uri = Uri.parse(uriOrPath)
        if (uri.scheme == "content") {
            val pfd = resolver.openFileDescriptor(uri, "r")
                ?: throw IllegalStateException("No se pudo abrir descriptor de lectura para la ISO: $uriOrPath")
            val channel = FileInputStream(pfd.fileDescriptor).channel
            return pfd to channel
        }
        val file = File(uri.path ?: uriOrPath)
        if (!file.exists()) {
            throw IllegalStateException("El archivo ISO no existe: ${file.absolutePath}")
        }
        val channel = FileInputStream(file).channel
        return null to channel
    }

    fun resolveDirectWritableDirOrNull(uriOrPath: String): File? {
        val uri = Uri.parse(uriOrPath)
        if (uri.scheme == "file" || uri.scheme == null) {
            val f = File(uri.path ?: uriOrPath)
            if ((f.exists() && f.canWrite()) || f.mkdirs()) {
                return f
            }
            return null
        }
        val docId = runCatching { DocumentsContract.getTreeDocumentId(uri) }.getOrNull() ?: return null
        if (docId.startsWith("primary:")) {
            val rel = docId.removePrefix("primary:").trimStart('/')
            val base = Environment.getExternalStorageDirectory()
            val target = if (rel.isEmpty()) base else File(base, rel)
            if (target.exists() && target.isDirectory && target.canWrite()) {
                val probe = File(target, ".wos_write_probe_${System.currentTimeMillis()}")
                val canActuallyWrite = runCatching {
                    probe.createNewFile().also { created -> if (created) probe.delete() }
                }.getOrDefault(false)
                if (canActuallyWrite) return target
            }
        }
        return null
    }

    /**
     * Copies all files from a local staging directory into a SAF DocumentTree URI,
     * creating subdirectories recursively as needed.
     */
    fun syncLocalFolderToSafTree(
        localRootDir: File,
        treeUri: Uri,
        targetFolderName: String,
        onProgress: ((copied: Int, total: Int) -> Unit)? = null
    ): String {
        val rootDocId = DocumentsContract.getTreeDocumentId(treeUri)
        val rootDocUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, rootDocId)
        val targetRootUri = findOrCreateSubdir(treeUri, rootDocUri, targetFolderName)

        val allFiles = localRootDir.walkTopDown().filter { it.isFile }.toList()
        val total = allFiles.size
        val dirCache = HashMap<String, Uri>()
        dirCache[""] = targetRootUri

        val buffer = ByteArray(65536)
        allFiles.forEachIndexed { idx, file ->
            val relParent = file.parentFile?.relativeTo(localRootDir)?.path?.replace('\\', '/') ?: ""
            val parentDocUri = if (relParent.isEmpty() || relParent == ".") {
                targetRootUri
            } else {
                ensureNestedSafDirs(treeUri, targetRootUri, relParent, dirCache)
            }

            val mime = guessMimeType(file.name)
            val existingChild = findChildUri(treeUri, parentDocUri, file.name)
            if (existingChild != null) {
                runCatching { DocumentsContract.deleteDocument(resolver, existingChild) }
            }
            val createdUri = DocumentsContract.createDocument(resolver, parentDocUri, mime, file.name)
                ?: throw IllegalStateException("No se pudo crear archivo SAF: ${file.name}")

            resolver.openOutputStream(createdUri, "w")?.use { out ->
                FileInputStream(file).use { input ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        out.write(buffer, 0, read)
                    }
                    out.flush()
                }
            }
            onProgress?.invoke(idx + 1, total)
        }

        val treeDisplay = describeTreeUri(treeUri).displayPath
        return "$treeDisplay/$targetFolderName"
    }

    /**
     * Copies a SAF DocumentTree into a local staging folder so random-access binary parsers
     * (PE32, XEX2, OBJ vertex/index scanners, MediaExtractor) can process files at native speed.
     */
    fun stageSafTreeToLocal(
        treeUri: Uri,
        localDestDir: File,
        onLog: ((String) -> Unit)? = null
    ): File {
        if (!localDestDir.exists()) localDestDir.mkdirs()
        val rootDocId = DocumentsContract.getTreeDocumentId(treeUri)
        val rootDocUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, rootDocId)
        copySafFolderRecursive(treeUri, rootDocUri, localDestDir, onLog)
        return localDestDir
    }

    private fun copySafFolderRecursive(
        treeUri: Uri,
        parentDocUri: Uri,
        localDir: File,
        onLog: ((String) -> Unit)?
    ) {
        if (!localDir.exists()) localDir.mkdirs()
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(
            treeUri,
            DocumentsContract.getDocumentId(parentDocUri)
        )
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE
        )
        val buffer = ByteArray(65536)
        resolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
            val idCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val mimeCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
            while (cursor.moveToNext()) {
                val docId = cursor.getString(idCol)
                val name = cursor.getString(nameCol) ?: continue
                val mime = cursor.getString(mimeCol) ?: ""
                val childUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                    copySafFolderRecursive(treeUri, childUri, File(localDir, name), onLog)
                } else {
                    val outFile = File(localDir, name)
                    resolver.openInputStream(childUri)?.use { input ->
                        FileOutputStream(outFile).use { out ->
                            while (true) {
                                val r = input.read(buffer)
                                if (r <= 0) break
                                out.write(buffer, 0, r)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun ensureNestedSafDirs(
        treeUri: Uri,
        rootUri: Uri,
        relPath: String,
        cache: MutableMap<String, Uri>
    ): Uri {
        cache[relPath]?.let { return it }
        val parts = relPath.split('/').filter { it.isNotBlank() }
        var currentUri = rootUri
        var currentPath = ""
        for (part in parts) {
            currentPath = if (currentPath.isEmpty()) part else "$currentPath/$part"
            val cached = cache[currentPath]
            if (cached != null) {
                currentUri = cached
            } else {
                val nextUri = findOrCreateSubdir(treeUri, currentUri, part)
                cache[currentPath] = nextUri
                currentUri = nextUri
            }
        }
        return currentUri
    }

    private fun findOrCreateSubdir(treeUri: Uri, parentDocUri: Uri, dirName: String): Uri {
        val existing = findChildUri(treeUri, parentDocUri, dirName)
        if (existing != null) return existing
        return DocumentsContract.createDocument(
            resolver,
            parentDocUri,
            DocumentsContract.Document.MIME_TYPE_DIR,
            dirName
        ) ?: throw IllegalStateException("No se pudo crear subcarpeta SAF: $dirName")
    }

    private fun findChildUri(treeUri: Uri, parentDocUri: Uri, displayName: String): Uri? {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(
            treeUri,
            DocumentsContract.getDocumentId(parentDocUri)
        )
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME
        )
        resolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
            val idCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            while (cursor.moveToNext()) {
                if (cursor.getString(nameCol) == displayName) {
                    return DocumentsContract.buildDocumentUriUsingTree(treeUri, cursor.getString(idCol))
                }
            }
        }
        return null
    }

    private fun guessMimeType(fileName: String): String {
        val lower = fileName.lowercase()
        return when {
            lower.endsWith(".json") -> "application/json"
            lower.endsWith(".csv") -> "text/csv"
            lower.endsWith(".txt") -> "text/plain"
            lower.endsWith(".wav") -> "audio/wav"
            lower.endsWith(".mp4") -> "video/mp4"
            lower.endsWith(".png") -> "image/png"
            lower.endsWith(".jpg") || lower.endsWith(".jpeg") -> "image/jpeg"
            else -> "application/octet-stream"
        }
    }
}
