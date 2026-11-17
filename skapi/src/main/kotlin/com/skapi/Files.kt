package com.skapi

import java.io.File
import java.io.InputStream
import java.net.URLConnection

/**
 * A file to attach to a record (postRecord, uploadFiles) or to send in a multipart forwardRequest.
 *
 * name: the field name the file is listed under in record.bin.
 * filename: the file's name. contentType: its media type; guessed from the filename when left out.
 */
public class FileUpload private constructor(
    public val name: String,
    public val filename: String,
    private val source: () -> ByteArray,
    public val contentType: String?,
) {
    /** The file's bytes (read when the upload starts). */
    public fun readBytes(): ByteArray = source()

    public companion object {
        /** A file on disk. filename defaults to the file's own name. */
        @JvmStatic
        public fun fromFile(name: String, file: File, filename: String? = null, contentType: String? = null): FileUpload =
            FileUpload(name, filename ?: file.name, { file.readBytes() }, contentType)

        /** Bytes in memory. */
        @JvmStatic
        public fun fromBytes(name: String, bytes: ByteArray, filename: String, contentType: String? = null): FileUpload =
            FileUpload(name, filename, { bytes }, contentType)

        /** A stream, read to its end (and closed) when the upload starts. */
        @JvmStatic
        public fun fromStream(name: String, stream: InputStream, filename: String, contentType: String? = null): FileUpload =
            FileUpload(name, filename, { stream.use { it.readBytes() } }, contentType)

        /** Text, uploaded as UTF-8. */
        @JvmStatic
        public fun fromText(name: String, text: String, filename: String, contentType: String? = null): FileUpload =
            FileUpload(name, filename, { text.toByteArray(Charsets.UTF_8) }, contentType)
    }
}

/** A file read and checked, ready to upload. */
internal class PreparedFile(
    val name: String,
    val filename: String,
    val content: ByteArray,
    val contentType: String?,
    /** already sealed by a revoke, under the key its roll is about to install */
    val presealed: Boolean = false,
) {
    fun copy(name: String = this.name, filename: String = this.filename, content: ByteArray = this.content,
             contentType: String? = this.contentType, presealed: Boolean = this.presealed): PreparedFile =
        PreparedFile(name, filename, content, contentType, presealed)
}

/** What an upload did: as skapi-py's {"completed", "failed", "errors", "bin_endpoints", "landed"}. */
internal class UploadResult(
    val completed: MutableList<String> = mutableListOf(),
    val failed: MutableList<String> = mutableListOf(),
    val errors: MutableList<UploadError> = mutableListOf(),
    /** one per file, "" for a file that got no upload permit */
    val binEndpoints: MutableList<String> = mutableListOf(),
    /** the CDN urls of the files that did upload */
    val landed: MutableList<String> = mutableListOf(),
) {
    fun toMap(): JMap = jmap(
        "completed" to completed.toMutableList<Any?>(),
        "failed" to failed.toMutableList<Any?>(),
        "errors" to errors.map { jmap("file" to it.file, "name" to it.name, "code" to it.error.code, "message" to it.error.message) }.toMutableList<Any?>(),
        "bin_endpoints" to binEndpoints.toMutableList<Any?>(),
    )
}

internal class UploadError(val file: String, val name: String, val error: SkapiException)

/** The media type of a file name, or null. */
internal fun guessContentType(filename: String): String? {
    val lower = filename.lowercase()
    val ext = lower.substringAfterLast('.', "")
    EXTRA_TYPES[ext]?.let { return it }
    return try { URLConnection.guessContentTypeFromName(filename) } catch (e: Exception) { null }
}

private val EXTRA_TYPES = mapOf(
    "json" to "application/json", "pdf" to "application/pdf", "txt" to "text/plain", "csv" to "text/csv",
    "html" to "text/html", "htm" to "text/html", "css" to "text/css", "js" to "text/javascript", "mjs" to "text/javascript",
    "png" to "image/png", "jpg" to "image/jpeg", "jpeg" to "image/jpeg", "gif" to "image/gif", "webp" to "image/webp",
    "svg" to "image/svg+xml", "ico" to "image/vnd.microsoft.icon", "heic" to "image/heic", "avif" to "image/avif",
    "mp4" to "video/mp4", "webm" to "video/webm", "mov" to "video/quicktime", "mp3" to "audio/mpeg", "wav" to "audio/x-wav",
    "m4a" to "audio/mp4", "ogg" to "audio/ogg", "zip" to "application/zip", "gz" to "application/gzip",
    "xml" to "text/xml", "md" to "text/markdown", "xlsx" to "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "docx" to "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pptx" to "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "xls" to "application/vnd.ms-excel", "doc" to "application/msword", "ppt" to "application/vnd.ms-powerpoint",
    "bin" to "application/octet-stream",
)

/** Files read and checked before anything is created, as skapi-py's _prepare_files. */
internal fun prepareFiles(files: List<FileUpload>?): List<PreparedFile> {
    val out = mutableListOf<PreparedFile>()
    for ((i, f) in (files ?: emptyList()).withIndex()) {
        if (f.name.isEmpty()) throw perr("\"files[$i]\" should have a field name.")
        val content = try {
            f.readBytes()
        } catch (e: java.io.IOException) {
            throw SkapiException("\"files[$i].file\" cannot be read: ${e.message ?: e}.", "INVALID_PARAMETER", e)
        }
        if (f.filename.isEmpty()) throw perr("\"files[$i].filename\" is required for bytes.")
        out.add(PreparedFile(f.name, f.filename, content, f.contentType ?: guessContentType(f.filename)))
    }
    return out
}
