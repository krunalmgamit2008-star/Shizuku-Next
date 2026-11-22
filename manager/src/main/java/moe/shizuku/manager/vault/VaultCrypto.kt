package moe.shizuku.manager.vault

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** One encrypted file in the vault. Nothing about it is readable without the master password. */
data class VaultItem(
    val id: String,
    val name: String,
    val size: Long,
    val folder: String
)

/**
 * The vault: AES-256-GCM files whose key is derived from the master password with PBKDF2 and is
 * never written to disk. The index - the file names, their sizes and their folders - is encrypted
 * with the same key, so the vault's contents cannot be listed without the password either.
 */
object VaultCrypto {
    private const val ITERATIONS = 120_000
    private const val KEY_BITS = 256
    private const val TAG_BITS = 128
    private const val IV_BYTES = 12
    private const val PREF = "vault"
    private const val KEY_SALT = "salt"
    private const val KEY_CHECK = "check"
    private const val INDEX = "index.enc"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun vaultDir(context: Context): File = File(context.filesDir, "vault").apply { mkdirs() }

    fun isConfigured(context: Context): Boolean = prefs(context).contains(KEY_SALT)

    /** Sets the master password. The key itself is never stored, only a salt and a verifier. */
    fun createMasterPassword(context: Context, password: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val key = derive(password, salt)
        prefs(context).edit()
            .putString(KEY_SALT, salt.toHex())
            .putString(KEY_CHECK, verifier(key))
            .apply()
    }

    /** The derived key, or null when the password is wrong. */
    fun unlock(context: Context, password: String): SecretKey? {
        val salt = prefs(context).getString(KEY_SALT, null)?.hexToBytes() ?: return null
        val check = prefs(context).getString(KEY_CHECK, null) ?: return null
        val key = derive(password, salt)
        return if (verifier(key) == check) key else null
    }

    private fun derive(password: String, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_BITS)
        // The SHA-1 variant is the one available from API 24; with 120k iterations it is still a
        // slow derivation, and the AES key it produces is a full 256-bit one.
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }

    private fun verifier(key: SecretKey): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        return mac.doFinal("nal-vault-check".toByteArray()).toHex()
    }

    private fun sealBytes(key: SecretKey, plain: ByteArray): ByteArray {
        val iv = ByteArray(IV_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        return iv + cipher.doFinal(plain)
    }

    private fun openBytes(key: SecretKey, sealed: ByteArray): ByteArray {
        if (sealed.size <= IV_BYTES) throw IllegalStateException("Vault index is corrupt")
        val iv = sealed.copyOfRange(0, IV_BYTES)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES)
    }

    fun encrypt(key: SecretKey, source: InputStream, target: File) {
        val iv = ByteArray(IV_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        target.outputStream().use { raw ->
            raw.write(iv)
            CipherOutputStream(raw, cipher).use { out -> source.copyTo(out) }
        }
    }

    fun decrypt(key: SecretKey, source: File, target: OutputStream) {
        source.inputStream().use { raw ->
            val iv = ByteArray(IV_BYTES)
            var read = 0
            while (read < IV_BYTES) {
                val n = raw.read(iv, read, IV_BYTES - read)
                if (n <= 0) throw IllegalStateException("Vault file is corrupt")
                read += n
            }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            CipherInputStream(raw, cipher).use { input -> input.copyTo(target) }
        }
    }

    fun items(context: Context, key: SecretKey): List<VaultItem> {
        val file = File(vaultDir(context), INDEX)
        if (!file.exists()) return emptyList()
        val array = JSONArray(String(openBytes(key, file.readBytes()), Charsets.UTF_8))
        return (0 until array.length()).map { i ->
            val o = array.getJSONObject(i)
            VaultItem(
                id = o.getString("id"),
                name = o.getString("name"),
                size = o.getLong("size"),
                folder = o.optString("folder", "")
            )
        }
    }

    private fun saveItems(context: Context, key: SecretKey, items: List<VaultItem>) {
        val array = JSONArray()
        items.forEach {
            array.put(
                JSONObject()
                    .put("id", it.id)
                    .put("name", it.name)
                    .put("size", it.size)
                    .put("folder", it.folder)
            )
        }
        File(vaultDir(context), INDEX).writeBytes(
            sealBytes(key, array.toString().toByteArray(Charsets.UTF_8))
        )
    }

    fun add(
        context: Context,
        key: SecretKey,
        name: String,
        folder: String,
        source: InputStream
    ): VaultItem {
        val id = UUID.randomUUID().toString()
        val target = File(vaultDir(context), "$id.enc")
        encrypt(key, source, target)
        val item = VaultItem(id, name, target.length(), folder)
        saveItems(context, key, items(context, key) + item)
        return item
    }

    fun remove(context: Context, key: SecretKey, id: String) {
        File(vaultDir(context), "$id.enc").delete()
        saveItems(context, key, items(context, key).filterNot { it.id == id })
    }

    fun fileFor(context: Context, id: String): File = File(vaultDir(context), "$id.enc")

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun String.hexToBytes(): ByteArray =
        ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
