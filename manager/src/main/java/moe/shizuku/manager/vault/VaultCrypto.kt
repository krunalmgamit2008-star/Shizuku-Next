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

/** One encrypted file in the vault. Only the name and the size are kept in the clear. */
data class VaultItem(val id: String, val name: String, val size: Long)

/**
 * The vault: AES-256-GCM files whose key is derived from the master password with PBKDF2 and is
 * never written to disk. Without the password the files cannot be read, not by another app, not by
 * a backup, and not by whoever built this app.
 */
object VaultCrypto {
    private const val ITERATIONS = 120_000
    private const val KEY_BITS = 256
    private const val TAG_BITS = 128
    private const val IV_BYTES = 12
    private const val PREF = "vault"
    private const val KEY_SALT = "salt"
    private const val KEY_CHECK = "check"

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
        // slow derivation, and the AES key it produces is full 256-bit.
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }

    private fun verifier(key: SecretKey): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        return mac.doFinal("nal-vault-check".toByteArray()).toHex()
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

    fun items(context: Context): List<VaultItem> {
        val file = File(vaultDir(context), "index.json")
        if (!file.exists()) return emptyList()
        val array = JSONArray(file.readText())
        return (0 until array.length()).map { i ->
            val o = array.getJSONObject(i)
            VaultItem(o.getString("id"), o.getString("name"), o.getLong("size"))
        }
    }

    private fun saveItems(context: Context, items: List<VaultItem>) {
        val array = JSONArray()
        items.forEach {
            array.put(JSONObject().put("id", it.id).put("name", it.name).put("size", it.size))
        }
        File(vaultDir(context), "index.json").writeText(array.toString())
    }

    fun add(context: Context, key: SecretKey, name: String, source: InputStream): VaultItem {
        val id = UUID.randomUUID().toString()
        val target = File(vaultDir(context), "$id.enc")
        encrypt(key, source, target)
        val item = VaultItem(id, name, target.length())
        saveItems(context, items(context) + item)
        return item
    }

    fun remove(context: Context, id: String) {
        File(vaultDir(context), "$id.enc").delete()
        saveItems(context, items(context).filterNot { it.id == id })
    }

    fun fileFor(context: Context, id: String): File = File(vaultDir(context), "$id.enc")

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun String.hexToBytes(): ByteArray =
        ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
