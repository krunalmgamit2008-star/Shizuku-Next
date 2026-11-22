package moe.shizuku.manager.ui.screen

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import moe.shizuku.manager.vault.VaultCrypto
import moe.shizuku.manager.vault.VaultItem
import java.io.File
import javax.crypto.SecretKey

/**
 * The vault: a master password unlocks a list of files that are stored AES-256 encrypted. Nothing
 * leaves the device, and the key is derived from the password on unlock, so the files cannot be
 * read without it - not by another app, not from a backup.
 */
@Composable
fun VaultScreen(bottomPadding: Dp, onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var configured by remember { mutableStateOf(VaultCrypto.isConfigured(context)) }
    var key by remember { mutableStateOf<SecretKey?>(null) }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var entries by remember { mutableStateOf<List<VaultItem>>(emptyList()) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val current = key
        if (uri == null || current == null) return@rememberLauncherForActivityResult
        busy = true
        error = null
        scope.launch {
            val failure = withContext(Dispatchers.IO) {
                runCatching {
                    val name = displayName(context, uri) ?: "file"
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        VaultCrypto.add(context, current, name, input)
                    } ?: throw IllegalStateException("The file could not be opened")
                }.exceptionOrNull()
            }
            if (failure != null) error = failure.message ?: "Could not add the file"
            entries = withContext(Dispatchers.IO) { VaultCrypto.items(context) }
            busy = false
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(bottom = bottomPadding)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 8.dp, end = 16.dp, top = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
            Text("Vault", style = MaterialTheme.typography.headlineSmall)
        }

        Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp)) {
            when {
                !configured -> {
                    Text(
                        "Set a master password. Files are encrypted with AES-256 and the key comes " +
                            "from this password, so keep it safe - without it the files cannot be " +
                            "opened again.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(Modifier.height(16.dp))
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("Master password") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = confirm,
                        onValueChange = { confirm = it },
                        label = { Text("Repeat password") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(16.dp))
                    Button(
                        onClick = {
                            error = when {
                                password.length < 6 -> "Use at least 6 characters"
                                password != confirm -> "The two passwords do not match"
                                else -> null
                            }
                            if (error == null) {
                                VaultCrypto.createMasterPassword(context, password)
                                configured = true
                                password = ""
                                confirm = ""
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Create vault") }
                }

                key == null -> {
                    Text(
                        "Unlock the vault with your master password.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(Modifier.height(16.dp))
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("Master password") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(16.dp))
                    Button(
                        onClick = {
                            busy = true
                            scope.launch {
                                val unlocked = withContext(Dispatchers.Default) {
                                    VaultCrypto.unlock(context, password)
                                }
                                busy = false
                                if (unlocked == null) {
                                    error = "Wrong master password"
                                } else {
                                    key = unlocked
                                    error = null
                                    password = ""
                                    entries = withContext(Dispatchers.IO) {
                                        VaultCrypto.items(context)
                                    }
                                }
                            }
                        },
                        enabled = !busy && password.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth()
                    ) { Text(if (busy) "Checking..." else "Unlock") }
                }

                else -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            if (entries.isEmpty()) "No files in the vault yet"
                            else "${entries.size} file(s), all encrypted",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Button(onClick = { picker.launch(arrayOf("*/*")) }, enabled = !busy) {
                            Icon(Icons.Filled.Add, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text("Add")
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(entries, key = { it.id }) { item ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.fillMaxWidth(0.72f)) {
                                    Text(item.name, style = MaterialTheme.typography.bodyLarge)
                                    Text(
                                        readableSize(item.size),
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                                Button(
                                    onClick = {
                                        val current = key ?: return@Button
                                        busy = true
                                        scope.launch {
                                            val failure = withContext(Dispatchers.IO) {
                                                runCatching { openItem(context, current, item) }
                                                    .exceptionOrNull()
                                            }
                                            if (failure != null) {
                                                error = failure.message ?: "Could not open the file"
                                            }
                                            busy = false
                                        }
                                    },
                                    enabled = !busy
                                ) { Text("Open") }
                                IconButton(
                                    onClick = {
                                        scope.launch {
                                            withContext(Dispatchers.IO) {
                                                VaultCrypto.remove(context, item.id)
                                            }
                                            entries = VaultCrypto.items(context)
                                        }
                                    }
                                ) {
                                    Icon(Icons.Filled.Delete, contentDescription = "Delete")
                                }
                            }
                        }
                    }
                }
            }

            error?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

private fun displayName(context: Context, uri: Uri): String? =
    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        ?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }

private fun readableSize(bytes: Long): String = when {
    bytes >= 1024L * 1024L -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
    bytes >= 1024L -> "%.0f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

private fun mimeOf(name: String): String {
    val extension = name.substringAfterLast('.', "").lowercase()
    return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension) ?: "*/*"
}

private fun openItem(context: Context, key: SecretKey, item: VaultItem) {
    val dir = File(context.cacheDir, "vault").apply { mkdirs() }
    val out = File(dir, item.name)
    out.outputStream().use { target ->
        VaultCrypto.decrypt(key, VaultCrypto.fileFor(context, item.id), target)
    }
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", out)
    val intent = Intent(Intent.ACTION_VIEW)
        .setDataAndType(uri, mimeOf(item.name))
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(intent)
}
