package moe.shizuku.manager.ui.screen

import android.app.Activity
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.content.ContextWrapper
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.view.WindowManager
import android.webkit.MimeTypeMap
import android.widget.VideoView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import moe.shizuku.manager.vault.VaultContents
import moe.shizuku.manager.vault.VaultCrypto
import moe.shizuku.manager.vault.VaultItem
import java.io.File
import javax.crypto.SecretKey

/**
 * The vault: a master password unlocks files stored AES-256 encrypted, with the index encrypted
 * too so even the names need the password. The key is derived on unlock and dropped when the app
 * leaves the foreground, so coming back asks for the password again.
 */
@Composable
fun VaultScreen(bottomPadding: Dp, onBack: () -> Unit = {}) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val lifecycleOwner = LocalLifecycleOwner.current

    var configured by remember { mutableStateOf(VaultCrypto.isConfigured(context)) }
    var key by remember { mutableStateOf<SecretKey?>(null) }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var contents by remember { mutableStateOf(VaultContents()) }
    var folder by remember { mutableStateOf("") }
    var showNewFolder by remember { mutableStateOf(false) }
    // True while the file picker or another app is on screen: the app goes to the background for
    // that, and locking then would drop the key the picker is about to need.
    var external by remember { mutableStateOf(false) }
    var preview by remember { mutableStateOf<Bitmap?>(null) }
    var playing by remember { mutableStateOf<File?>(null) }
    var folderName by remember { mutableStateOf("") }

    // No screenshots and no screen recording while the vault is on screen: the window is marked
    // secure for as long as this screen is composed, and the recents preview shows nothing.
    val view = LocalView.current
    DisposableEffect(view) {
        val window = view.context.findActivity()?.window
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }

    // Auto-lock: leaving the foreground drops the derived key, so the vault has to be unlocked
    // again rather than staying open in the background.
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && !external) {
                key = null
                password = ""
                confirm = ""
                contents = VaultContents()
                folder = ""
                status = null
                error = null
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    fun refresh(current: SecretKey) {
        scope.launch {
            contents = withContext(Dispatchers.IO) { VaultCrypto.contents(context, current) }
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val current = key
        external = false
        if (uri == null) {
            status = "No file was chosen"
            return@rememberLauncherForActivityResult
        }
        if (current == null) {
            error = "The vault locked itself, unlock it again"
            return@rememberLauncherForActivityResult
        }
        busy = true
        error = null
        status = null
        val target = folder
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val name = displayName(context, uri) ?: "file"
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        VaultCrypto.add(context, current, name, target, input)
                    } ?: throw IllegalStateException("The file could not be opened")
                }
            }
            busy = false
            result.onSuccess { item ->
                status = "${item.name} added to the vault"
                contents = withContext(Dispatchers.IO) { VaultCrypto.contents(context, current) }
            }.onFailure {
                error = it.message ?: it.javaClass.simpleName
            }
        }
    }

    val visible = if (folder.isEmpty()) {
        contents.items
    } else {
        contents.items.filter { it.folder == folder }
    }

    Box(modifier = Modifier.fillMaxSize()) {
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
                    !configured -> SetupVault(
                        password = password,
                        confirm = confirm,
                        onPassword = { password = it },
                        onConfirm = { confirm = it },
                        onCreate = {
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
                                status = "Vault created. Set folders and add files."
                            }
                        }
                    )

                    key == null -> UnlockVault(
                        password = password,
                        busy = busy,
                        onPassword = { password = it },
                        onUnlock = {
                            busy = true
                            error = null
                            scope.launch {
                                val unlocked = withContext(Dispatchers.Default) {
                                    VaultCrypto.unlock(context, password)
                                }
                                busy = false
                                if (unlocked == null) {
                                    error = "Wrong master password"
                                } else {
                                    key = unlocked
                                    password = ""
                                    contents = withContext(Dispatchers.IO) {
                                        VaultCrypto.contents(context, unlocked)
                                    }
                                }
                            }
                        }
                    )

                    else -> {
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            item {
                                FilterChip(
                                    selected = folder.isEmpty(),
                                    onClick = { folder = "" },
                                    label = { Text("All") }
                                )
                            }
                            items(contents.folders, key = { it }) { name ->
                                FilterChip(
                                    selected = folder == name,
                                    onClick = { folder = name },
                                    label = { Text(name) }
                                )
                            }
                            item {
                                FilterChip(
                                    selected = false,
                                    onClick = { showNewFolder = true },
                                    label = { Text("+ Folder") },
                                    leadingIcon = {
                                        Icon(
                                            Icons.Filled.CreateNewFolder,
                                            contentDescription = null
                                        )
                                    }
                                )
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                when {
                                    visible.isEmpty() -> "Nothing in this folder yet"
                                    else -> "${visible.size} file(s), AES-256 encrypted"
                                },
                                style = MaterialTheme.typography.bodySmall
                            )
                            Button(
                                onClick = { external = true; picker.launch(arrayOf("*/*")) },
                                enabled = !busy
                            ) {
                                Icon(Icons.Filled.Add, contentDescription = null)
                                Spacer(Modifier.width(6.dp))
                                Text(if (busy) "Adding..." else "Add file")
                            }
                        }
                        Spacer(Modifier.height(4.dp))
                        LazyColumn(modifier = Modifier.fillMaxSize()) {
                            items(visible, key = { it.id }) { item ->
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.fillMaxWidth(0.62f)) {
                                        Text(item.name, style = MaterialTheme.typography.bodyLarge)
                                        Text(
                                            if (item.folder.isEmpty()) readableSize(item.size)
                                            else "${item.folder} · ${readableSize(item.size)}",
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                    }
                                    Button(
                                        onClick = {
                                            val current = key ?: return@Button
                                            busy = true
                                            scope.launch {
                                                if (isMedia(item.name)) {
                                                    val file = withContext(Dispatchers.IO) {
                                                        runCatching {
                                                            decryptToCache(context, current, item)
                                                        }.getOrNull()
                                                    }
                                                    if (file == null) {
                                                        error = "This file could not be opened"
                                                    } else {
                                                        playing = file
                                                    }
                                                } else if (isImage(item.name)) {
                                                    // Images are shown inside the vault: handing them
                                                    // to a gallery would leave a decrypted copy in
                                                    // another app's hands.
                                                    val bitmap = withContext(Dispatchers.IO) {
                                                        runCatching {
                                                            BitmapFactory.decodeFile(
                                                                decryptToCache(context, current, item)
                                                                    .absolutePath
                                                            )
                                                        }.getOrNull()
                                                    }
                                                    if (bitmap == null) {
                                                        error = "This image could not be shown"
                                                    } else {
                                                        preview = bitmap
                                                    }
                                                } else {
                                                    external = true
                                                    val failure = withContext(Dispatchers.IO) {
                                                        runCatching { openItem(context, current, item) }
                                                            .exceptionOrNull()
                                                    }
                                                    external = false
                                                    if (failure != null) {
                                                        error = failure.message
                                                            ?: "Could not open the file"
                                                    }
                                                }
                                                busy = false
                                            }
                                        },
                                        enabled = !busy
                                    ) { Text("Open") }
                                    IconButton(
                                        onClick = {
                                            val current = key ?: return@IconButton
                                            scope.launch {
                                                withContext(Dispatchers.IO) {
                                                    VaultCrypto.remove(context, current, item.id)
                                                }
                                                contents = VaultCrypto.contents(context, current)
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

                status?.let {
                    Spacer(Modifier.height(12.dp))
                    Text(it, style = MaterialTheme.typography.bodySmall)
                }
                error?.let {
                    Spacer(Modifier.height(12.dp))
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
            }
        }

        playing?.let { file ->
            Box(modifier = Modifier.fillMaxSize().background(Color.Black)) {
                AndroidView(
                    factory = { ctx ->
                        VideoView(ctx).apply {
                            setVideoPath(file.absolutePath)
                            setOnPreparedListener { it.isLooping = false }
                            start()
                        }
                    },
                    modifier = Modifier.fillMaxSize()
                )
                IconButton(
                    onClick = { playing = null },
                    modifier = Modifier.align(Alignment.TopEnd).padding(12.dp)
                ) {
                    Icon(
                        Icons.Filled.Close,
                        contentDescription = "Close",
                        tint = Color.White
                    )
                }
            }
        }

        preview?.let { bitmap ->
            Box(modifier = Modifier.fillMaxSize().background(Color.Black)) {
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = null,
                    modifier = Modifier.fillMaxSize(),
                    contentScale = ContentScale.Fit
                )
                IconButton(
                    onClick = { preview = null },
                    modifier = Modifier.align(Alignment.TopEnd).padding(12.dp)
                ) {
                    Icon(
                        Icons.Filled.Close,
                        contentDescription = "Close",
                        tint = Color.White
                    )
                }
            }
        }

        if (key != null) {
            FloatingActionButton(
                onClick = { external = true; picker.launch(arrayOf("*/*")) },
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(end = 24.dp, bottom = bottomPadding + 96.dp)
            ) {
                Icon(Icons.Filled.Add, contentDescription = "Add files")
            }
        }
    }

    if (showNewFolder) {
        AlertDialog(
            onDismissRequest = { showNewFolder = false; folderName = "" },
            title = { Text("New folder") },
            text = {
                OutlinedTextField(
                    value = folderName,
                    onValueChange = { folderName = it },
                    label = { Text("Folder name") },
                    singleLine = true
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val current = key
                        val name = folderName.trim()
                        if (current != null && name.isNotEmpty()) {
                            scope.launch {
                                contents = withContext(Dispatchers.IO) {
                                    VaultCrypto.addFolder(context, current, name)
                                }
                                folder = name
                                status = "Folder \"$name\" created"
                            }
                        }
                        showNewFolder = false
                        folderName = ""
                    }
                ) { Text("Create") }
            },
            dismissButton = {
                TextButton(onClick = { showNewFolder = false; folderName = "" }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
private fun SetupVault(
    password: String,
    confirm: String,
    onPassword: (String) -> Unit,
    onConfirm: (String) -> Unit,
    onCreate: () -> Unit
) {
    Text(
        "Set a master password. Files are encrypted with AES-256 and the key comes from this " +
            "password, so keep it safe - without it the files cannot be opened again.",
        style = MaterialTheme.typography.bodyMedium
    )
    Spacer(Modifier.height(16.dp))
    OutlinedTextField(
        value = password,
        onValueChange = onPassword,
        label = { Text("Master password") },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(
        value = confirm,
        onValueChange = onConfirm,
        label = { Text("Repeat password") },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(Modifier.height(16.dp))
    Button(onClick = onCreate, modifier = Modifier.fillMaxWidth()) { Text("Create vault") }
}

@Composable
private fun UnlockVault(
    password: String,
    busy: Boolean,
    onPassword: (String) -> Unit,
    onUnlock: () -> Unit
) {
    Text(
        "Unlock the vault with your master password.",
        style = MaterialTheme.typography.bodyMedium
    )
    Spacer(Modifier.height(16.dp))
    OutlinedTextField(
        value = password,
        onValueChange = onPassword,
        label = { Text("Master password") },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(Modifier.height(16.dp))
    Button(
        onClick = onUnlock,
        enabled = !busy && password.isNotEmpty(),
        modifier = Modifier.fillMaxWidth()
    ) { Text(if (busy) "Checking..." else "Unlock") }
}

private fun Context.findActivity(): Activity? {
    var current: Context = this
    while (current is ContextWrapper) {
        if (current is Activity) return current
        current = current.baseContext
    }
    return current as? Activity
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

private fun isMedia(name: String): Boolean {
    val extension = name.substringAfterLast('.', "").lowercase()
    return extension in setOf(
        "mp4", "mkv", "webm", "3gp", "mov", "avi", "m4v",
        "mp3", "m4a", "aac", "ogg", "opus", "wav", "flac"
    )
}

private fun isImage(name: String): Boolean {
    val extension = name.substringAfterLast('.', "").lowercase()
    return extension in setOf("jpg", "jpeg", "png", "webp", "gif", "bmp", "heic", "heif")
}

private fun decryptToCache(context: Context, key: SecretKey, item: VaultItem): File {
    val dir = File(context.cacheDir, "vault").apply { mkdirs() }
    val out = File(dir, item.name)
    out.outputStream().use { target ->
        VaultCrypto.decrypt(key, VaultCrypto.fileFor(context, item.id), target)
    }
    return out
}

private fun openItem(context: Context, key: SecretKey, item: VaultItem) {
    val out = decryptToCache(context, key, item)
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", out)
    val intent = Intent(Intent.ACTION_VIEW)
        .setDataAndType(uri, mimeOf(item.name))
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(intent)
}
