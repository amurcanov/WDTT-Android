package com.wdtt.client.ui

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import com.wdtt.client.TunnelService
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.ChannelSftp
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.wdtt.client.DeployManager
import com.wdtt.client.SettingsStore
import com.wdtt.client.TunnelManager
import com.wdtt.client.WDTTColors
import com.wdtt.client.ui.dialogs.DeploySecretsDialog
import com.wdtt.client.ui.dialogs.UninstallConfirmDialog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.util.Properties

private const val CMD_TIMEOUT = 900000L 

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeployTab() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settingsStore = remember { SettingsStore(context) }

    LaunchedEffect(Unit) { DeployManager.init(context) }

    val savedIp by settingsStore.deployIp.collectAsStateWithLifecycle(initialValue = "")
    val savedLogin by settingsStore.deployLogin.collectAsStateWithLifecycle(initialValue = "")
    val savedPassword by settingsStore.deployPassword.collectAsStateWithLifecycle(initialValue = "")
    val savedUseSshKey by settingsStore.useSshKey.collectAsStateWithLifecycle(initialValue = false)
    val savedSshPrivateKey by settingsStore.sshPrivateKey.collectAsStateWithLifecycle(initialValue = "")

    var ip by remember { mutableStateOf("") }
    var login by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var useSshKey by remember { mutableStateOf(false) }
    var sshPrivateKey by remember { mutableStateOf("") }

    val savedDns1 by settingsStore.deployDns1.collectAsStateWithLifecycle(initialValue = "1.1.1.1")
    val savedDns2 by settingsStore.deployDns2.collectAsStateWithLifecycle(initialValue = "1.0.0.1")
    var dns1 by remember { mutableStateOf("1.1.1.1") }
    var dns2 by remember { mutableStateOf("1.0.0.1") }

    val savedMainPass by settingsStore.deployMainPassword.collectAsStateWithLifecycle(initialValue = "")
    val savedAdminId by settingsStore.deployAdminId.collectAsStateWithLifecycle(initialValue = "")
    val savedBotToken by settingsStore.deployBotToken.collectAsStateWithLifecycle(initialValue = "")
    val savedSshPort by settingsStore.deploySshPort.collectAsStateWithLifecycle(initialValue = "22")
    val savedManualPorts by settingsStore.manualPortsEnabled.collectAsStateWithLifecycle(initialValue = false)
    val savedServerDtlsPort by settingsStore.serverDtlsPort.collectAsStateWithLifecycle(initialValue = 56000)
    val savedServerWgPort by settingsStore.serverWgPort.collectAsStateWithLifecycle(initialValue = 56001)

    var showSecretsDialog by remember { mutableStateOf(false) }
    var showUninstallDialog by remember { mutableStateOf(false) }

    var showSuccessBanner by rememberSaveable { mutableStateOf(false) }
    var successCountdown by rememberSaveable { mutableIntStateOf(5) }

    LaunchedEffect(showSuccessBanner) {
        if (showSuccessBanner) {
            while (successCountdown > 0) {
                kotlinx.coroutines.delay(1000)
                successCountdown--
            }
            showSuccessBanner = false
        }
    }

    val isDeploying by DeployManager.isDeploying.collectAsStateWithLifecycle()
    val deployProgress by DeployManager.deployProgress.collectAsStateWithLifecycle()
    val currentStep by DeployManager.currentStep.collectAsStateWithLifecycle()

    LaunchedEffect(savedIp) { ip = savedIp }
    LaunchedEffect(savedLogin) { login = savedLogin }
    LaunchedEffect(savedPassword) { password = savedPassword }
    LaunchedEffect(savedUseSshKey) { useSshKey = savedUseSshKey }
    LaunchedEffect(savedSshPrivateKey) { sshPrivateKey = savedSshPrivateKey }
    LaunchedEffect(savedDns1) { dns1 = savedDns1 }
    LaunchedEffect(savedDns2) { dns2 = savedDns2 }
    val animatedProgress by animateFloatAsState(
        targetValue = deployProgress,
        animationSpec = tween(durationMillis = 1200, easing = androidx.compose.animation.core.FastOutSlowInEasing),
        label = "progress"
    )

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(
            "Настройки сервера",
            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
            color = MaterialTheme.colorScheme.onSurface
        )

        
        AppSectionCard(
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = ip,
                onValueChange = {
                    ip = it.filter { c -> !c.isWhitespace() }
                    scope.launch { settingsStore.saveDeploy(ip, login, password, savedSshPort, dns1, dns2) }
                },
                label = { Text("IP сервера или домен (без порта)") },
                placeholder = { Text("1.2.3.4 (без порта)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                enabled = !isDeploying,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedTextField(
                    value = login,
                    onValueChange = {
                        login = it.filter { c -> !c.isWhitespace() }
                        scope.launch { settingsStore.saveDeploy(ip, login, password, savedSshPort, dns1, dns2) }
                    },
                    label = { Text("Логин") },
                    placeholder = { Text("root") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(16.dp),
                    enabled = !isDeploying,
                )
                
                // Переключатель использования SSH ключа
                Row(
                    modifier = Modifier.weight(1f),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "SSH ключ",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(end = 4.dp)
                    )
                    Switch(
                        checked = useSshKey,
                        enabled = !isDeploying,
                        onCheckedChange = { enabled ->
                            useSshKey = enabled
                            scope.launch { settingsStore.saveUseSshKey(enabled) }
                            if (enabled) {
                                // Если включили ключ - очищаем пароль
                                password = ""
                                scope.launch { settingsStore.saveDeploy(ip, login, "", savedSshPort, dns1, dns2) }
                            }
                        }
                    )
                }
            }

            // Поле пароля или SSH ключа
            if (!useSshKey) {
                OutlinedTextField(
                    value = password,
                    onValueChange = {
                        password = it.filter { c -> !c.isWhitespace() }
                        scope.launch { settingsStore.saveDeploy(ip, login, password, savedSshPort, dns1, dns2) }
                    },
                    label = { Text("Пароль SSH") },
                    placeholder = { Text("password") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    enabled = !isDeploying,
                )
            } else {
                OutlinedTextField(
                    value = sshPrivateKey,
                    onValueChange = {
                        sshPrivateKey = it
                        scope.launch { settingsStore.saveSshPrivateKey(it) }
                    },
                    label = { Text("SSH Private Key") },
                    placeholder = { Text("-----BEGIN RSA PRIVATE KEY-----...") },
                    singleLine = false,
                    modifier = Modifier.fillMaxWidth().height(120.dp),
                    shape = RoundedCornerShape(16.dp),
                    enabled = !isDeploying,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedTextField(
                    value = dns1,
                    onValueChange = {
                        dns1 = it.filter { c -> !c.isWhitespace() }
                        scope.launch { settingsStore.saveDeploy(ip, login, password, savedSshPort, dns1, dns2) }
                    },
                    label = { Text("Основной DNS") },
                    placeholder = { Text("1.1.1.1") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(16.dp),
                    enabled = !isDeploying,
                )
                OutlinedTextField(
                    value = dns2,
                    onValueChange = {
                        dns2 = it.filter { c -> !c.isWhitespace() }
                        scope.launch { settingsStore.saveDeploy(ip, login, password, savedSshPort, dns1, dns2) }
                    },
                    label = { Text("Резервный DNS") },
                    placeholder = { Text("1.0.0.1") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(16.dp),
                    enabled = !isDeploying,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "Ручное управление портами",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.weight(1f),
                    color = MaterialTheme.colorScheme.onSurface
                )
                Switch(
                    checked = savedManualPorts,
                    enabled = !isDeploying,
                    onCheckedChange = { enabled ->
                        scope.launch { settingsStore.saveManualPortsEnabled(enabled) }
                    }
                )
            }
        }

        if (showSecretsDialog) {
            DeploySecretsDialog(
                settingsStore = settingsStore,
                initialMainPass = savedMainPass,
                initialAdminId = savedAdminId,
                initialBotToken = savedBotToken,
                initialSshPort = savedSshPort,
                manualPortsEnabled = savedManualPorts,
                initialServerDtlsPort = savedServerDtlsPort.toString(),
                initialServerWgPort = savedServerWgPort.toString(),
                onSaved = { _, _ -> },
                onDismiss = { showSecretsDialog = false }
            )
        }

        
        if (isDeploying) {
            AppSectionCard(
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = currentStep,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "${(animatedProgress * 100).toInt()}%",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                LinearProgressIndicator(
                    progress = { animatedProgress },
                    modifier = Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)),
                    color = MaterialTheme.colorScheme.primary,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant,
                )
            }
        }

        
        val deploySecretsMissing = savedMainPass.isBlank()
        OutlinedButton(
            onClick = { showSecretsDialog = true },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.outlinedButtonColors(
                containerColor = if (deploySecretsMissing) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surface,
                contentColor = if (deploySecretsMissing) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurface
            ),
            border = BorderStroke(
                1.dp,
                if (deploySecretsMissing) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
            )
        ) {
            Icon(Icons.Default.Key, null, Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(
                if (savedManualPorts) "Секреты (BOT, Пароли, Порты)" else "Секреты (BOT, Пароли)",
                fontWeight = FontWeight.SemiBold
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = {
                    // Валидация в зависимости от метода аутентификации
                    if (ip.isBlank() || savedMainPass.isBlank()) return@Button
                    if (useSshKey) {
                        if (sshPrivateKey.isBlank()) return@Button
                    } else {
                        if (password.isBlank()) return@Button
                    }
                    
                    val effectiveLogin = if (login.isBlank()) "root" else login
                    val effectiveDtlsPort = if (savedManualPorts) savedServerDtlsPort.coerceIn(1, 65535) else 56000
                    val effectiveWgPort = if (savedManualPorts) savedServerWgPort.coerceIn(1, 65535) else 56001
                    val appContext = context.applicationContext
                    DeployManager.scope.launch {
                        try {
                            DeployManager.startDeploy()
                            val intent = Intent(appContext, TunnelService::class.java).apply { action = "DEPLOY_START" }
                            if (Build.VERSION.SDK_INT >= 26) appContext.startForegroundService(intent)
                            else appContext.startService(intent)

                            val success = performDeploy(
                                context = appContext,
                                host = ip, 
                                user = effectiveLogin, 
                                pass = if (useSshKey) null else password,
                                sshKey = if (useSshKey) sshPrivateKey else null,
                                port = savedSshPort.toIntOrNull() ?: 22,
                                mainPass = savedMainPass, 
                                adminId = savedAdminId, 
                                botToken = savedBotToken,
                                dtlsPort = effectiveDtlsPort, 
                                wgPort = effectiveWgPort, 
                                dns1 = dns1, 
                                dns2 = dns2,
                                onProgress = { p, s -> DeployManager.updateProgress(p, s) }
                            )
                            if (success) {
                                successCountdown = 5
                                showSuccessBanner = true
                            }
                        } finally {
                            try { appContext.startService(Intent(appContext, TunnelService::class.java).apply { action = "DEPLOY_STOP" }) } catch (_: Exception) {}
                        }
                    }
                },
                modifier = Modifier.weight(1f).height(50.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(contentColor = MaterialTheme.colorScheme.onPrimary),
                enabled = !isDeploying && 
                          ip.isNotBlank() && 
                          savedMainPass.isNotBlank() &&
                          if (useSshKey) sshPrivateKey.isNotBlank() else password.isNotBlank()
            ) {
                if (isDeploying) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
                } else {
                    Icon(Icons.Default.CloudUpload, null, Modifier.size(18.dp))
                }
                Spacer(Modifier.width(8.dp))
                Text(if (isDeploying) "Установка..." else "Установить", fontWeight = FontWeight.Bold)
            }

            Button(
                onClick = {
                    if (ip.isBlank()) return@Button
                    if (useSshKey) {
                        if (sshPrivateKey.isBlank()) return@Button
                    } else {
                        if (password.isBlank()) return@Button
                    }
                    showUninstallDialog = true
                },
                modifier = Modifier.weight(1f).height(50.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError
                ),
                enabled = !isDeploying && 
                          ip.isNotBlank() &&
                          if (useSshKey) sshPrivateKey.isNotBlank() else password.isNotBlank()
            ) {
                Icon(Icons.Default.Delete, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Удалить", fontWeight = FontWeight.Bold)
            }
        }

        if (showUninstallDialog) {
            UninstallConfirmDialog(
                onDismiss = { showUninstallDialog = false },
                onConfirm = {
                    showUninstallDialog = false
                    val effectiveLogin = if (login.isBlank()) "root" else login
                    val effectiveDtlsPort = if (savedManualPorts) savedServerDtlsPort.coerceIn(1, 65535) else 56000
                    val effectiveWgPort = if (savedManualPorts) savedServerWgPort.coerceIn(1, 65535) else 56001
                    DeployManager.scope.launch {
                        try {
                            DeployManager.startDeploy()
                            performUninstall(
                                host = ip, 
                                user = effectiveLogin, 
                                pass = if (useSshKey) null else password,
                                sshKey = if (useSshKey) sshPrivateKey else null,
                                port = savedSshPort.toIntOrNull() ?: 22,
                                dtlsPort = effectiveDtlsPort, 
                                wgPort = effectiveWgPort,
                                onProgress = { p, s -> DeployManager.updateProgress(p, s) }
                            )
                        } catch (_: Exception) {}
                    }
                }
            )
        }

        Spacer(modifier = Modifier.weight(1f))

        
        if (showSuccessBanner) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = WDTTColors.connected.copy(alpha = 0.12f),
                contentColor = MaterialTheme.colorScheme.onSurface,
                border = BorderStroke(1.dp, WDTTColors.connected.copy(alpha = 0.4f))
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = WDTTColors.connected)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "Деплой успешно завершен ($successCountdown)",
                        color = WDTTColors.connected,
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }
    }
}

private class SSHClient(private val session: Session, private val pass: String?) {

    fun exec(command: String, timeout: Long = CMD_TIMEOUT): String {
        if (!session.isConnected) {
            DeployManager.writeError("SSH exec: сессия разорвана перед командой: ${command.take(80)}")
            return "error: session is down"
        }

        var channel: ChannelExec? = null
        val result = StringBuilder()

        return try {
            channel = session.openChannel("exec") as ChannelExec
            val cmd = if (command.contains("sudo") && !command.contains("sudo -S")) {
                command.replace("sudo ", "sudo -S ")
            } else command

            channel.setCommand(cmd)
            val outStream = channel.outputStream
            val input = channel.inputStream
            val err = channel.errStream
            channel.connect(15000)

            if (cmd.contains("sudo -S") && pass != null) {
                outStream.write("$pass\n".toByteArray())
                outStream.flush()
            }

            val reader = input.bufferedReader()
            val errReader = err.bufferedReader()
            val startTime = System.currentTimeMillis()
            val progressRegex = Regex("^WDTT_PROGRESS\\|(\\d+\\.?\\d*)\\|(.+)$")

            while (!channel.isClosed || reader.ready() || errReader.ready()) {
                if (System.currentTimeMillis() - startTime > timeout) {
                    DeployManager.writeError("SSH timeout (${timeout/1000}s): ${command.take(80)}")
                    try { channel.disconnect() } catch (_: Exception) {}
                    return "error: timeout"
                }

                if (reader.ready()) {
                    val line = reader.readLine()
                    if (line != null) {
                        val match = progressRegex.find(line.trim())
                        if (match != null) {
                            val p = match.groupValues[1].toFloatOrNull() ?: 0f
                            DeployManager.updateProgress(p, match.groupValues[2])
                        } else if (!line.contains("WDTT_PROGRESS")) {
                            val clean = line.replace(Regex("\u001B\\[[;\\d]*m"), "")
                            result.appendLine(clean)
                            if (clean.contains("[✗]") || clean.contains("FAIL") ||
                                (clean.contains("error", true) && !clean.contains("2>/dev/null"))) {
                                DeployManager.writeError("REMOTE: $clean")
                                TunnelManager.addDeployErrorLog("REMOTE: $clean")
                            }
                        }
                    }
                }
                if (errReader.ready()) {
                    val line = errReader.readLine()
                    if (line != null && !line.contains("password for")) {
                        val clean = line.replace(Regex("\u001B\\[[;\\d]*m"), "")
                        result.appendLine(clean)
                        if (clean.isNotBlank() && !clean.startsWith("Warning:")) {
                            DeployManager.writeError("STDERR: $clean")
                            TunnelManager.addDeployErrorLog("STDERR: $clean")
                        }
                    }
                }
                if (!reader.ready() && !errReader.ready()) Thread.sleep(100)
            }

            result.toString()
        } catch (e: Exception) {
            DeployManager.writeError("SSH exec error: ${e.message} | cmd: ${command.take(80)}")
            TunnelManager.addDeployErrorLog("SSH exec error: ${e.message}")
            "error: ${e.message}"
        } finally {
            try { channel?.disconnect() } catch (_: Exception) {}
        }
    }

    fun upload(localFile: File, remotePath: String) {
        if (!session.isConnected) {
            DeployManager.writeError("SSH upload: сессия разорвана")
            throw Exception("Session is down")
        }
        var sftp: ChannelSftp? = null
        try {
            sftp = session.openChannel("sftp") as ChannelSftp
            sftp.connect(15000)
            sftp.put(localFile.absolutePath, remotePath)
        } catch (e: Exception) {
            DeployManager.writeError("SFTP upload error: ${e.message} | file: ${localFile.name}")
            throw e
        } finally {
            try { sftp?.disconnect() } catch (_: Exception) {}
        }
    }
}

private fun createSSHSession(
    host: String, 
    user: String, 
    pass: String?, 
    port: Int = 22,
    privateKey: String? = null
): Session {
    val jsch = JSch()
    val session = jsch.getSession(user, host, port)
    
    // Настройка сессии
    val config = Properties().apply {
        put("StrictHostKeyChecking", "no")
        put("ServerAliveInterval", "10")
        put("ServerAliveCountMax", "6")
        put("ConnectTimeout", "15000")
    }
    session.setConfig(config)
    
    // Если есть приватный ключ - используем его
    if (privateKey != null && privateKey.isNotBlank()) {
        try {
            val tempFile = File.createTempFile("ssh_key", ".pem")
            tempFile.writeText(privateKey)
            tempFile.setReadable(true, true) // только для владельца
            tempFile.deleteOnExit()
            
            // Загружаем ключ без пароля (для простоты, можно добавить passphrase позже)
            jsch.addIdentity(tempFile.absolutePath)
            session.setConfig(Properties().apply {
                put("PreferredAuthentications", "publickey")
            })
        } catch (e: Exception) {
            DeployManager.writeError("Failed to load SSH key: ${e.message}")
            throw e
        }
    } else if (pass != null && pass.isNotBlank()) {
        // Используем пароль
        session.setPassword(pass)
        session.setConfig(Properties().apply {
            put("PreferredAuthentications", "password,keyboard-interactive")
        })
    } else {
        throw IllegalArgumentException("Either password or SSH key must be provided")
    }
    
    session.connect(20000)
    return session
}

private fun shellQuote(value: String): String {
    return "'" + value.replace("'", "'\"'\"'") + "'"
}

private fun rootCommand(command: String): String {
    val quoted = shellQuote(command)
    return "if command -v sudo >/dev/null 2>&1; then sudo bash -c $quoted; " +
        "elif [ \"\$(id -u)\" = \"0\" ]; then bash -c $quoted; " +
        "else echo 'error: root privileges required and sudo not found'; exit 1; fi"
}

private fun File.containsBinaryToken(token: String): Boolean {
    val data = readBytes()
    val needle = token.toByteArray()
    if (needle.isEmpty() || data.size < needle.size) return false
    for (i in 0..data.size - needle.size) {
        var matched = true
        for (j in needle.indices) {
            if (data[i + j] != needle[j]) {
                matched = false
                break
            }
        }
        if (matched) return true
    }
    return false
}

private fun isUnsafeLegacyServerAsset(serverFile: File): Boolean {
    return serverFile.containsBinaryToken("/etc/wireguard") ||
        (serverFile.containsBinaryToken("wg0") && !serverFile.containsBinaryToken("wdtt0"))
}

private suspend fun performDeploy(
    context: Context,
    host: String, 
    user: String, 
    pass: String?,
    sshKey: String?,
    port: Int,
    mainPass: String, 
    adminId: String, 
    botToken: String,
    dtlsPort: Int, 
    wgPort: Int, 
    dns1: String, 
    dns2: String,
    onProgress: (Float, String) -> Unit
): Boolean = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        onProgress(0.02f, "Подключение...")
        session = createSSHSession(
            host = host, 
            user = user, 
            pass = pass,
            port = port,
            privateKey = sshKey
        )
        DeployManager.activeSession = session
        val ssh = SSHClient(session, pass)

        onProgress(0.05f, "Подготовка файлов...")
        val passArg = if (mainPass.isNotBlank()) "-password $mainPass " else ""
        val adminArg = if (adminId.isNotBlank()) "-admin $adminId " else ""
        val botArg = if (botToken.isNotBlank()) "-bot-token $botToken " else ""
        
        
        val dnsValue = listOf(dns1, dns2).map { it.trim() }.filter { it.isNotEmpty() }.joinToString(",")
        val dnsArg = if (dnsValue.isNotEmpty()) "-dns $dnsValue " else ""
        val args = "$passArg$adminArg$botArg$dnsArg".trim()

        val scriptFile = File(context.cacheDir, "deploy.sh")
        val serverFile = File(context.cacheDir, "server")
        try {
            context.assets.open("deploy.sh").use { inp -> FileOutputStream(scriptFile).use { out -> inp.copyTo(out) } }
            context.assets.open("server").use { inp -> FileOutputStream(serverFile).use { out -> inp.copyTo(out) } }
        } catch (e: Exception) {
            DeployManager.writeError("Assets extraction failed: ${e.message}")
            DeployManager.stopDeploy("Ошибка: файлы не найдены в assets")
            return@withContext false
        }
        if (isUnsafeLegacyServerAsset(serverFile)) {
            scriptFile.delete()
            serverFile.delete()
            DeployManager.writeError("Unsafe legacy server asset: найдено wg0 или /etc/wireguard. Нужна пересборка server под wdtt0 и /etc/wdtt.")
            DeployManager.stopDeploy("Нужна пересборка server asset")
            return@withContext false
        }

        onProgress(0.06f, "Загрузка на сервер...")
        ssh.upload(scriptFile, "/tmp/deploy.sh")
        ssh.upload(serverFile, "/tmp/wdtt-server")
        scriptFile.delete()
        serverFile.delete()

        onProgress(0.08f, "Установка...")
        val output = ssh.exec(
            rootCommand("env WDTT_ARGS=${shellQuote(args)} WDTT_DTLS_PORT=$dtlsPort WDTT_WG_PORT=$wgPort WDTT_SSH_PORT=$port bash /tmp/deploy.sh"),
            timeout = CMD_TIMEOUT
        )

        if (output.contains("✅") || output.contains("Деплой успешно") || output.contains("active")) {
            DeployManager.stopDeploy("success")
            TunnelManager.addDeploySuccessLog("Деплой успешно завершен. Сервис активен.")
            return@withContext true
        } else if (output.contains("error:")) {
            DeployManager.writeError("Deploy script output contains error")
            DeployManager.stopDeploy("Ошибка выполнения скрипта (см. errors.log)")
            return@withContext false
        } else {
            DeployManager.stopDeploy("success")
            TunnelManager.addDeploySuccessLog("Деплой завершён. (Проверьте подключение)")
            return@withContext true
        }

    } catch (e: Exception) {
        DeployManager.writeError("Deploy critical: ${e.message}\n${e.stackTraceToString().take(500)}")
        DeployManager.stopDeploy("Ошибка: ${e.message?.take(100)}")
        return@withContext false
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
        DeployManager.activeSession = null
    }
}

private suspend fun performUninstall(
    host: String, 
    user: String, 
    pass: String?,
    sshKey: String?,
    port: Int,
    dtlsPort: Int, 
    wgPort: Int,
    onProgress: (Float, String) -> Unit
) = withContext(Dispatchers.IO) {
    var session: Session? = null
    try {
        onProgress(0.05f, "Подключение...")
        session = createSSHSession(
            host = host, 
            user = user, 
            pass = pass,
            port = port,
            privateKey = sshKey
        )
        DeployManager.activeSession = session
        val ssh = SSHClient(session, pass)

        onProgress(0.15f, "Остановка сервиса...")
        ssh.exec(
            rootCommand(
                "systemctl unmask wdtt 2>/dev/null || true; " +
                    "systemctl stop wdtt 2>/dev/null || true; " +
                    "systemctl disable wdtt 2>/dev/null || true; " +
                    "rm -f /etc/systemd/system/wdtt.service; " +
                    "systemctl daemon-reload 2>/dev/null || true"
            ),
            timeout = 15000L
        )

        onProgress(0.30f, "Удаление через deploy.sh...")
        ssh.exec(rootCommand("[ -f /tmp/deploy.sh ] && env WDTT_DTLS_PORT=$dtlsPort WDTT_WG_PORT=$wgPort WDTT_SSH_PORT=$port bash /tmp/deploy.sh uninstall 2>/dev/null || true"), timeout = 30000L)

        onProgress(0.45f, "Удаление бинарника...")
        ssh.exec(rootCommand("pkill -x wdtt-server 2>/dev/null || true; rm -f /usr/local/bin/wdtt-server"), timeout = 10000L)

        onProgress(0.60f, "Очистка firewall...")
        ssh.exec(
            rootCommand(
                "if command -v iptables >/dev/null 2>&1; then " +
                    "for i in 1 2 3 4 5; do " +
                    "for iface in $(ls /sys/class/net 2>/dev/null || true); do " +
                    "iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o \"${'$'}iface\" -m comment --comment WDTT_MANAGED -j MASQUERADE 2>/dev/null || true; " +
                    "done; " +
                    "iptables -D INPUT -p udp --dport $dtlsPort -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D INPUT -p udp --dport $wgPort -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D INPUT -p udp --dport 56000 -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D INPUT -p udp --dport 56001 -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D INPUT -p tcp --dport $port -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D INPUT -p tcp --dport 22 -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D FORWARD -i wdtt0 -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "iptables -D FORWARD -o wdtt0 -m comment --comment WDTT_MANAGED -j ACCEPT 2>/dev/null || true; " +
                    "done; fi; " +
                    "if command -v nft >/dev/null 2>&1; then " +
                    "nft delete table ip wdtt 2>/dev/null || true; " +
                    "nft delete table inet wdtt 2>/dev/null || true; " +
                    "nft delete table inet wdtt_mangle 2>/dev/null || true; " +
                    "fi"
            ),
            timeout = 15000L
        )

        onProgress(0.75f, "Удаление WDTT-интерфейса...")
        ssh.exec(
            rootCommand(
                "ip link show wdtt0 >/dev/null 2>&1 && ip link del wdtt0 2>/dev/null || true; " +
                    "[ -d /etc/wdtt ] && find /etc/wdtt -mindepth 1 -maxdepth 1 ! -name passwords.json -exec rm -rf {} + 2>/dev/null || true; " +
                    "[ -f /etc/wdtt/passwords.json ] && chmod 600 /etc/wdtt/passwords.json 2>/dev/null || true"
            ),
            timeout = 10000L
        )

        onProgress(0.90f, "Очистка sysctl...")
        ssh.exec(rootCommand("rm -f /etc/sysctl.d/99-wdtt.conf; sysctl --system >/dev/null 2>&1 || true"), timeout = 15000L)

        onProgress(1.0f, "Готово!")
        DeployManager.stopDeploy("success")

    } catch (e: Exception) {
        DeployManager.writeError("Uninstall error: ${e.message}")
        DeployManager.stopDeploy("Ошибка: ${e.message?.take(100)}")
    } finally {
        try { session?.disconnect() } catch (_: Exception) {}
        DeployManager.activeSession = null
    }
}
