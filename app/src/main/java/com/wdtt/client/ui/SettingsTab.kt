package com.wdtt.client.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.wdtt.client.SettingsStore
import com.wdtt.client.ConnectionProfile
import com.wdtt.client.ConnectionProfileParser
import com.wdtt.client.TunnelManager
import com.wdtt.client.TunnelService
import com.wdtt.client.WDTTColors
import com.wdtt.client.ui.dialogs.HashesDialog
import com.wdtt.client.ui.dialogs.SecretsDialog
import com.wdtt.client.ui.utils.stripVkUrlStatic
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.first
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import kotlin.math.roundToInt

private const val WORKERS_PER_GROUP = 9

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsTab() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val settingsStore = remember { SettingsStore(context) }

    val currentDensity = LocalDensity.current
    CompositionLocalProvider(
        LocalDensity provides Density(currentDensity.density, fontScale = 1f)
    ) {
        SettingsTabContent(context, scope, settingsStore)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsTabContent(context: android.content.Context, scope: kotlinx.coroutines.CoroutineScope, settingsStore: SettingsStore) {
    val savedConnectionPassword by settingsStore.connectionPassword.collectAsStateWithLifecycle(initialValue = "")
    val savedManualPortsEnabled by settingsStore.manualPortsEnabled.collectAsStateWithLifecycle(initialValue = false)
    val savedServerDtlsPort by settingsStore.serverDtlsPort.collectAsStateWithLifecycle(initialValue = 56000)
    val savedServerWgPort by settingsStore.serverWgPort.collectAsStateWithLifecycle(initialValue = 56001)
    val savedListenPort by settingsStore.listenPort.collectAsStateWithLifecycle(initialValue = 9000)

    val activeProfile by settingsStore.activeProfile.collectAsStateWithLifecycle(initialValue = 0)
    val wdttLinkMode by settingsStore.wdttLinkMode.collectAsStateWithLifecycle(initialValue = false)
    val connectionProfiles by settingsStore.connectionProfiles.collectAsStateWithLifecycle(initialValue = emptyList())
    val activeConnectionProfileId by settingsStore.activeConnectionProfileId.collectAsStateWithLifecycle(initialValue = "")
    val selectedConnectionProfile = connectionProfiles.firstOrNull { it.id == activeConnectionProfileId }
        ?: connectionProfiles.firstOrNull()

    val activeFingerprint by settingsStore.selectedFingerprint.collectAsStateWithLifecycle(initialValue = "firefox")
    val activeClientIds by settingsStore.activeClientIds.collectAsStateWithLifecycle(initialValue = "8202606,6287487")
    val savedObfsMode by settingsStore.obfsMode.collectAsStateWithLifecycle(initialValue = "audio")

    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()

    val cooldownActive by TunnelManager.cooldownActive.collectAsStateWithLifecycle()
    var wasRunning by remember { mutableStateOf(false) }

    LaunchedEffect(tunnelRunning) {
        if (wasRunning && !tunnelRunning) {
            TunnelManager.startCooldown(1500L)
        }
        wasRunning = tunnelRunning
    }

    var peerInput by rememberSaveable { mutableStateOf("") }
    var vkHash1 by rememberSaveable { mutableStateOf("") }
    var vkHash2 by rememberSaveable { mutableStateOf("") }
    var vkHash3 by rememberSaveable { mutableStateOf("") }
    var vkHash4 by rememberSaveable { mutableStateOf("") }
    var workersInput by rememberSaveable { mutableFloatStateOf(18f) }
    var showHashesDialog by rememberSaveable { mutableStateOf(false) }
    var useVKCallsAuth by rememberSaveable { mutableStateOf(true) }
    var obfsMode by rememberSaveable { mutableStateOf("audio") }
    var autoCaptchaEnabled by rememberSaveable { mutableStateOf(true) }
    var useWVCaptcha by rememberSaveable { mutableStateOf(false) }
    var isManualMode by rememberSaveable { mutableStateOf(true) }
    var wbvManualMode by rememberSaveable { mutableStateOf(true) }
    var manualPortsEnabled by rememberSaveable { mutableStateOf(false) }
    var serverDtlsPortInput by rememberSaveable { mutableStateOf("56000") }
    var serverWgPortInput by rememberSaveable { mutableStateOf("56001") }
    var showConnectionImport by rememberSaveable { mutableStateOf(false) }
    var connectionImportText by rememberSaveable { mutableStateOf("") }
    var connectionImportError by rememberSaveable { mutableStateOf("") }
    var detailsProfile by remember { mutableStateOf<ConnectionProfile?>(null) }
    var profileSwitching by remember { mutableStateOf(false) }

    val allHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4) { listOf(vkHash1, vkHash2, vkHash3, vkHash4) }
    val uniqueHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4) { allHashes.filter { it.isNotBlank() && it.length >= 16 }.distinct() }
    val parsedLinkHashes = remember(selectedConnectionProfile) {
        selectedConnectionProfile?.vkLinks
            ?.split(Regex("[,\\s\\n]+"))
            ?.map(::stripVkUrlStatic)
            ?.filter { it.isNotBlank() }
            .orEmpty()
    }
    val filledHashCount = remember(vkHash1, vkHash2, vkHash3, vkHash4, wdttLinkMode, parsedLinkHashes) { 
        if (wdttLinkMode) parsedLinkHashes.size else uniqueHashes.size 
    }
    val combinedHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4) { uniqueHashes.joinToString(",") }
    val dynamicMaxWorkers = remember(filledHashCount) { (filledHashCount.coerceAtLeast(1) * 27).toFloat() }
    var portInput by rememberSaveable { mutableStateOf("9000") }
    var sniInput by rememberSaveable { mutableStateOf("") }

    LaunchedEffect(dynamicMaxWorkers) {
        if (workersInput > dynamicMaxWorkers) {
            workersInput = dynamicMaxWorkers
        }
    }

    val currentWorkers = workersInput.coerceIn(WORKERS_PER_GROUP.toFloat(), dynamicMaxWorkers)

    val hashErrors = remember(vkHash1, vkHash2, vkHash3, vkHash4) {
        buildList {
            allHashes.forEachIndexed { i, h ->
                if (h.isNotBlank() && h.length < 16) add("Хеш ${i + 1} — короткий")
            }
            val filled = allHashes.filter { it.isNotBlank() && it.length >= 16 }
            if (filled.size != filled.distinct().size) add("Есть дубликаты хешей")
        }
    }
    val hasInputHashErrors = remember(vkHash1, vkHash2, vkHash3, vkHash4) { hashErrors.isNotEmpty() }

    var showSecretsDialog by rememberSaveable { mutableStateOf(false) }
    var initialized by remember { mutableStateOf(false) }

    fun parseHashes(raw: String) {
        val parts = raw.split(Regex("[,\\s\\n]+")).map { stripVkUrlStatic(it) }.filter { it.isNotEmpty() }
        vkHash1 = parts.getOrElse(0) { "" }
        vkHash2 = parts.getOrElse(1) { "" }
        vkHash3 = parts.getOrElse(2) { "" }
        vkHash4 = parts.getOrElse(3) { "" }
    }

    fun normalizeHashes(vararg hashes: String): String {
        return hashes
            .map { stripVkUrlStatic(it) }
            .filter { it.isNotBlank() && it.length >= 16 }
            .distinct()
            .joinToString(",")
    }

    LaunchedEffect(activeProfile) {
        val peer = settingsStore.peer.first()
        val hashes = settingsStore.vkHashes.first()
        val workers = settingsStore.workersPerHash.first()
        val port = settingsStore.listenPort.first()
        val manualPorts = settingsStore.manualPortsEnabled.first()
        val serverDtlsPort = settingsStore.serverDtlsPort.first()
        val serverWgPort = settingsStore.serverWgPort.first()
        val sni = settingsStore.sni.first()
        val vkAuthMode = settingsStore.vkAuthMode.first()
        val captchaMode = settingsStore.captchaMode.first()
        val captchaMethod = settingsStore.captchaSolveMethod.first()
        val wbvCaptchaMethod = settingsStore.captchaWbvSolveMethod.first()
        
        peerInput = peer
        parseHashes(hashes)
        workersInput = roundToGroup(workers.toFloat(), (listOf(vkHash1, vkHash2, vkHash3, vkHash4).count { it.isNotBlank() }.coerceAtLeast(1) * 27).toFloat())
        portInput = port.toString()
        manualPortsEnabled = manualPorts
        serverDtlsPortInput = serverDtlsPort.toString()
        serverWgPortInput = serverWgPort.toString()
        sniInput = sni
        useVKCallsAuth = vkAuthMode != "legacy"
        obfsMode = savedObfsMode
        autoCaptchaEnabled = captchaMode == "auto"
        useWVCaptcha = captchaMode != "rjs"
        wbvManualMode = wbvCaptchaMethod != "auto"
        isManualMode = if (captchaMode == "wv") wbvManualMode else captchaMethod != "auto"
        
        initialized = true
    }

    LaunchedEffect(savedManualPortsEnabled) {
        manualPortsEnabled = savedManualPortsEnabled
    }

    LaunchedEffect(savedServerDtlsPort) {
        serverDtlsPortInput = savedServerDtlsPort.toString()
    }

    LaunchedEffect(savedServerWgPort) {
        serverWgPortInput = savedServerWgPort.toString()
    }

    LaunchedEffect(savedListenPort) {
        portInput = savedListenPort.toString()
    }

    if (!initialized) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
        }
        return
    }

    var saveJob by remember { mutableStateOf<Job?>(null) }

    fun saveTunnelSettingsNow(hashes: String = combinedHashes, onSaved: (() -> Unit)? = null) {
        saveJob?.cancel()
        scope.launch {
            val savedLocalPort = if (manualPortsEnabled) portInput.toIntOrNull()?.coerceIn(1, 65535) ?: 9000 else 9000
            settingsStore.save(
                peerInput, hashes, "",
                workersInput.toInt(), "udp", savedLocalPort, sniInput, false
            )
            onSaved?.invoke()
        }
    }

    fun scheduleSave() {
        saveJob?.cancel()
        saveJob = scope.launch {
            delay(300)
            val savedLocalPort = if (manualPortsEnabled) portInput.toIntOrNull()?.coerceIn(1, 65535) ?: 9000 else 9000
            settingsStore.save(
                peerInput, combinedHashes, "",
                workersInput.toInt(), "udp", savedLocalPort, sniInput, false
            )
        }
    }

    val scrollState = rememberScrollState()

    val isPeerValid = peerInput.isNotBlank() && !peerInput.contains(":")
    val isHashesValid = combinedHashes.isNotBlank()
    val isLinkValid = selectedConnectionProfile?.isReady == true
    val isManualValid = isPeerValid && isHashesValid && savedConnectionPassword.isNotBlank() && !hasInputHashErrors
    val isValid = if (wdttLinkMode) isLinkValid else isManualValid
    val effectiveServerDtlsPort = if (manualPortsEnabled) serverDtlsPortInput.toIntOrNull()?.coerceIn(1, 65535) ?: 56000 else 56000
    val effectiveLocalPort = if (manualPortsEnabled) portInput.toIntOrNull()?.coerceIn(1, 65535) ?: 9000 else 9000
    var pendingStartAfterVpnPermission by remember { mutableStateOf(false) }

    fun startTunnelService(profileOverride: ConnectionProfile? = null) {
        val effectiveVkAuthMode = if (useVKCallsAuth) "vkcalls" else "legacy"
        val effectiveCaptchaMode = if (autoCaptchaEnabled) "auto" else if (useWVCaptcha) "wv" else "rjs"
        val effectiveCaptchaSolveMethod = if (!autoCaptchaEnabled && effectiveCaptchaMode == "wv" && isManualMode) "manual" else "auto"
        saveJob?.cancel()
        scope.launch {
            settingsStore.save(
                peerInput, combinedHashes, "",
                workersInput.toInt(), "udp", effectiveLocalPort, sniInput, false
            )
            settingsStore.saveVkAuthMode(effectiveVkAuthMode)
            settingsStore.saveCaptchaMode(effectiveCaptchaMode)
            settingsStore.saveCaptchaSolveMethod(effectiveCaptchaSolveMethod)
        }

        val connectionProfile = profileOverride ?: if (wdttLinkMode) selectedConnectionProfile else null
        val finalPeer = connectionProfile?.peer ?: "$peerInput:$effectiveServerDtlsPort"
        val finalHashes = connectionProfile?.vkLinks ?: combinedHashes
        val finalLocalPort = connectionProfile?.localPort ?: effectiveLocalPort
        val finalPassword = connectionProfile?.wrapAPassword ?: savedConnectionPassword

        val intent = Intent(context, TunnelService::class.java).apply {
            action = "START"
            putExtra("peer", finalPeer)
            putExtra("vk_hashes", finalHashes)
            putExtra("secondary_vk_hash", "")
            putExtra("workers_per_hash", connectionProfile?.workers ?: workersInput.toInt())
            putExtra("port", finalLocalPort)
            putExtra("sni", sniInput)
            putExtra("connection_password", finalPassword)
            putExtra("vk_auth_mode", effectiveVkAuthMode)
            putExtra("captcha_mode", effectiveCaptchaMode)
            putExtra("captcha_solve_method", effectiveCaptchaSolveMethod)
            putExtra("fingerprint", activeFingerprint)
            putExtra("client_ids", activeClientIds)
            putExtra("obfs_mode", obfsMode)
            putExtra("free_turn", connectionProfile?.mode?.name == "WRAP_S")
            putExtra("free_obf_key", connectionProfile?.obfKey.orEmpty())
            putExtra("free_obf_profile", connectionProfile?.obfProfile.orEmpty())
            putExtra("free_client_id", connectionProfile?.clientId.orEmpty())
            putExtra("wireguard_config", connectionProfile?.wireGuardConfig.orEmpty())
        }
        if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent)
        else context.startService(intent)
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        if (pendingStartAfterVpnPermission) {
            pendingStartAfterVpnPermission = false
            if (VpnService.prepare(context) == null) {
                startTunnelService()
            } else {
                Toast.makeText(context, "VPN-разрешение не выдано", Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun requestVpnAndStart() {
        val vpnIntent = VpnService.prepare(context)
        if (vpnIntent != null) {
            pendingStartAfterVpnPermission = true
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            startTunnelService()
        }
    }

    
    if (showSecretsDialog) {
        SecretsDialog(
            settingsStore = settingsStore,
            initialPassword = savedConnectionPassword,
            manualPortsEnabled = manualPortsEnabled,
            initialServerDtlsPort = serverDtlsPortInput,
            initialServerWgPort = serverWgPortInput,
            initialLocalPort = portInput,
            onSaved = { dtls, wg, local ->
                serverDtlsPortInput = dtls
                serverWgPortInput = wg
                portInput = local
            },
            onDismiss = { showSecretsDialog = false }
        )
    }

    if (showHashesDialog) {
        HashesDialog(
            hash1 = vkHash1,
            hash2 = vkHash2,
            hash3 = vkHash3,
            hash4 = vkHash4,
            onSave = { h1, h2, h3, h4 ->
                val cleaned1 = stripVkUrlStatic(h1)
                val cleaned2 = stripVkUrlStatic(h2)
                val cleaned3 = stripVkUrlStatic(h3)
                val cleaned4 = stripVkUrlStatic(h4)
                vkHash1 = cleaned1
                vkHash2 = cleaned2
                vkHash3 = cleaned3
                vkHash4 = cleaned4
                saveTunnelSettingsNow(normalizeHashes(cleaned1, cleaned2, cleaned3, cleaned4)) {
                    showHashesDialog = false
                }
            },
            onDismiss = { showHashesDialog = false }
        )
    }

    if (showConnectionImport) {
        AlertDialog(
            onDismissRequest = { showConnectionImport = false },
            title = { Text("Импорт конфига") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = connectionImportText,
                        onValueChange = { connectionImportText = it.trim() },
                        label = { Text("Ссылка подключения") },
                        supportingText = { Text("wdtt://, vkturnproxy:// или freeturn://") },
                        minLines = 3,
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (connectionImportError.isNotBlank()) {
                        Text(connectionImportError, color = MaterialTheme.colorScheme.error)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val imported = runCatching { ConnectionProfileParser.parse(connectionImportText) }
                    imported.onSuccess { profile ->
                        scope.launch { settingsStore.saveConnectionProfile(profile) }
                        connectionImportError = ""
                        connectionImportText = ""
                        showConnectionImport = false
                    }.onFailure { error -> connectionImportError = error.message ?: "Не удалось импортировать ссылку" }
                }) { Text("Импортировать") }
            },
            dismissButton = { TextButton(onClick = { showConnectionImport = false }) { Text("Отмена") } }
        )
    }

    detailsProfile?.let { profile ->
        AlertDialog(
            onDismissRequest = { detailsProfile = null },
            title = { Text(profile.name) },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Режим: ${profile.mode.label}")
                    Text("Сервер: ${profile.peer}")
                    Text("VK call link: ${profile.vkLinks}")
                    Text("Локальный порт: ${profile.localPort}")
                    Text("Потоков: ${profile.workers}")
                    if (profile.mode.name == "WRAP_A") {
                        Text("Пароль: ${profile.wrapAPassword}")
                    } else {
                        Text("OBF profile: ${profile.obfProfile}")
                        Text("OBF key: ${profile.obfKey}")
                        Text("Client ID: ${profile.clientId}")
                        Text("WireGuard:\n${profile.wireGuardConfig.ifBlank { "Конфиг не указан" }}")
                    }
                }
            },
            confirmButton = { TextButton(onClick = { detailsProfile = null }) { Text("Готово") } },
            dismissButton = {
                TextButton(onClick = {
                    scope.launch { settingsStore.removeConnectionProfile(profile.id) }
                    detailsProfile = null
                }) { Icon(Icons.Default.Delete, contentDescription = "Удалить конфиг") }
            }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (!wdttLinkMode) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    
                    Text(
                        "Настройки туннеля",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    
                    AppSectionCard(
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        OutlinedTextField(
                            value = peerInput,
                            onValueChange = {
                                peerInput = it.filter { c -> !c.isWhitespace() }
                                scheduleSave()
                            },
                            label = { Text("IP сервера или домен (без порта)") },
                            placeholder = { Text("1.2.3.4 (или test.com)") },
                            singleLine = true,
                            isError = !isPeerValid && peerInput.isNotEmpty(),
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = MaterialTheme.colorScheme.primary,
                                unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                            )
                        )

                        OutlinedButton(
                            onClick = { showHashesDialog = true },
                            modifier = Modifier.fillMaxWidth().height(56.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = ButtonDefaults.outlinedButtonColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                                contentColor = MaterialTheme.colorScheme.onSurface
                            ),
                            border = BorderStroke(
                                1.dp,
                                if (hasInputHashErrors) MaterialTheme.colorScheme.error
                                else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
                            )
                        ) {
                            Icon(Icons.Default.Tag, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Настройка VK Хешей ($filledHashCount/4)", fontWeight = FontWeight.SemiBold)
                        }

                        val errorTexts = hashErrors.filter { !it.contains("короткий") }
                        if (errorTexts.isNotEmpty()) {
                            Text(
                                text = errorTexts.joinToString(", "),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }

            
                AppSectionCard(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(0.dp)
                ) {
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Мощность",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            text = "${currentWorkers.toInt()}",
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.primary
                        )
                    }

                    Spacer(Modifier.height(4.dp))

                    val maxWorkers = dynamicMaxWorkers
                    val minWorkers = WORKERS_PER_GROUP.toFloat()
                    val currentWorkersVal = roundToGroup(currentWorkers.coerceIn(minWorkers, maxWorkers), maxWorkers)

                    CompactSteppedSlider(
                        value = currentWorkersVal,
                        onValueChange = { raw ->
                            workersInput = roundToGroup(raw, maxWorkers)
                            scheduleSave()
                        },
                        valueRange = minWorkers..maxWorkers,
                        stepSize = WORKERS_PER_GROUP.toFloat(),
                        enabled = !tunnelRunning,
                        modifier = Modifier.fillMaxWidth()
                    )

                    
                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "Режим",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.weight(1f)
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            ProtocolChip("Вызов", useVKCallsAuth, enabled = !tunnelRunning) {
                                useVKCallsAuth = true
                                scope.launch { settingsStore.saveVkAuthMode("vkcalls") }
                            }
                            ProtocolChip("Капча", !useVKCallsAuth, enabled = !tunnelRunning) {
                                useVKCallsAuth = false
                                scope.launch { settingsStore.saveVkAuthMode("legacy") }
                            }
                        }
                    }

                    
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "Маскировка",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.weight(1f)
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            ProtocolChip("Аудио", obfsMode == "audio", enabled = !tunnelRunning) {
                                obfsMode = "audio"
                                scope.launch { settingsStore.saveObfsMode("audio") }
                            }
                            ProtocolChip("Видео", obfsMode == "video", enabled = !tunnelRunning) {
                                obfsMode = "video"
                                scope.launch { settingsStore.saveObfsMode("video") }
                            }
                        }
                    }

                    AnimatedVisibility(
                        visible = !useVKCallsAuth,
                        enter = fadeIn() + expandVertically(),
                        exit = fadeOut() + shrinkVertically()
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                            HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                            )

                            
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    if (autoCaptchaEnabled) "Авто капча" else "Ручная капча",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium,
                                    modifier = Modifier.weight(1f)
                                )
                                Switch(
                                    checked = autoCaptchaEnabled,
                                    enabled = !tunnelRunning,
                                    onCheckedChange = { enabled ->
                                        autoCaptchaEnabled = enabled
                                        scope.launch {
                                            if (enabled) {
                                                settingsStore.saveCaptchaMode("auto")
                                                settingsStore.saveCaptchaSolveMethod("auto")
                                            } else {
                                                val mode = if (useWVCaptcha) "wv" else "rjs"
                                                settingsStore.saveCaptchaMode(mode)
                                                settingsStore.saveCaptchaSolveMethod(if (mode == "wv" && isManualMode) "manual" else "auto")
                                            }
                                        }
                                    }
                                )
                            }

                            AnimatedVisibility(
                                visible = !autoCaptchaEnabled,
                                enter = fadeIn() + expandVertically(),
                                exit = fadeOut() + shrinkVertically()
                            ) {
                                Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                                    
                                    HorizontalDivider(
                                        modifier = Modifier.padding(vertical = 4.dp),
                                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                                    )

                                    
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            "Метод обхода капчи",
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Medium,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            ProtocolChip("WBV", useWVCaptcha, enabled = !tunnelRunning) {
                                                useWVCaptcha = true
                                                isManualMode = wbvManualMode
                                                scope.launch {
                                                    settingsStore.saveCaptchaMode("wv")
                                                    settingsStore.saveCaptchaSolveMethod(if (wbvManualMode) "manual" else "auto")
                                                }
                                            }
                                            ProtocolChip("RJS", !useWVCaptcha, enabled = !tunnelRunning, isError = false) {
                                                useWVCaptcha = false
                                                isManualMode = false
                                                scope.launch {
                                                    settingsStore.saveCaptchaMode("rjs")
                                                    settingsStore.saveCaptchaSolveMethod("auto")
                                                }
                                            }
                                        }
                                    }

                                    
                                    HorizontalDivider(
                                        modifier = Modifier.padding(vertical = 4.dp),
                                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                                    )

                                    
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text(
                                            "Режим обхода",
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Medium,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            if (useWVCaptcha) {
                                                ProtocolChip(
                                                    "РУЧ",
                                                    isManualMode,
                                                    enabled = !tunnelRunning,
                                                    isError = false
                                                ) {
                                                    isManualMode = true
                                                    wbvManualMode = true
                                                    scope.launch { settingsStore.saveWbvCaptchaSolveMethod("manual") }
                                                }
                                                ProtocolChip(
                                                    "АВТ",
                                                    !isManualMode,
                                                    enabled = !tunnelRunning,
                                                    isError = false
                                                ) {
                                                    isManualMode = false
                                                    wbvManualMode = false
                                                    scope.launch { settingsStore.saveWbvCaptchaSolveMethod("auto") }
                                                }
                                            } else {
                                                ProtocolChip(
                                                    "АВТ",
                                                    selected = true,
                                                    enabled = false,
                                                    isError = false
                                                ) {}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp, bottom = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "Режим ссылки",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.weight(1f)
                        )
                        Switch(
                            checked = wdttLinkMode,
                            onCheckedChange = { enabled ->
                                scope.launch {
                                    settingsStore.saveWdttLinkMode(enabled)
                                }
                            }
                        )
                    }

                    if (wdttLinkMode) {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Конфиги", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
                                IconButton(onClick = { showConnectionImport = true }, enabled = !tunnelRunning) {
                                    Icon(Icons.Default.Add, contentDescription = "Добавить конфиг")
                                }
                            }
                            if (connectionProfiles.isEmpty()) {
                                Text("Добавьте ссылку wdtt://, vkturnproxy:// или freeturn://", color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            connectionProfiles.forEach { profile ->
                                val selected = profile.id == selectedConnectionProfile?.id
                                Surface(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(12.dp),
                                    color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                                    onClick = {
                                        if (profile.id != selectedConnectionProfile?.id && !profileSwitching) {
                                            scope.launch {
                                                profileSwitching = true
                                                try {
                                                    settingsStore.selectConnectionProfile(profile.id)
                                                    if (tunnelRunning && profile.isReady) {
                                                        TunnelManager.stopAndWait()
                                                        startTunnelService(profile)
                                                    }
                                                } finally {
                                                    profileSwitching = false
                                                }
                                            }
                                        }
                                    }
                                ) {
                                    Row(
                                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(profile.name, maxLines = 1, fontWeight = FontWeight.Medium)
                                            Text(
                                                "${profile.mode.label}${if (profile.mode.name == "WRAP_S") " · ${profile.obfProfile}" else ""}",
                                                style = MaterialTheme.typography.labelMedium,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                        IconButton(onClick = { detailsProfile = profile }) {
                                            Icon(Icons.Default.Info, contentDescription = "Параметры конфига")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

        
        val tunnelSecretsMissing = savedConnectionPassword.isBlank()

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (!wdttLinkMode) {
                OutlinedButton(
                    onClick = { showSecretsDialog = true },
                    modifier = Modifier.weight(1f).height(52.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        containerColor = if (tunnelSecretsMissing) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surface,
                        contentColor = if (tunnelSecretsMissing) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurface
                    ),
                    border = BorderStroke(
                        1.dp,
                        if (tunnelSecretsMissing) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
                    )
                ) {
                    Icon(imageVector = Icons.Default.Key, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Секреты", fontWeight = FontWeight.SemiBold, maxLines = 1)
                }
            }

            val buttonColor by animateColorAsState(
                targetValue = if (tunnelRunning) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                animationSpec = tween(400),
                label = "btn_color"
            )
            val buttonContentColor by animateColorAsState(
                targetValue = if (tunnelRunning) MaterialTheme.colorScheme.onError else MaterialTheme.colorScheme.onPrimary,
                animationSpec = tween(400),
                label = "btn_content_color"
            )

            Button(
                onClick = {
                    if (tunnelRunning) {
                        context.startService(
                            Intent(context, TunnelService::class.java).apply { action = "STOP" }
                        )
                    } else {
                        requestVpnAndStart()
                    }
                },
                enabled = (isValid && !cooldownActive) || tunnelRunning,
                modifier = Modifier
                    .weight(1f)
                    .height(52.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = buttonColor,
                    contentColor = buttonContentColor
                )
            ) {
                Icon(
                    imageVector = if (tunnelRunning) Icons.Default.Stop else Icons.Default.PowerSettingsNew,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = when {
                        tunnelRunning -> "Остановить"
                        cooldownActive -> "Подождите..."
                        else -> "Подключить"
                    },
                    fontWeight = FontWeight.Bold,
                    maxLines = 1
                )
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "Для мобильных сетей.\nЕсли не работает режим \"Вызов\", попробуйте \"Капча\". Если автокапча не работает, попробуйте ручную. Маскировка сильно роли не играет.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun ProtocolChip(label: String, selected: Boolean, enabled: Boolean = true, isError: Boolean = false, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        enabled = enabled,
        label = {
            Text(
                label,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium
            )
        },
        shape = RoundedCornerShape(16.dp),
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = MaterialTheme.colorScheme.primary,
            selectedLabelColor = MaterialTheme.colorScheme.onPrimary,
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
            labelColor = MaterialTheme.colorScheme.onSurface,
            disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.38f),
            disabledSelectedContainerColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.38f),
            disabledLabelColor = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f)
        ),
        border = FilterChipDefaults.filterChipBorder(
            enabled = enabled,
            selected = selected,
            borderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f),
            selectedBorderColor = MaterialTheme.colorScheme.primary,
            disabledBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f),
            disabledSelectedBorderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.38f)
        )
    )
}

@Composable
private fun CompactSteppedSlider(
    value: Float,
    onValueChange: (Float) -> Unit,
    valueRange: ClosedFloatingPointRange<Float>,
    stepSize: Float,
    enabled: Boolean,
    modifier: Modifier = Modifier
) {
    val activeColor = MaterialTheme.colorScheme.primary.copy(alpha = if (enabled) 1f else 0.38f)
    val inactiveColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = if (enabled) 1f else 0.55f)
    val thumbStrokeColor = MaterialTheme.colorScheme.surface
    val density = LocalDensity.current
    val thumbRadiusPx = with(density) { 9.dp.toPx() }
    val trackWidthPx = with(density) { 5.dp.toPx() }

    fun snap(raw: Float): Float {
        val min = valueRange.start
        val max = valueRange.endInclusive
        val snapped = (((raw - min) / stepSize).roundToInt() * stepSize) + min
        return snapped.coerceIn(min, max)
    }

    fun positionToValue(x: Float, width: Float): Float {
        val left = thumbRadiusPx
        val right = (width - thumbRadiusPx).coerceAtLeast(left + 1f)
        val fraction = ((x.coerceIn(left, right) - left) / (right - left)).coerceIn(0f, 1f)
        return snap(valueRange.start + fraction * (valueRange.endInclusive - valueRange.start))
    }

    Canvas(
        modifier = modifier
            .height(34.dp)
            .pointerInput(enabled, valueRange, stepSize) {
                if (!enabled) return@pointerInput
                detectTapGestures { offset ->
                    onValueChange(positionToValue(offset.x, size.width.toFloat()))
                }
            }
            .pointerInput(enabled, valueRange, stepSize) {
                if (!enabled) return@pointerInput
                detectDragGestures { change, _ ->
                    onValueChange(positionToValue(change.position.x, size.width.toFloat()))
                }
            }
    ) {
        val centerY = size.height / 2f
        val left = thumbRadiusPx
        val right = size.width - thumbRadiusPx
        val range = (valueRange.endInclusive - valueRange.start).coerceAtLeast(1f)
        val fraction = ((value - valueRange.start) / range).coerceIn(0f, 1f)
        val thumbX = left + (right - left) * fraction

        drawLine(
            color = inactiveColor,
            start = Offset(left, centerY),
            end = Offset(right, centerY),
            strokeWidth = trackWidthPx,
            cap = StrokeCap.Round
        )
        drawLine(
            color = activeColor,
            start = Offset(left, centerY),
            end = Offset(thumbX, centerY),
            strokeWidth = trackWidthPx,
            cap = StrokeCap.Round
        )

        val tickCount = (((valueRange.endInclusive - valueRange.start) / stepSize).roundToInt()).coerceAtLeast(1)
        repeat(tickCount + 1) { index ->
            val tickFraction = index / tickCount.toFloat()
            val tickX = left + (right - left) * tickFraction
            drawCircle(
                color = if (tickX <= thumbX) activeColor else inactiveColor,
                radius = 2.dp.toPx(),
                center = Offset(tickX, centerY)
            )
        }

        drawCircle(
            color = activeColor,
            radius = thumbRadiusPx,
            center = Offset(thumbX, centerY)
        )
        drawCircle(
            color = thumbStrokeColor,
            radius = thumbRadiusPx,
            center = Offset(thumbX, centerY),
            style = androidx.compose.ui.graphics.drawscope.Stroke(width = 2.dp.toPx())
        )
    }
}

/**
 * Округляет значение до ближайшего кратного группы.
 */
private fun roundToGroup(value: Float, groupSize: Float): Float {
    val groups = (value / groupSize).toInt()
    val remainder = value % groupSize
    return if (remainder >= groupSize / 2f) {
        (groups + 1) * groupSize
    } else {
        groups * groupSize
    }
}


