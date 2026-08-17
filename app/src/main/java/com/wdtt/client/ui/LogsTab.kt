package com.wdtt.client.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.animation.core.*
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.wdtt.client.LogEntry
import com.wdtt.client.TunnelManager
import com.wdtt.client.WDTTColors
import com.wdtt.client.SettingsStore
import com.wdtt.client.SystemStats
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsTab() {
    val context = LocalContext.current
    val settingsStore = remember { SettingsStore(context) }
    val loggingEnabled by settingsStore.loggingEnabled.collectAsStateWithLifecycle(initialValue = true)
    val scope = rememberCoroutineScope()
    val currentLogs by TunnelManager.logs.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    
    // Статистика системы
    val cpuUsage by SystemStats.cpuUsage.collectAsState()
    val ramUsage by SystemStats.ramUsage.collectAsState()
    val ramTotal by SystemStats.ramTotal.collectAsState()
    val ramUsed by SystemStats.ramUsed.collectAsState()

    // Обновляем статистику каждую секунду
    LaunchedEffect(Unit) {
        while (true) {
            SystemStats.updateStats(context)
            delay(1000)
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        
        Row(
            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "Лог событий",
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface
            )
            Row {
                IconButton(onClick = { TunnelManager.clearLogs() }) {
                    Icon(Icons.Default.Delete, contentDescription = "Clear", tint = MaterialTheme.colorScheme.primary)
                }
                IconButton(onClick = {
                    val text = currentLogs.joinToString("\n") { "${it.message} (x${it.count})" }
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = ClipData.newPlainText("WDTT Logs", text)
                    clipboard.setPrimaryClip(clip)
                    Toast.makeText(context, "Скопировано", Toast.LENGTH_SHORT).show()
                }) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy", tint = MaterialTheme.colorScheme.primary)
                }
            }
        }

        // Блок статистики
        Card(
            modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
            ),
            border = androidx.compose.foundation.BorderStroke(
                1.dp,
                MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    "📊 Статистика системы",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                
                // CPU
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.Memory,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = if (cpuUsage > 70) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(
                            "CPU:",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Text(
                        String.format("%.1f%%", cpuUsage),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = if (cpuUsage > 70) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                    )
                }
                
                // CPU Progress
                LinearProgressIndicator(
                    progress = { (cpuUsage / 100f).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth().height(4.dp),
                    color = when {
                        cpuUsage > 70 -> MaterialTheme.colorScheme.error
                        cpuUsage > 50 -> MaterialTheme.colorScheme.tertiary
                        else -> MaterialTheme.colorScheme.primary
                    },
                    trackColor = MaterialTheme.colorScheme.surfaceVariant
                )
                
                Spacer(Modifier.height(4.dp))
                
                // RAM
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.Storage,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = if (ramUsage > 80) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(
                            "RAM:",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Text(
                        "${formatBytes(ramUsed)} / ${formatBytes(ramTotal)} (${String.format("%.1f%%", ramUsage)})",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = if (ramUsage > 80) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                    )
                }
                
                // RAM Progress
                LinearProgressIndicator(
                    progress = { (ramUsage / 100f).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth().height(4.dp),
                    color = when {
                        ramUsage > 80 -> MaterialTheme.colorScheme.error
                        ramUsage > 60 -> MaterialTheme.colorScheme.tertiary
                        else -> MaterialTheme.colorScheme.primary
                    },
                    trackColor = MaterialTheme.colorScheme.surfaceVariant
                )
            }
        }

        
        AppSectionCard(
            modifier = Modifier.padding(bottom = 12.dp),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(0.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    "Активное логирование",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Switch(
                    checked = loggingEnabled,
                    onCheckedChange = { enabled ->
                        scope.launch {
                            settingsStore.saveLoggingEnabled(enabled)
                            if (!enabled) {
                                TunnelManager.clearLogs()
                            }
                        }
                    }
                )
            }
        }

        
        val isDark = isSystemInDarkTheme()
        val terminalBg = if (isDark) WDTTColors.terminalBgDark else WDTTColors.terminalBg

        Card(
            modifier = Modifier.fillMaxSize(),
            colors = CardDefaults.cardColors(containerColor = terminalBg),
            shape = RoundedCornerShape(20.dp),
            elevation = CardDefaults.cardElevation(defaultElevation = 6.dp)
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize().padding(12.dp),
                contentPadding = PaddingValues(bottom = 12.dp)
            ) {
                items(currentLogs, key = { it.key }) { entry ->
                    LogLine(entry)
                }
            }
        }
    }
}

@Composable
fun LogLine(entry: LogEntry) {
    val color = when {
        entry.isError -> WDTTColors.terminalRed
        entry.priority <= 2 -> WDTTColors.terminalGreen
        entry.priority == 3 -> WDTTColors.terminalBlue
        else -> WDTTColors.terminalText
    }

    var trigger by remember { mutableIntStateOf(0) }
    LaunchedEffect(entry.count) { trigger++ }

    val animatedScale by animateFloatAsState(
        targetValue = if (trigger > 0) 1.15f else 1.0f,
        animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy),
        label = "scale",
        finishedListener = { trigger = 0 }
    )

    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Surface(
            color = WDTTColors.terminalCounter.copy(alpha = 0.2f),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .defaultMinSize(minWidth = 24.dp, minHeight = 24.dp)
                .graphicsLayer(scaleX = animatedScale, scaleY = animatedScale)
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.padding(horizontal = 6.dp)
            ) {
                Text(
                    text = "${entry.count}",
                    color = WDTTColors.terminalBlue,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1
                )
            }
        }

        Spacer(modifier = Modifier.width(12.dp))

        Text(
            text = entry.message,
            color = color,
            fontSize = 13.sp,
            fontFamily = FontFamily.Monospace,
            fontWeight = if (entry.isError) FontWeight.Bold else FontWeight.Normal,
            lineHeight = 18.sp,
            modifier = Modifier.weight(1f)
        )
    }
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes >= 1_073_741_824 -> String.format("%.1f GB", bytes / 1_073_741_824.0)
        bytes >= 1_048_576 -> String.format("%.1f MB", bytes / 1_048_576.0)
        bytes >= 1024 -> String.format("%.1f KB", bytes / 1024.0)
        else -> "$bytes B"
    }
}
