package com.wdtt.client

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.Debug
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.BufferedReader
import java.io.FileReader

object SystemStats {
    private val _cpuUsage = MutableStateFlow(0f)
    val cpuUsage: StateFlow<Float> = _cpuUsage.asStateFlow()
    
    private val _ramUsage = MutableStateFlow(0f)
    val ramUsage: StateFlow<Float> = _ramUsage.asStateFlow()
    
    private val _ramTotal = MutableStateFlow(0L)
    val ramTotal: StateFlow<Long> = _ramTotal.asStateFlow()
    
    private val _ramUsed = MutableStateFlow(0L)
    val ramUsed: StateFlow<Long> = _ramUsed.asStateFlow()
    
    private var lastCpuTime = 0L
    private var lastProcessCpuTime = 0L
    
    fun updateStats(context: Context) {
        updateRamStats(context)
        updateCpuStats()
    }
    
    private fun updateRamStats(context: Context) {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memoryInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memoryInfo)
        
        val totalRam = memoryInfo.totalMem
        val availableRam = memoryInfo.availMem
        val usedRam = totalRam - availableRam
        
        _ramTotal.value = totalRam
        _ramUsed.value = usedRam
        _ramUsage.value = (usedRam.toFloat() / totalRam.toFloat()) * 100f
    }
    
    private fun updateCpuStats() {
        try {
            val pid = android.os.Process.myPid()
            val statFile = "/proc/$pid/stat"
            val cpuStatFile = "/proc/stat"
            
            // Читаем время процесса
            val processCpuTime = readProcessCpuTime(statFile)
            val totalCpuTime = readTotalCpuTime(cpuStatFile)
            
            if (lastProcessCpuTime > 0 && lastCpuTime > 0) {
                val processDelta = processCpuTime - lastProcessCpuTime
                val totalDelta = totalCpuTime - lastCpuTime
                
                if (totalDelta > 0) {
                    val usage = (processDelta.toFloat() / totalDelta.toFloat()) * 100f
                    _cpuUsage.value = usage.coerceIn(0f, 100f)
                }
            }
            
            lastProcessCpuTime = processCpuTime
            lastCpuTime = totalCpuTime
        } catch (_: Exception) {
            // Если не удалось прочитать, пробуем альтернативный метод
            updateCpuUsageAlternative()
        }
    }
    
    private fun readProcessCpuTime(statFile: String): Long {
        return try {
            val content = FileReader(statFile).use { BufferedReader(it).readText() }
            val parts = content.split(" ")
            // utime (14) + stime (15)
            val utime = parts.getOrNull(13)?.toLongOrNull() ?: 0
            val stime = parts.getOrNull(14)?.toLongOrNull() ?: 0
            utime + stime
        } catch (_: Exception) {
            0
        }
    }
    
    private fun readTotalCpuTime(cpuStatFile: String): Long {
        return try {
            val content = FileReader(cpuStatFile).use { BufferedReader(it).readText() }
            val firstLine = content.split("\n").firstOrNull() ?: "cpu 0 0 0 0 0 0 0 0"
            val parts = firstLine.split(" ")
            var total = 0L
            for (i in 1 until parts.size) {
                total += parts.getOrNull(i)?.toLongOrNull() ?: 0
            }
            total
        } catch (_: Exception) {
            0
        }
    }
    
    private fun updateCpuUsageAlternative() {
        try {
            val pid = android.os.Process.myPid()
            val statFile = "/proc/$pid/stat"
            val content = FileReader(statFile).use { BufferedReader(it).readText() }
            val parts = content.split(" ")
            
            val utime = parts.getOrNull(13)?.toLongOrNull() ?: 0
            val stime = parts.getOrNull(14)?.toLongOrNull() ?: 0
            val cutime = parts.getOrNull(15)?.toLongOrNull() ?: 0
            val cstime = parts.getOrNull(16)?.toLongOrNull() ?: 0
            
            val totalTime = utime + stime + cutime + cstime
            val hz = 100 // обычно 100, но может быть 1000
            
            // Простая оценка
            _cpuUsage.value = (totalTime.toFloat() / hz).coerceIn(0f, 100f)
        } catch (_: Exception) {
            _cpuUsage.value = 0f
        }
    }
}
