package com.wdtt.client

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object DeployManager {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _isDeploying = MutableStateFlow(false)
    val isDeploying: StateFlow<Boolean> = _isDeploying.asStateFlow()
    
    private val _deployProgress = MutableStateFlow(0f)
    val deployProgress: StateFlow<Float> = _deployProgress.asStateFlow()
    
    private val _currentStep = MutableStateFlow("")
    val currentStep: StateFlow<String> = _currentStep.asStateFlow()
    
    private val _lastResult = MutableStateFlow("")
    val lastResult: StateFlow<String> = _lastResult.asStateFlow()

    @Volatile
    var activeSession: com.jcraft.jsch.Session? = null
    private var deployStartTime = 0L
    private var errorsFile: File? = null
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())

    
    fun init(context: Context) {
        val dir = context.getExternalFilesDir(null) ?: context.filesDir
        errorsFile = File(dir, "errors.log")
    }

    fun getErrorsFile(): File? = errorsFile

    
    @Synchronized
    fun writeError(msg: String) {
        val file = errorsFile ?: return
        try {
            val timestamp = dateFormat.format(Date())
            file.appendText("[$timestamp] $msg\n")
            
            if (file.length() > 500_000) {
                val text = file.readText()
                file.writeText(text.takeLast(200_000))
            }
        } catch (_: Exception) { }
    }

    fun startDeploy() {
        
        if (_isDeploying.value && deployStartTime > 0 &&
            System.currentTimeMillis() - deployStartTime > 30 * 60 * 1000) {
            writeError("Автосброс: предыдущий деплой завис >30 мин")
            forceReset()
        }
        _isDeploying.value = true
        deployStartTime = System.currentTimeMillis()
        _deployProgress.value = 0f
        _currentStep.value = "Инициализация..."
        _lastResult.value = ""
    }

    fun stopDeploy(result: String = "") {
        _isDeploying.value = false
        deployStartTime = 0L
        if (result.isNotBlank()) _lastResult.value = result
        val session = activeSession
        activeSession = null
        try { session?.disconnect() } catch (_: Exception) {}
    }

    
    fun forceReset() {
        val session = activeSession
        activeSession = null
        try { session?.disconnect() } catch (_: Exception) {}
        _isDeploying.value = false
        deployStartTime = 0L
        _deployProgress.value = 0f
        _currentStep.value = ""
    }

    fun updateProgress(progress: Float, step: String) {
        _deployProgress.value = progress
        _currentStep.value = step
    }
}
