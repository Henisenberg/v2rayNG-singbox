package com.v2ray.ang.core

import android.content.Context
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit

/** Owns the packaged sing-box process for the daemon process. */
object SingBoxProcessManager {
    private const val CORE_FILE_NAME = "libsing-box.so"
    private const val CONFIG_FILE_NAME = "sing-box.json"
    private const val LOG_FILE_NAME = "sing-box.log"
    private const val PID_FILE_NAME = "sing-box.pid"

    /**
     * The core either dies within this window on a bad start or keeps the inbound
     * port open; polling readiness beats a fixed sleep on slow devices.
     */
    private const val STARTUP_TIMEOUT_MS = 4000L

    @Volatile
    private var process: Process? = null

    fun isRunning(): Boolean = process?.isAlive == true

    @Synchronized
    fun start(context: Context, config: String, listenPort: Int) {
        check(!isRunning()) { "sing-box is already running" }
        val binary = File(context.applicationInfo.nativeLibraryDir, CORE_FILE_NAME)
        check(binary.isFile) { "sing-box $SING_BOX_VERSION is not packaged for this ABI" }

        // A previous daemon death can orphan the core child process and keep the port bound.
        stopStaleProcess(context)

        // Another proxy app (for example the original v2rayNG) holding the port would make the
        // core die on bind; report that directly instead of surfacing the core's exit log.
        check(!isPortAccepting(listenPort)) {
            "Local port $listenPort is already in use by another process; stop it (for example the original v2rayNG) and try again"
        }

        val configFile = File(context.filesDir, CONFIG_FILE_NAME).apply { writeText(config) }
        // Fresh log per attempt: the failure summary must describe THIS start only.
        val logFile = File(context.cacheDir, LOG_FILE_NAME).apply { delete() }
        val pidFile = File(context.filesDir, PID_FILE_NAME)
        checkConfig(binary, configFile, logFile)
        // "sh -c" records the shell pid and exec replaces it with the core, so the pid file
        // tracks the core process on every API level (java.lang.Process#pid is unavailable).
        process = ProcessBuilder(
            "sh", "-c",
            "echo \$\$ > '${pidFile.absolutePath}'; exec '${binary.absolutePath}' run -c '${configFile.absolutePath}'"
        )
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.appendTo(logFile))
            .start()

        // Ready means: alive and the mixed inbound accepts TCP connections.
        val deadline = System.currentTimeMillis() + STARTUP_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (!isRunning()) {
                error("sing-box exited during startup: ${readStartupError(logFile)}")
            }
            if (isPortAccepting(listenPort)) {
                LogUtil.i(AppConfig.TAG, "Sing-box $SING_BOX_VERSION started")
                return
            }
            Thread.sleep(100)
        }
        error(
            if (isRunning()) {
                "sing-box did not open the local inbound port $listenPort in time: ${readStartupError(logFile)}"
            } else {
                "sing-box exited during startup: ${readStartupError(logFile)}"
            }
        )
    }

    @Synchronized
    fun stop() {
        val running = process ?: return
        try {
            running.destroy()
            if (!running.waitFor(3, TimeUnit.SECONDS)) {
                running.destroyForcibly()
                running.waitFor(3, TimeUnit.SECONDS)
            }
        } finally {
            process = null
        }
    }

    /**
     * Kills the core process left behind if the daemon died while sing-box kept running.
     * The orphan runs with the app's uid, so the shell "kill" is permitted to signal it.
     */
    private fun stopStaleProcess(context: Context) {
        val pidFile = File(context.filesDir, PID_FILE_NAME)
        val stalePid = pidFile.takeIf { it.isFile }?.readText()?.trim()?.toIntOrNull()
        if (stalePid != null) {
            try {
                val kill = Runtime.getRuntime().exec(arrayOf("kill", stalePid.toString()))
                kill.waitFor(2, TimeUnit.SECONDS)
                Thread.sleep(200)
            } catch (e: Exception) {
                LogUtil.w(AppConfig.TAG, "Sing-box: failed to kill stale process $stalePid", e)
            }
        }
        pidFile.delete()
    }

    private fun checkConfig(binary: File, configFile: File, logFile: File) {
        val checkProcess = ProcessBuilder(binary.absolutePath, "check", "-c", configFile.absolutePath)
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.appendTo(logFile))
            .start()
        if (!checkProcess.waitFor(5, TimeUnit.SECONDS)) {
            checkProcess.destroyForcibly()
            error("sing-box configuration check timed out: ${readStartupError(logFile)}")
        }
        if (checkProcess.exitValue() != 0) {
            error("sing-box rejected the generated configuration: ${readStartupError(logFile)}")
        }
    }

    /** True when something on the loopback accepts TCP connections on [port]. */
    private fun isPortAccepting(port: Int): Boolean = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(AppConfig.LOOPBACK, port), 250)
            true
        }
    } catch (_: Exception) {
        false
    }

    /**
     * The actionable lines of a failed start. Go panics print their reason at the TOP of
     * the trace, fatal config errors print a single FATAL line, so read the whole output
     * and pick the reason lines instead of blindly taking the tail.
     */
    private fun readStartupError(logFile: File): String = try {
        val lines = logFile.readLines().map(String::trim).filter(String::isNotEmpty)
        val reasons = lines.filter { line ->
            line.startsWith("panic:") ||
                line.startsWith("fatal error:") ||
                line.startsWith("runtime:") ||
                line.startsWith("FATAL") ||
                line.startsWith("start service") ||
                line.contains("FATA[") ||
                line.contains("ERROR[")
        }
        val picked = if (reasons.isEmpty()) lines.take(6) else (reasons.take(6) + lines.take(1)).distinct()
        picked.joinToString(" | ") { it.take(400) }.ifBlank { "no log output" }
    } catch (_: Exception) {
        "log unavailable"
    }

    const val SING_BOX_VERSION = "1.13.21"
}
