package com.wdtt.client

import android.net.Uri
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

enum class ConnectionMode(val label: String) {
    WRAP_A("SRTP-WRAP-A"),
    WRAP_S("SRTP-WRAP-S")
}

fun normalizeConnectionProfileWorkers(value: Int): Int =
    value.coerceIn(1, 108)

data class ConnectionProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val mode: ConnectionMode,
    val peer: String,
    val vkLinks: String,
    val localPort: Int = 9000,
    val workers: Int = 18,
    val wrapAPassword: String = "",
    val obfKey: String = "",
    val obfProfile: String = "rtpopus3",
    val clientId: String = "",
    val wireGuardConfig: String = "",
    val sourceLink: String = ""
) {
    val isReady: Boolean
        get() = peer.isNotBlank() && vkLinks.isNotBlank() && when (mode) {
            ConnectionMode.WRAP_A -> wrapAPassword.isNotBlank()
            ConnectionMode.WRAP_S -> obfKey.length == 64 && clientId.isNotBlank() && wireGuardConfig.isNotBlank()
        }

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("mode", mode.name)
        put("peer", peer)
        put("vkLinks", vkLinks)
        put("localPort", localPort)
        put("workers", workers)
        put("wrapAPassword", wrapAPassword)
        put("obfKey", obfKey)
        put("obfProfile", obfProfile)
        put("clientId", clientId)
        put("wireGuardConfig", wireGuardConfig)
        put("sourceLink", sourceLink)
    }

    companion object {
        fun fromJson(json: JSONObject): ConnectionProfile? = runCatching {
            val mode = ConnectionMode.valueOf(json.optString("mode"))
            ConnectionProfile(
                id = json.optString("id").ifBlank { UUID.randomUUID().toString() },
                name = json.optString("name").ifBlank { json.optString("peer") },
                mode = mode,
                peer = json.optString("peer"),
                vkLinks = json.optString("vkLinks"),
                localPort = json.optInt("localPort", 9000).coerceIn(1, 65535),
                workers = normalizeConnectionProfileWorkers(json.optInt("workers", 18)),
                wrapAPassword = json.optString("wrapAPassword"),
                obfKey = json.optString("obfKey"),
                obfProfile = json.optString("obfProfile", "rtpopus3"),
                clientId = json.optString("clientId"),
                wireGuardConfig = json.optString("wireGuardConfig"),
                sourceLink = json.optString("sourceLink")
            )
        }.getOrNull()

        fun encodeList(profiles: List<ConnectionProfile>): String = JSONArray().apply {
            profiles.forEach { put(it.toJson()) }
        }.toString()

        fun decodeList(value: String): List<ConnectionProfile> = runCatching {
            val array = JSONArray(value)
            buildList {
                for (index in 0 until array.length()) {
                    fromJson(array.optJSONObject(index) ?: continue)?.let(::add)
                }
            }
        }.getOrDefault(emptyList())
    }
}

object ConnectionProfileParser {
    fun parse(rawLink: String): ConnectionProfile {
        val raw = rawLink.trim()
        require(raw.isNotEmpty()) { "Ссылка пуста" }
        return when (Uri.parse(raw).scheme?.lowercase()) {
            "wdtt" -> parseWdtt(raw)
            "vkturnproxy" -> parseVkTurnProxy(raw)
            "freeturn" -> throw IllegalArgumentException(
                "freeturn:// не содержит VK-ссылку и WireGuard-конфиг; используйте vkturnproxy://"
            )
            else -> throw IllegalArgumentException("Поддерживаются ссылки wdtt:// и vkturnproxy://")
        }
    }

    private fun parseWdtt(raw: String): ConnectionProfile {
        val parts = raw.removePrefix("wdtt://").split(":")
        require(parts.size >= 6) { "Некорректная ссылка wdtt://" }
        val host = parts[0].trim()
        val dtlsPort = parts[1].toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw IllegalArgumentException("Некорректный DTLS-порт в wdtt://")
        val localPort = parts[3].toIntOrNull()?.takeIf { it in 1..65535 } ?: 9000
        val password = parts[4].trim()
        val vkLinks = parts.drop(5).joinToString(":").trim()
        require(host.isNotBlank() && password.isNotBlank() && vkLinks.isNotBlank()) {
            "Ссылка wdtt:// не содержит обязательные параметры"
        }
        return ConnectionProfile(
            name = "$host:$dtlsPort",
            mode = ConnectionMode.WRAP_A,
            peer = "$host:$dtlsPort",
            vkLinks = vkLinks,
            localPort = localPort,
            wrapAPassword = password,
            sourceLink = raw
        )
    }

    private fun parseVkTurnProxy(raw: String): ConnectionProfile {
        val uri = Uri.parse(raw)
        require(uri.host.isNullOrBlank() || uri.host.equals("import", true)) { "Неверный vkturnproxy:// URL" }
        val data = uri.getQueryParameter("data")?.takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("В vkturnproxy:// отсутствует data")
        val root = JSONObject(decodeBase64Url(data).toString(Charsets.UTF_8))
        val settings = root.optJSONObject("settings") ?: throw IllegalArgumentException("В vkturnproxy:// отсутствуют настройки")
        val useWrapS = settings.optBoolean("useWrapS", false)
        val useWrapA = settings.optBoolean("useWrapA", false)
        val peer = settings.stringValue("peerAddress")
        require(peer.isNotBlank()) { "В ссылке не указан адрес сервера" }
        return when {
            useWrapS -> freeTurnProfile(
                peer = peer,
                vkLinks = settings.stringValue("vkLink"),
                workers = settings.optInt("numConnections", 18),
                obfKey = settings.stringValue("wrapKeyHex"),
                obfProfile = settings.stringValue("obfProfile").ifBlank { "rtpopus3" },
                clientId = settings.stringValue("clientID"),
                privateKey = settings.stringValue("privateKey"),
                peerPublicKey = settings.stringValue("peerPublicKey"),
                tunnelAddress = settings.stringValue("tunnelAddress"),
                dnsServers = settings.stringValue("dnsServers"),
                raw = raw
            )
            useWrapA -> ConnectionProfile(
                name = peer,
                mode = ConnectionMode.WRAP_A,
                peer = peer,
                vkLinks = settings.stringValue("vkLink"),
                localPort = 9000,
                workers = normalizeConnectionProfileWorkers(settings.optInt("numConnections", 18)),
                wrapAPassword = settings.stringValue("wrapAPassword"),
                sourceLink = raw
            )
            else -> throw IllegalArgumentException("vkturnproxy:// не содержит SRTP-WRAP-A или SRTP-WRAP-S")
        }
    }

    private fun freeTurnProfile(
        peer: String,
        vkLinks: String,
        workers: Int,
        obfKey: String,
        obfProfile: String,
        clientId: String,
        privateKey: String,
        peerPublicKey: String,
        tunnelAddress: String,
        dnsServers: String,
        raw: String
    ): ConnectionProfile {
        require(obfProfile in setOf("rtpopus", "rtpopus2", "rtpopus3")) {
            "Неизвестный OBF profile: $obfProfile"
        }
        val wireGuardConfig = if (privateKey.isNotBlank() && peerPublicKey.isNotBlank() && tunnelAddress.isNotBlank()) {
            buildWireGuardConfig(privateKey, peerPublicKey, tunnelAddress, dnsServers)
        } else {
            ""
        }
        return ConnectionProfile(
            name = peer,
            mode = ConnectionMode.WRAP_S,
            peer = peer,
            vkLinks = vkLinks,
            localPort = 9000,
            workers = normalizeConnectionProfileWorkers(workers),
            obfKey = obfKey.lowercase(),
            obfProfile = obfProfile,
            clientId = clientId.ifBlank { UUID.randomUUID().toString() },
            wireGuardConfig = wireGuardConfig,
            sourceLink = raw
        )
    }

    private fun buildWireGuardConfig(
        privateKey: String,
        peerPublicKey: String,
        tunnelAddress: String,
        dnsServers: String
    ): String = buildString {
        appendLine("[Interface]")
        appendLine("PrivateKey = $privateKey")
        appendLine("Address = $tunnelAddress")
        if (dnsServers.isNotBlank()) appendLine("DNS = $dnsServers")
        appendLine("MTU = 1280")
        appendLine()
        appendLine("[Peer]")
        appendLine("PublicKey = $peerPublicKey")
        appendLine("AllowedIPs = 0.0.0.0/0, ::/0")
        appendLine("Endpoint = 127.0.0.1:9000")
        append("PersistentKeepalive = 25")
    }

    private fun decodeBase64Url(value: String): ByteArray {
        val normalized = value.replace('-', '+').replace('_', '/')
        val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
        return Base64.decode(padded, Base64.DEFAULT)
    }

    private fun JSONObject.stringValue(name: String): String = optString(name, "").trim()
}
