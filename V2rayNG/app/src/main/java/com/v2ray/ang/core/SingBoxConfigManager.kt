package com.v2ray.ang.core

import android.content.Context
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.ConfigResult
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.util.JsonUtil

/** Builds the sing-box 1.13 configuration consumed by [SingBoxProcessManager]. */
object SingBoxConfigManager {
    fun getConfig(context: Context, guid: String, profile: ProfileItem): ConfigResult = try {
        require(profile.configType !in setOf(EConfigType.CUSTOM, EConfigType.POLICYGROUP, EConfigType.PROXYCHAIN)) {
            "sing-box only supports individual proxy profiles"
        }
        ConfigResult(true, guid, buildConfig(profile))
    } catch (e: Exception) {
        ConfigResult(false, guid, errorMessage = "Failed to build sing-box config: ${e.message ?: e.javaClass.simpleName}")
    }

    internal fun buildConfig(profile: ProfileItem): String {
        val root = JsonObject()
        root.add("log", JsonObject().apply {
            addProperty("level", singBoxLogLevel())
            addProperty("timestamp", true)
        })
        // sing-box 1.12+ needs an explicit resolver for outbound server domains. The "local"
        // transport reads /etc/resolv.conf, which does not exist on Android, so it always fails
        // there; use plain UDP DNS to IP-addressed public resolvers instead (no bootstrap
        // resolution needed). Only the proxy server's own domain is resolved here - target
        // domains are passed to the proxy server untouched.
        root.add("dns", JsonObject().apply {
            add("servers", JsonArray().apply {
                add(JsonObject().apply {
                    addProperty("type", "udp")
                    addProperty("tag", "dns-ali")
                    addProperty("server", "223.5.5.5")
                })
                add(JsonObject().apply {
                    addProperty("type", "udp")
                    addProperty("tag", "dns-google")
                    addProperty("server", "8.8.8.8")
                })
            })
        })
        root.add("inbounds", JsonArray().apply {
            add(JsonObject().apply {
                addProperty("type", "mixed")
                addProperty("tag", "mixed-in")
                addProperty("listen", inboundListen())
                addProperty("listen_port", SettingsManager.getSocksPort())
                inboundUsers()?.let { add("users", it) }
            })
        })
        root.add("outbounds", JsonArray().apply {
            // sing-box 1.13 only accepts WireGuard as an endpoint, not as an outbound.
            // NOTE: never add a "direct" outbound here. On Android the CLI binary has no
            // platform interface, the network manager's interface monitor stays nil, and
            // direct.Outbound.fetchMyAddresses() dereferences it at PostStart and crashes
            // (sing-box issue #4498). route.final sends all traffic to "proxy", so a
            // direct outbound is not needed; the manager only creates its fallback direct
            // when no default outbound exists, and route.final provides one.
            if (profile.configType != EConfigType.WIREGUARD) {
                add(buildOutbound(profile))
            }
        })
        if (profile.configType == EConfigType.WIREGUARD) {
            root.add("endpoints", JsonArray().apply { add(buildWireguardEndpoint(profile)) })
        }
        root.add("route", JsonObject().apply {
            addProperty("final", "proxy")
            add("default_domain_resolver", JsonObject().apply {
                addProperty("server", "dns-ali")
            })
        })
        return JsonUtil.toJsonPretty(root) ?: error("Could not serialize sing-box config")
    }

    private fun buildOutbound(profile: ProfileItem): JsonObject {
        val server = profile.server?.trim().orEmpty().also { require(it.isNotEmpty()) { "Server address is required" } }
        val serverPort = profile.serverPort?.toIntOrNull() ?: 0
        fun JsonObject.server() {
            addProperty("server", server)
            if (serverPort > 0) addProperty("server_port", serverPort)
        }

        return JsonObject().apply {
            addProperty("tag", "proxy")
            when (profile.configType) {
                EConfigType.HYSTERIA2 -> {
                    addProperty("type", "hysteria2")
                    server()
                    addProperty("password", profile.password.orEmpty())
                    profile.obfsPassword?.takeIf { it.isNotBlank() }?.let { password ->
                        add("obfs", JsonObject().apply {
                            addProperty("type", "salamander")
                            addProperty("password", password)
                        })
                    }
                    parseServerPorts(profile.portHopping)?.let { ports ->
                        remove("server_port")
                        add("server_ports", ports)
                    }
                    profile.bandwidthUp?.toMegabits()?.let { addProperty("up_mbps", it) }
                    profile.bandwidthDown?.toMegabits()?.let { addProperty("down_mbps", it) }
                    addTls(profile, required = true)
                }

                EConfigType.SHADOWSOCKS -> {
                    addProperty("type", "shadowsocks")
                    server()
                    addProperty("method", profile.method.orEmpty())
                    addProperty("password", profile.password.orEmpty())
                }

                EConfigType.TROJAN -> {
                    addProperty("type", "trojan")
                    server()
                    addProperty("password", profile.password.orEmpty())
                    addTransport(profile)
                    addTls(profile, required = true)
                }

                EConfigType.VMESS -> {
                    addProperty("type", "vmess")
                    server()
                    addProperty("uuid", profile.password.orEmpty())
                    addProperty("security", profile.method?.takeIf { it.isNotBlank() } ?: "auto")
                    addTransport(profile)
                    addTls(profile)
                }

                EConfigType.VLESS -> {
                    addProperty("type", "vless")
                    server()
                    addProperty("uuid", profile.password.orEmpty())
                    profile.flow?.takeIf { it.isNotBlank() }?.let { addProperty("flow", it) }
                    addTransport(profile)
                    addTls(profile)
                }

                EConfigType.SOCKS -> {
                    addProperty("type", "socks")
                    server()
                    profile.username?.takeIf { it.isNotBlank() }?.let { addProperty("username", it) }
                    profile.password?.takeIf { it.isNotBlank() }?.let { addProperty("password", it) }
                }

                EConfigType.HTTP -> {
                    addProperty("type", "http")
                    server()
                    profile.username?.takeIf { it.isNotBlank() }?.let { addProperty("username", it) }
                    profile.password?.takeIf { it.isNotBlank() }?.let { addProperty("password", it) }
                    addTls(profile)
                }

                EConfigType.WIREGUARD -> error("WireGuard is converted to a sing-box endpoint")

                else -> error("${profile.configType} is not supported by the sing-box profile converter")
            }
        }
    }

    /**
     * sing-box 1.13 endpoint form for WireGuard: address/peers[].address/port/public_key/
     * allowed_ips are required, keys are standard padded base64.
     */
    private fun buildWireguardEndpoint(profile: ProfileItem): JsonObject = JsonObject().apply {
        addProperty("type", "wireguard")
        addProperty("tag", "proxy")
        addProperty("private_key", profile.secretKey.orEmpty())
        val addresses = profile.localAddress?.split(',')?.map(String::trim)?.filter(String::isNotEmpty)
            .takeUnless { it.isNullOrEmpty() } ?: listOf("172.16.0.2/32")
        add("address", JsonArray().apply { addresses.forEach(::add) })
        addProperty("mtu", profile.mtu?.takeIf { it > 0 } ?: 1420)
        add("peers", JsonArray().apply {
            add(JsonObject().apply {
                addProperty("address", profile.server.orEmpty())
                addProperty("port", profile.serverPort?.toIntOrNull() ?: 51820)
                addProperty("public_key", profile.publicKey.orEmpty())
                profile.preSharedKey?.takeIf { it.isNotBlank() }?.let { addProperty("pre_shared_key", it) }
                profile.reserved?.takeIf { it.isNotBlank() }?.let { raw ->
                    val reserved = raw.split(',')?.mapNotNull(String::trim)?.mapNotNull(String::toIntOrNull)
                    if (reserved?.size == 3) {
                        add("reserved", JsonArray().apply { reserved.forEach(::add) })
                    }
                }
                add("allowed_ips", JsonArray().apply {
                    add("0.0.0.0/0")
                    add("::/0")
                })
            })
        })
    }

    private fun JsonObject.addTransport(profile: ProfileItem) {
        val transport = JsonObject()
        when (profile.network) {
            "ws" -> {
                transport.addProperty("type", "ws")
                addWsPath(profile, transport)
                profile.host?.takeIf { it.isNotBlank() }?.let { host ->
                    transport.add("headers", JsonObject().apply { addProperty("Host", host) })
                }
            }

            "grpc" -> {
                transport.addProperty("type", "grpc")
                profile.serviceName?.takeIf { it.isNotBlank() }?.let { transport.addProperty("service_name", it) }
            }

            "httpupgrade" -> {
                transport.addProperty("type", "httpupgrade")
                profile.path?.takeIf { it.isNotBlank() }?.let { transport.addProperty("path", it) }
                profile.host?.takeIf { it.isNotBlank() }?.let { transport.addProperty("host", it) }
            }

            "h2" -> {
                transport.addProperty("type", "http")
                profile.path?.takeIf { it.isNotBlank() }?.let { transport.addProperty("path", it) }
                profile.host?.takeIf { it.isNotBlank() }?.let { host ->
                    transport.add("host", JsonArray().apply { add(host) })
                }
            }

            else -> return
        }
        add("transport", transport)
    }

    /** Splits the "?ed=" early-data convention out of the ws path into dedicated sing-box fields. */
    private fun addWsPath(profile: ProfileItem, transport: JsonObject) {
        val rawPath = profile.path.orEmpty()
        val earlyData = Regex("[?&]ed=(\\d+)").find(rawPath)?.groupValues?.get(1)?.toIntOrNull()
        if (earlyData != null && earlyData > 0) {
            transport.addProperty("max_early_data", earlyData)
            transport.addProperty("early_data_header_name", "sec_websocket_buffer")
            val cleanPath = rawPath.substringBefore("?ed=").substringBefore("&ed=")
            if (cleanPath.isNotBlank()) transport.addProperty("path", cleanPath)
        } else if (rawPath.isNotBlank()) {
            transport.addProperty("path", rawPath)
        }
    }

    private fun JsonObject.addTls(profile: ProfileItem, required: Boolean = false) {
        val enabled = required || profile.security == AppConfig.TLS || profile.security == AppConfig.REALITY
        if (!enabled) return
        add("tls", JsonObject().apply {
            addProperty("enabled", true)
            addProperty("server_name", profile.sni?.takeIf { it.isNotBlank() } ?: profile.server.orEmpty())
            addProperty("insecure", profile.insecure == true)
            profile.alpn?.split(',')?.map(String::trim)?.filter(String::isNotEmpty)?.let { values ->
                add("alpn", JsonArray().apply { values.forEach(::add) })
            }
            val fingerprint = profile.fingerPrint
                ?.takeIf { it.isNotBlank() && it != "none" }
                // REALITY requires uTLS in sing-box, fall back to a supported client fingerprint.
                ?: if (profile.security == AppConfig.REALITY) "chrome" else null
            fingerprint?.let { fingerprint ->
                add("utls", JsonObject().apply {
                    addProperty("enabled", true)
                    addProperty("fingerprint", fingerprint)
                })
            }
            if (profile.security == AppConfig.REALITY) {
                add("reality", JsonObject().apply {
                    addProperty("enabled", true)
                    addProperty("public_key", profile.publicKey.orEmpty())
                    profile.shortId?.takeIf { it.isNotBlank() }?.let { addProperty("short_id", it) }
                })
            }
        })
    }

    /** Mirrors the Xray inbound listen address (proxy sharing option). */
    private fun inboundListen(): String =
        if (MmkvManager.decodeSettingsBool(AppConfig.PREF_PROXY_SHARING) == true) "0.0.0.0" else AppConfig.LOOPBACK

    /** Mirrors the Xray inbound SOCKS username/password auth when both are configured. */
    private fun inboundUsers(): JsonArray? {
        val username = SettingsManager.getSocksUsername() ?: return null
        val password = SettingsManager.getSocksPassword() ?: return null
        return JsonArray().apply {
            add(JsonObject().apply {
                addProperty("username", username)
                addProperty("password", password)
            })
        }
    }

    /** Map the Xray style log level onto the levels sing-box accepts. */
    private fun singBoxLogLevel(): String =
        when (MmkvManager.decodeSettingsString(AppConfig.PREF_LOGLEVEL)) {
            "debug" -> "debug"
            "info" -> "info"
            "error" -> "error"
            else -> "warn"
        }

    /**
     * Converts the subscription "mport" notation ("443,2000-5000") into sing-box
     * server_ports ranges; every entry must be a "start:end" range.
     */
    private fun parseServerPorts(raw: String?): JsonArray? {
        val ports = raw?.split(',')
            ?.map(String::trim)
            ?.filter(String::isNotEmpty)
            ?.map { part ->
                val range = part.replace('-', ':')
                if (range.contains(':')) range else "$range:$range"
            }
            .orEmpty()
        if (ports.isEmpty()) return null
        return JsonArray().apply { ports.forEach(::add) }
    }

    private fun String.toMegabits(): Int? {
        val match = Regex("^(\\d+)([kKmMgGtT]?)$").matchEntire(trim()) ?: return null
        val value = match.groupValues[1].toLongOrNull() ?: return null
        val multiplier = when (match.groupValues[2].lowercase()) {
            "k" -> 1L / 1000L
            "g" -> 1000L
            "t" -> 1_000_000L
            else -> 1L
        }
        return (value * multiplier).coerceAtLeast(1L).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    }
}
