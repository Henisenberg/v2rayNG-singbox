package com.v2ray.ang.enums

enum class CoreType(val value: String, val displayName: String) {
    XRAY("xray", "Xray"),
    SING_BOX("sing-box", "sing-box");

    companion object {
        fun fromValue(value: String?): CoreType = entries.firstOrNull { it.value == value } ?: XRAY

        fun fromDisplayName(displayName: String): CoreType = entries.firstOrNull { it.displayName == displayName } ?: XRAY
    }
}
