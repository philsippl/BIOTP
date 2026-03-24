package com.biotp

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "hex string must have even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
