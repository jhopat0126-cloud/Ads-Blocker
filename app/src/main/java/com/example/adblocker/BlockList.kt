package com.example.adblocker

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Loads the blocklist from assets/blocklist.txt and answers whether a
 * given hostname (as seen in a DNS query) should be blocked.
 *
 * Matching is "domain or any subdomain of it" — e.g. blocking
 * "doubleclick.net" also blocks "stats.doubleclick.net".
 */
class BlockList private constructor(private val domains: Set<String>) {

    fun isBlocked(hostname: String): Boolean {
        val host = hostname.lowercase().removeSuffix(".")
        if (domains.contains(host)) return true
        var idx = host.indexOf('.')
        while (idx >= 0) {
            val parent = host.substring(idx + 1)
            if (domains.contains(parent)) return true
            idx = host.indexOf('.', idx + 1)
        }
        return false
    }

    val size: Int get() = domains.size

    companion object {
        fun loadFromAssets(context: Context): BlockList {
            val set = HashSet<String>()
            try {
                context.assets.open("blocklist.txt").use { input ->
                    BufferedReader(InputStreamReader(input)).useLines { lines ->
                        for (rawLine in lines) {
                            val line = rawLine.trim()
                            if (line.isEmpty() || line.startsWith("#")) continue
                            set.add(line.lowercase())
                        }
                    }
                }
            } catch (e: Exception) {
                // Fall back to an empty set if the asset is missing/corrupt;
                // the service will simply forward all DNS queries in that case.
            }
            return BlockList(set)
        }
    }
}
