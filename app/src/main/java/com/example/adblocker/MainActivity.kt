package com.example.adblocker

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.example.adblocker.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val handler = Handler(Looper.getMainLooper())

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startService(Intent(this, AdBlockVpnService::class.java))
        }
        updateUi()
    }

    private val refreshRunnable = object : Runnable {
        override fun run() {
            updateUi()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.toggleButton.setOnClickListener {
            if (AdBlockVpnService.instance?.isActive() == true) {
                stopService(Intent(this, AdBlockVpnService::class.java))
            } else {
                requestVpnPermissionAndStart()
            }
            updateUi()
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(refreshRunnable)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(refreshRunnable)
    }

    private fun requestVpnPermissionAndStart() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startService(Intent(this, AdBlockVpnService::class.java))
        }
    }

    private fun updateUi() {
        val running = AdBlockVpnService.instance?.isActive() == true
        binding.statusText.text = getString(
            if (running) R.string.status_running else R.string.status_stopped
        )
        binding.toggleButton.text = getString(
            if (running) R.string.btn_stop else R.string.btn_start
        )
        val count = AdBlockVpnService.instance?.blockedCount?.get() ?: 0
        binding.countText.text = getString(R.string.blocked_count_label, count)
    }
}
