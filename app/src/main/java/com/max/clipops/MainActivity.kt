package com.max.clipops

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.max.clipops.databinding.ActivityMainBinding
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var appAdapter: AppAdapter
    private var allApps = ArrayList<AppItem>()
    private var filteredApps = ArrayList<AppItem>()

    // Launcher for handling SetupAdbActivity response
    private val setupAdbLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            updateUIState()
            loadInstalledApps()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupRecyclerView()
        setupSearch()

        LocalAdbManager.initKeys(this)
        ClipOpsLogger.init(this)

        // Start persistent notification service
        val svcIntent = Intent(this, ClipOpsService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(svcIntent)
        } else {
            startService(svcIntent)
        }

        // Pairing button → trigger mDNS search via service broadcast
        binding.btnPairing.setOnClickListener {
            sendBroadcast(
                Intent(ClipOpsService.ACTION_START_SEARCH).setPackage(packageName)
            )
            Toast.makeText(this, "Searching for pairing service…", Toast.LENGTH_SHORT).show()
        }

        // Start button → open setup screen to enter port & connect
        binding.btnStart.setOnClickListener {
            setupAdbLauncher.launch(Intent(this, SetupAdbActivity::class.java))
        }

        // Export debug log
        binding.btnExportLog.setOnClickListener {
            val intent = ClipOpsLogger.exportIntent(this)
            if (intent != null) {
                startActivity(Intent.createChooser(intent, "Share debug log"))
            } else {
                Toast.makeText(this, "No log file found", Toast.LENGTH_SHORT).show()
            }
        }

        updateUIState()
        if (LocalAdbManager.isConnected()) {
            loadInstalledApps()
        }
    }

    override fun onResume() {
        super.onResume()
        updateUIState()
    }

    private fun updateUIState() {
        if (LocalAdbManager.isConnected()) {
            binding.statusIcon.text = "✓"
            binding.statusBanner.text = "ClipOps is running"
            binding.btnPairing.visibility = View.GONE
            binding.btnStart.text = "Stop"
            binding.searchEditText.visibility = View.VISIBLE
        } else {
            binding.statusIcon.text = "⚠"
            binding.statusBanner.text = "ClipOps is not running"
            binding.btnPairing.visibility = View.VISIBLE
            binding.btnStart.text = "Start"
            binding.searchEditText.visibility = View.GONE
        }
    }

    private fun setupRecyclerView() {
        appAdapter = AppAdapter(filteredApps) { appItem, isAllowed ->
            if (!LocalAdbManager.isConnected()) {
                Toast.makeText(this, "Please activate Local ADB first", Toast.LENGTH_LONG).show()
                appAdapter.notifyDataSetChanged()
                return@AppAdapter
            }

            thread {
                LocalAdbManager.setClipboardReadMode(appItem.packageName, isAllowed) { success ->
                    runOnUiThread {
                        if (success) {
                            appItem.isClipboardAllowed = isAllowed
                            val text = if (isAllowed) "Allowed clipboard access for ${appItem.name}" else "Blocked clipboard access for ${appItem.name}"
                            Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
                        } else {
                            // Reset state in case of fail
                            appAdapter.notifyDataSetChanged()
                            Toast.makeText(this, "Failed to write appops. Connect state lost?", Toast.LENGTH_SHORT).show()
                            updateUIState()
                        }
                    }
                }
            }
        }
        binding.recyclerView.layoutManager = LinearLayoutManager(this)
        binding.recyclerView.adapter = appAdapter
    }

    private fun setupSearch() {
        binding.searchEditText.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                filterApps(s.toString())
            }
            override fun afterTextChanged(s: Editable?) {}
        })
    }

    private fun loadInstalledApps() {
        binding.loadingBar.visibility = View.VISIBLE
        thread {
            val pm = packageManager
            val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            val list = ArrayList<AppItem>()

            for (appInfo in packages) {
                // Filter user apps (usually has Launcher Intent)
                if (pm.getLaunchIntentForPackage(appInfo.packageName) == null) continue

                val name = appInfo.loadLabel(pm).toString()
                val icon = appInfo.loadIcon(pm)
                val uid = appInfo.uid
                
                // Get AppOps state synchronously in worker thread.
                var isAllowed = true
                val lock = java.lang.Object()
                
                LocalAdbManager.getClipboardReadMode(appInfo.packageName) { allowed ->
                    isAllowed = allowed
                    synchronized(lock) {
                        lock.notify()
                    }
                }

                // Wait up to 500ms per app to avoid binder lock block, fast loop.
                synchronized(lock) {
                    try {
                        lock.wait(500)
                    } catch (e: Exception) {}
                }

                list.add(AppItem(name, appInfo.packageName, icon, uid, isAllowed))
            }

            // Sort alphabetical
            list.sortBy { it.name.lowercase() }

            runOnUiThread {
                binding.loadingBar.visibility = View.GONE
                allApps.clear()
                allApps.addAll(list)
                filterApps(binding.searchEditText.text.toString())
            }
        }
    }

    private fun filterApps(query: String) {
        filteredApps.clear()
        if (query.isEmpty()) {
            filteredApps.addAll(allApps)
        } else {
            val lowerCaseQuery = query.lowercase()
            for (app in allApps) {
                if (app.name.lowercase().contains(lowerCaseQuery) || app.packageName.lowercase().contains(lowerCaseQuery)) {
                    filteredApps.add(app)
                }
            }
        }
        appAdapter.updateData(filteredApps)
    }
}
