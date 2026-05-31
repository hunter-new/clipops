package com.max.clipops

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.max.clipops.databinding.ItemAppBinding

class AppAdapter(
    private var appsList: List<AppItem>,
    private val onToggle: (AppItem, Boolean) -> Unit
) : RecyclerView.Adapter<AppAdapter.AppViewHolder>() {

    class AppViewHolder(val binding: ItemAppBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AppViewHolder {
        val binding = ItemAppBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return AppViewHolder(binding)
    }

    override fun onBindViewHolder(holder: AppViewHolder, position: Int) {
        val app = appsList[position]
        holder.binding.appIcon.setImageDrawable(app.icon)
        holder.binding.appName.text = app.name
        holder.binding.packageName.text = app.packageName
        
        // Remove listener temporarily to prevent infinite loop
        holder.binding.clipboardSwitch.setOnCheckedChangeListener(null)
        holder.binding.clipboardSwitch.isChecked = app.isClipboardAllowed

        holder.binding.clipboardSwitch.setOnCheckedChangeListener { _, isChecked ->
            onToggle(app, isChecked)
        }
    }

    override fun getItemCount(): Int = appsList.size

    fun updateData(newApps: List<AppItem>) {
        appsList = newApps
        notifyDataSetChanged()
    }
}
