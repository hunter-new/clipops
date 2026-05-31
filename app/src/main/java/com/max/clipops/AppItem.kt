package com.max.clipops

import android.graphics.drawable.Drawable

data class AppItem(
    val name: String,
    val packageName: String,
    val icon: Drawable,
    val uid: Int,
    var isClipboardAllowed: Boolean
)
