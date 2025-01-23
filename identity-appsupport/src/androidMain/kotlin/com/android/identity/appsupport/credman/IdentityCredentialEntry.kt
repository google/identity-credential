package com.android.identity.appsupport.credman

import android.graphics.Bitmap
import java.io.ByteArrayOutputStream
import org.json.JSONArray
import org.json.JSONObject

class IdentityCredentialEntry(
  val id: Long,
  val format: String,
  val title: String,
  val subtitle: String,
  val icon: Bitmap,
  val fields: List<IdentityCredentialField>,
  val disclaimer: String?,
  val warning: String?,
) {
  fun getIconBytes(): ByteArrayOutputStream {
    val scaledIcon = Bitmap.createScaledBitmap(icon, 128, 128, true)
    val stream = ByteArrayOutputStream()
    scaledIcon.compress(Bitmap.CompressFormat.PNG, 100, stream)
    return stream
  }

  fun toJson(iconIndex: Int?): JSONObject {
    val credential = JSONObject()
    credential.put("format", format)
    val displayInfo = JSONObject()
    displayInfo.put("title", title)
    displayInfo.putOpt("subtitle", subtitle)
    displayInfo.putOpt("disclaimer", disclaimer)
    displayInfo.putOpt("warning", warning)
    displayInfo.putOpt("icon_id", iconIndex)
    credential.put("display_info", displayInfo)
    val fieldsJson = JSONArray()
    fields.forEach { fieldsJson.put(it.toJson()) }
    credential.put("fields", fieldsJson)

    val result = JSONObject()
    result.put("id", id)
    result.put("credential", credential)
    return result
  }
}