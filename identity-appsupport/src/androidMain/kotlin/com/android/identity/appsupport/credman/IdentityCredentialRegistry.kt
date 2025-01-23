package com.android.identity.appsupport.credman

import android.content.Context
import com.google.android.gms.identitycredentials.RegistrationRequest
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.json.JSONArray
import org.json.JSONObject

class IdentityCredentialRegistry(
  val entries: List<IdentityCredentialEntry>,
) {
  fun toRegistrationRequest(context: Context): RegistrationRequest {

    return RegistrationRequest(
      credentials = credentialBytes(),
      matcher = loadMatcher(context),
      type = "com.credman.IdentityCredential",
      requestType = "",
      protocolTypes = emptyList(),
    )
  }

  private fun loadMatcher(context: Context): ByteArray {
    val stream = context.assets.open("identitycredentialmatcher.wasm");
    val matcher = ByteArray(stream.available())
    stream.read(matcher)
    stream.close()
    return matcher
  }

  private fun credentialBytes(): ByteArray {
    val json = JSONObject()
    val credListJson = JSONArray()
    val icons = ByteArrayOutputStream()
    val iconSizeList = mutableListOf<Int>()
    entries.forEach { entry ->
      val iconBytes = entry.getIconBytes()
      credListJson.put(entry.toJson(iconSizeList.size))
      iconSizeList.add(iconBytes.size())
      iconBytes.writeTo(icons)
    }
    json.put("credentials", credListJson)
    val credsBytes = json.toString(0).toByteArray()
    val result = ByteArrayOutputStream()
    // header_size
    result.write(intBytes((3 + iconSizeList.size) * Int.SIZE_BYTES))
    // creds_size
    result.write(intBytes(credsBytes.size))
    // icon_size_array_size
    result.write(intBytes(iconSizeList.size))
    // icon offsets
    iconSizeList.forEach { result.write(intBytes(it)) }
    result.write(credsBytes)
    icons.writeTo(result)
    return result.toByteArray()
  }

  companion object {
    fun intBytes(num: Int): ByteArray =
      ByteBuffer.allocate(Int.SIZE_BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(num).array()
  }
}