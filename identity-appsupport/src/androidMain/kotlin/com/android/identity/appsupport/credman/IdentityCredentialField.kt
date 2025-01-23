package com.android.identity.appsupport.credman

import org.json.JSONObject

class IdentityCredentialField(
  val name: String,
  val value: Any?,
  val displayName: String,
  val displayValue: String?,
) {
  fun toJson(): JSONObject {
    val field = JSONObject()
    field.put("name", name)
    field.putOpt("value", value)
    field.put("display_name", displayName)
    field.putOpt("display_value", displayValue)
    return field
  }
}