package com.android.identity.cbor

/**
 * CBOR data item builder.
 */
class CborBuilder(private val item: DataItem) {
    /**
     * Builds the CBOR data items.
     *
     * @return a [DataItem]
     */
    fun build(): DataItem {
        return item
    }
}