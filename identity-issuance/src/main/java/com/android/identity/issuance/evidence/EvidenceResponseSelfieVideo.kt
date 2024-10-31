package com.android.identity.issuance.evidence

data class EvidenceResponseSelfieVideo(val selfieImage: ByteArray)
    : EvidenceResponse() {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EvidenceResponseSelfieVideo

        return selfieImage.contentEquals(other.selfieImage)
    }

    override fun hashCode(): Int {
        return selfieImage.contentHashCode()
    }
}