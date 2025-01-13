package com.android.identity.nfc

/**
 * Exception thrown if an NFC command doesn't return success.
 *
 * @property status the status word from the [ResponseApdu], never [Nfc.RESPONSE_STATUS_SUCCESS].
 */
class NfcCommandFailedException(
    message: String,
    val status: Int
): Exception(message)