package com.android.identity_credential.mrtd

import net.sf.scuba.smartcards.CardService
import org.jmrtd.PassportService

interface MrtdNfcReader<ResultT> {
    fun read(
        rawConnection: CardService,
        connection: PassportService?,
        onStatus: (MrtdNfc.Status) -> Unit,
    ): ResultT
}
