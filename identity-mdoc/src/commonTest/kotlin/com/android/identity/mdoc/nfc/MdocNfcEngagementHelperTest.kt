package com.android.identity.mdoc.nfc

import com.android.identity.crypto.Crypto
import com.android.identity.crypto.EcCurve
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethodBle
import com.android.identity.nfc.CommandApdu
import com.android.identity.nfc.Nfc
import com.android.identity.nfc.NfcCommandFailedException
import com.android.identity.nfc.NfcIsoTag
import com.android.identity.nfc.ResponseApdu
import com.android.identity.util.UUID
import com.android.identity.util.fromHex
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.io.bytestring.ByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.fail

/**
 * This test is mainly for verifying the correct functionality of MdocNfcEngagementHelper (the wallet side)
 * but it also exercises and verifies mdocReaderNfcHandover() and other things on the reader side.
 */
class MdocNfcEngagementHelperTest {

    // Provides access to MdocNfcEngagementHelper via NfcIsoTag abstraction
    class LoopbackIsoTag(val engagementHelper: MdocNfcEngagementHelper): NfcIsoTag() {
        override suspend fun transceive(apdu: CommandApdu): ResponseApdu {
            return engagementHelper.processApdu(apdu)
        }
    }

    private fun getConnectionMethods(): List<ConnectionMethod> {
        // Include all ConnectionMethods that can exist in OOB data
        val bleUuid = UUID.randomUUID()
        return listOf(
            ConnectionMethodBle(
                supportsPeripheralServerMode = false,
                supportsCentralClientMode = true,
                peripheralServerModeUuid = null,
                centralClientModeUuid = bleUuid
            ),
            ConnectionMethodBle(
                supportsPeripheralServerMode = true,
                supportsCentralClientMode = false,
                peripheralServerModeUuid = bleUuid,
                centralClientModeUuid = null
            )
        )
    }

    @Test
    fun testStaticHandover() = runTest {
        val staticHandoverConnectionMethods = getConnectionMethods()

        val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val engagementHelper = MdocNfcEngagementHelper(
            eDeviceKey = eDeviceKey.publicKey,
            onHandoverComplete = { connectionMethods, encodedDeviceEngagement, handover ->
                assertEquals(staticHandoverConnectionMethods, connectionMethods)
            },
            onError = { error ->
                fail("onError should not be called with $error")
            },
            staticHandoverMethods = staticHandoverConnectionMethods,
        )

        val handoverResult = mdocReaderNfcHandover(
            tag = LoopbackIsoTag(engagementHelper),
            negotiatedHandoverConnectionMethods = getConnectionMethods(),
        )
        assertNotNull(handoverResult)
        assertEquals(staticHandoverConnectionMethods, handoverResult.connectionMethods)
    }

    @Test
    fun testNegotiatedHandover() = runTest {
        val negotiatedHandoverConnectionMethods = getConnectionMethods()

        val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val engagementHelper = MdocNfcEngagementHelper(
            eDeviceKey = eDeviceKey.publicKey,
            onHandoverComplete = { connectionMethods, encodedDeviceEngagement, handover ->
                assertEquals(1, connectionMethods.size)
            },
            onError = { error ->
                fail("onError should not be called with $error")
            },
            negotiatedHandoverPicker = { methods -> methods.first() }
        )

        val handoverResult = mdocReaderNfcHandover(
            tag = LoopbackIsoTag(engagementHelper),
            negotiatedHandoverConnectionMethods = negotiatedHandoverConnectionMethods,
        )
        assertNotNull(handoverResult)
        assertEquals(1, handoverResult.connectionMethods.size)
        assertEquals(
            negotiatedHandoverConnectionMethods.first(),
            handoverResult.connectionMethods.first()
        )
    }

    private fun testNfcEngagementHelper(
        testBlock: suspend (tag: NfcIsoTag) -> Unit
    ): Pair<Boolean, Throwable?> {
        var handoverSuccess = false
        var handoverError: Throwable? = null
        val helper = MdocNfcEngagementHelper(
            eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256).publicKey,
            onHandoverComplete = { connectionMethods, encodedDeviceEngagement, handover -> handoverSuccess = true },
            onError = { error -> handoverError = error },
            staticHandoverMethods = getConnectionMethods(),
        )
        runBlocking { testBlock(LoopbackIsoTag(helper)) }
        return Pair(handoverSuccess, handoverError)
    }

    @Test
    fun testWrongApplicationIdSelected() {
        var (handoverSuccess, handoverError) = testNfcEngagementHelper { tag ->
            // Off by one from the NDEF AID
            assertFailsWith(NfcCommandFailedException::class) {
                tag.selectApplication(ByteString("D2760000850102".fromHex()))
            }
        }
        assertFalse(handoverSuccess)
        assertNotNull(handoverError)
        assertEquals(
            "SelectApplication: Expected NDEF AID but got d2760000850102",
            handoverError.message
        )
    }

    @Test
    fun testFiledIdBeforeApplicationSelectSelected() {
        var (handoverSuccess, handoverError) = testNfcEngagementHelper { tag ->
            // Fails because application is not yet selected
            assertFailsWith(NfcCommandFailedException::class) {
                tag.selectFile(Nfc.NDEF_CAPABILITY_CONTAINER_FILE_ID)
            }
        }
        assertFalse(handoverSuccess)
        assertNotNull(handoverError)
        assertEquals(
            "Error processing APDU: NDEF application not yet selected",
            handoverError.message
        )
    }

    @Test
    fun testUnexpectedFileIdSelected() {
        var (handoverSuccess, handoverError) = testNfcEngagementHelper { tag ->
            tag.selectApplication(Nfc.NDEF_APPLICATION_ID)
            // Fails because the FileID is unknown
            assertFailsWith(NfcCommandFailedException::class) {
                tag.selectFile(42)
            }
        }
        assertFalse(handoverSuccess)
        assertNotNull(handoverError)
        assertEquals(
            "SelectFile: Unexpected File ID 42",
            handoverError.message
        )
    }

    // TODO: add more tests to exercise implementation of READ_BINARY and UPDATE_BINARY

    @Test
    fun testBuilder() {
        assertFailsWith(
            IllegalStateException::class,
            "Must use either static or negotiated handover, none are selected"
        ) {
            MdocNfcEngagementHelper(
                eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256).publicKey,
                onHandoverComplete = { connectionMethods, encodedDeviceEngagement, handover -> },
                onError = { error -> }
            )
        }

        assertFailsWith(
            IllegalStateException::class,
            "Can't use both static and negotiated handover at the same time"
        ) {
            MdocNfcEngagementHelper(
                eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256).publicKey,
                onHandoverComplete = { connectionMethods, encodedDeviceEngagement, handover -> },
                onError = { error -> },
                staticHandoverMethods = getConnectionMethods(),
                negotiatedHandoverPicker = { methods -> methods.first() }
            )
        }


        assertFailsWith(
            IllegalStateException::class,
            "Must have at least one ConnectionMethod for static handover"
        ) {
            MdocNfcEngagementHelper(
                eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256).publicKey,
                onHandoverComplete = { connectionMethods, encodedDeviceEngagement, handover -> },
                onError = { error -> },
                staticHandoverMethods = listOf()
            )
        }

        MdocNfcEngagementHelper(
            eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256).publicKey,
            onHandoverComplete = { connectionMethods, encodedDeviceEngagement, handover -> },
            onError = { error -> },
            negotiatedHandoverPicker = { methods -> methods.first() }
        )

        MdocNfcEngagementHelper(
            eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256).publicKey,
            onHandoverComplete = { connectionMethods, encodedDeviceEngagement, handover -> },
            onError = { error -> },
            staticHandoverMethods = getConnectionMethods()
        )
    }
}