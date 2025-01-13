package com.android.identity.mdoc.connectionmethod

import com.android.identity.asn1.ASN1String
import com.android.identity.cbor.Cbor.decode
import com.android.identity.cbor.Cbor.encode
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborMap
import com.android.identity.mdoc.transport.MdocTransport
import com.android.identity.nfc.NdefRecord
import com.android.identity.nfc.Nfc
import com.android.identity.util.Logger
import com.android.identity.util.UUID
import kotlinx.io.Buffer
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.io.readByteArray
import kotlinx.io.readByteString
import kotlinx.io.readLongLe
import kotlinx.io.write
import kotlinx.io.writeULongLe

/**
 * Connection method for BLE.
 *
 * @param supportsPeripheralServerMode whether mdoc peripheral mode is supported.
 * @param supportsCentralClientMode    whether mdoc central client mode is supported.
 * @param peripheralServerModeUuid     the UUID to use for mdoc peripheral server mode.
 * @param centralClientModeUuid        the UUID to use for mdoc central client mode.
 */
class ConnectionMethodBle(
    val supportsPeripheralServerMode: Boolean,
    val supportsCentralClientMode: Boolean,
    val peripheralServerModeUuid: UUID?,
    val centralClientModeUuid: UUID?
) : ConnectionMethod() {

    /**
     * The L2CAP PSM, if set.
     *
     * This is currently not standardized so use at your own risk.
     */
    var peripheralServerModePsm: Int? = null


    /**
     * The peripheral MAC address, if set.
     */
    var peripheralServerModeMacAddress: ByteArray? = null
        set(macAddress) {
            require(macAddress == null || macAddress.size == 6) {                 
                "MAC address should be 6 bytes, got ${macAddress!!.size}"
            }
            field = macAddress
        }

    override fun equals(other: Any?): Boolean {
        return other is ConnectionMethodBle &&
                other.supportsPeripheralServerMode == supportsPeripheralServerMode &&
                other.supportsCentralClientMode == supportsCentralClientMode &&
                other.peripheralServerModeUuid == peripheralServerModeUuid &&
                other.centralClientModeUuid == centralClientModeUuid &&
                other.peripheralServerModePsm == peripheralServerModePsm &&
                other.peripheralServerModeMacAddress == peripheralServerModeMacAddress
    }

    override fun toString(): String {
        val sb = StringBuilder("ble")
        if (supportsPeripheralServerMode) {
            sb.append(":peripheral_server_mode:uuid=$peripheralServerModeUuid")
        }
        if (supportsCentralClientMode) {
            sb.append(":central_client_mode:uuid=$centralClientModeUuid")
        }
        if (peripheralServerModePsm != null) {
            sb.append(":psm=" + peripheralServerModePsm.toString())
        }
        if (peripheralServerModeMacAddress != null) {
            sb.append(":mac=")
            for (n in 0..5) {
                if (n > 0) {
                    sb.append("-")
                }
                val value = peripheralServerModeMacAddress!![n]
                sb.append(HEX_DIGITS[value.toInt().and(0xff) shr 4])
                sb.append(HEX_DIGITS[value.toInt().and(0x0f)])
            }
        }
        return sb.toString()
    }

    override fun toDeviceEngagement(): ByteArray {
        val builder = CborMap.builder()
        builder.put(OPTION_KEY_SUPPORTS_PERIPHERAL_SERVER_MODE, supportsPeripheralServerMode)
        builder.put(OPTION_KEY_SUPPORTS_CENTRAL_CLIENT_MODE, supportsCentralClientMode)
        if (peripheralServerModeUuid != null) {
            builder.put(
                OPTION_KEY_PERIPHERAL_SERVER_MODE_UUID,
                peripheralServerModeUuid.toByteArray()
            )
        }
        if (centralClientModeUuid != null) {
            builder.put(
                OPTION_KEY_CENTRAL_CLIENT_MODE_UUID,
                centralClientModeUuid.toByteArray()
            )
        }
        if (peripheralServerModePsm != null) {
            builder.put(OPTION_KEY_PERIPHERAL_SERVER_MODE_PSM, peripheralServerModePsm as Int)
        }
        if (peripheralServerModeMacAddress != null) {
            builder.put(
                OPTION_KEY_PERIPHERAL_SERVER_MODE_BLE_DEVICE_ADDRESS,
                peripheralServerModeMacAddress!!
            )
        }
        return encode(
            CborArray.builder()
                .add(METHOD_TYPE)
                .add(METHOD_MAX_VERSION)
                .add(builder.end().build())
                .end()
                .build()
        )
    }

    companion object {
        private const val TAG = "ConnectionOptionsBle"
        private val HEX_DIGITS = "0123456789abcdef".toCharArray()

        const val METHOD_TYPE = 2L
        const val METHOD_MAX_VERSION = 1L

        private const val OPTION_KEY_SUPPORTS_PERIPHERAL_SERVER_MODE = 0L
        private const val OPTION_KEY_SUPPORTS_CENTRAL_CLIENT_MODE = 1L
        private const val OPTION_KEY_PERIPHERAL_SERVER_MODE_UUID = 10L
        private const val OPTION_KEY_CENTRAL_CLIENT_MODE_UUID = 11L
        private const val OPTION_KEY_PERIPHERAL_SERVER_MODE_BLE_DEVICE_ADDRESS = 20L
        private const val OPTION_KEY_PERIPHERAL_SERVER_MODE_PSM = 21L // NOTE: as per drafts of 18013-5 Second Edition

        internal fun fromDeviceEngagement(encodedDeviceRetrievalMethod: ByteArray): ConnectionMethodBle? {
            val array = decode(encodedDeviceRetrievalMethod)
            val type = array[0].asNumber
            val version = array[1].asNumber
            require(type == METHOD_TYPE)
            if (version > METHOD_MAX_VERSION) {
                return null
            }
            val map = array[2]
            val supportsPeripheralServerMode = map[OPTION_KEY_SUPPORTS_PERIPHERAL_SERVER_MODE].asBoolean
            val supportsCentralClientMode = map[OPTION_KEY_SUPPORTS_CENTRAL_CLIENT_MODE].asBoolean
            val peripheralServerModeUuidDi = map.getOrNull(OPTION_KEY_PERIPHERAL_SERVER_MODE_UUID)
            val centralClientModeUuidDi = map.getOrNull(OPTION_KEY_CENTRAL_CLIENT_MODE_UUID)
            var peripheralServerModeUuid: UUID? = null
            if (peripheralServerModeUuidDi != null) {
                peripheralServerModeUuid = UUID.fromByteArray(peripheralServerModeUuidDi.asBstr)
            }
            var centralClientModeUuid: UUID? = null
            if (centralClientModeUuidDi != null) {
                centralClientModeUuid = UUID.fromByteArray(centralClientModeUuidDi.asBstr)
            }
            val cm = ConnectionMethodBle(
                supportsPeripheralServerMode,
                supportsCentralClientMode,
                peripheralServerModeUuid,
                centralClientModeUuid
            )
            val psm = map.getOrNull(OPTION_KEY_PERIPHERAL_SERVER_MODE_PSM)
            if (psm != null) {
                cm.peripheralServerModePsm = psm.asNumber.toInt()
            }
            cm.peripheralServerModeMacAddress =
                map.getOrNull(OPTION_KEY_PERIPHERAL_SERVER_MODE_BLE_DEVICE_ADDRESS)?.asBstr
            return cm
        }

        // Constants related to Bluetooth
        //
        // Reference: https://www.bluetooth.com/specifications/assigned-numbers/
        //
        private const val BLE_LE_COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS = 0x07
        private const val BLE_LE_BLUETOOTH_MAC_ADDRESS = 0x1b
        private const val BLE_LE_ROLE = 0x1c
        private const val BLE_PSM_NOT_YET_ALLOCATED = 0x77  // TODO: allocated this number (0x77) with Bluetooth SIG

        // Bluetooth LE role constants
        //
        // Reference: https://www.bluetooth.com/specifications/specs/core-specification-supplement-9/
        //
        // See section 1.17.2 for values.
        //
        private const val BLE_LE_ROLE_CENTRAL_CLIENT_ROLE_ONLY = 0x00
        private const val BLE_LE_ROLE_PERIPHERAL_ROLE_ONLY = 0x01
        private const val BLE_LE_ROLE_PERIPHERAL_CENTRAL_ROLES_PERIPHERAL_PREFERRED = 0x02
        private const val BLE_LE_ROLE_PERIPHERAL_CENTRAL_ROLES_CENTRAL_PREFERRED = 0x03

        internal fun fromNdefRecord(
            record: NdefRecord,
            role: MdocTransport.Role,
            uuidToReplace: UUID?
        ): ConnectionMethodBle? {
            var centralClient = false
            var peripheral = false
            var uuid: UUID? = uuidToReplace
            var gotLeRole = false
            var psm : Int? = null
            var macAddress: ByteArray? = null

            // See createNdefRecords() method for how this data is encoded.
            //
            val payload = Buffer()
            payload.write(record.payload)
            while (!payload.exhausted()) {
                val len = payload.readByte().toInt()
                val type = payload.readByte().toInt()
                if (type == BLE_LE_ROLE && len == 2) {
                    gotLeRole = true
                    val value = payload.readByte().toInt()
                    when (value) {
                        BLE_LE_ROLE_CENTRAL_CLIENT_ROLE_ONLY -> {
                            if (role == MdocTransport.Role.MDOC) {
                                peripheral = true
                            } else {
                                centralClient = true
                            }
                        }
                        BLE_LE_ROLE_PERIPHERAL_ROLE_ONLY -> {
                            if (role == MdocTransport.Role.MDOC) {
                                centralClient = true
                            } else {
                                peripheral = true
                            }
                        }
                        BLE_LE_ROLE_PERIPHERAL_CENTRAL_ROLES_PERIPHERAL_PREFERRED,
                        BLE_LE_ROLE_PERIPHERAL_CENTRAL_ROLES_CENTRAL_PREFERRED -> {
                            centralClient = true
                            peripheral = true
                        }
                        else -> {
                            Logger.w(TAG, "Invalid value $value for LE role")
                            return null
                        }
                    }
                } else if (type == BLE_LE_COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS) {
                    val uuidLen = len - 1
                    if (uuidLen % 16 != 0) {
                        Logger.w(TAG, "UUID len $uuidLen is not divisible by 16")
                        return null
                    }
                    // We only use the last UUID...
                    if (uuidLen > 16) {
                        payload.skip(16*(uuidLen/16 - 1).toLong())
                    }
                    val lsb = payload.readLongLe().toULong()
                    val msb = payload.readLongLe().toULong()
                    uuid = UUID(msb, lsb)
                } else if (type == BLE_LE_BLUETOOTH_MAC_ADDRESS && len == 0x07) {
                    // MAC address
                    macAddress = payload.readByteArray(6)
                } else if (type == BLE_PSM_NOT_YET_ALLOCATED && len == 0x05) {
                    // PSM
                    psm = payload.readInt()
                } else {
                    Logger.d(TAG, "Skipping unknown type $type of length $len")
                    payload.skip(len.toLong() - 1L)
                }
            }
            if (!gotLeRole) {
                Logger.w(TAG, "Did not find LE role")
                return null
            }

            // Note that UUID may _not_ be set.

            // Note that the UUID for both modes is the same if both peripheral and
            // central client mode is used!
            val cm = ConnectionMethodBle(
                peripheral,
                centralClient,
                if (peripheral) uuid else null,
                if (centralClient) uuid else null
            )
            cm.peripheralServerModePsm = psm
            cm.peripheralServerModeMacAddress = macAddress
            return cm
        }
    }

    override fun toNdefRecord(
        auxiliaryReferences: List<String>,
        role: MdocTransport.Role,
        skipUuids: Boolean
    ): Pair<NdefRecord, NdefRecord> {
        // The OOB data is defined in "Supplement to the Bluetooth Core Specification".
        //
        // See section 1.17.2 for values
        //
        val uuid: UUID?
        val leRole: Int
        if (supportsCentralClientMode && supportsPeripheralServerMode) {
            leRole = BLE_LE_ROLE_PERIPHERAL_CENTRAL_ROLES_CENTRAL_PREFERRED
            check(centralClientModeUuid == peripheralServerModeUuid) {
                "UUIDs for both BLE modes must be the same"
            }
            uuid = centralClientModeUuid
        } else if (supportsCentralClientMode) {
            leRole = when (role) {
                MdocTransport.Role.MDOC -> BLE_LE_ROLE_PERIPHERAL_ROLE_ONLY
                MdocTransport.Role.MDOC_READER -> BLE_LE_ROLE_CENTRAL_CLIENT_ROLE_ONLY
            }
            uuid = centralClientModeUuid
        } else if (supportsPeripheralServerMode) {
            leRole = when (role) {
                MdocTransport.Role.MDOC -> BLE_LE_ROLE_CENTRAL_CLIENT_ROLE_ONLY
                MdocTransport.Role.MDOC_READER -> BLE_LE_ROLE_PERIPHERAL_ROLE_ONLY
            }
            uuid = peripheralServerModeUuid
        } else {
            throw IllegalStateException("At least one of the BLE modes must be set")
        }

        // See "3 Handover to a Bluetooth Carrier" of "Bluetooth® Secure Simple Pairing Using
        // NFC Application Document" Version 1.2. This says:
        //
        //   For Bluetooth LE OOB the name “application/vnd.bluetooth.le.oob” is used as the
        //   [NDEF] record type name. The payload of this type of record is then defined by the
        //   Advertising and Scan Response Data (AD) format that is specified in the Bluetooth Core
        //   Specification ([BLUETOOTH_CORE], Volume 3, Part C, Section 11).
        //
        // Looking that up it says it's just a sequence of {length, AD type, AD data} where each
        // AD is defined in the "Bluetooth Supplement to the Core Specification" document.
        //
        val buf = Buffer()
        buf.writeByte(0x02)  // Length
        buf.writeByte(BLE_LE_ROLE.toByte())
        buf.writeByte(leRole.toByte())
        if (uuid != null && !skipUuids) {
            buf.writeByte(0x11) // Length
            buf.writeByte(BLE_LE_COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS.toByte())
            buf.writeULongLe(uuid.leastSignificantBits)
            buf.writeULongLe(uuid.mostSignificantBits)
        }
        val macAddress = peripheralServerModeMacAddress
        if (macAddress != null) {
            require(macAddress.size == 6) {
                "MAC address should be six bytes, found ${macAddress.size}"
            }
            buf.writeByte(0x07)
            buf.writeByte(BLE_LE_BLUETOOTH_MAC_ADDRESS.toByte())
            buf.write(macAddress)
        }
        val psm = peripheralServerModePsm
        if (psm != null) {
            buf.writeByte(0x05) // Length
            buf.writeByte(BLE_PSM_NOT_YET_ALLOCATED.toByte())
            buf.writeInt(psm)
        }
        val oobData = buf.readByteString()
        val record = NdefRecord(
            NdefRecord.Tnf.MIME_MEDIA,
            Nfc.MIME_TYPE_CONNECTION_HANDOVER_BLE.encodeToByteString(),
            "0".encodeToByteString(),
            oobData
        )

        // From NFC Forum Connection Handover Technical Specification section 7.1 Alternative Carrier Record
        //
        check(auxiliaryReferences.size < 0x100)
        val acrBuf = Buffer()
        acrBuf.writeByte(0x01) // CPS: active
        acrBuf.writeByte(0x01) // Length of carrier data reference ("0")
        acrBuf.writeByte('0'.code.and(0xff).toByte()) // Carrier data reference
        acrBuf.writeByte(auxiliaryReferences.size.and(0xff).toByte()) // Number of auxiliary references
        for (auxRef in auxiliaryReferences) {
            // Each auxiliary reference consists of a single byte for the length and then as
            // many bytes for the reference itself.
            val auxRefUtf8 = auxRef.encodeToByteArray()
            check(auxRefUtf8.size < 0x100)
            acrBuf.writeByte(auxRefUtf8.size.and(0xff).toByte())
            acrBuf.write(auxRefUtf8, 0, auxRefUtf8.size)
        }
        val acRecordPayload = acrBuf.readByteArray()
        val acRecord = NdefRecord(
            tnf = NdefRecord.Tnf.WELL_KNOWN,
            type = Nfc.RTD_ALTERNATIVE_CARRIER,
            payload = ByteString(acRecordPayload)
        )
        return Pair(record, acRecord)
    }
}
