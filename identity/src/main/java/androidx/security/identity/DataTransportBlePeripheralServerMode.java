/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package androidx.security.identity;

import static android.content.Context.BLUETOOTH_SERVICE;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.os.ParcelUuid;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.security.identity.Constants.LoggingFlag;

import java.util.List;
import java.util.UUID;

/**
 * @hide
 *
 * BLE data transport implementation conforming to ISO 18013-5 mdoc
 * peripheral server mode.
 */
public class DataTransportBlePeripheralServerMode extends DataTransportBle {
    private static final String TAG = "DataTransportBlePeripheralServerMode";

    UUID mCharacteristicStateUuid =         UUID.fromString("00000001-a123-48ce-896b-4c76973373e6");
    UUID mCharacteristicClient2ServerUuid = UUID.fromString("00000002-a123-48ce-896b-4c76973373e6");
    UUID mCharacteristicServer2ClientUuid = UUID.fromString("00000003-a123-48ce-896b-4c76973373e6");
    // Note: Ident UUID not used in peripheral server mode

    BluetoothManager mBluetoothManager;
    BluetoothLeAdvertiser mBluetoothLeAdvertiser;
    private GattServer mGattServer;
    GattClient mGattClient;
    BluetoothLeScanner mScanner;
    byte[] mEncodedEDeviceKeyBytes;
    private UUID mServiceUuid;
    private long mTimeScanningStartedMillis;

    public DataTransportBlePeripheralServerMode(@NonNull Context context,
        @LoggingFlag int loggingFlags) {
        super(context, loggingFlags);
    }

    @Override
    public void setEDeviceKeyBytes(@NonNull byte[] encodedEDeviceKeyBytes) {
        mEncodedEDeviceKeyBytes = encodedEDeviceKeyBytes;
    }

    private DataRetrievalAddress mListeningAddress;

    @Override
    public @NonNull DataRetrievalAddress getListeningAddress() {
        return mListeningAddress;
    }

    public void setServiceUuid(@NonNull UUID serviceUuid) {
        mServiceUuid = serviceUuid;
    }

    @Override
    public void listen() {
        if (mEncodedEDeviceKeyBytes == null) {
            reportError(new Error("EDeviceKeyBytes not set"));
            return;
        }

        BluetoothManager bluetoothManager =
            (BluetoothManager) mContext.getSystemService(BLUETOOTH_SERVICE);
        BluetoothAdapter bluetoothAdapter = bluetoothManager.getAdapter();

        if (mServiceUuid == null) {
            mServiceUuid = UUID.randomUUID();
        }

        mListeningAddress = new DataRetrievalAddressBlePeripheralServerMode(mServiceUuid);

        // TODO: It would be nice if we got get the MAC address that will be assigned to
        //  this advertisement so we can send it to the mDL reader, out of band. Android
        //  currently doesn't have any APIs to do this but it's possible this could be
        //  added without violating the security/privacy goals behind removing identifiers.
        //

        reportListeningSetupCompleted(mListeningAddress);

        // TODO: Check if BLE is enabled and error out if not so...

        mGattServer = new GattServer(mContext, mLoggingFlags, bluetoothManager, mServiceUuid,
            mEncodedEDeviceKeyBytes,
            mCharacteristicStateUuid, mCharacteristicClient2ServerUuid,
            mCharacteristicServer2ClientUuid, null);
        mGattServer.setListener(new GattServer.Listener() {
            @Override
            public void onPeerConnected() {
                Log.d(TAG, "onPeerConnected");
                reportListeningPeerConnected();
                // No need to advertise anymore since we now have a client...
                if (mBluetoothLeAdvertiser != null) {
                    if ((mLoggingFlags & Constants.LOGGING_FLAG_TRANSPORT_SPECIFIC) != 0) {
                        Log.i(TAG, "Stopping advertising UUID " + mServiceUuid);
                    }
                    mBluetoothLeAdvertiser.stopAdvertising(mAdvertiseCallback);
                    mBluetoothLeAdvertiser = null;
                }
            }

            @Override
            public void onPeerDisconnected() {
                Log.d(TAG, "onPeerDisconnected");
                reportListeningPeerDisconnected();
            }

            @Override
            public void onMessageReceived(@NonNull byte[] data) {
                Log.d(TAG, "onMessageReceived");
                reportMessageReceived(data);
            }

            @Override
            public void onTransportSpecificSessionTermination() {
                Log.d(TAG, "onTransportSpecificSessionTermination");
                reportTransportSpecificSessionTermination();
            }

            @Override
            public void onError(@NonNull Throwable error) {
                Log.d(TAG, "onError", error);
                reportError(error);
            }
        });
        if (!mGattServer.start()) {
            reportError(new Error("Error starting Gatt Server"));
        }

        mBluetoothLeAdvertiser = bluetoothAdapter.getBluetoothLeAdvertiser();
        if (mBluetoothLeAdvertiser == null) {
            reportError(new Error("Failed to create BLE advertiser"));
            mGattServer.stop();
            mGattServer = null;
        } else {
            AdvertiseSettings settings = new AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
                .setConnectable(true)
                .setTimeout(0)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .build();
            AdvertiseData data = new AdvertiseData.Builder()
                .setIncludeTxPowerLevel(false)
                .addServiceUuid(new ParcelUuid(mServiceUuid))
                .build();
            if ((mLoggingFlags & Constants.LOGGING_FLAG_TRANSPORT_SPECIFIC) != 0) {
                Log.i(TAG, "Started advertising UUID " + mServiceUuid);
            }
            mBluetoothLeAdvertiser.startAdvertising(settings, data, mAdvertiseCallback);
        }

    }

    /**
     * Callback to receive information about the advertisement process.
     */
    AdvertiseCallback mAdvertiseCallback = new AdvertiseCallback() {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect) {
        }

        @Override
        public void onStartFailure(int errorCode) {
            reportError(new Error("BLE advertise failed with error code " + errorCode));
        }
    };

    @Override
    public void connect(@NonNull DataRetrievalAddress genericAddress) {
        DataRetrievalAddressBlePeripheralServerMode address =
            (DataRetrievalAddressBlePeripheralServerMode) genericAddress;

        // TODO: Check if BLE is enabled and error out if not so...

        if (mEncodedEDeviceKeyBytes == null) {
            reportError(new Error("EDeviceKeyBytes not set"));
            return;
        }

        mServiceUuid = address.uuid;

        // Start scanning...
        mBluetoothManager = (BluetoothManager) mContext.getSystemService(BLUETOOTH_SERVICE);
        BluetoothAdapter bluetoothAdapter = mBluetoothManager.getAdapter();

        ScanFilter filter = new ScanFilter.Builder()
            .setServiceUuid(new ParcelUuid(mServiceUuid))
            .build();

        ScanSettings settings = new ScanSettings.Builder()
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build();

        if ((mLoggingFlags & Constants.LOGGING_FLAG_TRANSPORT_SPECIFIC) != 0) {
            mTimeScanningStartedMillis = System.currentTimeMillis();
            Log.i(TAG, "Started scanning for UUID " + mServiceUuid);
        }
        mScanner = bluetoothAdapter.getBluetoothLeScanner();
        mScanner.startScan(List.of(filter), settings, mScanCallback);
    }

    ScanCallback mScanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            mGattClient = new GattClient(mContext, mLoggingFlags,
                mServiceUuid, mEncodedEDeviceKeyBytes,
                mCharacteristicStateUuid, mCharacteristicClient2ServerUuid,
                mCharacteristicServer2ClientUuid, null);
            mGattClient.setListener(new GattClient.Listener() {
                @Override
                public void onPeerConnected() {
                    reportConnectionResult(null);
                }

                @Override
                public void onPeerDisconnected() {
                    if (mGattClient != null) {
                        mGattClient.setListener(null);
                        mGattClient.disconnect();
                        mGattClient = null;
                    }
                    reportConnectionDisconnected();
                }

                @Override
                public void onMessageReceived(@NonNull byte[] data) {
                    reportMessageReceived(data);
                }

                @Override
                public void onTransportSpecificSessionTermination() {
                    reportTransportSpecificSessionTermination();
                }

                @Override
                public void onError(@NonNull Throwable error) {
                    reportError(error);
                }
            });

            reportListeningPeerConnecting();
            if ((mLoggingFlags & Constants.LOGGING_FLAG_TRANSPORT_SPECIFIC) != 0) {
                long scanTimeMillis = System.currentTimeMillis() - mTimeScanningStartedMillis;
                Log.i(TAG, "Scanned for " + scanTimeMillis + " milliseconds. "
                    + "Connecting to device with address " + result.getDevice().getAddress());
            }
            mGattClient.connect(result.getDevice());
            if (mScanner != null) {
                if ((mLoggingFlags & Constants.LOGGING_FLAG_TRANSPORT_SPECIFIC) != 0) {
                    Log.i(TAG, "Stopped scanning for UUID " + mServiceUuid);
                }
                mScanner.stopScan(mScanCallback);
                mScanner = null;
            }
            // TODO: Investigate. When testing with Reader C (which is on iOS) we get two callbacks
            //  and thus a NullPointerException when calling stopScan().
        }

        @Override
        public void onBatchScanResults(List<ScanResult> results) {
            Log.w(TAG, "Ignoring unexpected onBatchScanResults");
        }

        @Override
        public void onScanFailed(int errorCode) {
            reportError(new Error("BLE scan failed with error code " + errorCode));
        }
    };

    @Override
    public void close() {
        inhibitCallbacks();
        if (mBluetoothLeAdvertiser != null) {
            if ((mLoggingFlags & Constants.LOGGING_FLAG_TRANSPORT_SPECIFIC) != 0) {
                Log.i(TAG, "Stopping advertising UUID " + mServiceUuid);
            }
            mBluetoothLeAdvertiser.stopAdvertising(mAdvertiseCallback);
            mBluetoothLeAdvertiser = null;
        }
        if (mGattServer != null) {
            mGattServer.setListener(null);
            mGattServer.stop();
        }
        if (mScanner != null) {
            mScanner.stopScan(mScanCallback);
            mScanner = null;
        }
        if (mGattClient != null) {
            mGattClient.setListener(null);
            mGattClient.disconnect();
            mGattClient = null;
        }
    }

    @Override
    public void sendMessage(@NonNull byte[] data) {
        if (mGattServer != null) {
            mGattServer.sendMessage(data);
        } else if (mGattClient != null) {
            mGattClient.sendMessage(data);
        }
    }

    @Override
    public void sendTransportSpecificTerminationMessage() {
        if (mGattServer == null) {
            if (mGattClient == null) {
                reportError(new Error("Transport-specific termination not available"));
                return;
            }
            mGattClient.sendTransportSpecificTermination();
            return;
        }
        mGattServer.sendTransportSpecificTermination();
    }

    @Override
    public boolean supportsTransportSpecificTerminationMessage() {
        return true;
    }
}
