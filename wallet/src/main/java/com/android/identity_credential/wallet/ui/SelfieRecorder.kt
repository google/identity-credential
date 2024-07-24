package com.android.identity_credential.wallet.ui

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.provider.MediaStore
import androidx.camera.core.CameraSelector
import androidx.camera.core.MirrorMode.MIRROR_MODE_ON_FRONT_ONLY
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.video.FallbackStrategy
import androidx.camera.video.FileOutputOptions
import androidx.camera.video.MediaStoreOutputOptions
import androidx.camera.video.OutputOptions
import androidx.camera.video.Quality
import androidx.camera.video.QualitySelector
import androidx.camera.video.Recorder
import androidx.camera.video.Recording
import androidx.camera.video.VideoCapture
import androidx.camera.video.VideoRecordEvent
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.android.identity.issuance.evidence.EvidenceRequestSelfieVideo
import com.android.identity.util.Logger
import com.android.identity_credential.wallet.FaceImageClassifier
import kotlinx.coroutines.guava.await
import java.io.File
import java.text.SimpleDateFormat


/**
 * Video recorder to record a selfie video for identity verification.
 */
class SelfieRecorder(
    private val lifecycleOwner: LifecycleOwner,
    private val context: Context,
    private val onRecordingStarted: () -> Unit,
    private val onFinished: (ByteArray) -> Unit,
    private val onStateChange: (FaceImageClassifier.RecognitionState, EvidenceRequestSelfieVideo.Poses?) -> Unit
) {
    companion object {
        private const val TAG = "SelfieRecorder"
        private const val FILENAME_TIME_FORMAT = "yyyy-MM-dd-HH-mm-ss-SSS"
        private const val FILENAME_FORMAT = "VerificationSelfie-\$datetime.mp4"
    }

    private lateinit var cameraProvider: ProcessCameraProvider
    private lateinit var videoCapture: VideoCapture<Recorder>
    private var recording: Recording? = null
    var faceClassifier: FaceImageClassifier? = null

    /**
     * Starts camera and prepares to record and return a video.
     */
    suspend fun launchCamera(surfaceProvider: Preview.SurfaceProvider) {
        if (::cameraProvider.isInitialized) {
            throw IllegalStateException("Camera already started.")
        }
        cameraProvider = ProcessCameraProvider.getInstance(context).await()

        // Configure preview, so the user can see what they're recording:
        val previewUseCase = Preview.Builder().build()
        previewUseCase.setSurfaceProvider(surfaceProvider)

        // Configure video recording:
        val recorder = Recorder.Builder()
            .setQualitySelector(QualitySelector.from(Quality.HIGHEST,
                FallbackStrategy.higherQualityOrLowerThan(Quality.SD)))
            .build()
        videoCapture = VideoCapture.Builder(recorder)
            .setMirrorMode(MIRROR_MODE_ON_FRONT_ONLY)
            .build()

        // Configure face classifier:
        faceClassifier = FaceImageClassifier(onStateChange, context)

        // Unbind any existing use cases and bind our own:
        cameraProvider.unbindAll()
        cameraProvider.bindToLifecycle(
            lifecycleOwner, CameraSelector.DEFAULT_FRONT_CAMERA,
            previewUseCase, videoCapture, faceClassifier!!.analysisUseCase
        )
    }

    /**
     * Returns a [MediaStoreOutputOptions] for recording a selfie video and saving it to a file
     * in the MediaStore.
     */
    private fun getRecordingOptions(): FileOutputOptions {
        // Save the recording to a local file while it's being created. It'll be uploaded once it's
        // done.
        val fileName = FILENAME_FORMAT.replace(
            "\$datetime",
            SimpleDateFormat(FILENAME_TIME_FORMAT)
                .format(System.currentTimeMillis()))
        val privateDirectory = context.filesDir
        val outputFile = File(privateDirectory, fileName)
        Logger.i(TAG, "Saving selfie video to ${outputFile.absolutePath}")

        return FileOutputOptions.Builder(outputFile)
            .setFileSizeLimit(256 * 1024 * 1024)
            .build()
    }

    /**
     * Starts video recording.
     */
    fun startRecording() {
        if (!::cameraProvider.isInitialized || !::videoCapture.isInitialized) {
            throw IllegalStateException("Recording requested when camera has not been started.")
        }
        if (recording != null) {
            // The UI flow shouldn't allow multiple recordings at once.
            throw IllegalStateException("Recording already in progress.")
        }

        recording = videoCapture.output
            .prepareRecording(context, getRecordingOptions())
            .start(ContextCompat.getMainExecutor(context)) { recordEvent ->
                when(recordEvent) {
                    is VideoRecordEvent.Start -> onRecordingStarted()
                    is VideoRecordEvent.Finalize -> {
                        recording?.close()
                        recording = null
                        if (recordEvent.hasError()) {
                            Logger.e(TAG, "Selfie failed to record: ${recordEvent.error}")
                            onFinished(ByteArray(0))
                        } else {
                            Logger.i(
                                TAG,
                                "Selfie recorded: ${recordEvent.outputResults.outputUri}"
                            )
                            val inputStream = context.contentResolver.openInputStream(
                                recordEvent.outputResults.outputUri)
                            // TODO(kdeus): readAllBytes is new in API level 33. For older versions,
                            //  implement this ourselves. Or find a way to avoid loading the file
                            //  into memory.
                            val videoContents = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                inputStream!!.readAllBytes()
                            } else {
                                TODO("VERSION.SDK_INT < TIRAMISU")
                                ByteArray(0)
                            }
                            inputStream?.close()
                            Logger.i(TAG, "Loaded video file into memory (${videoContents.size} bytes)")
                            onFinished(videoContents)

                            // Now that the file has been sent, we don't need it on disk anymore.
                            Logger.i(TAG, "Deleting file ${recordEvent.outputResults.outputUri}")
                            File(recordEvent.outputResults.outputUri.path!!).delete()
                        }
                    }
                }
            }
    }

    /**
     * Stops the recording and calls the completion handler.
     */
    fun finish() {
        if (recording == null) {
            // The UI flow shouldn't allow finishing the recording if it hasn't started.
            throw IllegalStateException("Can't stop recording if the recording hasn't started.")
        }
        recording?.stop()
        recording = null

        cameraProvider.unbindAll()
    }
}
