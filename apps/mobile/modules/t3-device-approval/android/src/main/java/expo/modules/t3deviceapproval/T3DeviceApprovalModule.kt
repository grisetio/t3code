package expo.modules.t3deviceapproval

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import androidx.annotation.RequiresApi
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import java.security.GeneralSecurityException
import java.security.ProviderException
import java.security.Signature
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class SignPrompt : Record {
  @Field val title: String = ""

  @Field val subtitle: String? = null

  @Field val description: String? = null
}

class T3DeviceApprovalModule : Module() {
  // Signing runs off the main thread: StrongBox operations can take hundreds of milliseconds.
  private val promptExecutor = Executors.newSingleThreadExecutor()

  override fun definition() = ModuleDefinition {
    Name("T3DeviceApproval")

    OnDestroy { promptExecutor.shutdown() }

    AsyncFunction("getAvailability") {
      val context = appContext.reactContext ?: throw ApprovalException(ApprovalError.UNAVAILABLE)
      DeviceApprovalKeys.availability(context)
    }

    AsyncFunction("generateKey") { alias: String, attestationChallenge: String ->
      val context = appContext.reactContext
      if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
        throw ApprovalException(ApprovalError.UNAVAILABLE)
      }
      DeviceApprovalKeys.generate(context, alias, attestationChallenge)
    }

    AsyncFunction("sign") { alias: String, payload: String, prompt: SignPrompt, promise: Promise ->
      val activity = appContext.currentActivity
      if (activity == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
        throw ApprovalException(ApprovalError.UNAVAILABLE)
      }
      val bytes =
        DeviceApprovalCodec.decodeBase64Url(payload)
          ?: throw ApprovalException(ApprovalError.FAILED)
      if (prompt.title.isBlank()) throw ApprovalException(ApprovalError.FAILED)
      val signature = DeviceApprovalKeys.prepareSignature(alias)
      activity.runOnUiThread { authenticate(activity, signature, bytes, prompt, promise) }
    }

    AsyncFunction("deleteKey") { alias: String -> DeviceApprovalKeys.delete(alias) }

    AsyncFunction("hasKey") { alias: String -> DeviceApprovalKeys.has(alias) }
  }

  @RequiresApi(Build.VERSION_CODES.R)
  private fun authenticate(
    activity: Activity,
    signature: Signature,
    payload: ByteArray,
    prompt: SignPrompt,
    promise: Promise
  ) {
    val settled = AtomicBoolean(false)
    fun reject(error: ApprovalError, cause: Throwable? = null) {
      if (settled.compareAndSet(false, true)) promise.reject(ApprovalException(error, cause))
    }

    val builder = BiometricPrompt.Builder(activity)
      .setTitle(prompt.title)
      .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      // A passive strong face match must not approve a command at a glance.
      .setConfirmationRequired(true)
      .setNegativeButton(activity.getString(android.R.string.cancel), promptExecutor) { _, _ ->
        reject(ApprovalError.CANCELLED)
      }
    prompt.subtitle?.let { builder.setSubtitle(it) }
    prompt.description?.let { builder.setDescription(it) }

    val callback = object : BiometricPrompt.AuthenticationCallback() {
      // The prompt authorized this same Signature through its CryptoObject.
      override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        try {
          val signed = DeviceApprovalCodec.sign(signature, payload)
          if (settled.compareAndSet(false, true)) {
            promise.resolve(mapOf("signature" to DeviceApprovalCodec.encodeBase64Url(signed)))
          }
        } catch (e: GeneralSecurityException) {
          reject(ApprovalError.FAILED, e)
        } catch (e: ProviderException) {
          reject(ApprovalError.FAILED, e)
        }
      }

      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        reject(DeviceApprovalCodec.errorForPrompt(errorCode))
      }
    }

    try {
      builder.build().authenticate(
        BiometricPrompt.CryptoObject(signature),
        CancellationSignal(),
        promptExecutor,
        callback
      )
    } catch (e: IllegalArgumentException) {
      reject(ApprovalError.FAILED, e)
    }
  }
}
