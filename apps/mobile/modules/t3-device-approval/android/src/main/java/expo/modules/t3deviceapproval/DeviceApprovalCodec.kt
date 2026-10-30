package expo.modules.t3deviceapproval

import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.util.Base64
import java.security.MessageDigest
import java.security.Signature

/** Wire codes the TS API rejects with; keep in sync with `ApprovalError` in index.ts. */
enum class ApprovalError(val code: String) {
  UNAVAILABLE("unavailable"),
  NO_BIOMETRICS("no_biometrics"),
  CANCELLED("cancelled"),
  LOCKOUT("lockout"),
  KEY_INVALIDATED("key_invalidated"),
  NOT_FOUND("not_found"),
  FAILED("failed")
}

/** Formats from docs/internals/device-approval.md, kept free of Keystore so JVM tests cover them. */
object DeviceApprovalCodec {
  private val CONTEXT = "t3-elevation-v1\u0000".toByteArray(Charsets.US_ASCII)
  private const val KEY_ID_BYTES = 16
  const val ATTESTATION_CHALLENGE_BYTES = 32
  private const val MAX_ALIAS_LENGTH = 512

  private val base64UrlPattern = Regex("^[A-Za-z0-9_-]*$")

  // Matches what encodeURIComponent leaves unescaped, plus `%`, so index.ts's alias always
  // passes and no alias can reach Keystore entries that other modules own.
  private val aliasPattern = Regex("^t3-elevation:[A-Za-z0-9%._~!*'()-]+:[A-Za-z0-9%._~!*'()-]+$")

  fun isAlias(alias: String): Boolean =
    alias.length <= MAX_ALIAS_LENGTH && aliasPattern.matches(alias)

  /** Unpadded base64url only; anything else is `null`, as the contract requires of decoders. */
  fun decodeBase64Url(text: String): ByteArray? {
    if (!base64UrlPattern.matches(text) || text.length % 4 == 1) return null
    return try {
      Base64.decode(text, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
      null
    }
  }

  fun encodeBase64Url(bytes: ByteArray): String =
    Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

  fun keyId(spkiDer: ByteArray): String =
    encodeBase64Url(MessageDigest.getInstance("SHA-256").digest(spkiDer).copyOf(KEY_ID_BYTES))

  /** Signs `context || payload` with an initialized `SHA256withECDSA`, giving a DER signature. */
  fun sign(signature: Signature, payload: ByteArray): ByteArray {
    signature.update(CONTEXT)
    signature.update(payload)
    return signature.sign()
  }

  fun errorForPrompt(errorCode: Int): ApprovalError = when (errorCode) {
    BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
    BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
    BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT -> ApprovalError.CANCELLED
    BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT,
    BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT -> ApprovalError.LOCKOUT
    BiometricPrompt.BIOMETRIC_ERROR_NO_BIOMETRICS -> ApprovalError.NO_BIOMETRICS
    BiometricPrompt.BIOMETRIC_ERROR_HW_NOT_PRESENT,
    BiometricPrompt.BIOMETRIC_ERROR_HW_UNAVAILABLE,
    BiometricPrompt.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> ApprovalError.UNAVAILABLE
    else -> ApprovalError.FAILED
  }

  /** `null` when strong biometrics can authenticate now. */
  fun errorForCanAuthenticate(status: Int): ApprovalError? = when (status) {
    BiometricManager.BIOMETRIC_SUCCESS -> null
    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> ApprovalError.NO_BIOMETRICS
    else -> ApprovalError.UNAVAILABLE
  }
}
