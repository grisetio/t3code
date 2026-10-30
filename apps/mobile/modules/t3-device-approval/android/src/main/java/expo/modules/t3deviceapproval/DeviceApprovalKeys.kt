package expo.modules.t3deviceapproval

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import expo.modules.kotlin.exception.CodedException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class ApprovalException(error: ApprovalError, cause: Throwable? = null) :
  CodedException(error.code, "Device approval failed: ${error.code}", cause)

/**
 * Hardware-backed P-256 keys that sign only after a fresh strong biometric. Every entry point
 * checks the alias first so this module never reads or deletes another module's Keystore entry.
 * Unexpected Keystore exceptions keep Expo's own code, which index.ts reports as `failed`.
 */
object DeviceApprovalKeys {
  private const val PROVIDER = "AndroidKeyStore"

  private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

  private fun requireAlias(alias: String) {
    if (!DeviceApprovalCodec.isAlias(alias)) throw ApprovalException(ApprovalError.FAILED)
  }

  private fun hasStrongBox(context: Context): Boolean =
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
      context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

  @RequiresApi(Build.VERSION_CODES.R)
  private fun biometricError(context: Context): ApprovalError? {
    val manager =
      context.getSystemService(BiometricManager::class.java) ?: return ApprovalError.UNAVAILABLE
    return DeviceApprovalCodec.errorForCanAuthenticate(
      manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    )
  }

  fun availability(context: Context): Map<String, Any> {
    val strongBox = hasStrongBox(context)
    // Per-use biometric binding (`setUserAuthenticationParameters(0, ...)`) needs Android 11.
    val error = if (Build.VERSION.SDK_INT >=
      Build.VERSION_CODES.R
    ) {
      biometricError(context)
    } else {
      ApprovalError.UNAVAILABLE
    }
    return if (error == null) {
      mapOf("available" to true, "strongBox" to strongBox)
    } else {
      mapOf("available" to false, "strongBox" to strongBox, "reason" to error.code)
    }
  }

  fun has(alias: String): Boolean {
    requireAlias(alias)
    return keyStore().containsAlias(alias)
  }

  fun delete(alias: String) {
    requireAlias(alias)
    val store = keyStore()
    if (store.containsAlias(alias)) store.deleteEntry(alias)
  }

  private fun requireChallenge(text: String): ByteArray =
    DeviceApprovalCodec.decodeBase64Url(text)
      ?.takeIf { it.size == DeviceApprovalCodec.ATTESTATION_CHALLENGE_BYTES }
      ?: throw ApprovalException(ApprovalError.FAILED)

  /** Replaces any key under [alias], which is how a phone re-enrolls after invalidation. */
  @RequiresApi(Build.VERSION_CODES.R)
  fun generate(context: Context, alias: String, attestationChallenge: String): Map<String, Any> {
    requireAlias(alias)
    val challenge = requireChallenge(attestationChallenge)
    // Keystore refuses biometric-bound keys while no biometric is enrolled.
    biometricError(context)?.let { throw ApprovalException(it) }

    val strongBox = hasStrongBox(context) &&
      try {
        generateKeyPair(alias, challenge, strongBox = true)
        true
      } catch (_: StrongBoxUnavailableException) {
        false
      }
    if (!strongBox) generateKeyPair(alias, challenge, strongBox = false)

    val store = keyStore()
    val chain = store.getCertificateChain(alias)
    val securityLevel = (store.getKey(alias, null) as? PrivateKey)?.let {
      securityLevel(it, strongBox)
    }
    if (chain.isNullOrEmpty() || securityLevel == null) {
      store.deleteEntry(alias)
      throw ApprovalException(ApprovalError.UNAVAILABLE)
    }
    val spki = chain[0].publicKey.encoded
    return mapOf(
      "keyId" to DeviceApprovalCodec.keyId(spki),
      "publicKeySpki" to DeviceApprovalCodec.encodeBase64Url(spki),
      "attestationChain" to chain.map { DeviceApprovalCodec.encodeBase64Url(it.encoded) },
      "securityLevel" to securityLevel,
    )
  }

  @RequiresApi(Build.VERSION_CODES.R)
  private fun generateKeyPair(alias: String, challenge: ByteArray, strongBox: Boolean) {
    // The helper checks the attested CREATION_DATETIME for freshness; Keystore adds it itself.
    val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setUserAuthenticationRequired(true)
      .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
      .setInvalidatedByBiometricEnrollment(true)
      .setUnlockedDeviceRequired(true)
      .setAttestationChallenge(challenge)
      .setIsStrongBoxBacked(strongBox)
      .build()
    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).apply {
      initialize(spec)
      generateKeyPair()
    }
  }

  /** `null` for software keys, which the API never hands out. */
  private fun securityLevel(privateKey: PrivateKey, strongBox: Boolean): String? {
    val info = KeyFactory.getInstance(
      privateKey.algorithm,
      PROVIDER
    ).getKeySpec(privateKey, KeyInfo::class.java)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      return when (info.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "tee"
        else -> null
      }
    }
    @Suppress("DEPRECATION")
    val secure = info.isInsideSecureHardware
    return when {
      !secure -> null
      strongBox -> "strongbox"
      else -> "tee"
    }
  }

  /**
   * An initialized signature for the prompt's `CryptoObject`. Missing biometrics and lockout are
   * left to the prompt, which reports them more precisely than `canAuthenticate`.
   */
  fun prepareSignature(alias: String): Signature {
    requireAlias(alias)
    val privateKey =
      keyStore().getKey(alias, null) as? PrivateKey
        ?: throw ApprovalException(ApprovalError.NOT_FOUND)
    val signature = Signature.getInstance("SHA256withECDSA")
    try {
      signature.initSign(privateKey)
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw ApprovalException(ApprovalError.KEY_INVALIDATED, e)
    }
    return signature
  }
}
