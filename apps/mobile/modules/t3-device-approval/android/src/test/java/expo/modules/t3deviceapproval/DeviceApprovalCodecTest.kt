package expo.modules.t3deviceapproval

import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import java.io.File
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], manifest = Config.NONE)
class DeviceApprovalCodecTest {
  private val vectors = JSONObject(File(System.getProperty("deviceApprovalVectors")!!).readText())

  private fun bytes(text: String) = DeviceApprovalCodec.decodeBase64Url(text)!!

  private fun publicKey(spki: String): PublicKey =
    KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes(spki)))

  private fun privateKey(pkcs8: String): PrivateKey =
    KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(bytes(pkcs8)))

  private fun testKeys() = vectors.getJSONObject("keys").let { keys ->
    listOf("enrolled", "other", "newDevice").map { keys.getJSONObject(it) }
  }

  private fun verifies(spki: String, message: ByteArray, signature: ByteArray): Boolean = try {
    Signature.getInstance("SHA256withECDSA").run {
      initVerify(publicKey(spki))
      update(message)
      verify(signature)
    }
  } catch (_: SignatureException) {
    false
  }

  private fun signedMessage(payload: ByteArray) =
    bytes(vectors.getString("contextBase64Url")) + payload

  @Test
  fun derivesKeyIdsFromSpki() {
    val codes = vectors.getJSONArray("comparisonCodes")
    val cases = testKeys() + (0 until codes.length()).map { codes.getJSONObject(it) }
    for (case in cases) {
      assertEquals(
        case.getString("keyId"),
        DeviceApprovalCodec.keyId(bytes(case.getString("spkiDer")))
      )
    }
  }

  @Test
  fun signsContextThenPayloadAsDer() {
    val payloads = vectors.getJSONArray("payloads")
    for (key in testKeys()) {
      for (i in 0 until payloads.length()) {
        val payload = bytes(payloads.getJSONObject(i).getString("payload"))
        val signer = Signature.getInstance("SHA256withECDSA").apply {
          initSign(privateKey(key.getString("pkcs8Der")))
        }

        val signature = DeviceApprovalCodec.sign(signer, payload)

        assertTrue(verifies(key.getString("spkiDer"), signedMessage(payload), signature))
        assertFalse(verifies(key.getString("spkiDer"), payload, signature))
      }
    }
  }

  @Test
  fun vectorSignaturesVerifyOverTheSameMessage() {
    val keysById = testKeys().associateBy { it.getString("keyId") }
    val payloads = vectors.getJSONArray("payloads")
    for (i in 0 until payloads.length()) {
      val case = payloads.getJSONObject(i)
      val response = case.getJSONObject("signature")
      val spki = keysById.getValue(response.getString("keyId")).getString("spkiDer")
      val message = signedMessage(bytes(case.getString("payload")))
      assertTrue(
        case.getString("name"),
        verifies(spki, message, bytes(response.getString("signature")))
      )
    }

    // Only the signature-shaped outcomes; keyId, expiry, and alg checks belong to the module.
    val verify = vectors.getJSONArray("verify")
    for (i in 0 until verify.length()) {
      val case = verify.getJSONObject(i)
      val expected = case.getString("expected")
      val response = case.getJSONObject("response")
      if (expected != "ok" && expected != "bad_signature") continue
      val spki = vectors.getJSONObject("keys").getJSONObject("enrolled").getString("spkiDer")
      val message = signedMessage(bytes(case.getString("payload")))
      val signature =
        DeviceApprovalCodec.decodeBase64Url(response.getString("signature")) ?: ByteArray(0)
      assertEquals(case.getString("name"), expected == "ok", verifies(spki, message, signature))
    }
  }

  @Test
  fun base64UrlIsStrict() {
    assertArrayEquals(
      "t3-elevation-v1\u0000".toByteArray(),
      bytes(vectors.getString("contextBase64Url"))
    )
    assertEquals(
      vectors.getString("contextBase64Url"),
      DeviceApprovalCodec.encodeBase64Url("t3-elevation-v1\u0000".toByteArray())
    )
    assertArrayEquals(byteArrayOf(-5, -1), bytes("-_8"))
    assertArrayEquals(ByteArray(0), bytes(""))
    for (invalid in listOf("-_8=", "+/8", "ab cd", "abc\n", "a", "abcde")) {
      assertNull(invalid, DeviceApprovalCodec.decodeBase64Url(invalid))
    }
  }

  @Test
  fun acceptsOnlyItsOwnAliases() {
    // encodeURIComponent("env:1/ü") and encodeURIComponent("o'brien.x_y-z~")
    assertTrue(DeviceApprovalCodec.isAlias("t3-elevation:env%3A1%2F%C3%BC:o'brien.x_y-z~"))
    assertTrue(DeviceApprovalCodec.isAlias("t3-elevation:environment-1:kgriset"))
    for (alias in listOf(
      "",
      "t3-elevation:",
      "t3-elevation::kgriset",
      "t3-elevation:env:",
      "t3-elevation:env:a:b",
      "t3-elevation:env:k griset",
      "t3-elevation:env:kgriset\n",
      "T3-elevation:env:kgriset",
      "expo-secure-store-master-key",
      "t3-elevation:${"e".repeat(500)}:kgriset",
    )) {
      assertFalse(alias, DeviceApprovalCodec.isAlias(alias))
    }
  }

  @Test
  fun mapsPromptErrors() {
    val expected = mapOf(
      BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED to ApprovalError.CANCELLED,
      BiometricPrompt.BIOMETRIC_ERROR_CANCELED to ApprovalError.CANCELLED,
      BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT to ApprovalError.CANCELLED,
      BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT to ApprovalError.LOCKOUT,
      BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT to ApprovalError.LOCKOUT,
      BiometricPrompt.BIOMETRIC_ERROR_NO_BIOMETRICS to ApprovalError.NO_BIOMETRICS,
      BiometricPrompt.BIOMETRIC_ERROR_HW_NOT_PRESENT to ApprovalError.UNAVAILABLE,
      BiometricPrompt.BIOMETRIC_ERROR_HW_UNAVAILABLE to ApprovalError.UNAVAILABLE,
      BiometricPrompt.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED to ApprovalError.UNAVAILABLE,
      BiometricPrompt.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL to ApprovalError.FAILED,
      BiometricPrompt.BIOMETRIC_ERROR_UNABLE_TO_PROCESS to ApprovalError.FAILED,
      BiometricPrompt.BIOMETRIC_ERROR_VENDOR to ApprovalError.FAILED,
    )
    for ((code, error) in expected) {
      assertEquals(
        "prompt error $code",
        error,
        DeviceApprovalCodec.errorForPrompt(code)
      )
    }
  }

  @Test
  fun mapsAvailability() {
    assertNull(DeviceApprovalCodec.errorForCanAuthenticate(BiometricManager.BIOMETRIC_SUCCESS))
    assertEquals(
      ApprovalError.NO_BIOMETRICS,
      DeviceApprovalCodec.errorForCanAuthenticate(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED)
    )
    for (status in listOf(
      BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
      BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
      BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
    )) {
      assertEquals(ApprovalError.UNAVAILABLE, DeviceApprovalCodec.errorForCanAuthenticate(status))
    }
  }
}
