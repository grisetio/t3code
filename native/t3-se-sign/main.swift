// The desktop's Touch ID approver: a Secure Enclave P-256 key that needs Touch ID for every
// signature, kept as a CryptoKit blob in a file (no keychain, so no entitlements). It runs inside
// a bundle named "T3 Code" so the sheet reads "T3 Code is trying to …".
//
//   status [--key FILE]                  no prompt: Touch ID, lid, model, and the key's state
//   create --key FILE                    no prompt: writes FILE, prints the SPKI DER public key
//   sign --key FILE --purpose P          one Touch ID sheet; stdin is one line, the base64url
//                                        message; prints the DER signature over
//                                        "t3-elevation-v1\0" || message
//
// Every command prints one JSON object. Closing stdin or SIGTERM during `sign` closes the sheet.
// Formats: docs/internals/device-approval.md.
import CryptoKit
import Foundation
import IOKit
import LocalAuthentication
import SystemConfiguration

let signatureContext = Data("t3-elevation-v1".utf8) + Data([0])

// macOS writes "T3 Code is trying to <reason>."; the desktop picks one of these, never free text.
let reasons = [
  "approve": "approve an admin request",
  "setup": "set up approvals on this Mac",
  "remove": "remove this Mac as an approver",
]

func emit(_ object: [String: Any]) {
  let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  FileHandle.standardOutput.write(data + Data("\n".utf8))
}

func fail(_ code: String, _ message: String) -> Never {
  emit(["ok": false, "error": ["code": code, "message": message]])
  exit(1)
}

func base64Url(_ data: Data) -> String {
  data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

func fromBase64Url(_ text: String) -> Data? {
  guard text.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
  else { return nil }
  var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
  base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
  return Data(base64Encoded: base64)
}

func option(_ name: String) -> String? {
  let args = CommandLine.arguments
  guard let index = args.firstIndex(of: name), index + 1 < args.count else { return nil }
  return args[index + 1]
}

final class Flag: @unchecked Sendable {
  private let lock = NSLock()
  private var value = false
  func set() { lock.withLock { value = true } }
  var isSet: Bool { lock.withLock { value } }
}

struct KeyFile: Codable {
  var version = 1
  /** CryptoKit's `dataRepresentation`: only this Mac's Secure Enclave can use it. */
  var blob: String
  var publicKey: String
  /** The enrolled fingerprints when the key was made; `.biometryCurrentSet` dies when they change. */
  var domainState: String?
}

func readKey(_ path: String) -> KeyFile? {
  guard let data = FileManager.default.contents(atPath: path) else { return nil }
  return try? JSONDecoder().decode(KeyFile.self, from: data)
}

/// `canEvaluatePolicy` never prompts. It fills `evaluatedPolicyDomainState` when it succeeds.
func biometry(_ context: LAContext) -> (state: String, domainState: Data?) {
  var error: NSError?
  if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
    return ("available", context.evaluatedPolicyDomainState)
  }
  switch (error as? LAError)?.code {
  case .biometryNotAvailable?: return ("not_available", nil)
  case .biometryNotEnrolled?: return ("not_enrolled", nil)
  case .biometryLockout?: return ("lockout", nil)
  case .biometryDisconnected?: return ("disconnected", nil)
  case .biometryNotPaired?: return ("not_paired", nil)
  default: return ("other", nil)
  }
}

func keyState(_ key: KeyFile?, current: Data?) -> String {
  guard let key else { return "absent" }
  guard let current, let stored = key.domainState else { return "unknown" }
  return base64Url(current) == stored ? "valid" : "invalidated"
}

func registryString(_ entry: io_registry_entry_t, _ name: String) -> String? {
  guard entry != 0,
    let value = IORegistryEntryCreateCFProperty(entry, name as CFString, kCFAllocatorDefault, 0)?
      .takeRetainedValue()
  else { return nil }
  if let data = value as? Data {
    return String(decoding: data.prefix { $0 != 0 }, as: UTF8.self)
  }
  return value as? String
}

/// Only laptops report a clamshell; null elsewhere.
func clamshellClosed() -> Bool? {
  let root = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPMrootDomain"))
  defer { IOObjectRelease(root) }
  guard root != 0,
    let value = IORegistryEntryCreateCFProperty(
      root, "AppleClamshellState" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue()
  else { return nil }
  return value as? Bool
}

func status() {
  let context = LAContext()
  let (state, domainState) = biometry(context)
  let product = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/product")
  defer { IOObjectRelease(product) }
  let platform = IOServiceGetMatchingService(
    kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
  defer { IOObjectRelease(platform) }
  var result: [String: Any] = [
    "ok": true,
    "secureEnclave": SecureEnclave.isAvailable,
    "biometry": state,
    "touchId": context.biometryType == .touchID,
    "key": keyState(option("--key").flatMap(readKey), current: domainState),
    "productName": registryString(product, "product-name") ?? NSNull(),
    "hwModel": registryString(platform, "model") ?? NSNull(),
    "computerName": (SCDynamicStoreCopyComputerName(nil, nil) as String?) ?? NSNull(),
  ]
  result["clamshellClosed"] = clamshellClosed() ?? NSNull()
  emit(result)
}

func create(_ path: String) {
  var error: Unmanaged<CFError>?
  guard
    let access = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet],
      &error)
  else { fail("failed", "access control: \(String(describing: error?.takeRetainedValue()))") }
  let (_, domainState) = biometry(LAContext())
  do {
    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    let file = KeyFile(
      blob: key.dataRepresentation.base64EncodedString(),
      publicKey: base64Url(key.publicKey.derRepresentation),
      domainState: domainState.map(base64Url))
    try JSONEncoder().encode(file).write(to: URL(fileURLWithPath: path), options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    emit(["ok": true, "publicKey": file.publicKey])
  } catch { fail("failed", "create: \(error)") }
}

func sign(_ path: String, purpose: String) {
  guard let reason = reasons[purpose] else { fail("usage", "unknown purpose \(purpose)") }
  guard let key = readKey(path), let blob = Data(base64Encoded: key.blob) else {
    fail("no_key", "no key at \(path)")
  }
  guard let line = readLine(strippingNewline: true), let message = fromBase64Url(line) else {
    fail("usage", "stdin must start with one base64url line")
  }
  let context = LAContext()
  context.localizedReason = reason
  // Biometrics only: without this, a failed match offers a password button that can't sign.
  context.localizedFallbackTitle = ""
  let (state, domainState) = biometry(context)
  if state != "available" { fail("unavailable", "Touch ID: \(state)") }
  if keyState(key, current: domainState) == "invalidated" {
    fail("invalidated", "the fingerprints changed since this key was made")
  }

  // Another device answered, or the desktop gave up: close the sheet. `invalidate` makes the
  // pending signature throw, which reports `cancelled` below.
  let aborted = Flag()
  let abort = {
    aborted.set()
    context.invalidate()
  }
  signal(SIGTERM, SIG_IGN)
  let terminate = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
  terminate.setEventHandler(handler: abort)
  terminate.resume()
  Thread.detachNewThread {
    while readLine(strippingNewline: false) != nil {}
    abort()
  }

  Thread.detachNewThread {
    do {
      let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
        dataRepresentation: blob, authenticationContext: context)
      let signature = try privateKey.signature(for: signatureContext + message)
      emit(["ok": true, "signature": base64Url(signature.derRepresentation)])
      exit(0)
    } catch {
      let ns = error as NSError
      let detail = "\(ns.domain) \(ns.code): \(error)"
      if aborted.isSet { fail("cancelled", detail) }
      // Cancel on the sheet: LocalAuthentication's codes, or Security's errSecUserCanceled.
      if ns.domain == LAErrorDomain && [-2, -4, -9, -10].contains(ns.code)
        || ns.domain == NSOSStatusErrorDomain && ns.code == -128
      {
        fail("cancelled", detail)
      }
      if ns.domain == LAErrorDomain && ns.code == LAError.biometryLockout.rawValue {
        fail("unavailable", detail)
      }
      fail("failed", detail)
    }
  }
  dispatchMain()
}

let args = CommandLine.arguments
switch args.count > 1 ? args[1] : "" {
case "status":
  status()
case "create":
  guard let path = option("--key") else { fail("usage", "create --key FILE") }
  create(path)
case "sign":
  guard let path = option("--key"), let purpose = option("--purpose") else {
    fail("usage", "sign --key FILE --purpose approve|setup|remove")
  }
  sign(path, purpose: purpose)
default:
  fail("usage", "status [--key FILE] | create --key FILE | sign --key FILE --purpose P")
}
