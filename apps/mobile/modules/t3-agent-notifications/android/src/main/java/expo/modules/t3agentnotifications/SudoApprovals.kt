package expo.modules.t3agentnotifications

import android.app.Activity
import android.app.Application
import android.app.Dialog
import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.provider.Settings
import android.view.ViewGroup
import androidx.core.app.NotificationCompat
import java.security.KeyStore
import java.util.UUID
import org.json.JSONObject

/**
 * Opens a sudo approval push. It is declared `showWhenLocked`, which is what lets SystemUI open
 * it from the lock screen without asking to unlock first; it then hands the request to the app's
 * activity, which shows over the lock screen only for that request, behind a cover.
 */
class SudoApprovalActivity : Activity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    SudoApprovals.open(this, intent.getStringExtra(SudoApprovals.EXTRA_PATH))
    finish()
  }
}

/** Sudo approval pushes: their own channel, only on phones that hold a key for the machine. */
object SudoApprovals {
  const val CHANNEL = "sudo-approvals"
  private const val TAG = "t3-sudo-approval"
  const val EXTRA_PATH = "expo.modules.t3agentnotifications.SUDO_APPROVAL_PATH"
  private const val STORE = "t3-sudo-approvals"
  private const val KEY_ALIAS_PREFIX = "t3-elevation:"

  // A request lives at most 300 s (the approval window's maximum).
  private const val TIMEOUT_MS = 5 * 60 * 1000L

  /** The relay marks a single-thread sudo approval alert with `alert_request_kind: "sudo"`. */
  private const val SUDO_KIND = "sudo"

  fun isSudoApproval(data: Map<String, String>): Boolean = data["alert_request_kind"] == SUDO_KIND

  private val threadPath = Regex("^/threads/([^/?#]+)/[^/?#]+$")

  /** The environment id as the path carries it, encoded the same way as key aliases. */
  fun environmentSegment(path: String?): String? =
    path?.let { threadPath.matchEntire(it)?.groupValues?.get(1) }

  fun canApprove(path: String?, aliases: Iterable<String>): Boolean {
    val segment = environmentSegment(path) ?: return false
    return aliases.any { it.startsWith("$KEY_ALIAS_PREFIX$segment:") }
  }

  /** Overridden in tests; Robolectric has no AndroidKeyStore. */
  @Volatile var keyAliases: () -> Iterable<String> = {
    try {
      KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.aliases().toList()
    } catch (_: Exception) {
      emptyList()
    }
  }

  fun channel(): NotificationChannel? =
    if (Build.VERSION.SDK_INT >= 26) {
      NotificationChannel(CHANNEL, "Sudo approvals", NotificationManager.IMPORTANCE_HIGH).apply {
        description = "An agent asks to run a command as admin."
        lockscreenVisibility = Notification.VISIBILITY_PRIVATE
      }
    } else {
      null
    }

  /** Machine names as the user named them on this phone, keyed by environment id. */
  fun setMachines(context: Context, machines: Map<String, String>) {
    context.getSharedPreferences(STORE, Context.MODE_PRIVATE).edit()
      .putString("machines", JSONObject(machines).toString()).apply()
  }

  private fun machine(context: Context, path: String?): String? {
    val segment = environmentSegment(path)
    val text = context.getSharedPreferences(STORE, Context.MODE_PRIVATE)
      .getString("machines", null)
    if (segment == null || text == null) return null
    return try {
      JSONObject(text).optString(Uri.decode(segment)).takeIf { it.isNotBlank() }?.take(120)
    } catch (_: org.json.JSONException) {
      null
    }
  }

  /**
   * Posts the push for [alertId]. The push carries no request content; the card is read from the
   * server once opened. Returns false when this phone can't approve for that machine.
   */
  fun post(context: Context, data: Map<String, String>, alertId: String): Boolean {
    val path = data["alert_path"]
    if (!canApprove(path, keyAliases())) return false
    val manager = context.getSystemService(NotificationManager::class.java)
    val icon = context.resources.getIdentifier("notification_icon", "drawable", context.packageName)
    val title = "Approval needed"
    val public = NotificationCompat.Builder(context, CHANNEL)
      .setSmallIcon(if (icon != 0) icon else android.R.drawable.ic_dialog_info)
      .setContentTitle(title)
      .build()
    val builder = NotificationCompat.Builder(context, CHANNEL)
      .setSmallIcon(if (icon != 0) icon else android.R.drawable.ic_dialog_info)
      .setPriority(NotificationCompat.PRIORITY_HIGH)
      .setDefaults(Notification.DEFAULT_ALL)
      .setContentTitle(title)
      .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
      .setPublicVersion(public)
      .setAutoCancel(true)
      .setTimeoutAfter(TIMEOUT_MS)
      .setContentIntent(openIntent(context, path, alertId.hashCode()))
    machine(context, path)?.let { builder.setContentText(it) }
    manager.notify(TAG, alertId.hashCode(), builder.build())
    return true
  }

  fun clear(context: Context) {
    val manager = context.getSystemService(NotificationManager::class.java)
    manager.activeNotifications.filter { it.tag == TAG }.forEach { manager.cancel(it.tag, it.id) }
  }

  private fun openIntent(context: Context, path: String?, id: Int): PendingIntent =
    PendingIntent.getActivity(
      context,
      id,
      Intent(context, SudoApprovalActivity::class.java)
        .putExtra(EXTRA_PATH, path)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION),
      PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )

  // --- Opening a request, possibly over the lock screen

  /** A tapped request the app hasn't read yet. */
  data class Launch(val path: String, val lockScreen: Boolean) {
    fun toMap() = mapOf("path" to path, "lockScreen" to lockScreen)
  }

  @Volatile private var pending: Launch? = null

  /** Set by the module while JS is running, so a tap reaches an app already on screen. */
  @Volatile var onLaunch: ((Launch) -> Unit)? = null

  const val EXTRA_LOCK_TOKEN = "expo.modules.t3agentnotifications.SUDO_APPROVAL_LOCK_TOKEN"

  /** A lock-screen tap handed to the app: only the activity its launch intent reaches takes it. */
  private data class Armed(val token: String, val at: Long)

  private var armed: Armed? = null
  private const val ARM_WINDOW_MS = 10_000L

  /** Overridden in tests. */
  @Volatile var clock: () -> Long = { SystemClock.elapsedRealtime() }

  /** The activity shown over the lock screen, and the cover that hides the app inside it. */
  private class Shown(val activity: Activity, val cover: Dialog)

  @Volatile private var shown: Shown? = null
  private var callbacksRegistered: Application? = null

  fun consume(): Launch? = synchronized(this) { pending.also { pending = null } }

  fun open(trampoline: Activity, path: String?) {
    val route = path?.takeIf { threadPath.matches(it) } ?: return
    val lockScreen = isLocked(trampoline) && Build.VERSION.SDK_INT >= 27
    val launch = Launch(route, lockScreen)
    val token = if (lockScreen) UUID.randomUUID().toString() else null
    // A newer tap replaces an older arm, including with none.
    synchronized(this) {
      pending = launch
      armed = token?.let { Armed(it, clock()) }
    }
    registerCallbacks(trampoline.application)
    val intent = trampoline.packageManager.getLaunchIntentForPackage(trampoline.packageName)
      ?: return
    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    if (token != null) intent.putExtra(EXTRA_LOCK_TOKEN, token)
    trampoline.startActivity(intent)
    onLaunch?.invoke(launch)
  }

  /**
   * The app's activity is not `showWhenLocked` in its manifest. It shows over the lock screen
   * only when it receives the launch a lock-screen tap armed, once and soon after the tap, and
   * stops as soon as it leaves the screen. A cold start reads the token here; an activity that
   * was already running gets it through [onNewIntent].
   */
  @Synchronized
  private fun registerCallbacks(application: Application) {
    if (callbacksRegistered === application) return
    callbacksRegistered = application
    application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
      override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) =
        take(activity, activity.intent)

      override fun onActivityStarted(activity: Activity) = Unit

      override fun onActivityResumed(activity: Activity) = Unit

      override fun onActivityPaused(activity: Activity) = Unit

      override fun onActivityStopped(activity: Activity) {
        if (shown?.activity === activity) end(activity, leave = false)
      }

      override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

      override fun onActivityDestroyed(activity: Activity) {
        if (shown?.activity === activity) end(activity, leave = false)
      }
    })
  }

  /** From the module, for an activity that was already running when the tap arrived. */
  fun onNewIntent(activity: Activity, intent: Intent) = take(activity, intent)

  /** Spends the arm when [intent] is the launch it was made for; true if that came in time. */
  private fun claim(intent: Intent?): Boolean = synchronized(this) {
    val token = intent?.getStringExtra(EXTRA_LOCK_TOKEN)
    val current = armed?.takeIf { token != null && it.token == token }
    if (current != null) armed = null
    current != null && clock() - current.at in 0..ARM_WINDOW_MS
  }

  /** Shows [activity] over the lock screen when [intent] is the armed launch. */
  fun take(activity: Activity, intent: Intent?) {
    if (activity is SudoApprovalActivity || Build.VERSION.SDK_INT < 27 || !claim(intent)) return
    shown?.let { end(it.activity, leave = false) }
    // The app's own screen (threads, composer) must never show over the lock screen, and JS
    // can't render anything until the activity is visible. So an opaque window covers the
    // activity and any dialog it already had open, from its first frame; the request's card
    // opens as a newer window above it. Back on the cover returns to the lock screen.
    val cover = Dialog(activity, android.R.style.Theme_DeviceDefault_NoActionBar).apply {
      window?.setBackgroundDrawable(ColorDrawable(Color.BLACK))
      window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
      setCanceledOnTouchOutside(false)
      setOnCancelListener { end(activity, leave = true) }
    }
    shown = Shown(activity, cover)
    activity.setShowWhenLocked(true)
    cover.show()
  }

  /** Whether the app is showing over the lock screen for a request right now. */
  fun overLockScreen(): Boolean = shown != null

  fun isLocked(context: Context): Boolean =
    context.getSystemService(KeyguardManager::class.java)?.isKeyguardLocked == true

  /** Ends showing over the lock screen; [leave] returns to the lock screen if still locked. */
  fun end(activity: Activity, leave: Boolean) {
    if (Build.VERSION.SDK_INT >= 27) activity.setShowWhenLocked(false)
    val current = shown
    if (current?.activity === activity) {
      shown = null
      current.cover.setOnCancelListener(null)
      current.cover.dismiss()
    }
    if (leave && isLocked(activity)) activity.moveTaskToBack(true)
  }

  fun requestUnlock(activity: Activity, done: (Boolean) -> Unit) {
    val keyguard = activity.getSystemService(KeyguardManager::class.java)
    if (keyguard == null || !keyguard.isKeyguardLocked) return done(true)
    if (Build.VERSION.SDK_INT < 26) return done(false)
    keyguard.requestDismissKeyguard(
      activity,
      object : KeyguardManager.KeyguardDismissCallback() {
        override fun onDismissSucceeded() {
          end(activity, leave = false)
          done(true)
        }

        override fun onDismissCancelled() = done(false)

        override fun onDismissError() = done(false)
      }
    )
  }

  /**
   * Whether the lock screen hides notification content, per Android's setting or a device policy.
   * Unreadable counts as hidden: showing less is the safe mistake.
   */
  fun hidesSensitiveContent(context: Context): Boolean {
    val policy = context.getSystemService(DevicePolicyManager::class.java)
    val disabled = policy?.getKeyguardDisabledFeatures(null) ?: 0
    val byPolicy = disabled and DevicePolicyManager.KEYGUARD_DISABLE_UNREDACTED_NOTIFICATIONS != 0
    val byChannel = Build.VERSION.SDK_INT >= 26 &&
      context.getSystemService(NotificationManager::class.java)
        .getNotificationChannel(CHANNEL)?.lockscreenVisibility == Notification.VISIBILITY_SECRET
    return byPolicy || byChannel || !allowsPrivateNotifications(context)
  }

  private fun allowsPrivateNotifications(context: Context): Boolean = try {
    Settings.Secure.getInt(
      context.contentResolver,
      "lock_screen_allow_private_notifications",
      0
    ) != 0
  } catch (_: SecurityException) {
    false
  }
}
