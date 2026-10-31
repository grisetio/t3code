package expo.modules.t3agentnotifications

import android.app.NotificationManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * Reads and opens the "Sudo approvals" channel. T3 keeps no copy of the
 * setting: the channel is the setting, and Settings → Device approval only
 * mirrors it and links to Android's page.
 */
class SudoApprovalChannelModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("T3SudoApprovalChannel")

    /** "app_off" when the app-wide switch blocks it, "missing" before the channel exists. */
    Function("state") {
      val context = appContext.reactContext ?: return@Function "missing"
      channelState(context)
    }

    /** Opens the channel's page, or the app's page when the app-wide switch is the blocker. */
    Function("openSettings") {
      val context = appContext.reactContext ?: return@Function false
      val channelPage =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
          channelState(context).let { it == "on" || it == "off" }
      val intent =
        if (channelPage) {
          Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
            .putExtra(Settings.EXTRA_CHANNEL_ID, SudoApprovals.CHANNEL)
        } else {
          Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
        }
      try {
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
      } catch (_: ActivityNotFoundException) {
        false
      }
    }
  }

  private fun channelState(context: Context): String {
    if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) return "app_off"
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return "on"
    val manager = context.getSystemService(NotificationManager::class.java)
    // The channel is the setting, so make sure it exists before the user is sent to it.
    val channel =
      manager.getNotificationChannel(SudoApprovals.CHANNEL)
        ?: SudoApprovals.channel()?.also(manager::createNotificationChannel)
        ?: return "missing"
    val groupBlocked =
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
        channel.group?.let { manager.getNotificationChannelGroup(it)?.isBlocked } == true
    val blocked = channel.importance == NotificationManager.IMPORTANCE_NONE || groupBlocked
    return if (blocked) "off" else "on"
  }
}
