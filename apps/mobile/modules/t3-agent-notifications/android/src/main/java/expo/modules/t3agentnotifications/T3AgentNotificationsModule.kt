package expo.modules.t3agentnotifications

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Build
import android.provider.Settings
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class T3AgentNotificationsModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("T3AgentNotifications")

    // A signal only: JS reads the tap with `consumeSudoApprovalOpen`, which also covers cold starts.
    Events("onSudoApprovalOpened")

    OnCreate {
      SudoApprovals.onLaunch = { sendEvent("onSudoApprovalOpened", emptyMap<String, Any>()) }
    }

    OnDestroy { SudoApprovals.onLaunch = null }

    Function("configure") {
        deviceId: String,
        userId: String,
        scheme: String,
        ongoingEnabled: Boolean
      ->
      appContext.reactContext?.let {
        AgentNotifications.configure(it, deviceId, userId, scheme, ongoingEnabled)
      }
    }

    Function("clear") {
      appContext.reactContext?.let { AgentNotifications.clear(it) }
    }

    Function("showShowcaseActivity") { scheme: String, data: Map<String, String> ->
      appContext.reactContext?.let { AgentNotifications.showcase(it, scheme, data) }
    }

    Function("setThreadOnScreen") { path: String? ->
      AgentNotifications.setThreadOnScreen(path)
    }

    Function("openLiveUpdateSettings") {
      val context = appContext.reactContext
      if (context == null || Build.VERSION.SDK_INT < 36) {
        false
      } else {
        try {
          context.startActivity(
            Intent(Settings.ACTION_APP_NOTIFICATION_PROMOTION_SETTINGS)
              .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
              .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
          )
          true
        } catch (_: ActivityNotFoundException) {
          false
        }
      }
    }

    // Sudo approvals: a tapped push, optionally over the lock screen.

    Function("setSudoApprovalMachines") { machines: Map<String, String> ->
      appContext.reactContext?.let { SudoApprovals.setMachines(it, machines) }
    }

    Function("clearSudoApprovals") {
      appContext.reactContext?.let { SudoApprovals.clear(it) }
    }

    Function("consumeSudoApprovalOpen") { SudoApprovals.consume()?.toMap() }

    Function("isOverLockScreen") { SudoApprovals.overLockScreen() }

    Function("lockScreenHidesSensitiveContent") {
      appContext.reactContext?.let { SudoApprovals.hidesSensitiveContent(it) } ?: true
    }

    Function("leaveLockScreen") {
      appContext.currentActivity?.let { activity ->
        activity.runOnUiThread { SudoApprovals.end(activity, leave = true) }
      }
    }

    AsyncFunction("requestUnlock") { promise: Promise ->
      val activity = appContext.currentActivity
      if (activity == null) {
        promise.resolve(false)
      } else {
        activity.runOnUiThread { SudoApprovals.requestUnlock(activity) { promise.resolve(it) } }
      }
    }
  }
}
