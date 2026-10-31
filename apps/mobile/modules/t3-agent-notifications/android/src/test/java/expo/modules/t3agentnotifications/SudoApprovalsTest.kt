package expo.modules.t3agentnotifications

import android.app.Activity
import android.app.Application
import android.app.Notification
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleRegistry
import androidx.lifecycle.ProcessLifecycleOwner
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 36], manifest = Config.NONE)
class SudoApprovalsTest {
  private lateinit var context: Application
  private lateinit var manager: NotificationManager
  private var aliases = listOf("t3-elevation:env%201:alice")

  @Before
  fun setUp() {
    context = RuntimeEnvironment.getApplication()
    manager = context.getSystemService(NotificationManager::class.java)
    shadowOf(manager).setNotificationsEnabled(true)
    (ProcessLifecycleOwner.get().lifecycle as LifecycleRegistry).currentState =
      Lifecycle.State.CREATED
    val launcher = ComponentName(context, Activity::class.java)
    shadowOf(context.packageManager).addActivityIfNotPresent(launcher)
    shadowOf(context.packageManager).addIntentFilterForActivity(
      launcher,
      IntentFilter(Intent.ACTION_MAIN).apply { addCategory(Intent.CATEGORY_LAUNCHER) }
    )
    SudoApprovals.keyAliases = { aliases }
    AgentNotifications.clear(context)
    AgentNotifications.configure(context, "device", "user", "t3code-dev", false)
    AgentNotifications.setThreadOnScreen(null)
  }

  @After
  fun tearDown() {
    SudoApprovals.keyAliases = { emptyList() }
  }

  private fun push(alertId: String, path: String, kind: String? = "sudo_approval") = buildMap {
    put("device_id", "device")
    put("user_id", "user")
    put("updated_at", System.currentTimeMillis().toString())
    put("active", "true")
    put("alert_id", alertId)
    put("alert_title", "Fix the audio")
    put("alert_body", "Waiting for approval")
    put("alert_path", path)
    if (kind != null) put("alert_kind", kind)
  }

  @Test
  fun sudoPushPostsOnItsOwnChannelWithoutServerText() {
    SudoApprovals.setMachines(context, mapOf("env 1" to "Killian's MacBook Pro"))
    AgentNotifications.receive(context, push("sudo", "/threads/env%201/thread"))

    val posted = manager.activeNotifications.single()
    assertEquals("t3-sudo-approval", posted.tag)
    val extras = posted.notification.extras
    assertEquals("Approval needed", extras.getString(Notification.EXTRA_TITLE))
    assertEquals("Killian's MacBook Pro", extras.getCharSequence(Notification.EXTRA_TEXT))
    if (Build.VERSION.SDK_INT >= 26) {
      assertEquals(SudoApprovals.CHANNEL, posted.notification.channelId)
      assertEquals(
        "Sudo approvals",
        manager.getNotificationChannel(SudoApprovals.CHANNEL).name
      )
    }
  }

  @Test
  fun phoneWithoutAKeyForThatMachinePostsNothing() {
    AgentNotifications.receive(context, push("other-machine", "/threads/env-2/thread"))
    aliases = emptyList()
    AgentNotifications.receive(context, push("no-key", "/threads/env%201/thread"))

    assertTrue(manager.activeNotifications.isEmpty())
  }

  @Test
  fun otherAlertsStayOnTheAgentChannel() {
    AgentNotifications.receive(context, push("plain", "/threads/env%201/thread", kind = null))

    assertEquals("t3-agent-alert", manager.activeNotifications.single().tag)
  }

  @Test
  fun keyMatchingUsesTheWholeEnvironmentSegment() {
    assertTrue(SudoApprovals.canApprove("/threads/env/t", listOf("t3-elevation:env:bob")))
    assertFalse(SudoApprovals.canApprove("/threads/env/t", listOf("t3-elevation:env2:bob")))
    assertFalse(SudoApprovals.canApprove("/", listOf("t3-elevation:env:bob")))
    assertNull(SudoApprovals.environmentSegment("/threads/env/t?x=1"))
  }

  @Test
  fun recognisesSudoPushesOnlyByTheirKind() {
    assertTrue(SudoApprovals.isSudoApproval(mapOf("alert_kind" to "sudo_approval")))
    assertTrue(SudoApprovals.isSudoApproval(mapOf("alert_kind" to "elevation")))
    assertFalse(SudoApprovals.isSudoApproval(mapOf("alert_kind" to "approval")))
    assertFalse(SudoApprovals.isSudoApproval(emptyMap()))
  }
}
