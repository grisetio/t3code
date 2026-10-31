package expo.modules.t3deviceapproval

import android.app.Application
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], manifest = Config.NONE)
class LockScreenKeysTest {
  private val context: Application = RuntimeEnvironment.getApplication()
  private val alias = "t3-elevation:env-1:alice"
  private val other = "t3-elevation:env-2:alice"

  @Test
  fun keysFromEarlierBuildsAreNotRecorded() {
    // A key created before this build has no record, so the phone asks to set it up again.
    assertFalse(LockScreenKeys.isRecorded(context, alias))
  }

  @Test
  fun recordsOnlyTheCreatedAlias() {
    LockScreenKeys.record(context, alias)
    assertTrue(LockScreenKeys.isRecorded(context, alias))
    assertFalse(LockScreenKeys.isRecorded(context, other))
  }

  @Test
  fun forgettingOneAliasKeepsTheOthers() {
    LockScreenKeys.record(context, alias)
    LockScreenKeys.record(context, other)
    LockScreenKeys.forget(context, alias)
    assertFalse(LockScreenKeys.isRecorded(context, alias))
    assertTrue(LockScreenKeys.isRecorded(context, other))
  }
}
