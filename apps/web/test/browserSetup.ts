import { beforeEach } from "vite-plus/test";
import { commands } from "vite-plus/test/browser";

declare module "vite-plus/test/browser" {
  interface BrowserCommands {
    /** Defined in vite.config.ts. Moves Playwright's mouse off the page. */
    resetPointer: () => Promise<void>;
    /** Defined in vite.config.ts. A platform passkey authenticator, replacing any previous one. */
    addVirtualAuthenticator: (options?: {
      /** Makes passkeys that can sync, as Google Password Manager or iCloud Keychain do. */
      readonly backupEligible?: boolean;
    }) => Promise<void>;
    setVirtualAuthenticator: (options: {
      /** False fails user verification, as cancelling the prompt does. */
      readonly userVerified?: boolean;
      /** False leaves every request waiting for a touch that never comes. */
      readonly presence?: boolean;
    }) => Promise<void>;
    removeVirtualAuthenticator: () => Promise<void>;
  }
}

// Playwright's mouse outlives each test and each file, so whatever the next test mounts
// under its last position starts hovered. Registered here rather than in render() so tests
// that mount without it are covered too. Before each test, not after: a timed-out test keeps
// running and can move the mouse after its own afterEach.
beforeEach(async () => {
  await commands.resetPointer();
});
