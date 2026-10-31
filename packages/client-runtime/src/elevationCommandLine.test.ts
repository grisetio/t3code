import { describe, expect, it } from "vite-plus/test";

import { elevationCommandContainsArgv, elevationCommandLine } from "./elevationCommandLine.ts";

describe("elevationCommandContainsArgv", () => {
  it("finds the signed argv inside the agent's line, quoted the way a shell takes it", () => {
    expect(
      elevationCommandContainsArgv(
        "sudo launchctl kickstart -k system/com.apple.audio.coreaudiod",
        ["launchctl", "kickstart", "-k", "system/com.apple.audio.coreaudiod"],
      ),
    ).toBe(true);
    expect(
      elevationCommandContainsArgv('sudo sh -c "echo x > /etc/f"', ["sh", "-c", "echo x > /etc/f"]),
    ).toBe(true);
  });

  it("rejects a line that only resembles the argv", () => {
    // A different argument, a prefix of a longer word, or words out of order.
    expect(elevationCommandContainsArgv("sudo rm -rf /tmp/x", ["rm", "-rf", "/"])).toBe(false);
    expect(
      elevationCommandContainsArgv("sudo killall coreaudiodx", ["killall", "coreaudiod"]),
    ).toBe(false);
    expect(elevationCommandContainsArgv("sudo -k ls", ["ls", "-k"])).toBe(false);
  });
});

describe("elevationCommandLine", () => {
  it("shows the first line and the admin programs of a long agent command", () => {
    const view = elevationCommandLine({
      agentCommand:
        "sudo darwin-rebuild switch --flake ~/nix-hosts#macbook-pro \\\n  && sudo launchctl kickstart -k system/com.apple.audio.coreaudiod \\\n  && system_profiler SPAudioDataType",
      argv: ["darwin-rebuild", "switch", "--flake", "~/nix-hosts#macbook-pro"],
    });
    expect(view).toMatchObject({
      source: "agent",
      // Display escaping doubles backslashes so escapes stay unambiguous.
      firstLine: "sudo darwin-rebuild switch --flake ~/nix-hosts#macbook-pro \\\\",
      moreLines: 2,
      programs: ["darwin-rebuild", "launchctl"],
    });
  });

  it("falls back to the signed argv when the agent's line doesn't contain it", () => {
    expect(
      elevationCommandLine({ agentCommand: "sudo make install", argv: ["rm", "-rf", "/"] }),
    ).toEqual({ source: "signed", firstLine: "rm -rf /", rest: null, moreLines: 0, programs: [] });
    expect(elevationCommandLine({ agentCommand: undefined, argv: ["true"] }).source).toBe("signed");
  });

  it("escapes control characters from the unverified line", () => {
    const view = elevationCommandLine({ agentCommand: "sudo ls‮ /", argv: ["ls‮", "/"] });
    expect(view.firstLine).toBe("sudo ls\\u{202E} /");
  });
});
