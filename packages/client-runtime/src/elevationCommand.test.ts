import { describe, expect, it } from "vite-plus/test";

import {
  elevationArgvInCommand,
  elevationCommandDisplay,
  elevationCommandMoreLabel,
  elevationSudoPrograms,
} from "./elevationCommand.ts";

describe("elevationArgvInCommand", () => {
  it("finds the signed argv as consecutive shell words", () => {
    expect(
      elevationArgvInCommand(
        ["launchctl", "kickstart", "-k", "system/com.apple.audio.coreaudiod"],
        "sudo launchctl kickstart -k system/com.apple.audio.coreaudiod",
      ),
    ).toBe(true);
  });

  it("unquotes the way the shell does", () => {
    expect(
      elevationArgvInCommand(["sh", "-c", 'echo "x" > /etc/f'], `sudo sh -c 'echo "x" > /etc/f'`),
    ).toBe(true);
    expect(
      elevationArgvInCommand(["tee", "/etc/a b"], 'echo hi | sudo tee "/etc/a b" >/dev/null'),
    ).toBe(true);
  });

  it("follows line continuations", () => {
    expect(
      elevationArgvInCommand(
        ["launchctl", "kickstart", "-k", "system/x"],
        "sudo true \\\n  && sudo launchctl kickstart \\\n  -k system/x",
      ),
    ).toBe(true);
  });

  it("rejects a command line that differs from what was signed", () => {
    expect(elevationArgvInCommand(["rm", "-rf", "/tmp/x"], "sudo rm -rf /tmp/y")).toBe(false);
    // An extra or missing word changes what runs.
    expect(elevationArgvInCommand(["rm", "-rf", "/tmp/x"], "sudo rm /tmp/x")).toBe(false);
    // Unexpanded `~` and variables never match the path they expanded to.
    expect(
      elevationArgvInCommand(
        ["darwin-rebuild", "switch", "--flake", "/Users/k/nix-hosts#mbp"],
        "sudo darwin-rebuild switch --flake ~/nix-hosts#mbp",
      ),
    ).toBe(false);
    // Shell syntax is never an argument.
    expect(elevationArgvInCommand(["echo", "&&"], "sudo echo && true")).toBe(false);
    expect(elevationArgvInCommand([], "sudo true")).toBe(false);
  });
});

describe("elevationSudoPrograms", () => {
  it("lists what each sudo runs, skipping sudo's options", () => {
    expect(
      elevationSudoPrograms(
        "sudo darwin-rebuild switch \\\n && sudo -u root /bin/launchctl kickstart -k x \\\n && sudo -- darwin-rebuild check | grep sudo",
      ),
    ).toEqual(["darwin-rebuild", "launchctl"]);
  });
});

describe("elevationCommandDisplay", () => {
  const long =
    "sudo darwin-rebuild switch --flake .#mbp \\\n  && sudo launchctl kickstart -k system/x \\\n  && system_profiler SPAudioDataType";

  it("shows the agent's lines and the admin programs when the argv is in them", () => {
    const display = elevationCommandDisplay({
      commandArgv: ["darwin-rebuild", "switch", "--flake", ".#mbp"],
      agentCommand: long,
    });
    expect(display.fromAgent).toBe(true);
    expect(display.lines).toEqual([
      "sudo darwin-rebuild switch --flake .#mbp \\",
      "  && sudo launchctl kickstart -k system/x \\",
      "  && system_profiler SPAudioDataType",
    ]);
    expect(elevationCommandMoreLabel(display)).toBe("+2 more lines · darwin-rebuild, launchctl");
  });

  it("falls back to the signed argv alone", () => {
    const display = elevationCommandDisplay({
      commandArgv: ["killall", "coreaudiod"],
      agentCommand: "sudo killall -9 coreaudiod",
    });
    expect(display).toEqual({
      lines: ["killall coreaudiod"],
      programs: ["killall"],
      fromAgent: false,
    });
    expect(elevationCommandMoreLabel(display)).toBeNull();
    expect(elevationCommandDisplay({ commandArgv: ["/usr/bin/id"] }).programs).toEqual(["id"]);
  });

  it("escapes control characters from either source", () => {
    expect(elevationCommandDisplay({ commandArgv: ["echo", "a‮b"] }).lines).toEqual([
      "echo a\\u{202E}b",
    ]);
    expect(
      elevationCommandDisplay({ commandArgv: ["echo", "a‮b"], agentCommand: "sudo echo 'a‮b'" })
        .lines,
    ).toEqual(["sudo echo 'a\\u{202E}b'"]);
  });
});
