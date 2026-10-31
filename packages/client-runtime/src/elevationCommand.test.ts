import { describe, expect, it } from "vite-plus/test";

import vectorsJson from "../../contracts/test-vectors/elevation-commands.json" with { type: "json" };
import {
  elevationAgentCommand,
  elevationCommandDisplay,
  elevationCommandMoreLabel,
  elevationCoverageLabel,
  elevationSudoCalls,
} from "./elevationCommand.ts";

const vectors = vectorsJson as {
  readonly commands: ReadonlyArray<{
    name: string;
    command: string;
    agentCommand: string;
    sudos: ReadonlyArray<{ args: ReadonlyArray<string | null>; execTail: boolean }> | null;
  }>;
};

describe("the shared command vectors", () => {
  it.each(vectors.commands)("reads $name as the module does", (vector) => {
    expect(elevationAgentCommand(vector.command)).toBe(vector.agentCommand);
    expect(elevationSudoCalls(vector.command)).toEqual(vector.sudos);
  });
});

const session = (command: string, maxUses = 1) => ({ id: 10, leaderStart: 1, maxUses, command });

describe("elevationCommandDisplay", () => {
  it("shows the signed argv alone without a signed command string", () => {
    const display = elevationCommandDisplay({ command: { argv: ["killall", "coreaudiod"] } });
    expect(display).toMatchObject({
      lines: ["killall coreaudiod"],
      programs: ["killall"],
      hidden: false,
      covers: null,
    });
    expect(elevationCommandMoreLabel(display)).toBeNull();
    expect(elevationCoverageLabel(display)).toBeNull();
  });

  it("shows the signed command string and the programs of its sudos", () => {
    const command =
      "sudo darwin-rebuild switch --flake .#mbp \\\n  && sudo launchctl kickstart -k system/x \\\n  && system_profiler SPAudioDataType";
    const display = elevationCommandDisplay({
      command: { argv: ["darwin-rebuild", "switch", "--flake", ".#mbp"] },
      session: session(command),
    });
    expect(display.lines).toEqual([
      "sudo darwin-rebuild switch --flake .#mbp \\",
      "  && sudo launchctl kickstart -k system/x \\",
      "  && system_profiler SPAudioDataType",
    ]);
    expect(elevationCommandMoreLabel(display)).toBe("+2 more lines · darwin-rebuild, launchctl");
    expect(elevationCoverageLabel(display)).toBe("Covers up to 2 sudo in this command");
  });

  // Review H2: the card's agent line could misstate what the signed sudo runs.
  it("lists only sudos the shell runs, with their target", () => {
    const programs = (command: string) =>
      elevationCommandDisplay({ command: { argv: ["id"] }, session: session(command) }).programs;
    expect(programs("echo sudo rm -rf /tmp/x && sudo id")).toEqual(["id"]);
    expect(programs("printf '%s\\n' 'sudo rm -rf /tmp/x' && sudo id")).toEqual(["id"]);
    expect(programs("sudo id && cat <<EOF\nsudo rm -rf /tmp/x\nEOF")).toEqual(["id"]);
    expect(programs("sudo id && sudo -u postgres psql && sudo -nupostgres psql")).toEqual([
      "id",
      "psql as postgres",
    ]);
    expect(programs("sudo id && sudo --user=www rm x && sudo -- ls")).toEqual([
      "id",
      "rm as www",
      "ls",
    ]);
  });

  it("labels a long single line that the two-row form hides", () => {
    const command = `echo start${" ".repeat(300)}&& sudo rm -rf /tmp/x && sudo id`;
    const display = elevationCommandDisplay({
      command: { argv: ["rm", "-rf", "/tmp/x"] },
      session: session(command),
    });
    expect(display.collapsed).toBe("echo start && sudo rm -rf /tmp/x && sudo id");
    expect(elevationCommandMoreLabel(display)).toBe("More · rm, id");
    const long = elevationCommandDisplay({ command: { argv: ["echo", "x".repeat(80)] } });
    expect(elevationCommandMoreLabel(long)).toBe("More · echo");
  });

  it("shows the agent's command from Claude Code's wrapper", () => {
    const command =
      "source /h/.claude/shell-snapshots/s.sh 2>/dev/null || true && eval 'sudo apt update && sudo apt install -y '\"'\"'nginx'\"'\"'' < /dev/null && pwd -P >| /tmp/claude-1a2b-cwd";
    const display = elevationCommandDisplay({
      command: { argv: ["apt", "update"] },
      session: session(command),
    });
    expect(display.lines).toEqual(["sudo apt update && sudo apt install -y 'nginx'"]);
    expect(display.programs).toEqual(["apt"]);
  });

  it("says when an older module covers the session without signing the command", () => {
    const display = elevationCommandDisplay({
      command: { argv: ["id"] },
      session: { id: 10, leaderStart: 1, maxUses: 16 },
    });
    expect(display.lines).toEqual(["id"]);
    expect(elevationCoverageLabel(display)).toBe("Also covers later sudo in this session");
  });

  it("escapes control characters", () => {
    expect(elevationCommandDisplay({ command: { argv: ["echo", "a‮b"] } }).lines).toEqual([
      "echo a\\u{202E}b",
    ]);
    expect(
      elevationCommandDisplay({
        command: { argv: ["echo", "a‮b"] },
        session: session("sudo echo 'a‮b' && sudo id"),
      }).lines,
    ).toEqual(["sudo echo 'a\\u{202E}b' && sudo id"]);
  });
});
