import { describe, expect, it } from "vite-plus/test";

import vectorsJson from "../../contracts/test-vectors/elevation-commands.json" with { type: "json" };
import {
  elevationAgentCommand,
  elevationCommandDisplay,
  elevationCommandOneLine,
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
      short: "killall coreaudiod",
    });
    expect(elevationCommandOneLine(display)).toBe("killall coreaudiod");
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
    expect(display.short).toBe("darwin-rebuild, launchctl");
    expect(elevationCommandOneLine(display)).toBe(
      "sudo darwin-rebuild switch --flake .#mbp && sudo launchctl kickstart -k system/x && system_profiler SPAudioDataType",
    );
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

  it("shortens one sudo to its program by name and arguments, never sudo itself", () => {
    const short = (command: string, argv = ["/bin/ls", "/var/db"]) =>
      elevationCommandDisplay({ command: { argv }, session: session(command) }).short;
    expect(short("sudo -k /bin/ls /var/db")).toBe("ls /var/db");
    expect(short("cd /tmp && sudo -u postgres /usr/bin/psql -c 'select 1'")).toBe(
      "psql -c select 1",
    );
    expect(elevationCommandDisplay({ command: { argv: ["/usr/bin/id", "-u"] } }).short).toBe(
      "id -u",
    );
    // A word the shell may expand isn't shown as if it were literal.
    expect(short('f=/var/db; sudo -k /bin/ls "$f"')).toBe("ls");
  });

  it("elides the middle of long path arguments, so two requests tell apart", () => {
    const deploy =
      "/Users/k/.local/state/t3-code-visuals/worktrees/nix-hosts/t3-device-approval/hosts/darwin/deploy/deploy.py";
    const short = (command: string) =>
      elevationCommandDisplay({ command: { argv: ["python3"] }, session: session(command) }).short;
    expect(
      short(
        `sudo python3 ${deploy} _submit-system /Users/k/w/t3-device-approval /nix/store/q8v0w8bwh4n1i1ymbib7pdqy2qkzl6sm-nix-2.31/bin/nix darwin-7ede7e6d`,
      ),
    ).toBe(
      "python3 /Users/…/deploy.py _submit-system /Users/k/w/t3-device-approval /nix/…/nix darwin-7ede7e6d",
    );
    expect(short(`sudo python3 ${deploy} _status-system darwin-7ede7e6d --wait`)).toBe(
      "python3 /Users/…/deploy.py _status-system darwin-7ede7e6d --wait",
    );
    // The full command is still there to expand.
    expect(
      elevationCommandDisplay({
        command: { argv: ["python3"] },
        session: session(`sudo python3 ${deploy} --wait`),
      }).lines,
    ).toEqual([`sudo python3 ${deploy} --wait`]);
    // Values after `=`, for options and variables alike.
    expect(
      short(
        "sudo --preserve-env=PATH nix --config=/etc/nix/conf.d/machines/remote-builders/x.conf run",
      ),
    ).toBe("nix --config=/etc/…/x.conf run");
    expect(short("sudo NIX_CONF=/etc/nix/conf.d/x.conf nix run")).toBe("nix run");
    expect(
      elevationCommandDisplay({
        command: { argv: ["env", "CONF=./config/environments/production/eu-west/c.toml", "x"] },
      }).short,
    ).toBe("env CONF=./…/c.toml x");
    // Where it acts stays readable; words with a slash aren't all paths.
    expect(short("sudo rm -rf /usr/local/share/applications/vendor-name/app")).toBe(
      "rm -rf /usr/…/app",
    );
    expect(short("sudo rm -rf /etc")).toBe("rm -rf /etc");
    expect(short("sudo launchctl kickstart -k system/com.example.agent")).toBe(
      "launchctl kickstart -k system/com.example.agent",
    );
    expect(short("sudo curl -o /tmp/x https://example.com/a/b/c/d/e/f/g/h/i/j/k")).toBe(
      "curl -o /tmp/x https://example.com/a/b/c/d/e/f/g/h/i/j/k",
    );
    // Shortening happens before escaping, so the name still shows its control characters.
    expect(
      elevationCommandDisplay({
        command: { argv: ["cat", "/var/log/applications/vendor-name/a\u202Eb.log"] },
      }).short,
    ).toBe("cat /var/…/a\\u{202E}b.log");
  });

  it("keeps paths up to a card row whole, where the middle directory is the difference", () => {
    const short = (command: string) =>
      elevationCommandDisplay({ command: { argv: ["ln"] }, session: session(command) }).short;
    expect(
      short("sudo ln -sf /etc/nginx/sites-available/app.conf /etc/nginx/sites-enabled/app.conf"),
    ).toBe("ln -sf /etc/nginx/sites-available/app.conf /etc/nginx/sites-enabled/app.conf");
    expect(short("sudo systemctl edit /etc/systemd/system/nginx.service")).toBe(
      "systemctl edit /etc/systemd/system/nginx.service",
    );
    // A long source elides, keeping its start; the short target next to it stays whole.
    expect(
      short(
        "sudo install -m 0644 /home/t3dev/project/deploy/nginx/sites/app.conf /etc/nginx/sites-available/app.conf",
      ),
    ).toBe("install -m 0644 /home/…/app.conf /etc/nginx/sites-available/app.conf");
  });

  it("keeps two long paths whole when shortening would make them read the same", () => {
    const display = elevationCommandDisplay({
      command: {
        argv: [
          "/usr/bin/cp",
          "/var/lib/containers/storage/overlay/a1/diff/etc/app.conf",
          "/var/lib/containers/storage/overlay/b2/diff/etc/app.conf",
        ],
      },
    });
    expect(display.short).toBe(
      "cp /var/lib/containers/storage/overlay/a1/diff/etc/app.conf /var/lib/containers/storage/overlay/b2/diff/etc/app.conf",
    );
    // A path repeated as is still shortens.
    expect(
      elevationCommandDisplay({
        command: {
          argv: [
            "diff",
            "/var/lib/containers/storage/overlay/a1/diff/etc/app.conf",
            "/var/lib/containers/storage/overlay/a1/diff/etc/app.conf",
          ],
        },
      }).short,
    ).toBe("diff /var/…/app.conf /var/…/app.conf");
  });

  it("lists the programs when the command runs several sudos", () => {
    const display = elevationCommandDisplay({
      command: { argv: ["/usr/bin/id", "-u"] },
      session: session("sudo -k /usr/bin/id -u; sudo -k /bin/ls /var/db"),
    });
    expect(display.short).toBe("id, ls");
    expect(display.lines).toEqual(["sudo -k /usr/bin/id -u; sudo -k /bin/ls /var/db"]);
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

  it("shows the signed argv when an older module covers the session without signing the command", () => {
    const display = elevationCommandDisplay({
      command: { argv: ["id"] },
      session: { id: 10, leaderStart: 1, maxUses: 16 },
    });
    expect(display.lines).toEqual(["id"]);
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
