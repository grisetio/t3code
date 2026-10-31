import { escapeElevationDisplayText } from "@t3tools/contracts";

// The command line an approval card shows. Only the sudo argv is signed; the agent's own command
// line is server data. The card shows the agent's line only when the signed argv appears in it,
// word for word, so it can add context but never change what will run.

interface ShellWord {
  readonly text: string;
  /** Unquoted shell syntax such as `&&`, `|` or `;`. */
  readonly operator: boolean;
}

const OPERATOR_CHARS = new Set([";", "&", "|", "<", ">", "(", ")"]);

/**
 * Splits a POSIX shell line into words the way the shell would before expansion. Expansions
 * (`$VAR`, `~`, globs) stay literal, so a word that needs one never equals the argv it became,
 * which is the conservative answer.
 */
function shellWords(line: string): ShellWord[] {
  const words: ShellWord[] = [];
  let current = "";
  let inWord = false;
  const flush = () => {
    if (inWord) words.push({ text: current, operator: false });
    current = "";
    inWord = false;
  };
  for (let index = 0; index < line.length; index++) {
    const char = line[index]!;
    if (char === "\\") {
      const next = line[index + 1];
      index++;
      // A backslash-newline joins lines; anything else is the escaped character.
      if (next === undefined || next === "\n") continue;
      current += next;
      inWord = true;
    } else if (char === "'") {
      const end = line.indexOf("'", index + 1);
      const stop = end === -1 ? line.length : end;
      current += line.slice(index + 1, stop);
      inWord = true;
      index = stop;
    } else if (char === '"') {
      inWord = true;
      index++;
      for (; index < line.length && line[index] !== '"'; index++) {
        const inner = line[index]!;
        const next = line[index + 1];
        if (inner === "\\" && next !== undefined && '"\\$`\n'.includes(next)) {
          if (next !== "\n") current += next;
          index++;
        } else {
          current += inner;
        }
      }
    } else if (char === " " || char === "\t" || char === "\n") {
      flush();
    } else if (OPERATOR_CHARS.has(char)) {
      flush();
      let operator = char;
      while (index + 1 < line.length && OPERATOR_CHARS.has(line[index + 1]!)) {
        operator += line[++index];
      }
      words.push({ text: operator, operator: true });
    } else if (char === "#" && !inWord) {
      // A comment runs to the end of its line.
      const end = line.indexOf("\n", index);
      index = end === -1 ? line.length : end - 1;
    } else {
      current += char;
      inWord = true;
    }
  }
  flush();
  return words;
}

/** Whether `argv` appears, as consecutive words, in the agent's command line. */
export function elevationArgvInCommand(argv: readonly string[], agentCommand: string): boolean {
  if (argv.length === 0) return false;
  const words = shellWords(agentCommand);
  for (let start = 0; start + argv.length <= words.length; start++) {
    if (
      argv.every(
        (arg, offset) => !words[start + offset]!.operator && words[start + offset]!.text === arg,
      )
    ) {
      return true;
    }
  }
  return false;
}

/** sudo options that take a value as the next word. */
const SUDO_OPTIONS_WITH_VALUE = new Set([
  "-C",
  "-D",
  "-g",
  "-h",
  "-p",
  "-R",
  "-r",
  "-T",
  "-t",
  "-U",
  "-u",
]);

function basename(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1) || path;
}

/** The programs each `sudo` in the line runs, in order, without repeats. */
export function elevationSudoPrograms(agentCommand: string): string[] {
  const words = shellWords(agentCommand);
  const programs: string[] = [];
  for (let index = 0; index < words.length; index++) {
    const word = words[index]!;
    if (word.operator || basename(word.text) !== "sudo") continue;
    let next = index + 1;
    while (next < words.length && !words[next]!.operator && words[next]!.text.startsWith("-")) {
      const option = words[next]!.text;
      next += option === "--" ? 1 : SUDO_OPTIONS_WITH_VALUE.has(option) ? 2 : 1;
      if (option === "--") break;
    }
    const program = words[next];
    if (program === undefined || program.operator) continue;
    const name = basename(program.text);
    if (!programs.includes(name)) programs.push(name);
  }
  return programs;
}

/** What the card's command line shows, all text escaped for display. */
export interface ElevationCommandDisplay {
  /** One entry per line of the command as written. */
  readonly lines: readonly string[];
  /** Programs run as admin, for the collapsed form of a multi-line command. */
  readonly programs: readonly string[];
  /** True when this is the agent's line rather than the signed argv alone. */
  readonly fromAgent: boolean;
}

/**
 * The agent's command line when the signed `commandArgv` appears in it, otherwise the signed argv.
 * `commandArgv` is the raw argv from the decoded payload, not its escaped view.
 */
export function elevationCommandDisplay(input: {
  readonly commandArgv: readonly string[];
  readonly agentCommand?: string | undefined;
}): ElevationCommandDisplay {
  const { agentCommand, commandArgv } = input;
  if (agentCommand !== undefined && elevationArgvInCommand(commandArgv, agentCommand)) {
    const lines = agentCommand
      .trim()
      .split("\n")
      .map((line) => line.trimEnd())
      // A line continuation is shell syntax, so it keeps its single backslash.
      .map((line) =>
        line.endsWith("\\")
          ? `${escapeElevationDisplayText(line.slice(0, -1))}\\`
          : escapeElevationDisplayText(line),
      );
    const programs = elevationSudoPrograms(agentCommand).map(escapeElevationDisplayText);
    return { lines, programs, fromAgent: true };
  }
  const program = commandArgv[0];
  return {
    lines: [commandArgv.map(escapeElevationDisplayText).join(" ")],
    programs: program === undefined ? [] : [escapeElevationDisplayText(basename(program))],
    fromAgent: false,
  };
}

/** "+2 more lines · darwin-rebuild, launchctl", or null for a one-line command. */
export function elevationCommandMoreLabel(display: ElevationCommandDisplay): string | null {
  const more = display.lines.length - 1;
  if (more <= 0) return null;
  const lines = `+${more} more line${more === 1 ? "" : "s"}`;
  return display.programs.length > 0 ? `${lines} · ${display.programs.join(", ")}` : lines;
}
