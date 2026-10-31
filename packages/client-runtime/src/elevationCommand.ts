import { escapeElevationDisplayText, type ElevationPayload } from "@t3tools/contracts";

// The command line an approval card shows, from the signed payload only. With `session.command`
// the module signed the agent's command string and covers the other sudos written in it, so the
// card shows that string and those sudos' programs. Without it, only the signed argv.
//
// The reader below is a port of native/t3-elevation/src/shell_words.rs, which decides what a grant
// covers; packages/contracts/test-vectors/elevation-commands.json keeps the two in step. Change
// both together.

interface Word {
  readonly text: string;
  /** No expansion can change it. */
  readonly literal: boolean;
  /** Part of it was quoted or escaped, so it is never a reserved word. */
  readonly quoted: boolean;
}

type Token = { readonly word: Word } | { readonly op: string };

/** Longest first, so `&&` wins over `&`. */
const OPERATORS = [
  ";;&",
  "&>>",
  "<<-",
  "<<<",
  "&&",
  "||",
  ";;",
  ";&",
  "|&",
  "<<",
  ">>",
  "<&",
  ">&",
  "<>",
  ">|",
  "&>",
  "&",
  "|",
  ";",
  "<",
  ">",
  "(",
  ")",
  "\n",
];
const REDIRECTS = new Set([
  "<",
  ">",
  ">>",
  "<&",
  ">&",
  "<>",
  ">|",
  "&>",
  "&>>",
  "<<<",
  "<<",
  "<<-",
]);
const KEEP_COMMAND = new Set(["!", "{", "if", "then", "else", "elif", "while", "until", "do"]);
const UNREADABLE = new Set(["case", "select", "function", "coproc", "[[", "esac"]);
const OPERATOR_START = new Set([";", "&", "|", "<", ">", "(", ")", "\n"]);

/** Length of the `$…` at `at`, or null when it can't be read with certainty. */
function dollar(chars: readonly string[], at: number, inDouble: boolean): number | null {
  const next = chars[at + 1];
  if (next === "(") return null;
  if (!inDouble && (next === "'" || next === '"')) return null;
  if (next !== "{") return 1;
  const close = chars.indexOf("}", at + 2);
  if (close === -1) return null;
  const inner = chars.slice(at + 2, close).join("");
  return /^([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])$/.test(inner) ? close + 1 - at : null;
}

function tokenize(line: string): Token[] | null {
  const chars = Array.from(line);
  const tokens: Token[] = [];
  let word = "";
  let inWord = false;
  let expands = false;
  let quoted = false;
  let heredocs: Array<{ delimiter: string; strip: boolean }> = [];
  let delimiterNext: boolean | null = null;
  const flush = (): boolean => {
    if (!inWord) return true;
    const token: Word = { text: word, literal: !expands, quoted };
    word = "";
    inWord = false;
    expands = false;
    quoted = false;
    if (delimiterNext !== null) {
      if (!token.literal) return false;
      heredocs.push({ delimiter: token.text, strip: delimiterNext });
      delimiterNext = null;
    }
    tokens.push({ word: token });
    return true;
  };
  let index = 0;
  while (index < chars.length) {
    const char = chars[index]!;
    if (char === "\\") {
      const next = chars[index + 1];
      if (next === undefined) return null;
      // A backslash-newline joins lines; anything else is quoted.
      if (next !== "\n") {
        word += next;
        inWord = true;
        quoted = true;
      }
      index += 2;
    } else if (char === "'") {
      const end = chars.indexOf("'", index + 1);
      if (end === -1) return null;
      word += chars.slice(index + 1, end).join("");
      inWord = true;
      quoted = true;
      index = end + 1;
    } else if (char === '"') {
      inWord = true;
      quoted = true;
      index++;
      for (;;) {
        const inner = chars[index];
        if (inner === undefined || inner === "`") return null;
        if (inner === '"') break;
        if (inner === "\\") {
          const next = chars[index + 1];
          if (next === undefined) return null;
          if (next === "$" || next === "`" || next === '"' || next === "\\") word += next;
          else if (next !== "\n") word += `\\${next}`;
          index += 2;
        } else if (inner === "$") {
          const length = dollar(chars, index, true);
          if (length === null) return null;
          word += chars.slice(index, index + length).join("");
          expands = true;
          index += length;
        } else {
          word += inner;
          index++;
        }
      }
      index++;
    } else if (char === "`") {
      return null;
    } else if (char === "$") {
      const length = dollar(chars, index, false);
      if (length === null) return null;
      word += chars.slice(index, index + length).join("");
      inWord = true;
      expands = true;
      index += length;
    } else if (char === " " || char === "\t") {
      if (!flush()) return null;
      index++;
    } else if (char === "#" && !inWord) {
      const end = chars.indexOf("\n", index);
      index = end === -1 ? chars.length : end;
    } else if (OPERATOR_START.has(char)) {
      const rest = chars.slice(index, index + 3).join("");
      const op = OPERATORS.find((candidate) => rest.startsWith(candidate))!;
      if (op === ";;" || op === ";&" || op === ";;&") return null;
      const after = chars[index + op.length];
      // `<(…)`, `>(…)`, `((…))`, and `(` against a word except `name()`.
      if ((op === "<" || op === ">" || op === "(") && after === "(") return null;
      if (op === "(" && inWord && after !== ")") return null;
      const ioNumber =
        inWord && !quoted && !expands && /^[0-9]*$/.test(word) && (op[0] === "<" || op[0] === ">");
      if (ioNumber) {
        word = "";
        inWord = false;
      } else if (!flush()) {
        return null;
      }
      if (op === "<<" || op === "<<-") delimiterNext = op === "<<-";
      tokens.push({ op });
      index += op.length;
      if (op === "\n") {
        if (delimiterNext !== null) return null;
        for (const { delimiter, strip } of heredocs) {
          for (;;) {
            if (index >= chars.length) return null;
            const newline = chars.indexOf("\n", index);
            const end = newline === -1 ? chars.length : newline;
            let body = chars.slice(index, end).join("");
            index = end + 1;
            if (strip) body = body.replace(/^\t+/, "");
            if (body === delimiter) break;
          }
        }
        heredocs = [];
      }
    } else {
      if (
        char === "*" ||
        char === "?" ||
        char === "[" ||
        char === "~" ||
        char === "{" ||
        char === "}" ||
        (char === "=" && !inWord)
      ) {
        expands = true;
      }
      word += char;
      inWord = true;
      index++;
    }
  }
  if (!flush() || delimiterNext !== null || heredocs.length > 0) return null;
  return tokens;
}

/** One `sudo` the command string runs. */
export interface ElevationSudoCall {
  /** sudo's arguments as the shell passes them; null for a word an expansion may change. */
  readonly args: readonly (string | null)[];
  /** The string's last command, which zsh and bash exec in place of the shell. */
  readonly execTail: boolean;
}

function isSudo(word: Word): boolean {
  return (
    word.literal &&
    (word.text === "sudo" || (word.text.startsWith("/") && word.text.endsWith("/sudo")))
  );
}

function calls(tokens: readonly Token[]): ElevationSudoCall[] | null {
  const wordAt = (index: number) => {
    const token = tokens[index];
    return token !== undefined && "word" in token;
  };
  const found: ElevationSudoCall[] = [];
  let command = true;
  let topLevel = true;
  let index = 0;
  while (index < tokens.length) {
    const token = tokens[index]!;
    if ("op" in token) {
      if (REDIRECTS.has(token.op)) {
        if (!wordAt(index + 1)) return null;
        index += 2;
      } else {
        command = true;
        topLevel = token.op === ";" || token.op === "&&" || token.op === "||" || token.op === "\n";
        index++;
      }
      continue;
    }
    const word = token.word;
    index++;
    if (!command) continue;
    if (!word.quoted && UNREADABLE.has(word.text)) return null;
    if (!word.quoted && KEEP_COMMAND.has(word.text)) {
      topLevel = false;
      continue;
    }
    command = false;
    if (!isSudo(word)) continue;
    const args: (string | null)[] = [];
    while (index < tokens.length) {
      const next = tokens[index]!;
      if ("word" in next) {
        args.push(next.word.literal ? next.word.text : null);
        index++;
      } else if (REDIRECTS.has(next.op)) {
        if (!wordAt(index + 1)) return null;
        index += 2;
      } else {
        break;
      }
    }
    const last = tokens
      .slice(index)
      .every((rest) => "op" in rest && (rest.op === ";" || rest.op === "\n"));
    if (args.length > 0) found.push({ args, execTail: topLevel && last });
  }
  return found;
}

/** The eval'd command of Claude Code's Bash tool wrapper (see shell_words.rs `claude_eval`). */
function claudeEval(tokens: readonly Token[]): string | null {
  if (tokens.length < 10) return null;
  const tail = tokens.slice(-10);
  const word = (index: number) => {
    const token = tail[index]!;
    return "word" in token ? token.word : null;
  };
  const op = (index: number) => {
    const token = tail[index]!;
    return "op" in token ? token.op : null;
  };
  const evalWord = word(1);
  const commandWord = word(2);
  const pwd = word(6);
  const matches =
    op(0) === "&&" &&
    evalWord?.text === "eval" &&
    !evalWord.quoted &&
    commandWord?.literal === true &&
    op(3) === "<" &&
    word(4)?.text === "/dev/null" &&
    op(5) === "&&" &&
    pwd?.text === "pwd" &&
    !pwd.quoted &&
    word(7)?.text === "-P" &&
    op(8) === ">|" &&
    word(9) !== null;
  return matches ? commandWord!.text : null;
}

/** The command the agent wrote, from its shell's `-c` string. */
export function elevationAgentCommand(commandString: string): string {
  const tokens = tokenize(commandString);
  return (tokens && claudeEval(tokens)) ?? commandString;
}

/** Every sudo in command position, in order, or null when the string can't be read with certainty. */
export function elevationSudoCalls(commandString: string): ElevationSudoCall[] | null {
  const tokens = tokenize(commandString);
  if (tokens === null) return null;
  const evaled = claudeEval(tokens);
  if (evaled === null) return calls(tokens);
  const inner = tokenize(evaled);
  const found = inner && calls(inner);
  return found?.map((call) => ({ ...call, execTail: false })) ?? null;
}

/** sudo options that take a value: as the next word, or the rest of a short cluster. */
const SHORT_WITH_VALUE = new Set(["C", "D", "g", "h", "p", "R", "r", "T", "t", "U", "u"]);
const LONG_WITH_VALUE = new Set([
  "--chdir",
  "--chroot",
  "--close-from",
  "--command-timeout",
  "--group",
  "--host",
  "--other-user",
  "--prompt",
  "--role",
  "--type",
  "--user",
]);

function basename(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1) || path;
}

/** "psql as postgres": the program a sudo runs and its target when that isn't root. */
function sudoProgram(args: readonly (string | null)[]): string | null {
  let user: string | null = null;
  let index = 0;
  for (; index < args.length; index++) {
    const arg = args[index];
    if (arg === null || arg === undefined) return null;
    if (arg === "--") {
      index++;
      break;
    }
    if (!arg.startsWith("-") || arg === "-") break;
    if (arg.startsWith("--")) {
      const [name, value] = arg.split("=", 2);
      if (value === undefined && LONG_WITH_VALUE.has(name!)) {
        if (name === "--user") user = args[index + 1] ?? null;
        index++;
      } else if (name === "--user") {
        user = value ?? null;
      }
      continue;
    }
    for (let at = 1; at < arg.length; at++) {
      const flag = arg[at]!;
      if (!SHORT_WITH_VALUE.has(flag)) continue;
      const inline = arg.slice(at + 1);
      const value = inline === "" ? (args[++index] ?? null) : inline;
      if (flag === "u") user = value;
      break;
    }
  }
  // `sudo NAME=value program` passes the variable on.
  while (/^[A-Za-z_][A-Za-z0-9_]*=/.test(args[index] ?? "")) index++;
  const program = args[index];
  if (program === null || program === undefined) return null;
  const name = basename(program);
  return user === null || user === "root" || user === "#0" ? name : `${name} as ${user}`;
}

/** Characters of a collapsed first line that two rows show on the narrowest phone. */
const COLLAPSED_VISIBLE_CHARS = 40;

/** What the card's command line shows, all text escaped for display. */
export interface ElevationCommandDisplay {
  /** Every line of the command as written. */
  readonly lines: readonly string[];
  /** The first line with runs of blanks collapsed, for the two-row form. */
  readonly collapsed: string;
  /** Whether the two-row form leaves text out. */
  readonly hidden: boolean;
  /** Programs run as admin, with their target when it isn't root. */
  readonly programs: readonly string[];
  /** How many sudo the approval covers, this one included, when it covers others. */
  readonly covers: number | null;
  /** True when the approval covers later sudo, but an older module didn't sign which. */
  readonly coversSession: boolean;
}

function escapeLine(line: string): string {
  // A line continuation is shell syntax, so it keeps its single backslash.
  return line.endsWith("\\")
    ? `${escapeElevationDisplayText(line.slice(0, -1))}\\`
    : escapeElevationDisplayText(line);
}

/**
 * The signed command string when the payload carries one, otherwise the signed argv. Pass the
 * decoded payload's raw values, not their escaped views.
 */
export function elevationCommandDisplay(
  payload: Pick<ElevationPayload, "session"> & {
    readonly command: Pick<ElevationPayload["command"], "argv">;
  },
): ElevationCommandDisplay {
  const { session } = payload;
  const argv = payload.command.argv;
  const sessionCommand = session?.command;
  const found = sessionCommand === undefined ? null : elevationSudoCalls(sessionCommand);
  let raw: readonly string[];
  let programs: string[];
  if (sessionCommand !== undefined && found !== null) {
    raw = elevationAgentCommand(sessionCommand)
      .trim()
      .split("\n")
      .map((line) => line.trimEnd());
    programs = [];
    for (const call of found) {
      const program = sudoProgram(call.args);
      if (program !== null && !programs.includes(program)) programs.push(program);
    }
  } else {
    raw = [argv.join(" ")];
    programs = argv[0] === undefined ? [] : [basename(argv[0])];
  }
  const first = raw[0] ?? "";
  const collapsedRaw = first.replace(/[ \t]+/g, " ");
  const covered = session !== undefined && session.maxUses > 0;
  return {
    lines: raw.map(escapeLine),
    collapsed: escapeLine(collapsedRaw),
    hidden:
      raw.length > 1 ||
      collapsedRaw !== first ||
      Array.from(collapsedRaw).length > COLLAPSED_VISIBLE_CHARS,
    programs: programs.map(escapeElevationDisplayText),
    covers: covered && sessionCommand !== undefined ? session.maxUses + 1 : null,
    coversSession: covered && sessionCommand === undefined,
  };
}

/** "+2 more lines · darwin-rebuild, launchctl", "More · apt", or null when nothing is hidden. */
export function elevationCommandMoreLabel(display: ElevationCommandDisplay): string | null {
  if (!display.hidden) return null;
  const more = display.lines.length - 1;
  const lead = more > 0 ? `+${more} more line${more === 1 ? "" : "s"}` : "More";
  return display.programs.length > 0 ? `${lead} · ${display.programs.join(", ")}` : lead;
}

/** Says in plain words that one approval covers other sudo, or null when it covers only this one. */
export function elevationCoverageLabel(display: ElevationCommandDisplay): string | null {
  if (display.covers !== null) return `Covers up to ${display.covers} sudo in this command`;
  return display.coversSession ? "Also covers later sudo in this session" : null;
}
