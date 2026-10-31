import { escapeElevationDisplayText } from "@t3tools/contracts";

/** The quiet command line on a request card (decision 3). All text is escaped. */
export interface ElevationCommandLine {
  /** "agent" when the agent's command line contains the signed argv; otherwise only the argv. */
  readonly source: "agent" | "signed";
  readonly firstLine: string;
  /** Every line after the first, for the expanded view; null for a one-line command. */
  readonly rest: string | null;
  readonly moreLines: number;
  /** Programs the command runs as admin, for the collapsed "+N more lines · …" hint. */
  readonly programs: readonly string[];
}

const basename = (path: string) => path.split("/").at(-1) ?? path;

const escapeRegExp = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Whether the signed argv appears, in order and contiguously, inside the
 * command line: words separated only by whitespace (or a line continuation),
 * each optionally wrapped in quotes as a shell would take them.
 */
export function elevationCommandContainsArgv(command: string, argv: readonly string[]): boolean {
  if (argv.length === 0) return false;
  const words = argv.map((word) => {
    const escaped = escapeRegExp(word);
    return `(?:${escaped}|'${escaped}'|"${escaped}")`;
  });
  return new RegExp(`(?:^|[\\s;&|(])${words.join("(?:\\s|\\\\\\n)+")}(?=$|[\\s;&|)])`).test(
    command,
  );
}

function adminPrograms(command: string, signedProgram: string | undefined): readonly string[] {
  const programs = new Set<string>();
  for (const match of command.matchAll(/(?:^|[\s;&|(])sudo\s+(?:-\S+\s+)*([^\s;&|)]+)/g)) {
    if (match[1] !== undefined) programs.add(basename(match[1]));
  }
  if (programs.size === 0 && signedProgram !== undefined) programs.add(basename(signedProgram));
  return [...programs];
}

/**
 * The agent's command line is unverified, so a card shows it only when the
 * signed argv is inside it; the user then reads the signed part in context.
 */
export function elevationCommandLine(input: {
  readonly agentCommand: string | undefined;
  /** The payload's `command.argv`, unescaped. */
  readonly argv: readonly string[];
}): ElevationCommandLine {
  const { agentCommand, argv } = input;
  if (agentCommand !== undefined && elevationCommandContainsArgv(agentCommand, argv)) {
    const lines = agentCommand.split("\n").map(escapeElevationDisplayText);
    return {
      source: "agent",
      firstLine: lines[0] ?? "",
      rest: lines.length > 1 ? lines.slice(1).join("\n") : null,
      moreLines: lines.length - 1,
      programs: lines.length > 1 ? adminPrograms(agentCommand, argv[0]) : [],
    };
  }
  return {
    source: "signed",
    firstLine: argv.map(escapeElevationDisplayText).join(" "),
    rest: null,
    moreLines: 0,
    programs: [],
  };
}
