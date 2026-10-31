//! The sudos an agent's command string runs, read the way a POSIX shell reads
//! it before expansion. A session grant covers exactly these calls, and the
//! clients show the same command and programs through the TypeScript port in
//! `packages/client-runtime/src/elevationCommand.ts`; the shared vectors in
//! `packages/contracts/test-vectors/elevation-commands.json` keep the two in step.
//!
//! Only words in command position count, so `echo sudo x`, quoted text and
//! heredoc bodies never do. Anything the reader can't follow with certainty
//! (command or process substitution, `case`, `[[`, unbalanced quotes) yields
//! no calls at all: an unreadable string costs a phone prompt per sudo, never
//! a guess.

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(Word),
    Op(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Word {
    text: String,
    /// No expansion can change it: nothing unquoted or double-quoted that
    /// starts one (`$`, globs, `~`, braces, a leading `=`).
    literal: bool,
    /// Part of it was quoted or escaped, so it is never a reserved word.
    quoted: bool,
}

/// Longest first, so `&&` wins over `&`.
const OPERATORS: &[&str] = &[
    ";;&", "&>>", "<<-", "<<<", "&&", "||", ";;", ";&", "|&", "<<", ">>", "<&", ">&", "<>", ">|",
    "&>", "&", "|", ";", "<", ">", "(", ")", "\n",
];

const REDIRECTS: &[&str] = &[
    "<", ">", ">>", "<&", ">&", "<>", ">|", "&>", "&>>", "<<<", "<<", "<<-",
];

/// Reserved words after which the next word is still a command.
const KEEP_COMMAND: &[&str] = &[
    "!", "{", "if", "then", "else", "elif", "while", "until", "do",
];

/// Constructs whose words the reader can't place.
const UNREADABLE: &[&str] = &["case", "select", "function", "coproc", "[[", "esac"];

#[derive(Default)]
struct Reader {
    tokens: Vec<Token>,
    word: String,
    in_word: bool,
    expands: bool,
    quoted: bool,
    /// Heredoc delimiters whose bodies start after the next newline, and
    /// whether `<<-` strips their leading tabs.
    heredocs: Vec<(String, bool)>,
    delimiter_next: Option<bool>,
}

impl Reader {
    fn flush(&mut self) -> Option<()> {
        if !self.in_word {
            return Some(());
        }
        let word = Word {
            text: std::mem::take(&mut self.word),
            literal: !self.expands,
            quoted: self.quoted,
        };
        self.in_word = false;
        self.expands = false;
        self.quoted = false;
        if let Some(strip) = self.delimiter_next.take() {
            if !word.literal {
                return None;
            }
            self.heredocs.push((word.text.clone(), strip));
        }
        self.tokens.push(Token::Word(word));
        Some(())
    }

    fn push(&mut self, ch: char) {
        self.word.push(ch);
        self.in_word = true;
    }
}

/// `$` at `chars[at]`. `${name}` is read whole so its braces don't end the
/// word; `$(`, `$'…'`, `$"…"` and any other `${…}` are unreadable.
fn dollar(chars: &[char], at: usize, in_double: bool) -> Option<usize> {
    match chars.get(at + 1) {
        Some('(') => None,
        Some('\'' | '"') if !in_double => None,
        Some('{') => {
            let end = at + 2 + chars[at + 2..].iter().position(|ch| *ch == '}')?;
            let inner = &chars[at + 2..end];
            let name = inner
                .first()
                .is_some_and(|ch| ch.is_ascii_alphabetic() || *ch == '_')
                && inner
                    .iter()
                    .all(|ch| ch.is_ascii_alphanumeric() || *ch == '_');
            let digits = !inner.is_empty() && inner.iter().all(char::is_ascii_digit);
            let special = matches!(inner, ['@' | '*' | '#' | '?' | '$' | '!' | '-']);
            (name || digits || special).then_some(end + 1 - at)
        }
        _ => Some(1),
    }
}

fn tokenize(line: &str) -> Option<Vec<Token>> {
    let chars: Vec<char> = line.chars().collect();
    let mut reader = Reader::default();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        match ch {
            '\\' => {
                let next = *chars.get(index + 1)?;
                // A backslash-newline joins lines; anything else is quoted.
                if next != '\n' {
                    reader.push(next);
                    reader.quoted = true;
                }
                index += 2;
            }
            '\'' => {
                let end = index + 1 + chars[index + 1..].iter().position(|ch| *ch == '\'')?;
                reader.word.extend(&chars[index + 1..end]);
                reader.in_word = true;
                reader.quoted = true;
                index = end + 1;
            }
            '"' => {
                reader.in_word = true;
                reader.quoted = true;
                index += 1;
                loop {
                    match *chars.get(index)? {
                        '"' => break,
                        '`' => return None,
                        '\\' => {
                            let next = *chars.get(index + 1)?;
                            match next {
                                '\n' => {}
                                '$' | '`' | '"' | '\\' => reader.word.push(next),
                                _ => reader.word.extend(['\\', next]),
                            }
                            index += 2;
                        }
                        '$' => {
                            let length = dollar(&chars, index, true)?;
                            reader.word.extend(&chars[index..index + length]);
                            reader.expands = true;
                            index += length;
                        }
                        other => {
                            reader.word.push(other);
                            index += 1;
                        }
                    }
                }
                index += 1;
            }
            '`' => return None,
            '$' => {
                let length = dollar(&chars, index, false)?;
                reader.word.extend(&chars[index..index + length]);
                reader.in_word = true;
                reader.expands = true;
                index += length;
            }
            ' ' | '\t' => {
                reader.flush()?;
                index += 1;
            }
            '#' if !reader.in_word => {
                index += chars[index..]
                    .iter()
                    .position(|ch| *ch == '\n')
                    .unwrap_or(chars.len() - index);
            }
            ';' | '&' | '|' | '<' | '>' | '(' | ')' | '\n' => {
                let rest: String = chars[index..chars.len().min(index + 3)].iter().collect();
                let op = *OPERATORS.iter().find(|op| rest.starts_with(**op))?;
                if matches!(op, ";;" | ";&" | ";;&") {
                    return None;
                }
                let after = chars.get(index + op.chars().count()).copied();
                // `<(…)`, `>(…)`, `((…))`, and `(` against a word (zsh's
                // `=(…)`, extglob `!(…)`, glob qualifiers) except `name()`.
                if matches!(op, "<" | ">" | "(") && after == Some('(') {
                    return None;
                }
                if op == "(" && reader.in_word && after != Some(')') {
                    return None;
                }
                let io_number = reader.in_word
                    && !reader.quoted
                    && !reader.expands
                    && reader.word.chars().all(|ch| ch.is_ascii_digit())
                    && (op.starts_with('<') || op.starts_with('>'));
                if io_number {
                    reader.word.clear();
                    reader.in_word = false;
                } else {
                    reader.flush()?;
                }
                if matches!(op, "<<" | "<<-") {
                    reader.delimiter_next = Some(op == "<<-");
                }
                reader.tokens.push(Token::Op(op));
                index += op.chars().count();
                if op == "\n" {
                    if reader.delimiter_next.is_some() {
                        return None;
                    }
                    for (delimiter, strip) in std::mem::take(&mut reader.heredocs) {
                        loop {
                            if index >= chars.len() {
                                return None;
                            }
                            let end = chars[index..]
                                .iter()
                                .position(|ch| *ch == '\n')
                                .map_or(chars.len(), |offset| index + offset);
                            let body: String = chars[index..end].iter().collect();
                            index = end + 1;
                            let body = if strip {
                                body.trim_start_matches('\t')
                            } else {
                                &body
                            };
                            if body == delimiter {
                                break;
                            }
                        }
                    }
                }
            }
            other => {
                // Globs, `~`, brace expansion and zsh's `=command` change the
                // word; a lone `{` or `}` is a reserved word and stays a word.
                if matches!(other, '*' | '?' | '[' | '~' | '{' | '}')
                    || (other == '=' && !reader.in_word)
                {
                    reader.expands = true;
                }
                reader.push(other);
                index += 1;
            }
        }
    }
    reader.flush()?;
    if reader.delimiter_next.is_some() || !reader.heredocs.is_empty() {
        return None;
    }
    Some(reader.tokens)
}

/// One `sudo` the command string runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SudoCall {
    /// sudo's arguments as the shell passes them; None for a word an
    /// expansion may change, which no argv can be shown to match.
    pub args: Vec<Option<String>>,
    /// The string's last command, which zsh and bash exec in place of the
    /// shell, so this sudo leads the session itself.
    pub exec_tail: bool,
}

impl SudoCall {
    /// Whether `args` (sudo's argv without argv[0]) is this call.
    pub fn is(&self, args: &[String]) -> bool {
        self.args.len() == args.len()
            && self
                .args
                .iter()
                .zip(args)
                .all(|(word, arg)| word.as_deref() == Some(arg.as_str()))
    }
}

fn is_sudo(word: &Word) -> bool {
    word.literal
        && (word.text == "sudo" || (word.text.starts_with('/') && word.text.ends_with("/sudo")))
}

fn calls(tokens: &[Token]) -> Option<Vec<SudoCall>> {
    let word_at = |index: usize| matches!(tokens.get(index), Some(Token::Word(_)));
    let mut calls = Vec::new();
    let mut command = true;
    // Whether a command starting here is in the string's top-level list.
    let mut top_level = true;
    let mut index = 0;
    while index < tokens.len() {
        match &tokens[index] {
            Token::Op(op) if REDIRECTS.contains(op) => {
                word_at(index + 1).then_some(())?;
                index += 2;
            }
            Token::Op(op) => {
                command = true;
                top_level = matches!(*op, ";" | "&&" | "||" | "\n");
                index += 1;
            }
            Token::Word(word) if command => {
                if !word.quoted && UNREADABLE.contains(&word.text.as_str()) {
                    return None;
                }
                if !word.quoted && KEEP_COMMAND.contains(&word.text.as_str()) {
                    top_level = false;
                    index += 1;
                    continue;
                }
                command = false;
                index += 1;
                if !is_sudo(word) {
                    continue;
                }
                let mut args = Vec::new();
                while let Some(token) = tokens.get(index) {
                    match token {
                        Token::Word(word) => {
                            args.push(word.literal.then(|| word.text.clone()));
                            index += 1;
                        }
                        Token::Op(op) if REDIRECTS.contains(op) => {
                            word_at(index + 1).then_some(())?;
                            index += 2;
                        }
                        Token::Op(_) => break,
                    }
                }
                let last = tokens[index..]
                    .iter()
                    .all(|token| matches!(token, Token::Op(";" | "\n")));
                if !args.is_empty() {
                    calls.push(SudoCall {
                        args,
                        exec_tail: top_level && last,
                    });
                }
            }
            Token::Word(_) => index += 1,
        }
    }
    Some(calls)
}

/// Claude Code runs each Bash tool call as `bash -c '<shell snapshot and
/// setup> && eval '<command>' < /dev/null && pwd -P >| <file>'`. Only the
/// eval'd command is the agent's; the setup before it isn't shown, and none
/// of its sudos are covered.
fn claude_eval(tokens: &[Token]) -> Option<&str> {
    use Token::{Op, Word};
    match tokens.get(tokens.len().checked_sub(10)?..)? {
        [
            Op("&&"),
            Word(eval),
            Word(command),
            Op("<"),
            Word(null),
            Op("&&"),
            Word(pwd),
            Word(physical),
            Op(">|"),
            Word(_),
        ] if eval.text == "eval"
            && !eval.quoted
            && command.literal
            && null.text == "/dev/null"
            && pwd.text == "pwd"
            && !pwd.quoted
            && physical.text == "-P" =>
        {
            Some(&command.text)
        }
        _ => None,
    }
}

/// The command the agent wrote, from its shell's `-c` string.
pub fn agent_command(command_string: &str) -> String {
    tokenize(command_string)
        .as_deref()
        .and_then(claude_eval)
        .unwrap_or(command_string)
        .to_string()
}

/// Every sudo in command position in the agent's command, in order, or None
/// when the string can't be read with certainty.
pub fn sudo_calls(command_string: &str) -> Option<Vec<SudoCall>> {
    let tokens = tokenize(command_string)?;
    match claude_eval(&tokens) {
        // bash doesn't exec inside eval, and `&& pwd` follows it anyway.
        Some(command) => Some(
            calls(&tokenize(command)?)?
                .into_iter()
                .map(|call| SudoCall {
                    exec_tail: false,
                    ..call
                })
                .collect(),
        ),
        None => calls(&tokens),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(command: &str) -> Option<Vec<Vec<Option<String>>>> {
        sudo_calls(command).map(|calls| calls.into_iter().map(|call| call.args).collect())
    }

    fn literal(words: &[&str]) -> Vec<Option<String>> {
        words.iter().map(|word| Some(word.to_string())).collect()
    }

    /// Review H2: the argv "appeared" in echo, printf and heredoc text.
    #[test]
    fn only_command_positions_count() {
        assert_eq!(args("echo sudo rm -rf /"), Some(vec![]));
        assert_eq!(args("printf 'sudo rm -rf /\\n'"), Some(vec![]));
        assert_eq!(
            args("sudo tee /etc/x <<'EOF'\nsudo rm -rf /\nEOF\nsudo id"),
            Some(vec![literal(&["tee", "/etc/x"]), literal(&["id"])])
        );
        assert_eq!(
            args("sudo -u postgres psql"),
            Some(vec![literal(&["-u", "postgres", "psql"])])
        );
    }

    #[test]
    fn calls_match_only_the_whole_argv() {
        let call = &sudo_calls("sudo rm -rf /tmp/x 2>/dev/null").unwrap()[0];
        assert!(call.is(&["rm".into(), "-rf".into(), "/tmp/x".into()]));
        assert!(!call.is(&["rm".into(), "-rf".into()]));
        let expanded = &sudo_calls("sudo rm \"$DIR\"").unwrap()[0];
        assert!(!expanded.is(&["rm".into(), "$DIR".into()]));
    }
}
