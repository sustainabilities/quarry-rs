//! Token stream for the DSL. Mirrors the Lark terminal set in
//! `quarry/dsl/grammar.py`: ESCAPED_STRING, NUMBER, SIGNED_INT (subscript
//! context), STRING_VAR, identifiers/keywords, operators, and punctuation.
//! `//` line comments are ignored.

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// `"…"` with escapes resolved.
    StringLit(String),
    /// Unquoted number (INTEGER | DECIMAL).
    Number(f64),
    /// `$name`.
    StringVar(String),
    /// Bare identifier or keyword — disambiguated contextually by the parser.
    Ident(String),
    // Operators
    Eq,    // ==
    Neq,   // !=
    Gte,   // >=
    Lte,   // <=
    Gt,    // >
    Lt,    // <
    Tilde, // ~
    Plus,
    Minus,
    Star, // multiplication OR wildcard — parser decides by position
    Assign, // =
    // Punctuation
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    Dot,
    At,    // @
    Hash,  // #
}

impl Token {
    pub fn describe(&self) -> String {
        match self {
            Token::StringLit(s) => format!("string literal \"{s}\""),
            Token::Number(n) => format!("number {n}"),
            Token::StringVar(s) => format!("string variable {s}"),
            Token::Ident(s) => format!("identifier `{s}`"),
            Token::Eq => "`==`".into(),
            Token::Neq => "`!=`".into(),
            Token::Gte => "`>=`".into(),
            Token::Lte => "`<=`".into(),
            Token::Gt => "`>`".into(),
            Token::Lt => "`<`".into(),
            Token::Tilde => "`~`".into(),
            Token::Plus => "`+`".into(),
            Token::Minus => "`-`".into(),
            Token::Star => "`*`".into(),
            Token::Assign => "`=`".into(),
            Token::LParen => "`(`".into(),
            Token::RParen => "`)`".into(),
            Token::LBracket => "`[`".into(),
            Token::RBracket => "`]`".into(),
            Token::LBrace => "`{`".into(),
            Token::RBrace => "`}`".into(),
            Token::Comma => "`,`".into(),
            Token::Colon => "`:`".into(),
            Token::Dot => "`.`".into(),
            Token::At => "`@`".into(),
            Token::Hash => "`#`".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Spanned {
    pub token: Token,
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexError {
    pub message: String,
    pub line: usize,
    pub col: usize,
}

pub fn lex(src: &str) -> Result<Vec<Spanned>, LexError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0usize;
    let mut line = 1usize;
    let mut col = 1usize;

    macro_rules! bump {
        () => {{
            if chars[i] == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            i += 1;
        }};
    }

    while i < chars.len() {
        let c = chars[i];
        let (tok_line, tok_col) = (line, col);

        // Whitespace
        if c.is_whitespace() {
            bump!();
            continue;
        }
        // Line comment
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            while i < chars.len() && chars[i] != '\n' {
                bump!();
            }
            continue;
        }
        // String literal
        if c == '"' {
            bump!();
            let mut out = String::new();
            let mut closed = false;
            while i < chars.len() {
                let ch = chars[i];
                if ch == '"' {
                    bump!();
                    closed = true;
                    break;
                }
                if ch == '\\' {
                    bump!();
                    if i >= chars.len() {
                        break;
                    }
                    let esc = chars[i];
                    match esc {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        '0' => out.push('\0'),
                        '\\' => out.push('\\'),
                        '"' => out.push('"'),
                        'u' => {
                            // \uXXXX — take four hex digits.
                            let mut v: u32 = 0;
                            let mut taken = 0;
                            while i + 1 < chars.len() && taken < 4 {
                                let h = chars[i + 1];
                                if let Some(d) = h.to_digit(16) {
                                    v = v * 16 + d;
                                    taken += 1;
                                    bump!();
                                } else {
                                    break;
                                }
                            }
                            if taken == 4 {
                                if let Some(ch) = char::from_u32(v) {
                                    out.push(ch);
                                }
                            }
                            continue;
                        }
                        other => out.push(other),
                    }
                    bump!();
                    continue;
                }
                out.push(ch);
                bump!();
            }
            if !closed {
                return Err(LexError {
                    message: "unterminated string literal".into(),
                    line: tok_line,
                    col: tok_col,
                });
            }
            tokens.push(Spanned {
                token: Token::StringLit(out),
                line: tok_line,
                col: tok_col,
            });
            continue;
        }
        // String variable
        if c == '$' {
            bump!();
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                bump!();
            }
            if start == i {
                return Err(LexError {
                    message: "`$` must be followed by a name".into(),
                    line: tok_line,
                    col: tok_col,
                });
            }
            let name: String = chars[start..i].iter().collect();
            tokens.push(Spanned {
                token: Token::StringVar(name),
                line: tok_line,
                col: tok_col,
            });
            continue;
        }
        // Number
        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                bump!();
            }
            if i + 1 < chars.len() && chars[i] == '.' && chars[i + 1].is_ascii_digit() {
                bump!();
                while i < chars.len() && chars[i].is_ascii_digit() {
                    bump!();
                }
            }
            if i < chars.len() && (chars[i] == 'e' || chars[i] == 'E') {
                let save = i;
                bump!();
                if i < chars.len() && (chars[i] == '+' || chars[i] == '-') {
                    bump!();
                }
                if i < chars.len() && chars[i].is_ascii_digit() {
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        bump!();
                    }
                } else {
                    i = save;
                }
            }
            let text: String = chars[start..i].iter().collect();
            let value: f64 = text.parse().map_err(|_| LexError {
                message: format!("invalid number `{text}`"),
                line: tok_line,
                col: tok_col,
            })?;
            tokens.push(Spanned {
                token: Token::Number(value),
                line: tok_line,
                col: tok_col,
            });
            continue;
        }
        // Identifier / keyword
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                bump!();
            }
            let name: String = chars[start..i].iter().collect();
            tokens.push(Spanned {
                token: Token::Ident(name),
                line: tok_line,
                col: tok_col,
            });
            continue;
        }
        // Two-char operators
        if i + 1 < chars.len() {
            let two: String = chars[i..i + 2].iter().collect();
            let op = match two.as_str() {
                "==" => Some(Token::Eq),
                "!=" => Some(Token::Neq),
                ">=" => Some(Token::Gte),
                "<=" => Some(Token::Lte),
                _ => None,
            };
            if let Some(t) = op {
                bump!();
                bump!();
                tokens.push(Spanned {
                    token: t,
                    line: tok_line,
                    col: tok_col,
                });
                continue;
            }
        }
        // Single-char tokens
        let single = match c {
            '>' => Token::Gt,
            '<' => Token::Lt,
            '~' => Token::Tilde,
            '+' => Token::Plus,
            '-' => Token::Minus,
            '*' => Token::Star,
            '=' => Token::Assign,
            '(' => Token::LParen,
            ')' => Token::RParen,
            '[' => Token::LBracket,
            ']' => Token::RBracket,
            '{' => Token::LBrace,
            '}' => Token::RBrace,
            ',' => Token::Comma,
            ':' => Token::Colon,
            '.' => Token::Dot,
            '@' => Token::At,
            '#' => Token::Hash,
            other => {
                return Err(LexError {
                    message: format!("unexpected character `{other}`"),
                    line: tok_line,
                    col: tok_col,
                })
            }
        };
        bump!();
        tokens.push(Spanned {
            token: single,
            line: tok_line,
            col: tok_col,
        });
    }

    Ok(tokens)
}
