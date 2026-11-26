use crate::error::{ParseError, ParseErrorKind, Span};
use crate::token::{Token, TokenKind};

const KEYWORDS: &[(&str, TokenKind)] = &[
    ("vector", TokenKind::Vector),
    ("wallet", TokenKind::Wallet),
    ("bind", TokenKind::Bind),
    ("certify", TokenKind::Certify),
    ("transfer", TokenKind::Transfer),
    ("drain", TokenKind::Drain),
    ("project", TokenKind::Project),
    ("reconstruct", TokenKind::Reconstruct),
    ("query", TokenKind::Query),
    ("record", TokenKind::Record),
    ("contract", TokenKind::Contract),
    ("action", TokenKind::Action),
    ("with", TokenKind::With),
    ("to", TokenKind::To),
    ("amount", TokenKind::Amount),
    ("by", TokenKind::By),
    ("into", TokenKind::Into),
    ("from", TokenKind::From),
    ("policy", TokenKind::Policy),
    ("ctx", TokenKind::Ctx),
    ("space", TokenKind::Space),
    ("op", TokenKind::Op),
    ("risk", TokenKind::Risk),
    ("threshold_version", TokenKind::ThresholdVersion),
    ("outcome", TokenKind::Outcome),
    ("gain", TokenKind::Gain),
    ("loss", TokenKind::Loss),
    ("partial", TokenKind::Partial),
    ("release", TokenKind::Release),
    ("staged", TokenKind::Staged),
    ("as", TokenKind::As),
    ("import", TokenKind::Import),
    ("network", TokenKind::Network),
    ("connect", TokenKind::Connect),
    ("target", TokenKind::Target),
    ("participant", TokenKind::Participant),
    ("join", TokenKind::Join),
    ("scope", TokenKind::Scope),
    ("region", TokenKind::Region),
    ("ghost", TokenKind::Ghost),
    ("token", TokenKind::Token),
    ("create", TokenKind::Create),
    ("in", TokenKind::In),
    ("authorize", TokenKind::Authorize),
    ("key", TokenKind::Key),
    ("role", TokenKind::Role),
    ("receive", TokenKind::Receive),
    ("execute", TokenKind::Execute),
    ("loan", TokenKind::Loan),
    ("verify", TokenKind::Verify),
    ("proof", TokenKind::Proof),
    ("history", TokenKind::History),
    ("blake3", TokenKind::Blake3),
    ("sha256", TokenKind::Sha256),
    ("public", TokenKind::Public),
    ("private", TokenKind::Private),
    ("true", TokenKind::Bool(true)),
    ("false", TokenKind::Bool(false)),
];

#[derive(Debug, Clone)]
pub struct Lexer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_next(&self) -> Option<u8> {
        self.bytes.get(self.pos + 1).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let ch = self.peek()?;
        self.pos += 1;
        if ch == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(ch)
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
                self.bump();
            }
            let mut skipped = false;
            if self.peek() == Some(b'/') && self.peek_next() == Some(b'/') {
                skipped = true;
                self.bump();
                self.bump();
                while let Some(ch) = self.bump() {
                    if ch == b'\n' {
                        break;
                    }
                }
            } else if self.peek() == Some(b'/') && self.peek_next() == Some(b'*') {
                skipped = true;
                self.bump();
                self.bump();
                while let Some(ch) = self.bump() {
                    if ch == b'*' && self.peek() == Some(b'/') {
                        self.bump();
                        break;
                    }
                }
            } else if self.peek() == Some(b'#') {
                skipped = true;
                self.bump();
                while let Some(ch) = self.bump() {
                    if ch == b'\n' {
                        break;
                    }
                }
            }
            if !skipped {
                break;
            }
        }
    }

    fn lex_number(&mut self, start: usize, line: usize, col: usize) -> Result<Token, ParseError> {
        let mut end = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit() || c == b'_') {
            self.bump();
            end = self.pos;
        }
        let raw = &self.src[start..end];
        let cleaned: String = raw.chars().filter(|c| *c != '_').collect();
        let value = cleaned.parse::<u128>().map_err(|_| {
            ParseError::new(
                Span::with_line_col(start, end, line, col),
                ParseErrorKind::InvalidNumber(raw.to_string()),
            )
        })?;
        Ok(Token::new(TokenKind::Integer(value), start, end, line, col))
    }

    fn lex_ident_or_keyword(&mut self, start: usize, line: usize, col: usize) -> Token {
        let mut end = self.pos;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            // Keep '-' as part of identifier only if preceded by ident chars and followed by ident chars
            if self.peek() == Some(b'-') {
                break;
            }
            self.bump();
            end = self.pos;
        }
        let text = &self.src[start..end];
        if let Some((_, keyword)) = KEYWORDS.iter().find(|(k, _)| *k == text) {
            Token::new(keyword.clone(), start, end, line, col)
        } else {
            Token::new(TokenKind::Ident(text.to_string()), start, end, line, col)
        }
    }

    fn lex_string(&mut self, start: usize, line: usize, col: usize) -> Result<Token, ParseError> {
        let mut out = String::new();
        loop {
            let ch = self.bump().ok_or_else(|| {
                ParseError::new(
                    Span::with_line_col(start, self.pos, line, col),
                    ParseErrorKind::UnexpectedEof,
                )
            })?;
            match ch {
                b'"' => break,
                b'\\' => {
                    let esc = self.bump().ok_or_else(|| {
                        ParseError::new(
                            Span::with_line_col(start, self.pos, line, col),
                            ParseErrorKind::UnexpectedEof,
                        )
                    })?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        other => out.push(other as char),
                    }
                }
                other => out.push(other as char),
            }
        }
        Ok(Token::new(
            TokenKind::String(out),
            start,
            self.pos,
            line,
            col,
        ))
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Result<Token, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.skip_ws_and_comments();
        let start = self.pos;
        let line = self.line;
        let col = self.col;
        let ch = self.bump()?;
        let token = match ch {
            b'(' => Ok(Token::new(TokenKind::LParen, start, self.pos, line, col)),
            b')' => Ok(Token::new(TokenKind::RParen, start, self.pos, line, col)),
            b'{' => Ok(Token::new(TokenKind::LBrace, start, self.pos, line, col)),
            b'}' => Ok(Token::new(TokenKind::RBrace, start, self.pos, line, col)),
            b'[' => Ok(Token::new(TokenKind::LBracket, start, self.pos, line, col)),
            b']' => Ok(Token::new(TokenKind::RBracket, start, self.pos, line, col)),
            b':' => Ok(Token::new(TokenKind::Colon, start, self.pos, line, col)),
            b';' => Ok(Token::new(TokenKind::Semi, start, self.pos, line, col)),
            b',' => Ok(Token::new(TokenKind::Comma, start, self.pos, line, col)),
            b'.' => Ok(Token::new(TokenKind::Dot, start, self.pos, line, col)),
            b'=' => Ok(Token::new(TokenKind::Eq, start, self.pos, line, col)),
            b'"' => self.lex_string(start, line, col),
            b'0'..=b'9' => self.lex_number(start, line, col),
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => Ok(self.lex_ident_or_keyword(start, line, col)),
            other => Err(ParseError::new(
                Span::with_line_col(start, self.pos, line, col),
                ParseErrorKind::Message(format!("unexpected character `{}`", other as char)),
            )),
        };
        Some(token)
    }
}

pub fn lex(src: &str) -> Result<Vec<Token>, ParseError> {
    let mut lexer = Lexer::new(src);
    let mut tokens = Vec::new();
    while let Some(item) = lexer.next() {
        tokens.push(item?);
    }
    let len = src.len();
    tokens.push(Token::new(
        TokenKind::Eof,
        len,
        len,
        lexer.line,
        lexer.col,
    ));
    Ok(tokens)
}
