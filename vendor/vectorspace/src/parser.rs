use crate::ast::*;
use crate::error::{ParseError, ParseErrorKind, Span};
use crate::lexer::lex;
use crate::token::{Token, TokenKind};

#[derive(Debug, Clone)]
pub struct Parser {
    tokens: Vec<Token>,
    index: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, index: 0 }
    }

    pub fn from_source(source: &str) -> Result<Self, ParseError> {
        Ok(Self::new(lex(source)?))
    }

    fn current(&self) -> &Token {
        &self.tokens[self.index]
    }

    fn peek_at(&self, offset: usize) -> &Token {
        self.tokens
            .get(self.index + offset)
            .unwrap_or_else(|| self.tokens.last().unwrap())
    }

    fn current_span(&self) -> Span {
        let t = self.current();
        Span::with_line_col(t.start, t.end, t.line, t.col)
    }

    fn at_end(&self) -> bool {
        self.kind_eq(&TokenKind::Eof)
    }

    fn kind_eq(&self, kind: &TokenKind) -> bool {
        std::mem::discriminant(&self.current().kind) == std::mem::discriminant(kind)
    }

    fn advance(&mut self) {
        if !self.at_end() {
            self.index += 1;
        }
    }

    fn error_here(&self, expected: impl Into<String>) -> ParseError {
        let token = self.current();
        ParseError::new(
            Span::with_line_col(token.start, token.end, token.line, token.col),
            ParseErrorKind::UnexpectedToken {
                expected: expected.into(),
                found: format!("{:?}", token.kind),
            },
        )
    }

    fn expect_semi(&mut self) -> Result<(), ParseError> {
        if self.kind_eq(&TokenKind::Semi) {
            self.advance();
            Ok(())
        } else {
            Err(self.error_here("`;`"))
        }
    }

    fn eat_optional_semi(&mut self) {
        if self.kind_eq(&TokenKind::Semi) {
            self.advance();
        }
    }

    fn expect_kind(
        &mut self,
        kind: fn(&TokenKind) -> bool,
        expected: &'static str,
    ) -> Result<(), ParseError> {
        if kind(&self.current().kind) {
            self.advance();
            Ok(())
        } else {
            Err(self.error_here(expected))
        }
    }

    #[allow(dead_code)]
    fn take_ident(&mut self) -> Result<String, ParseError> {
        match &self.current().kind {
            TokenKind::Ident(text) => {
                let out = text.clone();
                self.advance();
                Ok(out)
            }
            _ => Err(self.error_here("identifier")),
        }
    }

    fn take_ident_or_kw(&mut self) -> Result<String, ParseError> {
        if let Some(s) = self.current().kind.as_ident_str() {
            let out = s.to_string();
            self.advance();
            Ok(out)
        } else {
            Err(self.error_here("identifier"))
        }
    }

    fn take_string_like(&mut self) -> Result<String, ParseError> {
        match &self.current().kind {
            TokenKind::String(text) | TokenKind::Ident(text) => {
                let out = text.clone();
                self.advance();
                Ok(out)
            }
            TokenKind::Integer(v) => {
                let out = v.to_string();
                self.advance();
                Ok(out)
            }
            other => {
                if let Some(kw) = other.as_ident_str() {
                    let out = kw.to_string();
                    self.advance();
                    Ok(out)
                } else {
                    Err(self.error_here("string or identifier"))
                }
            }
        }
    }

    fn take_integer(&mut self) -> Result<u128, ParseError> {
        match &self.current().kind {
            TokenKind::Integer(v) => {
                let out = *v;
                self.advance();
                Ok(out)
            }
            _ => Err(self.error_here("integer")),
        }
    }

    fn parse_vector_type(&mut self) -> Result<VectorType, ParseError> {
        let span = self.current_span();
        let name = self.take_ident_or_kw()?;
        VectorType::parse(&name).ok_or_else(|| {
            ParseError::new(
                span,
                ParseErrorKind::Message(format!("unknown vector type `{name}`")),
            )
        })
    }

    fn parse_integer_list(&mut self, terminator: TokenKind) -> Result<Vec<u128>, ParseError> {
        let mut components = Vec::new();
        if !self.kind_eq(&terminator) {
            loop {
                let value = self.take_integer()?;
                components.push(value);
                if self.kind_eq(&TokenKind::Comma) {
                    self.advance();
                    if self.kind_eq(&terminator) {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        Ok(components)
    }

    fn parse_vector_literal(&mut self) -> Result<Vec<u128>, ParseError> {
        if self.kind_eq(&TokenKind::LBracket) {
            self.advance();
            let vals = self.parse_integer_list(TokenKind::RBracket)?;
            self.expect_kind(|k| k == &TokenKind::RBracket, "`]`")?;
            Ok(vals)
        } else {
            self.expect_kind(|k| k == &TokenKind::LParen, "`(`")?;
            let vals = self.parse_integer_list(TokenKind::RParen)?;
            self.expect_kind(|k| k == &TokenKind::RParen, "`)`")?;
            Ok(vals)
        }
    }

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_path_or_primary()
    }

    fn parse_path_or_primary(&mut self) -> Result<Expr, ParseError> {
        let mut expr = match &self.current().kind {
            TokenKind::Integer(v) => {
                let v = *v;
                self.advance();
                Expr::Integer(v)
            }
            TokenKind::Bool(b) => {
                let b = *b;
                self.advance();
                Expr::Bool(b)
            }
            TokenKind::String(s) => {
                let s = s.clone();
                self.advance();
                Expr::String(s)
            }
            TokenKind::LBracket => {
                let vals = self.parse_vector_literal()?;
                Expr::VectorLiteral(vals)
            }
            TokenKind::LParen => {
                let save = self.index;
                self.advance();
                if matches!(self.current().kind, TokenKind::Integer(_))
                    && matches!(self.peek_at(1).kind, TokenKind::Comma)
                {
                    self.index = save;
                    let vals = self.parse_vector_literal()?;
                    Expr::VectorLiteral(vals)
                } else {
                    let expr = self.parse_expr()?;
                    self.expect_kind(|k| k == &TokenKind::RParen, "`)`")?;
                    Expr::Group(Box::new(expr))
                }
            }
            other => {
                if let Some(name) = other.as_ident_str() {
                    let name = name.to_string();
                    self.advance();
                    if self.kind_eq(&TokenKind::LParen) {
                        self.advance();
                        let args = self.parse_named_args(TokenKind::RParen)?;
                        self.expect_kind(|k| k == &TokenKind::RParen, "`)`")?;
                        Expr::Call { callee: name, args }
                    } else {
                        Expr::Ident(name)
                    }
                } else {
                    return Err(self.error_here("expression"));
                }
            }
        };

        while self.kind_eq(&TokenKind::Dot) {
            self.advance();
            let part = self.take_ident_or_kw()?;
            expr = match expr {
                Expr::Ident(first) => Expr::Path(vec![first, part]),
                Expr::Path(mut parts) => {
                    parts.push(part);
                    Expr::Path(parts)
                }
                other => {
                    return Err(ParseError::new(
                        self.current_span(),
                        ParseErrorKind::Message(format!("cannot apply path access to {other:?}")),
                    ))
                }
            };
        }

        Ok(expr)
    }

    fn parse_named_args(&mut self, terminator: TokenKind) -> Result<Vec<NamedArg>, ParseError> {
        let mut args = Vec::new();
        if self.kind_eq(&terminator) {
            return Ok(args);
        }
        loop {
            let arg = if let Some(name) = self.current().kind.as_ident_str() {
                let name = name.to_string();
                let save = self.index;
                self.advance();
                if self.kind_eq(&TokenKind::Eq) {
                    self.advance();
                    let value = self.parse_expr()?;
                    NamedArg {
                        name: Some(name),
                        value,
                    }
                } else {
                    self.index = save;
                    let value = self.parse_expr()?;
                    NamedArg { name: None, value }
                }
            } else {
                let value = self.parse_expr()?;
                NamedArg { name: None, value }
            };
            args.push(arg);

            if self.kind_eq(&TokenKind::Comma) {
                self.advance();
                if self.kind_eq(&terminator) {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(args)
    }

    fn parse_property_block(&mut self) -> Result<Vec<PropertyField>, ParseError> {
        self.expect_kind(|k| k == &TokenKind::LBrace, "`{`")?;
        let mut fields = Vec::new();
        while !self.kind_eq(&TokenKind::RBrace) {
            let span = self.current_span();
            let name = self.take_ident_or_kw()?;
            self.expect_kind(
                |k| k == &TokenKind::Eq || k == &TokenKind::Colon,
                "`=` or `:`",
            )?;
            let value = self.parse_expr()?;
            if self.kind_eq(&TokenKind::Semi) || self.kind_eq(&TokenKind::Comma) {
                self.advance();
            }
            fields.push(PropertyField { name, value, span });
        }
        self.expect_kind(|k| k == &TokenKind::RBrace, "`}`")?;
        Ok(fields)
    }

    fn parse_context_expr(&mut self) -> Result<ContextExpr, ParseError> {
        if !self.kind_eq(&TokenKind::Ctx) {
            return Err(self.error_here("ctx(...)"));
        }
        self.advance();
        self.expect_kind(|k| k == &TokenKind::LParen, "`(`")?;
        let args = self.parse_named_args(TokenKind::RParen)?;
        self.expect_kind(|k| k == &TokenKind::RParen, "`)`")?;
        Ok(ContextExpr::new(args))
    }

    fn parse_contract_action(&mut self) -> Result<ContractAction, ParseError> {
        self.expect_kind(|k| k == &TokenKind::Action, "`action`")?;
        let name = self.take_ident_or_kw()?;
        let mut args = Vec::new();
        if self.kind_eq(&TokenKind::LParen) {
            self.advance();
            args = self.parse_named_args(TokenKind::RParen)?;
            self.expect_kind(|k| k == &TokenKind::RParen, "`)`")?;
        }
        self.expect_semi()?;
        Ok(ContractAction { name, args })
    }

    fn parse_scope_list(&mut self) -> Result<Vec<String>, ParseError> {
        if self.kind_eq(&TokenKind::LParen) || self.kind_eq(&TokenKind::LBracket) {
            let term = if self.kind_eq(&TokenKind::LBracket) {
                TokenKind::RBracket
            } else {
                TokenKind::RParen
            };
            self.advance();
            let mut scopes = Vec::new();
            while !self.kind_eq(&term) {
                scopes.push(self.take_string_like()?);
                if self.kind_eq(&TokenKind::Comma) {
                    self.advance();
                } else {
                    break;
                }
            }
            if self.kind_eq(&term) {
                self.advance();
            } else {
                return Err(self.error_here("closing scope delimiter"));
            }
            Ok(scopes)
        } else {
            Ok(vec![self.take_string_like()?])
        }
    }

    fn parse_space_create(&mut self, ghost: bool, span: Span) -> Result<Statement, ParseError> {
        self.expect_kind(|k| k == &TokenKind::Space, "`space`")?;
        self.expect_kind(|k| k == &TokenKind::Create, "`create`")?;
        let name = self.take_ident_or_kw()?;
        let fields = if self.kind_eq(&TokenKind::LBrace) {
            let f = self.parse_property_block()?;
            self.eat_optional_semi();
            f
        } else {
            self.expect_semi()?;
            Vec::new()
        };
        Ok(Statement::SpaceCreate(SpaceCreateStmt {
            name,
            ghost,
            fields,
            span,
        }))
    }

    fn parse_region_create(&mut self, ghost: bool, span: Span) -> Result<Statement, ParseError> {
        self.expect_kind(|k| k == &TokenKind::Region, "`region`")?;
        self.expect_kind(|k| k == &TokenKind::Create, "`create`")?;
        let name = self.take_ident_or_kw()?;
        let space = if self.kind_eq(&TokenKind::In) {
            self.advance();
            self.take_string_like()?
        } else if ghost {
            String::new()
        } else {
            return Err(self.error_here("`in`"));
        };
        let fields = if self.kind_eq(&TokenKind::LBrace) {
            let f = self.parse_property_block()?;
            self.eat_optional_semi();
            f
        } else {
            self.expect_semi()?;
            Vec::new()
        };
        Ok(Statement::RegionCreate(RegionCreateStmt {
            name,
            space,
            ghost,
            fields,
            span,
        }))
    }

    fn parse_wallet_stmt(&mut self, ghost: bool, span: Span) -> Result<Statement, ParseError> {
        self.expect_kind(|k| k == &TokenKind::Wallet, "`wallet`")?;
        if self.kind_eq(&TokenKind::Create) {
            self.advance();
            let name = self.take_ident_or_kw()?;
            let region = if self.kind_eq(&TokenKind::In) {
                self.advance();
                self.take_string_like()?
            } else if ghost {
                String::new()
            } else {
                return Err(self.error_here("`in`"));
            };
            let mut context = None;
            if self.kind_eq(&TokenKind::With) {
                self.advance();
                context = Some(self.parse_context_expr()?);
            }
            let fields = if self.kind_eq(&TokenKind::LBrace) {
                let f = self.parse_property_block()?;
                self.eat_optional_semi();
                f
            } else {
                self.expect_semi()?;
                Vec::new()
            };
            return Ok(Statement::WalletCreate(WalletCreateStmt {
                name,
                region,
                ghost,
                context,
                fields,
                span,
            }));
        }
        if ghost {
            return Err(self.error_here("`create` after `ghost wallet`"));
        }
        if self.kind_eq(&TokenKind::Authorize) {
            self.advance();
            let wallet = self.take_string_like()?;
            self.expect_kind(|k| k == &TokenKind::Key, "`key`")?;
            let public_key = self.parse_expr()?;
            let mut role = None;
            if self.kind_eq(&TokenKind::Role) {
                self.advance();
                role = Some(self.take_string_like()?);
            }
            let fields = if self.kind_eq(&TokenKind::LBrace) {
                let f = self.parse_property_block()?;
                self.eat_optional_semi();
                f
            } else {
                self.expect_semi()?;
                Vec::new()
            };
            return Ok(Statement::WalletAuthorize(WalletAuthorizeStmt {
                wallet,
                public_key,
                role,
                fields,
                span,
            }));
        }

        // Original syntax: wallet <name> = bind(<pk>);
        let name = self.take_ident_or_kw()?;
        self.expect_kind(|k| k == &TokenKind::Eq, "`=`")?;
        if !self.kind_eq(&TokenKind::Bind) {
            return Err(self.error_here("bind(...)"));
        }
        self.advance();
        self.expect_kind(|k| k == &TokenKind::LParen, "`(`")?;
        let public_key = self.take_string_like()?;
        self.expect_kind(|k| k == &TokenKind::RParen, "`)`")?;
        self.expect_semi()?;
        Ok(Statement::WalletDecl(WalletDecl { name, public_key }))
    }

    fn parse_token_create(&mut self, ghost: bool, span: Span) -> Result<Statement, ParseError> {
        self.expect_kind(|k| k == &TokenKind::Token, "`token`")?;
        self.expect_kind(|k| k == &TokenKind::Create, "`create`")?;
        let name = self.take_ident_or_kw()?;
        let wallet = if self.kind_eq(&TokenKind::In) {
            self.advance();
            self.take_string_like()?
        } else if ghost {
            String::new()
        } else {
            return Err(self.error_here("`in`"));
        };
        let fields = if self.kind_eq(&TokenKind::LBrace) {
            let f = self.parse_property_block()?;
            self.eat_optional_semi();
            f
        } else {
            self.expect_semi()?;
            Vec::new()
        };
        Ok(Statement::TokenCreate(TokenCreateStmt {
            name,
            wallet,
            ghost,
            fields,
            span,
        }))
    }

    fn parse_statement(&mut self) -> Result<Statement, ParseError> {
        let span = self.current_span();
        match &self.current().kind {
            TokenKind::Import => {
                self.advance();
                let path = self.take_string_like()?;
                let mut hash_algorithm = None;
                let mut expected_hash = None;
                let mut alias = None;
                if self.kind_eq(&TokenKind::Blake3) {
                    self.advance();
                    hash_algorithm = Some("blake3".to_string());
                    expected_hash = Some(self.take_string_like()?);
                } else if self.kind_eq(&TokenKind::Sha256) {
                    self.advance();
                    hash_algorithm = Some("sha256".to_string());
                    expected_hash = Some(self.take_string_like()?);
                }
                if self.kind_eq(&TokenKind::As) {
                    self.advance();
                    alias = Some(self.take_ident_or_kw()?);
                }
                self.expect_semi()?;
                Ok(Statement::Import(ImportStmt {
                    path,
                    hash_algorithm,
                    expected_hash,
                    alias,
                    span,
                }))
            }
            TokenKind::Network => {
                self.advance();
                let target_only = if self.kind_eq(&TokenKind::Connect) {
                    self.advance();
                    false
                } else if self.kind_eq(&TokenKind::Target) {
                    self.advance();
                    true
                } else {
                    return Err(self.error_here("`connect` or `target`"));
                };
                let network_id = self.take_string_like()?;
                self.expect_semi()?;
                Ok(Statement::NetworkConnect(NetworkConnectStmt {
                    network_id,
                    target_only,
                    span,
                }))
            }
            TokenKind::Participant => {
                self.advance();
                self.expect_kind(|k| k == &TokenKind::Join, "`join`")?;
                let name = self.take_string_like()?;
                let mut scopes = Vec::new();
                let mut context = None;
                while !self.kind_eq(&TokenKind::Semi) {
                    if self.kind_eq(&TokenKind::Scope) {
                        self.advance();
                        scopes = self.parse_scope_list()?;
                    } else if self.kind_eq(&TokenKind::With) {
                        self.advance();
                        context = Some(self.parse_context_expr()?);
                    } else {
                        return Err(self.error_here("`scope`, `with`, or `;`"));
                    }
                }
                self.expect_semi()?;
                Ok(Statement::ParticipantJoin(ParticipantJoinStmt {
                    name,
                    scopes,
                    context,
                    span,
                }))
            }
            TokenKind::Ghost => {
                self.advance();
                match &self.current().kind {
                    TokenKind::Space => self.parse_space_create(true, span),
                    TokenKind::Region => self.parse_region_create(true, span),
                    TokenKind::Wallet => self.parse_wallet_stmt(true, span),
                    TokenKind::Token => self.parse_token_create(true, span),
                    _ => Err(self.error_here("`space`, `region`, `wallet`, or `token`")),
                }
            }
            TokenKind::Space => self.parse_space_create(false, span),
            TokenKind::Region => self.parse_region_create(false, span),
            TokenKind::Wallet => self.parse_wallet_stmt(false, span),
            TokenKind::Token => self.parse_token_create(false, span),
            TokenKind::Vector => {
                self.advance();
                let name = self.take_ident_or_kw()?;
                self.expect_kind(|k| k == &TokenKind::Colon, "`:`")?;
                let vector_type = self.parse_vector_type()?;
                self.expect_kind(|k| k == &TokenKind::Eq, "`=`")?;
                let components = self.parse_vector_literal()?;
                self.expect_semi()?;
                Ok(Statement::VectorDecl(VectorDecl {
                    name,
                    vector_type,
                    components,
                }))
            }
            TokenKind::Certify => {
                self.advance();
                let target = self.take_string_like()?;
                if !self.kind_eq(&TokenKind::With) {
                    return Err(self.error_here("with ctx(...)"));
                }
                self.advance();
                let context = self.parse_context_expr()?;
                self.expect_semi()?;
                Ok(Statement::Certify(CertifyStmt { target, context }))
            }
            TokenKind::Transfer => {
                self.advance();
                let first = self.take_string_like()?;
                let (token, source) = if self.kind_eq(&TokenKind::From) {
                    self.advance();
                    (Some(first), self.take_string_like()?)
                } else {
                    (None, first)
                };
                if !self.kind_eq(&TokenKind::To) {
                    return Err(self.error_here("to"));
                }
                self.advance();
                let destination = self.take_string_like()?;
                if !self.kind_eq(&TokenKind::Amount) {
                    return Err(self.error_here("amount"));
                }
                self.advance();
                let amount = self.parse_expr()?;
                let mut drain = None;
                let mut policy = None;
                while !self.kind_eq(&TokenKind::Semi) {
                    match &self.current().kind {
                        TokenKind::Drain => {
                            self.advance();
                            drain = Some(self.parse_expr()?);
                        }
                        TokenKind::Policy => {
                            self.advance();
                            policy = Some(self.parse_expr()?);
                        }
                        _ => return Err(self.error_here("`drain`, `policy`, or `;`")),
                    }
                }
                self.expect_semi()?;
                Ok(Statement::Transfer(TransferStmt {
                    token,
                    source,
                    destination,
                    amount,
                    drain,
                    policy,
                }))
            }
            TokenKind::Receive => {
                self.advance();
                let token = self.take_string_like()?;
                self.expect_kind(|k| k == &TokenKind::Into, "`into`")?;
                let wallet = self.take_string_like()?;
                self.expect_kind(|k| k == &TokenKind::From, "`from`")?;
                let source = self.take_string_like()?;
                self.expect_kind(|k| k == &TokenKind::Amount, "`amount`")?;
                let amount = self.parse_expr()?;
                self.expect_semi()?;
                Ok(Statement::Receive(ReceiveStmt {
                    token,
                    wallet,
                    source,
                    amount,
                    span,
                }))
            }
            TokenKind::Drain => {
                self.advance();
                let target = self.take_string_like()?;
                let mut wallet = None;
                if self.kind_eq(&TokenKind::In) {
                    self.advance();
                    wallet = Some(self.take_string_like()?);
                }
                if !self.kind_eq(&TokenKind::By) {
                    return Err(self.error_here("by"));
                }
                self.advance();
                let amount = self.parse_expr()?;
                let mut policy = None;
                if self.kind_eq(&TokenKind::Policy) {
                    self.advance();
                    policy = Some(self.parse_expr()?);
                }
                self.expect_semi()?;
                Ok(Statement::Drain(DrainStmt {
                    target,
                    wallet,
                    amount,
                    policy,
                }))
            }
            TokenKind::Project => {
                self.advance();
                let source = self.take_ident_or_kw()?;
                if !self.kind_eq(&TokenKind::Into) {
                    return Err(self.error_here("into"));
                }
                self.advance();
                let environment = self.take_ident_or_kw()?;
                if !self.kind_eq(&TokenKind::Amount) {
                    return Err(self.error_here("amount"));
                }
                self.advance();
                let amount = self.parse_expr()?;
                let mut policy = None;
                while !self.kind_eq(&TokenKind::Semi) {
                    match &self.current().kind {
                        TokenKind::Policy => {
                            self.advance();
                            policy = Some(self.parse_expr()?);
                        }
                        _ => return Err(self.error_here("`policy` or `;`")),
                    }
                }
                self.expect_semi()?;
                Ok(Statement::Project(ProjectStmt {
                    source,
                    environment,
                    amount,
                    policy,
                }))
            }
            TokenKind::Reconstruct => {
                self.advance();
                let target = self.take_string_like()?;
                let projection_id = if self.kind_eq(&TokenKind::From) {
                    self.advance();
                    Some(self.take_string_like()?)
                } else {
                    None
                };
                self.expect_semi()?;
                Ok(Statement::Reconstruct(ReconstructStmt {
                    target,
                    projection_id,
                }))
            }
            TokenKind::Query => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect_semi()?;
                Ok(Statement::Query(QueryStmt { expr }))
            }
            TokenKind::History => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect_semi()?;
                Ok(Statement::History(HistoryStmt { expr, span }))
            }
            TokenKind::Verify => {
                self.advance();
                self.expect_kind(|k| k == &TokenKind::Proof, "`proof`")?;
                let expr = self.parse_expr()?;
                self.expect_semi()?;
                Ok(Statement::VerifyProof(VerifyProofStmt { expr, span }))
            }
            TokenKind::Record => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect_semi()?;
                Ok(Statement::Record(RecordStmt { expr }))
            }
            TokenKind::Contract => {
                self.advance();
                if self.kind_eq(&TokenKind::Execute) {
                    self.advance();
                    let contract = self.take_string_like()?;
                    self.expect_kind(|k| k == &TokenKind::Dot, "`.`")?;
                    let action = self.take_ident_or_kw()?;
                    let mut args = Vec::new();
                    if self.kind_eq(&TokenKind::LParen) {
                        self.advance();
                        args = self.parse_named_args(TokenKind::RParen)?;
                        self.expect_kind(|k| k == &TokenKind::RParen, "`)`")?;
                    }
                    self.expect_semi()?;
                    return Ok(Statement::ContractExecute(ContractExecuteStmt {
                        contract,
                        action,
                        args,
                        span,
                    }));
                }
                if self.kind_eq(&TokenKind::Create) {
                    self.advance();
                }
                let name = self.take_ident_or_kw()?;
                self.expect_kind(|k| k == &TokenKind::LBrace, "`{`")?;
                let mut actions = Vec::new();
                let mut fields = Vec::new();
                while !self.kind_eq(&TokenKind::RBrace) {
                    if self.kind_eq(&TokenKind::Action) {
                        actions.push(self.parse_contract_action()?);
                    } else {
                        let fspan = self.current_span();
                        let fname = self.take_ident_or_kw()?;
                        self.expect_kind(
                            |k| k == &TokenKind::Eq || k == &TokenKind::Colon,
                            "`=` or `:`",
                        )?;
                        let value = self.parse_expr()?;
                        if self.kind_eq(&TokenKind::Semi) || self.kind_eq(&TokenKind::Comma) {
                            self.advance();
                        }
                        fields.push(PropertyField {
                            name: fname,
                            value,
                            span: fspan,
                        });
                    }
                }
                self.expect_kind(|k| k == &TokenKind::RBrace, "`}`")?;
                self.eat_optional_semi();
                Ok(Statement::Contract(ContractDecl {
                    name,
                    actions,
                    fields,
                }))
            }
            TokenKind::Loan => {
                self.advance();
                if self.kind_eq(&TokenKind::Execute) {
                    self.advance();
                    let loan = self.take_string_like()?;
                    self.expect_kind(|k| k == &TokenKind::Dot, "`.`")?;
                    let action = self.take_ident_or_kw()?;
                    let mut args = Vec::new();
                    if self.kind_eq(&TokenKind::LParen) {
                        self.advance();
                        args = self.parse_named_args(TokenKind::RParen)?;
                        self.expect_kind(|k| k == &TokenKind::RParen, "`)`")?;
                    }
                    self.expect_semi()?;
                    return Ok(Statement::LoanExecute(LoanExecuteStmt {
                        loan,
                        action,
                        args,
                        span,
                    }));
                }
                self.expect_kind(|k| k == &TokenKind::Create, "`create`")?;
                let name = self.take_ident_or_kw()?;
                let fields = self.parse_property_block()?;
                self.eat_optional_semi();
                Ok(Statement::LoanCreate(LoanCreateStmt { name, fields, span }))
            }
            _ => Err(self.error_here("statement")),
        }
    }

    pub fn parse_program(&mut self) -> Result<Program, ParseError> {
        let mut statements = Vec::new();
        while !self.at_end() {
            statements.push(self.parse_statement()?);
        }
        Ok(Program { statements })
    }
}

pub fn parse(source: &str) -> Result<Program, ParseError> {
    let mut parser = Parser::from_source(source)?;
    parser.parse_program()
}
