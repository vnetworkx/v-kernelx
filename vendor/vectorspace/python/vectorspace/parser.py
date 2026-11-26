from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .ast import *
from .lexer import lex, Token


class ParserError(SyntaxError):
    pass


class Parser:
    def __init__(self, source: str):
        self.tokens = list(lex(source))
        self.i = 0

    @property
    def cur(self) -> Token:
        return self.tokens[self.i]

    def advance(self):
        if self.cur.kind != "EOF":
            self.i += 1

    def expect(self, kind: str) -> Token:
        if self.cur.kind != kind:
            raise ParserError(f"expected {kind}, got {self.cur.kind} at {self.cur.start}")
        tok = self.cur
        self.advance()
        return tok

    def take_ident(self) -> str:
        if self.cur.kind != "IDENT":
            raise ParserError(f"expected IDENT, got {self.cur.kind} at {self.cur.start}")
        v = self.cur.value
        self.advance()
        return v

    def take_scalar(self):
        if self.cur.kind in {"IDENT", "STRING", "INTEGER"}:
            val = self.cur.value
            self.advance()
            return val
        raise ParserError(f"expected scalar, got {self.cur.kind}")

    def take_symbolic(self) -> str:
        """
        Accept identifier-like tokens including reserved words, but reject
        punctuation and literal tokens.
        """
        if self.cur.kind in {
            "EOF",
            "INTEGER",
            "STRING",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            ",",
            ";",
            "=",
            ".",
        }:
            raise ParserError(f"expected identifier-like token, got {self.cur.kind} at {self.cur.start}")
        return self._consume_symbolic()

    def _consume_symbolic(self) -> str:
        value = self.cur.value if self.cur.kind == "IDENT" else self.cur.kind
        self.advance()
        return value

    def parse_program(self) -> Program:
        stmts = []
        while self.cur.kind != "EOF":
            stmts.append(self.parse_statement())
        return Program(stmts)

    def parse_statement(self):
        kind = self.cur.kind
        if kind == "vector":
            return self.parse_vector_decl()
        if kind == "wallet":
            return self.parse_wallet_decl()
        if kind == "certify":
            return self.parse_certify()
        if kind == "transfer":
            return self.parse_transfer()
        if kind == "drain":
            return self.parse_drain()
        if kind == "project":
            return self.parse_project()
        if kind == "reconstruct":
            return self.parse_reconstruct()
        if kind == "query":
            return self.parse_query()
        if kind == "record":
            return self.parse_record()
        if kind == "contract":
            return self.parse_contract()
        raise ParserError(f"unexpected token {kind} at {self.cur.start}")

    def parse_vector_decl(self):
        self.expect("vector")
        name = self.take_ident()
        self.expect(":")
        vector_type = self.take_ident()
        self.expect("=")
        self.expect("(")
        components = []
        if self.cur.kind != ")":
            components.append(self.expect("INTEGER").value)
            while self.cur.kind == ",":
                self.advance()
                components.append(self.expect("INTEGER").value)
        self.expect(")")
        self.expect(";")
        return VectorDecl(name, vector_type, [int(x) for x in components])

    def parse_wallet_decl(self):
        self.expect("wallet")
        name = self.take_ident()
        self.expect("=")
        self.expect("bind")
        self.expect("(")
        pk = self.take_scalar()
        self.expect(")")
        self.expect(";")
        return WalletDecl(name, pk)

    def parse_context(self):
        self.expect("ctx")
        self.expect("(")
        args = []
        if self.cur.kind != ")":
            args.append(self.parse_named_arg())
            while self.cur.kind == ",":
                self.advance()
                args.append(self.parse_named_arg())
        self.expect(")")
        return ContextExpr(args)

    def _is_named_arg_name_token(self) -> bool:
        """
        Accept any word-like token that can legally appear as a named argument key,
        including reserved words such as amount, policy, into, from, with, etc.
        """
        return self.cur.kind not in {
            "EOF",
            "INTEGER",
            "STRING",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            ",",
            ";",
            "=",
            ".",
        }

    def parse_named_arg(self):
        # Named arg form: <name> = <expr>
        # The name may be IDENT or a keyword token such as amount/policy/into/from.
        if self.cur.kind in {")", ",", "EOF"}:
            raise ParserError(f"expected named argument, got {self.cur.kind}")

        if (
            self.i + 1 < len(self.tokens)
            and self.tokens[self.i + 1].kind == "="
            and self._is_named_arg_name_token()
        ):
            name = self.cur.value if self.cur.kind == "IDENT" else self.cur.kind
            self.advance()
            self.expect("=")
            value = self.parse_expr()
            return NamedArg(name, value)

        return NamedArg(None, self.parse_expr())

    def parse_expr(self):
        if self.cur.kind == "INTEGER":
            v = int(self.cur.value)
            self.advance()
            return Expr("integer", v)

        if self.cur.kind == "STRING":
            v = self.cur.value
            self.advance()
            return Expr("string", v)

        # Any identifier-like token can begin a symbol/path/call.
        # This includes reserved words like vector, amount, policy, from, into, etc.
        if self.cur.kind not in {"INTEGER", "STRING", "(", ")", "EOF", ",", ";"}:
            value = self.take_symbolic()

            if self.cur.kind == "(":
                self.advance()
                args = []
                if self.cur.kind != ")":
                    args.append(self.parse_named_arg())
                    while self.cur.kind == ",":
                        self.advance()
                        args.append(self.parse_named_arg())
                self.expect(")")
                return Expr("call", {"callee": value, "args": args})

            parts = [value]
            while self.cur.kind == ".":
                self.advance()
                parts.append(self.take_symbolic())

            return Expr("path", parts if len(parts) > 1 else value)

        if self.cur.kind == "(":
            self.advance()
            inner = self.parse_expr()
            self.expect(")")
            return Expr("group", inner)

        raise ParserError(f"unexpected token in expression {self.cur.kind}")

    def parse_certify(self):
        self.expect("certify")
        target = self.take_ident()
        self.expect("with")
        context = self.parse_context()
        self.expect(";")
        return CertifyStmt(target, context)

    def parse_transfer(self):
        self.expect("transfer")
        source = self.take_ident()
        self.expect("to")
        destination = self.take_ident()
        self.expect("amount")
        amount = self.parse_expr()
        drain = None
        policy = None
        while self.cur.kind != ";":
            if self.cur.kind == "drain":
                self.advance()
                drain = self.parse_expr()
            elif self.cur.kind == "policy":
                self.advance()
                policy = self.parse_expr()
            else:
                raise ParserError(f"unexpected token {self.cur.kind} in transfer")
        self.expect(";")
        return TransferStmt(source, destination, amount, drain, policy)

    def parse_drain(self):
        self.expect("drain")
        target = self.take_ident()
        self.expect("by")
        amount = self.parse_expr()
        self.expect(";")
        return DrainStmt(target, amount)

    def parse_project(self):
        self.expect("project")
        source = self.take_ident()
        self.expect("into")
        environment = self.take_ident()
        self.expect("amount")
        amount = self.parse_expr()
        policy = None
        while self.cur.kind != ";":
            if self.cur.kind == "policy":
                self.advance()
                policy = self.parse_expr()
            else:
                raise ParserError(f"unexpected token {self.cur.kind} in project")
        self.expect(";")
        return ProjectStmt(source, environment, amount, policy)

    def parse_reconstruct(self):
        self.expect("reconstruct")
        target = self.take_ident()
        self.expect("from")
        projection_id = self.take_ident()
        self.expect(";")
        return ReconstructStmt(target, projection_id)

    def parse_query(self):
        self.expect("query")
        expr = self.parse_expr()
        self.expect(";")
        return QueryStmt(expr)

    def parse_record(self):
        self.expect("record")
        expr = self.parse_expr()
        self.expect(";")
        return RecordStmt(expr)

    def parse_contract(self):
        self.expect("contract")
        name = self.take_ident()
        self.expect("{")
        actions = []
        while self.cur.kind != "}":
            self.expect("action")
            action_name = self.take_ident()
            args = []
            if self.cur.kind == "(":
                self.advance()
                if self.cur.kind != ")":
                    args.append(self.parse_named_arg())
                    while self.cur.kind == ",":
                        self.advance()
                        args.append(self.parse_named_arg())
                self.expect(")")
            self.expect(";")
            actions.append(ContractAction(action_name, args))
        self.expect("}")
        return ContractDecl(name, actions)


def parse(source: str) -> Program:
    return Parser(source).parse_program()