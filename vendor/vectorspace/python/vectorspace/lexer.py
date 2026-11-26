from dataclasses import dataclass

KEYWORDS = {
    "vector", "wallet", "bind", "certify", "transfer", "drain", "project",
    "reconstruct", "query", "record", "contract", "action", "with", "to",
    "amount", "by", "into", "from", "policy", "ctx"
}

@dataclass
class Token:
    kind: str
    value: str
    start: int
    end: int

def lex(source: str):
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch.isspace():
            i += 1
            continue
        if ch == '/' and i + 1 < n and source[i + 1] == '/':
            i += 2
            while i < n and source[i] != '\n':
                i += 1
            continue
        if ch == '#':
            i += 1
            while i < n and source[i] != '\n':
                i += 1
            continue
        start = i
        if ch in '(){}:;,.=':
            i += 1
            yield Token(ch, ch, start, i)
            continue
        if ch == '"':
            i += 1
            buf = []
            while i < n:
                c = source[i]
                if c == '"':
                    i += 1
                    break
                if c == '\\' and i + 1 < n:
                    i += 1
                    esc = source[i]
                    mapping = {'n': '\n', 'r': '\r', 't': '\t', '"': '"', '\\': '\\'}
                    buf.append(mapping.get(esc, esc))
                    i += 1
                    continue
                buf.append(c)
                i += 1
            yield Token("STRING", ''.join(buf), start, i)
            continue
        if ch.isdigit():
            while i < n and source[i].isdigit():
                i += 1
            yield Token("INTEGER", source[start:i], start, i)
            continue
        if ch.isalpha() or ch == '_':
            while i < n and (source[i].isalnum() or source[i] == '_'):
                i += 1
            text = source[start:i]
            yield Token(text if text in KEYWORDS else "IDENT", text, start, i)
            continue
        raise SyntaxError(f"unexpected character {ch!r} at {start}")
    yield Token("EOF", "", n, n)
