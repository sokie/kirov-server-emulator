"""
Sake search filters: the SQL-like filter and targetRecordFilter strings of SearchForRecords.
"""

import re

_TOKEN = re.compile(
    r"\s*(?:(?P<num>-?\d+(?:\.\d+)?)|(?P<str>'(?:[^']|'')*'|\"[^\"]*\")|(?P<op><=|>=|<>|!=|==|=|<|>)"
    r"|(?P<punct>[(),])|(?P<name>[A-Za-z_][A-Za-z0-9_]*))"
)
_KEYWORDS = {"and", "or", "not", "in", "like", "is", "null"}


class FilterError(ValueError):
    pass


def _tokens(text: str):
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise FilterError(f"cannot read the filter at {text[pos:]!r}")
        pos = m.end()
        kind = m.lastgroup or ""
        value = m.group(kind)
        if kind == "str":
            value = value[1:-1].replace("''", "'")
        elif kind == "name" and value.lower() in _KEYWORDS:
            kind, value = "kw", value.lower()
        out.append((kind, value))
    return out


class _Parser:
    def __init__(self, tokens):
        self.t = tokens
        self.i = 0

    def peek(self, kind=None, value=None):
        if self.i >= len(self.t):
            return None
        tok = self.t[self.i]
        if (kind and tok[0] != kind) or (value and tok[1] != value):
            return None
        return tok

    def take(self, kind=None, value=None):
        tok = self.peek(kind, value)
        if tok is None:
            raise FilterError(f"expected {value or kind} in the filter")
        self.i += 1
        return tok

    def expr(self):
        left = self.conj()
        while self.peek("kw", "or"):
            self.i += 1
            right = self.conj()
            left = (lambda a, b: lambda get: a(get) or b(get))(left, right)
        return left

    def conj(self):
        left = self.neg()
        while self.peek("kw", "and"):
            self.i += 1
            right = self.neg()
            left = (lambda a, b: lambda get: a(get) and b(get))(left, right)
        return left

    def neg(self):
        if self.peek("kw", "not"):
            self.i += 1
            inner = self.neg()
            return lambda get: not inner(get)
        if self.peek("punct", "("):
            self.i += 1
            inner = self.expr()
            self.take("punct", ")")
            return inner
        return self.comparison()

    def value(self):
        tok = self.take()
        if tok[0] in ("num", "str", "name"):
            return tok[1]
        raise FilterError(f"unexpected {tok[1]!r} in the filter")

    def comparison(self):
        name = self.take("name")[1]
        if self.peek("kw", "is"):
            self.i += 1
            negate = bool(self.peek("kw", "not"))
            if negate:
                self.i += 1
            self.take("kw", "null")
            return lambda get: (get(name) is None) != negate
        negate = bool(self.peek("kw", "not"))
        if negate:
            self.i += 1
        if self.peek("kw", "in"):
            self.i += 1
            self.take("punct", "(")
            values = [self.value()]
            while self.peek("punct", ","):
                self.i += 1
                values.append(self.value())
            self.take("punct", ")")
            return lambda get: any(_compare(get(name), "=", v) for v in values) != negate
        if self.peek("kw", "like"):
            self.i += 1
            pattern = _like(self.value())
            return lambda get: (get(name) is not None and bool(pattern.fullmatch(str(get(name))))) != negate
        op = self.take("op")[1]
        value = self.value()
        return lambda get: _compare(get(name), op, value)


def _like(pattern: str):
    regex = "".join(".*" if c == "%" else "." if c == "_" else re.escape(c) for c in pattern)
    return re.compile(regex, re.IGNORECASE | re.DOTALL)


def _number(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


_OPS = {
    "=": lambda a, b: a == b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "<>": lambda a, b: a != b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
}


def _compare(left, op, right) -> bool:
    if left is None:
        return False
    a, b = _number(left), _number(right)
    if a is None or b is None:
        return bool(_OPS[op](str(left).lower(), str(right).lower()))
    return bool(_OPS[op](a, b))


def compile_filter(text: str):
    if not text or not text.strip():
        return None
    parser = _Parser(_tokens(text))
    predicate = parser.expr()
    if parser.i != len(parser.t):
        raise FilterError(f"unexpected {parser.t[parser.i][1]!r} in the filter")
    return predicate


def referenced_fields(text: str) -> set:
    try:
        return {v for k, v in _tokens(text) if k == "name"}
    except FilterError:
        return set()
