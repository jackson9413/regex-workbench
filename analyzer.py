"""Regex Workbench - static analyzer core (parsing, explanation, ReDoS, portability)."""
import re as _re
import random
import re

# ---------------------------------------------------------------- engine matrix

ENGINES = [
    ("python", "Python re", "3.11+"),
    ("js", "JavaScript RegExp", "ES2024"),
    ("java", "Java Pattern", "17+"),
    ("dotnet", ".NET Regex", "8"),
    ("pcre2", "PCRE2", "10.x"),
    ("go", "Go regexp (RE2)", "1.22"),
    ("posix", "POSIX ERE", "grep -E"),
    ("rust", "Rust regex", "1.8"),
]

# feature -> {engine: (status, note)}
# status: yes | partial | no | diff
FEATURES = {
    "lookahead": {"python": ("yes", ""), "js": ("yes", ""), "java": ("yes", ""), "dotnet": ("yes", ""),
                  "pcre2": ("yes", ""), "go": ("yes", "only non-capturing lookarounds"), "posix": ("no", ""),
                  "rust": ("no", "")},
    "lookbehind": {"python": ("partial", "fixed width only"), "js": ("partial", "V8 only, finite"),
                   "java": ("partial", "bounded length, no \\s inside"), "dotnet": ("yes", ""),
                   "pcre2": ("yes", "alternatives must be fixed length"), "go": ("no", ""),
                   "posix": ("no", ""), "rust": ("no", "")},
    "backref": {"python": ("yes", ""), "js": ("yes", ""), "java": ("yes", ""), "dotnet": ("yes", ""),
                "pcre2": ("yes", ""), "go": ("no", "RE2 forbids all backreferences"),
                "posix": ("no", ""), "rust": ("no", "")},
    "named_group": {"python": ("yes", "(?<n>) accepted since 3.12; (?P<n>) is the portable form"),
                    "js": ("yes", ""), "java": ("yes", ""), "dotnet": ("yes", ""), "pcre2": ("yes", ""),
                    "go": ("yes", ""), "posix": ("no", ""), "rust": ("yes", "")},
    "named_group_py": {"python": ("yes", ""), "js": ("no", "use (?<name>)"), "java": ("no", "use (?<name>)"),
                       "dotnet": ("no", "use (?<name>)"), "pcre2": ("yes", ""), "go": ("yes", ""),
                       "posix": ("no", ""), "rust": ("no", "use (?<name>)")},
    "atomic_group": {"python": ("yes", "3.11+"), "js": ("no", ""), "java": ("no", ""), "dotnet": ("no", ""),
                     "pcre2": ("yes", ""), "go": ("no", ""), "posix": ("no", ""), "rust": ("no", "")},
    "possessive": {"python": ("yes", "3.11+"), "js": ("no", ""), "java": ("no", ""), "dotnet": ("no", ""),
                   "pcre2": ("yes", ""), "go": ("no", ""), "posix": ("no", ""), "rust": ("no", "")},
    "inline_flags": {"python": ("partial", "(?i) allowed only at pattern start in 3.11"),
                     "js": ("no", "no inline flags at all"), "java": ("yes", "at pattern start"),
                     "dotnet": ("no", "pass RegexOptions.IgnoreCase"), "pcre2": ("yes", ""),
                     "go": ("yes", ""), "posix": ("no", ""), "rust": ("yes", "as (?-u) style modifier")},
    "scoped_flags": {"python": ("yes", "(?i:...)"), "js": ("no", ""), "java": ("no", ""),
                     "dotnet": ("no", ""), "pcre2": ("yes", ""), "go": ("yes", ""), "posix": ("no", ""),
                     "rust": ("yes", "")},
    "comment_group": {"python": ("yes", ""), "js": ("no", ""), "java": ("no", ""), "dotnet": ("no", ""),
                      "pcre2": ("yes", ""), "go": ("no", ""), "posix": ("no", ""), "rust": ("no", "")},
    "conditional": {"python": ("no", "stdlib re lacks (?(1)yes|no); the regex module has it"),
                    "js": ("no", ""), "java": ("no", ""), "dotnet": ("yes", ""), "pcre2": ("yes", ""),
                    "go": ("no", ""), "posix": ("no", ""), "rust": ("no", "")},
    "posix_class": {"python": ("yes", ""), "js": ("no", "JS has \\d \\w \\s only"), "java": ("no", ""),
                    "dotnet": ("no", ""), "pcre2": ("yes", ""), "go": ("no", ""), "posix": ("yes", ""),
                    "rust": ("no", "")},
    "unicode_prop": {"python": ("no", "no \\p{} in stdlib re"), "js": ("yes", "needs the u flag"),
                     "java": ("yes", ""), "dotnet": ("yes", ""), "pcre2": ("yes", ""), "go": ("no", ""),
                     "posix": ("no", ""), "rust": ("no", "")},
    "unicode_escape_braces": {"python": ("no", "use \\UXXXXXXXX"), "js": ("no", "use \\u{...}"),
                              "java": ("no", ""), "dotnet": ("no", ""), "pcre2": ("yes", "\\x{...}"),
                              "go": ("no", ""), "posix": ("no", ""), "rust": ("no", "")},
    "quote_escape": {"python": ("no", ""), "js": ("no", ""), "java": ("no", ""), "dotnet": ("no", ""),
                     "pcre2": ("yes", "\\Q...\\E"), "go": ("no", ""), "posix": ("no", ""), "rust": ("no", "")},
    "recursion": {"python": ("no", ""), "js": ("no", ""), "java": ("no", ""), "dotnet": ("yes", "(?1)"),
                  "pcre2": ("yes", "(?1) / (?R)"), "go": ("no", ""), "posix": ("no", ""), "rust": ("no", "")},
    "callout": {"python": ("no", ""), "js": ("no", ""), "java": ("no", ""), "dotnet": ("no", ""),
                "pcre2": ("yes", "(*FAIL) etc"), "go": ("no", ""), "posix": ("no", ""), "rust": ("no", "")},
    "dollar_end": {"python": ("diff", "$ also matches just before a trailing \\n"), "js": ("diff", "$ is end of input unless m is set"),
                   "java": ("diff", "$ is end of input, \\n included"), "dotnet": ("diff", "$ matches before a trailing \\n"),
                   "pcre2": ("diff", "$ matches before a final newline by default"), "go": ("diff", "$ is \\z (end of text)"),
                   "posix": ("diff", "$ is end of line"), "rust": ("diff", "no \\z; use (?-s).$ - careful")},
    "word_boundary": {"python": ("diff", "\\b is Unicode aware"), "js": ("diff", "\\b is ASCII only unless u"),
                      "java": ("yes", "ASCII"), "dotnet": ("diff", "\\b is Unicode aware"),
                      "pcre2": ("diff", "ASCII unless UCP"), "go": ("diff", "ASCII \\b"),
                      "posix": ("no", "no word boundary operator"), "rust": ("yes", "Unicode by default")},
    "anchors_a_z": {"python": ("yes", ""), "js": ("no", "no \\A \\z in JS"), "java": ("no", ""),
                    "dotnet": ("yes", ""), "pcre2": ("yes", ""), "go": ("yes", ""), "posix": ("no", ""),
                    "rust": ("yes", "(\\A) is \\A; \\z supported")},
    "digit_unicode": {"python": ("diff", "\\d matches Unicode digits, not just 0-9"),
                      "js": ("diff", "\\d is [0-9]"), "java": ("diff", "\\d is [0-9] by default"),
                      "dotnet": ("diff", "\\d is Unicode aware"), "pcre2": ("diff", "ASCII unless UCP"),
                      "go": ("diff", "\\d is [0-9]"), "posix": ("no", ""), "rust": ("diff", "Unicode by default")},
}

FLAG_MAP = {
    "python": ["re.I", "re.M", "re.S", "re.X", "re.A"],
    "js": ["i", "m", "s", None, None],
    "java": ["CASE_INSENSITIVE", "MULTILINE", "DOTALL", "COMMENTS", None],
    "dotnet": ["IgnoreCase", "Multiline", "Singleline", "IgnorePatternWhitespace", None],
    "pcre2": ["i", "m", "s", "x", None],
    "go": ["(?i)", "(?m)", "(?s)", None, None],
    "posix": [None, None, None, None, None],
    "rust": ["(?i)", "(?m)", "(?s)", "(?x)", None],
}
FLAG_ORDER = ["i", "m", "s", "x", "a"]
FLAG_LABEL = {
    "i": "ignore case", "m": "multiline (^ and $ match at line breaks)",
    "s": "dot matches newline", "x": "verbose / ignore whitespace",
    "a": "ASCII only (\\w \\d \\b become ASCII)",
}
PY_FLAGS = {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A}

SYNTAX = {
    "literal": "a literal character",
    "dot": "any character except newline",
    "class": "a character class",
    "escape": "an escape sequence",
    "anchor": "an anchor",
    "zero_width": "a zero-width assertion",
    "backref": "a backreference",
    "group": "a group",
    "alt": "an alternation",
    "seq": "a sequence",
    "repeat": "a repetition",
    "flags": "inline flag settings",
}


# ---------------------------------------------------------------- AST + parser

CHAR_CLASSES = {
    "d": "any digit (0-9 unless Unicode mode is on)",
    "D": "any character that is NOT a digit",
    "w": "any word character (letters, digits, underscore)",
    "W": "any character that is NOT a word character",
    "s": "any whitespace (space, tab, newline...)",
    "S": "any character that is NOT whitespace",
}
POSIX = {"alpha", "digit", "alnum", "space", "upper", "lower", "punct", "word", "xdigit", "blank", "cntrl", "print", "graph"}


class Node:
    __slots__ = ("kind", "value", "children", "start", "end", "flags")

    def __init__(self, kind, value=None, start=0, end=0, flags=""):
        self.kind = kind
        self.value = value
        self.children = []
        self.start = start
        self.end = end
        self.flags = flags

    def add(self, child):
        self.children.append(child)
        return child

    def to_dict(self):
        d = {"kind": self.kind, "value": self.value, "start": self.start, "end": self.end}
        if self.flags:
            d["flags"] = self.flags
        if self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d

    def __repr__(self):
        return "Node(%s,%r,%d)" % (self.kind, self.value, len(self.children))


class ParseError(Exception):
    pass


class RegexParser:
    """Recursive-descent parser for the common regex grammar. Never executes."""

    def __init__(self, pattern):
        self.s = pattern
        self.i = 0
        self.n = len(pattern)
        self.group_count = 0
        self.named = {}

    def error(self, msg):
        raise ParseError("%s at position %d" % (msg, self.i))

    def peek(self, off=0):
        j = self.i + off
        return self.s[j] if j < self.n else ""

    def parse(self):
        node = self.parse_alt()
        if self.i < self.n:
            raise ParseError("unexpected %r at position %d" % (self.s[self.i], self.i))
        return node

    def parse_alt(self):
        start = self.i
        branches = [self.parse_seq()]
        while self.peek() == "|":
            self.i += 1
            branches.append(self.parse_seq())
        if len(branches) == 1:
            return branches[0]
        n = Node("alt", None, start, self.i)
        n.children = branches
        return n

    def parse_seq(self):
        start = self.i
        items = []
        while self.i < self.n and self.peek() not in "|)":
            items.append(self.parse_quantified())
        if not items:
            return Node("empty", None, start, start)
        if len(items) == 1:
            return items[0]
        n = Node("seq", None, start, self.i)
        n.children = items
        return n

    def parse_quantified(self):
        atom = self.parse_atom()
        while True:
            start = atom.start
            c = self.peek()
            if c == "*":
                lo, hi = 0, None
                self.i += 1
            elif c == "+":
                lo, hi = 1, None
                self.i += 1
            elif c == "?":
                lo, hi = 0, 1
                self.i += 1
            elif c == "{":
                m = re.compile(r"\{(\d*)(,?)(\d*)\}").match(self.s, self.i)
                if not m or (not m.group(1) and not m.group(3)):
                    break
                lo = int(m.group(1) or 0)
                hi = lo if not m.group(2) else (int(m.group(3)) if m.group(3) else None)
                self.i = m.end()
            else:
                break
            mod = ""
            if self.peek() in ("?", "+"):
                mod = self.peek()
                self.i += 1
            rep = Node("repeat", (lo, hi), start, self.i, flags=mod)
            rep.children = [atom]
            atom = rep
            if hi is not None and hi <= lo:
                break
        return atom

    def parse_atom(self):
        start = self.i
        c = self.peek()
        if c == "(":
            return self.parse_group()
        if c == "[":
            return self.parse_class()
        if c == ".":
            self.i += 1
            return Node("dot", None, start, self.i)
        if c == "^":
            self.i += 1
            return Node("anchor", "^", start, self.i)
        if c == "$":
            self.i += 1
            return Node("anchor", "$", start, self.i)
        if c == "\\":
            return self.parse_escape()
        if c in "*+?":
            self.error("nothing to repeat")
        if c == "]":
            self.i += 1
            return Node("literal", "]", start, self.i)
        self.i += 1
        return Node("literal", c, start, self.i)

    def parse_group(self):
        start = self.i
        self.i += 1
        kind = "capture"
        name = None
        if self.peek() == "?":
            nxt = self.peek(1)
            if nxt == ":":
                kind, self.i = "noncapture", self.i + 2
            elif nxt == "=":
                kind, self.i = "lookahead", self.i + 2
            elif nxt == "!":
                kind, self.i = "neglookahead", self.i + 2
            elif nxt == "<" and self.peek(2) in ("=", "!"):
                kind = "lookbehind" if nxt and self.peek(2) == "=" else "neglookbehind"
                self.i += 3
            elif nxt == "<":
                m = re.compile(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>").match(self.s, self.i - 1)
                if not m:
                    raise ParseError("bad named group at position %d" % self.i)
                kind, name, self.i = "named", m.group(1), m.end()
            elif nxt == "P":
                if self.peek(2) == "<":
                    m = re.compile(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>").match(self.s, self.i - 1)
                    if not m:
                        raise ParseError("bad named group at position %d" % self.i)
                    kind, name, self.i = "named_py", m.group(1), m.end()
                elif self.peek(2) == "=":
                    m = re.compile(r"\(\?P=([A-Za-z_][A-Za-z0-9_]*)\)").match(self.s, self.i - 1)
                    if not m:
                        raise ParseError("bad named backreference at position %d" % self.i)
                    n = Node("backref_named", m.group(1), start, m.end())
                    self.i = m.end()
                    return n
            elif nxt == ">":
                kind, self.i = "atomic", self.i + 2
            elif nxt == "#":
                j = self.s.find(")", self.i)
                if j < 0:
                    raise ParseError("unterminated comment group")
                self.i = j + 1
                return Node("comment", None, start, self.i)
            elif nxt in "imsxaU-":
                j = self.i + 1
                fl = ""
                while j < self.n and self.s[j] in "imsxaU-":
                    fl += self.s[j]
                    j += 1
                if j < self.n and self.s[j] == ")":
                    self.i = j + 1
                    return Node("flags", fl, start, self.i)
                if j < self.n and self.s[j] == ":":
                    self.i = j + 1
                    body = self.parse_alt()
                    if self.peek() != ")":
                        self.error("unterminated flag group")
                    self.i += 1
                    g = Node("group", "scoped_flags", start, self.i, flags=fl)
                    g.children = [body]
                    return g
            elif nxt == "(":
                raise ParseError("conditional groups (?(1)yes|no) are not supported by Python re "
                                 "- use PCRE2, .NET, or the third-party regex module")
            else:
                raise ParseError("unknown group type (?%s at position %d" % (nxt, self.i))
        self.group_count += 1
        idx = self.group_count
        if name:
            if name in self.named:
                raise ParseError("duplicate group name %r" % name)
            self.named[name] = idx
        g = Node("group", kind if kind != "capture" else idx, start, self.i)
        if name:
            g.flags = name
        g.children = [self.parse_alt()]
        if self.peek() != ")":
            self.error("unterminated group (missing close paren)")
        self.i += 1
        g.end = self.i
        return g

    def parse_class(self):
        start = self.i
        self.i += 1
        negated = False
        if self.peek() == "^":
            negated = True
            self.i += 1
        items = []
        first = True
        while True:
            if self.i >= self.n:
                raise ParseError("unterminated character class")
            c = self.peek()
            if c == "]" and not first:
                self.i += 1
                break
            first = False
            if c == "[" and self.peek(1) == ":":
                m = re.compile(r"\[:(\^?)([a-z]+):\]").match(self.s, self.i)
                if m:
                    name = m.group(2)
                    if name not in POSIX:
                        raise ParseError("unknown POSIX class [:%s:]" % name)
                    items.append({"t": "posix", "name": name, "neg": bool(m.group(1))})
                    self.i = m.end()
                    continue
            if c == "\\":
                esc = self.read_class_escape()
                if esc.get("rangeable") and self.peek() == "-" and self.peek(1) not in ("]", ""):
                    hi_start = self.i + 1
                    save = self.i
                    self.i += 1
                    if self.peek() == "\\":
                        hi = self.read_class_escape()
                    else:
                        hi = {"t": "char", "c": self.peek()}
                        self.i += 1
                    if hi.get("rangeable"):
                        items.append({"t": "range", "a": esc["c"], "b": hi["c"], "_s": esc["_s"], "_e": hi["_e"]})
                        continue
                    self.i = save
                    items.append(esc)
                    continue
                items.append(esc)
                continue
            if c == "-" and self.peek(1) not in ("]", ""):
                if items and items[-1].get("t") in ("char", "range_end"):
                    pass
                self.i += 1
                items.append({"t": "char", "c": "-"})
                continue
            self.i += 1
            items.append({"t": "char", "c": c, "_s": start, "_e": self.i})
        return Node("class", items, start, self.i, flags="neg" if negated else "")

    def read_class_escape(self):
        start = self.i
        self.i += 1
        if self.i >= self.n:
            raise ParseError("trailing backslash")
        c = self.s[self.i]
        self.i += 1
        if c in CHAR_CLASSES:
            return {"t": "esc_class", "c": c, "_s": start, "_e": self.i, "rangeable": False}
        return {"t": "char", "c": chr(_escape_value(self.s, c, start)), "_s": start, "_e": self.i,
                "rangeable": True, "raw": "\\" + c}

    def parse_escape(self):
        start = self.i
        self.i += 1
        if self.i >= self.n:
            raise ParseError("pattern ends with a dangling backslash")
        c = self.s[self.i]
        self.i += 1
        if c in CHAR_CLASSES:
            return Node("esc_class", c, start, self.i)
        if c in "bBAZzG":
            return Node("zero_width", "\\" + c, start, self.i)
        if c.isdigit() and c != "0":
            j = self.i
            while j < self.n and self.s[j].isdigit():
                j += 1
            num = c + self.s[self.i:j]
            self.i = j
            return Node("backref_num", int(num), start, self.i)
        if c == "k" and self.peek() in ("<", "'", "{"):
            close = {"<": ">", "'": "'", "{": "}"}[self.peek()]
            j = self.s.find(close, self.i + 1)
            if j < 0:
                raise ParseError("unterminated named backreference")
            name = self.s[self.i + 1:j]
            self.i = j + 1
            return Node("backref_named", name, start, self.i)
        if c == "Q":
            j = self.s.find("\\E", self.i)
            if j < 0:
                body = self.s[self.i:]
                self.i = self.n
            else:
                body = self.s[self.i:j]
                self.i = j + 2
            return Node("quote", body, start, self.i)
        val = _escape_value(self.s, c, start)
        return Node("esc_char", chr(val), start, self.i, flags="\\" + c)


def _escape_value(s, c, pos):
    simple = {"n": 10, "t": 9, "r": 13, "f": 12, "v": 11, "a": 7, "0": 0, "e": 27}
    if c in simple:
        return simple[c]
    if c == "x":
        m = re.compile(r"\\x([0-9A-Fa-f]{2})").match(s, pos - 1)
        if m:
            return int(m.group(1), 16)
        raise ParseError("bad \\x escape at position %d" % pos)
    if c == "u":
        m = re.compile(r"\\u([0-9A-Fa-f]{4})").match(s, pos - 1)
        if m:
            return int(m.group(1), 16)
        m2 = re.compile(r"\\u\{([0-9A-Fa-f]+)\}").match(s, pos - 1)
        if m2:
            return int(m2.group(1), 16)
        raise ParseError("bad \\u escape at position %d" % pos)
    if c == "U":
        m = re.compile(r"\\U([0-9A-Fa-f]{8})").match(s, pos - 1)
        if m:
            return int(m.group(1), 16)
        raise ParseError("bad \\U escape at position %d" % pos)
    if c == "N":
        m = re.compile(r"\\N\{([^}]*)\}").match(s, pos - 1)
        if m:
            try:
                import unicodedata
                return ord(unicodedata.lookup(m.group(1)))
            except Exception:
                raise ParseError("unknown \\N{...} name at position %d" % pos)
        raise ParseError("bad \\N escape at position %d" % pos)
    if c == "p" or c == "P":
        raise ParseError("unicode property \\p{%s} is not supported by Python re (position %d)" % (s[pos:pos + 12], pos))
    if c == "R":
        raise ParseError("\\R (any linebreak) is not supported by Python re (position %d)" % pos)
    return ord(c)


# ---------------------------------------------------------------- ReDoS

def _nullable(node):
    if node.kind in ("dot", "literal", "esc_class", "esc_char", "class", "backref_num", "backref_named"):
        return False
    if node.kind in ("empty", "anchor", "zero_width"):
        return True
    if node.kind == "repeat":
        lo = node.value[0]
        return lo == 0 or _nullable(node.children[0])
    if node.kind == "seq":
        return all(_nullable(c) for c in node.children)
    if node.kind == "alt":
        return any(_nullable(c) for c in node.children)
    if node.kind == "group":
        k = node.value
        if k in ("lookahead", "neglookahead", "lookbehind", "neglookbehind"):
            return True
        return _nullable(node.children[0]) if node.children else True
    return False


def _first_set(node):
    """Approximate set of characters (or class markers) a node can start with."""
    if node.kind == "literal":
        return {node.value}
    if node.kind == "esc_char":
        return {node.value}
    if node.kind == "dot":
        return {"ANY"}
    if node.kind == "esc_class":
        return {"CLS:" + node.value}
    if node.kind == "class":
        out = set()
        for it in node.value:
            if it["t"] == "char":
                out.add(it["c"])
            elif it["t"] == "esc_class":
                out.add("CLS:" + it["c"])
            elif it["t"] == "posix":
                out.add("POSIX:" + it["name"])
            elif it["t"] == "range":
                if len(it["a"]) == 1 and len(it["b"]) == 1:
                    for o in range(ord(it["a"]), min(ord(it["b"]), ord(it["a"]) + 128) + 1):
                        out.add(chr(o))
                else:
                    out.add("ANY")
        return out or {"ANY"}
    if node.kind in ("seq", "alt"):
        out = set()
        for c in node.children:
            out |= _first_set(c)
            if node.kind == "seq" and not _nullable(c):
                break
        return out
    if node.kind == "repeat":
        return _first_set(node.children[0])
    if node.kind == "group":
        return _first_set(node.children[0]) if node.children else set()
    if node.kind == "empty":
        return set()
    return {"ANY"}


def _overlapping(a, b):
    if not a or not b:
        return True
    if "ANY" in a or "ANY" in b:
        return True
    for x in a:
        for y in b:
            if x == y:
                return True
            if x.startswith("CLS:") or y.startswith("CLS:"):
                cx = x[4:] if x.startswith("CLS:") else None
                cy = y[4:] if y.startswith("CLS:") else None
                if cx and cy:
                    compatible = {
                        frozenset("dw"), frozenset("dW"), frozenset("Ws"),
                        frozenset("wD"), frozenset("Ws"), frozenset("sW"),
                        frozenset("wS"), frozenset("Ds"), frozenset("sD"),
                        frozenset("dS"), frozenset("Ws"), frozenset("sw"),
                        frozenset("SW"), frozenset("SD"), frozenset("sW"),
                    }
                    if cx != cy or cx in ("d", "w", "s"):
                        return True
                elif cx or cy:
                    if (cx or cy) in ("d", "w", "s"):
                        return True
            if x.startswith("POSIX:") or y.startswith("POSIX:"):
                return True
    return False


def _pump(node, depth=0):
    """Find a single character an attacker string can be built from, or None."""
    if depth > 6:
        return None
    if node.kind in ("literal", "esc_char"):
        return node.value
    if node.kind == "dot":
        return "a"
    if node.kind == "esc_class":
        return {"d": "1", "D": "a", "w": "a", "W": "!", "s": " ", "S": "a"}.get(node.value, "a")
    if node.kind == "class":
        for it in node.value:
            if it["t"] == "char":
                return it["c"]
            if it["t"] == "esc_class":
                return {"d": "1", "D": "a", "w": "a", "W": "!", "s": " ", "S": "a"}.get(it["c"], "a")
            if it["t"] == "range":
                return it["a"]
        return "a"
    if node.kind in ("seq", "alt"):
        for c in node.children:
            got = _pump(c, depth + 1)
            if got:
                return got
        return None
    if node.kind in ("repeat", "group"):
        if node.children:
            return _pump(node.children[0], depth + 1)
        return None
    return None


def find_redos(root, pattern):
    findings = []
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        if n.kind != "repeat":
            continue
        lo, hi = n.value
        if hi == 0:
            continue
        body = n.children[0]
        unbounded = hi is None or hi >= 2
        # classic (a+)+ / (a*)* / (a+)* / (a*)+
        nested = False
        for d in stack_inner(body):
            if d.kind == "repeat" and (d.value[1] is None or d.value[1] >= 2):
                nested = True
        if nested and unbounded:
            pump = _pump(body) or "a"
            critical = hi is None
            findings.append({
                "severity": "critical" if critical else "medium",
                "kind": "nested_quantifier",
                "where": [n.start, n.end],
                "snippet": pattern[max(0, n.start - 12):n.end + 4],
                "attack": pump * 20 + "!",
                "title": "Nested unbounded quantifier" if critical else "Nested quantifier (outer repeat is bounded)",
                "why": ("A quantifier inside another unbounded quantifier lets the engine try every way to split the same input between them. On a non-matching string that is exponential, not linear."
                        if critical else
                        "The outer repeat is bounded so the blowup is capped, but each outer pass still re-scans the inner repeat, so cost grows quickly with input length."),
                "fix": "Collapse to a single quantifier (e.g. (ab+)+ -> (ab)+), use a possessive/atomic group (?>...), or make the outer bound finite.",
            })
        # nullable body under unbounded quantifier: (a?)* style
        if _nullable(body) and unbounded and hi is None:
            pump = _pump(body) or "a"
            findings.append({
                "severity": "high",
                "kind": "nullable_loop",
                "where": [n.start, n.end],
                "snippet": pattern[max(0, n.start - 12):n.end + 4],
                "attack": pump * 16 + "!",
                "title": "Quantifier that can match empty",
                "why": "The repeated expression can match the empty string, so the engine retries the same position endlessly (or until the recursion guard fires) on every attempt.",
                "fix": "Require at least one repetition, or wrap the body in an atomic group so the empty match is committed once.",
            })
    # ambiguous alternation inside an unbounded repeat, with or without a capturing group
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        if n.kind != "repeat" or n.value[1] is not None:
            continue
        body = n.children[0]
        while body.kind == "group" and body.children and (isinstance(body.value, int) or body.value in ("noncapture", "atomic", "scoped_flags")):
            body = body.children[0]
        if body.kind != "alt":
            continue
        sets = [_first_set(b) for b in body.children]
        if len(sets) < 2:
            continue
        if any(_overlapping(sets[a], sets[b]) for a in range(len(sets)) for b in range(a + 1, len(sets))):
            pumped = _pump(body) or "a"
            findings.append({
                "severity": "high",
                "kind": "ambiguous_alternation",
                "where": [n.start, n.end],
                "snippet": pattern[max(0, n.start - 12):n.end + 4],
                "attack": pumped * 18 + "!",
                "title": "Ambiguous alternation under a quantifier",
                "why": "The repeated group offers branches that start with the same characters, so every character can be split between them more than one way. On a non-matching tail that is exponential.",
                "fix": "Make the branches disjoint (ab*|c instead of a|ab), order the longer branch first, or pull the shared prefix out: (?:a(?:b)?)+.",
            })

    # ambiguous alternation under a quantifier: (a|a)+ / (a|ab)+
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        if n.kind == "group" and n.value in ("capture",) and n.children:
            inner = n.children[0]
            if inner.kind == "alt" and inner.children:
                sets = [_first_set(b) for b in inner.children]
                dup = False
                for a in range(len(sets)):
                    for b in range(a + 1, len(sets)):
                        if _overlapping(sets[a], sets[b]):
                            dup = True
                if dup:
                    pumped = _pump(inner) or "a"
                    findings.append({
                        "severity": "high",
                        "kind": "ambiguous_alternation",
                        "where": [n.start, n.end],
                        "snippet": pattern[max(0, n.start - 12):n.end + 4],
                        "attack": pumped * 18 + "!",
                        "title": "Ambiguous alternation",
                        "why": "Two branches can start with the same characters, so the engine cannot decide which branch to take without backtracking.",
                        "fix": "Make branches disjoint ([ab] instead of (a|b)), or order them so a longer branch comes first and anchor the tail.",
                    })
    # catastrophic timing check against the real engine
    return findings


def stack_inner(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


PROBE_CODE = (
    "import re,time,json,sys\n"
    "p=json.load(sys.stdin)\n"
    "rx=re.compile(p['pattern'], p['flags'])\n"
    "t=time.time()\n"
    "rx.search(p['attack'])\n"
    "print(json.dumps({'t': time.time()-t}))\n"
)


def _time_match(rx, s, budget=1.0):
    """Run one search in a throwaway process so a catastrophic pattern cannot hang the server."""
    import json as _json
    import subprocess as _sp
    import sys as _sys
    payload = _json.dumps({"pattern": rx.pattern, "flags": rx.flags & ~_re.UNICODE, "attack": s})
    try:
        proc = _sp.run([_sys.executable, "-c", PROBE_CODE], input=payload, text=True,
                       capture_output=True, timeout=budget)
    except _sp.TimeoutExpired:
        return "timeout"
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    try:
        return round(float(_json.loads(proc.stdout.strip().splitlines()[-1])["t"]), 6)
    except Exception:
        return None


# ---------------------------------------------------------------- explain

def _exp_count(node):
    return {"dot": 1, "literal": 1, "esc_class": 1, "esc_char": 1,
            "class": 1, "empty": 0, "anchor": 0, "zero_width": 0,
            "backref_num": 1, "backref_named": 1, "quote": len(node.value or "")}.get(node.kind, 0)


def explain(node, pattern, depth=0):
    """Turn an AST node into a readable list of {text, kind, note, pos}."""
    out = []
    k = node.kind
    if k == "literal":
        ch = node.value
        if ch.isprintable():
            shown = repr(ch)
        else:
            shown = "'%s'" % ch
        out.append({"text": ch, "shown": shown, "kind": "literal", "pos": node.start,
                    "note": "matches the literal character %s" % shown})
    elif k == "dot":
        out.append({"text": ".", "shown": ".", "kind": "dot", "pos": node.start,
                    "note": "any character except newline (use the s flag to include newline)"})
    elif k == "esc_class":
        out.append({"text": "\\" + node.value, "shown": "\\" + node.value, "kind": "class",
                    "pos": node.start, "note": CHAR_CLASSES[node.value]})
    elif k == "esc_char":
        raw = node.flags or ("\\" + node.value)
        out.append({"text": raw, "shown": raw, "kind": "escape", "pos": node.start,
                    "note": "escape for %s" % _pretty_char(node.value)})
    elif k == "class":
        items = node.value or []
        parts = []
        for it in items:
            if it["t"] == "char":
                parts.append(it["c"] if it["c"].isprintable() else repr(it["c"]))
            elif it["t"] == "range":
                parts.append("%s-%s" % (it["a"], it["b"]))
            elif it["t"] == "esc_class":
                parts.append("\\" + it["c"])
            elif it["t"] == "posix":
                parts.append("[:%s%s:]" % ("^" if it["neg"] else "", it["name"]))
        body = "".join(parts)
        neg = " not" if node.flags == "neg" else ""
        out.append({"text": pattern[node.start:node.end], "shown": pattern[node.start:node.end],
                    "kind": "class", "pos": node.start,
                    "note": "one character from the set {%s}%s" % (body, neg)})
    elif k == "anchor":
        note = "start of the string (or line, with the m flag)" if node.value == "^" else \
               "end of the string (or line, with the m flag)"
        out.append({"text": node.value, "shown": node.value, "kind": "anchor", "pos": node.start, "note": note})
    elif k == "zero_width":
        out.append({"text": node.value, "shown": node.value, "kind": "zero_width", "pos": node.start,
                    "note": {"\\b": "a word boundary (transition between word and non-word characters)",
                             "\\B": "not a word boundary",
                             "\\A": "start of the string",
                             "\\Z": "end of the string, allowing a final newline",
                             "\\z": "end of the string",
                             "\\G": "end of the previous match"}.get(node.value, "zero-width assertion")})
    elif k == "backref_num":
        out.append({"text": "\\" + str(node.value), "shown": "\\" + str(node.value), "kind": "backref",
                    "pos": node.start, "note": "must match the exact text captured by group %d" % node.value})
    elif k == "backref_named":
        out.append({"text": "\\k<%s>" % node.value, "shown": "\\k<%s>" % node.value, "kind": "backref",
                    "pos": node.start, "note": "must match the text captured by the group named %r" % node.value})
    elif k == "empty":
        out.append({"text": "", "shown": "(empty)", "kind": "empty", "pos": node.start,
                    "note": "matches the empty string"})
    elif k == "quote":
        out.append({"text": pattern[node.start:node.end], "shown": pattern[node.start:node.end],
                    "kind": "quote", "pos": node.start,
                    "note": "literal text block, with every metacharacter treated as a normal character"})
    elif k == "comment":
        out.append({"text": pattern[node.start:node.end], "shown": pattern[node.start:node.end],
                    "kind": "comment", "pos": node.start, "note": "comment, ignored by the engine"})
    elif k == "flags":
        on = [f for f in node.value if f != "-"]
        off = []
        j = 0
        for f in node.value:
            if f == "-":
                off = []
                continue
            if j > 0 and False:
                pass
            j += 1
        letters = "".join(sorted(set(on)))
        out.append({"text": pattern[node.start:node.end], "shown": pattern[node.start:node.end],
                    "kind": "flags", "pos": node.start,
                    "note": "turn on %s for the rest of the pattern" % ", ".join(
                        FLAG_LABEL.get(f, f) for f in letters) if letters else "toggle flags"})
    elif k == "repeat":
        lo, hi = node.value
        inner = explain(node.children[0], pattern, depth + 1)
        if hi is None:
            q = "%d or more times" % lo if lo > 0 else "zero or more times"
        elif hi == 0:
            q = "never matches"
        elif lo == hi:
            q = "exactly %d time%s" % (lo, "" if lo == 1 else "s")
        elif lo == 0:
            q = "between 0 and %d times" % hi
        else:
            q = "between %d and %d times" % (lo, hi)
        greedy = {"": "greedy (takes as much as possible)", "?": "lazy (takes as little as possible)",
                  "+": "possessive (takes as much as possible and never gives it back)"}[node.flags]
        head = {"text": pattern[node.start:node.end], "shown": pattern[node.start:node.end],
                "kind": "repeat", "pos": node.start,
                "note": "repeat the previous item %s, %s" % (q, greedy)}
        out.append(head)
        out.extend(inner)
        return out
    elif k == "group":
        v = node.value
        inner = []
        for c in node.children:
            inner.extend(explain(c, pattern, depth + 1))
        if isinstance(v, int):
            note = "capture group %d: remembers what it matched so you can pull it out by index" % v
            kind = "group_capture"
        elif v == "named":
            note = "named capture group %r: readable instead of index 1, 2, 3..." % node.flags
            kind = "group_capture"
        elif v == "named_py":
            note = "named capture group %r written in Python style" % node.flags
            kind = "group_capture"
        elif v == "noncapture":
            note = "grouping only (no capture), used to apply a quantifier or alternation to several items"
            kind = "group_plain"
        elif v == "atomic":
            note = "atomic group: once a match is found inside, the engine never backtracks into it"
            kind = "group_plain"
        elif v == "lookahead":
            note = "lookahead: the text ahead must match this, but it is not consumed"
            kind = "group_assert"
        elif v == "neglookahead":
            note = "negative lookahead: the text ahead must NOT match this"
            kind = "group_assert"
        elif v == "lookbehind":
            note = "lookbehind: the text behind must match this, but it is not consumed"
            kind = "group_assert"
        elif v == "neglookbehind":
            note = "negative lookbehind: the text behind must NOT match this"
            kind = "group_assert"
        elif v == "conditional":
            note = "conditional: match the first branch if the group matched, the second branch otherwise"
            kind = "group_plain"
        else:
            note = "group"
            kind = "group_plain"
        head = {"text": pattern[node.start:node.end], "shown": pattern[node.start:node.end],
                "kind": kind, "pos": node.start, "note": note}
        out.append(head)
        out.extend(inner)
        return out
    elif k == "seq":
        for c in node.children:
            out.extend(explain(c, pattern, depth + 1))
        return out
    elif k == "alt":
        out.append({"text": pattern[node.start:node.end], "shown": "a|b", "kind": "alt", "pos": node.start,
                    "note": "match ANY ONE of the %d alternatives below" % len(node.children)})
        for b in node.children:
            out.append({"text": "", "shown": "|", "kind": "alt_branch", "pos": b.start,
                        "note": "alternative: " + _flat_text(b)})
            for piece in explain(b, pattern, depth + 1):
                piece["kind"] = "alt_body"
                out.append(piece)
        return out
    return out


def _flat_text(node):
    bits = []
    for c in node.children or [node]:
        if c.kind == "literal":
            bits.append(c.value)
        elif c.kind == "esc_class":
            bits.append("\\" + c.value)
        elif c.kind == "esc_char":
            bits.append(c.flags or "\\" + c.value)
        elif c.kind == "dot":
            bits.append(".")
        elif c.kind == "class":
            bits.append("[...]")
        elif c.kind == "repeat":
            lo, hi = c.value
            bits.append("x{%d,%s}" % (lo, hi if hi is not None else ""))
        else:
            bits.append(c.kind)
    return "".join(bits) or "(empty)"


def _pretty_char(ch):
    if ch == "\n":
        return "a newline"
    if ch == "\t":
        return "a tab"
    if ch == " ":
        return "a space"
    return repr(ch) if not ch.isprintable() else "'%s'" % ch


# ---------------------------------------------------------------- features + score

def detect_features(root):
    feats = set()
    kinds = set()
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        kinds.add(n.kind)
        if n.kind == "group":
            if n.value in ("lookahead", "neglookahead"):
                feats.add("lookahead")
            if n.value in ("lookbehind", "neglookbehind"):
                feats.add("lookbehind")
            if n.value == "atomic":
                feats.add("atomic_group")
            if n.value == "named":
                feats.add("named_group")
            if n.value == "named_py":
                feats.add("named_group")
                feats.add("named_group_py")
            if n.value == "conditional":
                feats.add("conditional")
            if n.value == "scoped_flags":
                feats.add("scoped_flags")
        if n.kind == "flags":
            feats.add("inline_flags")
        if n.kind == "comment":
            feats.add("comment_group")
        if n.kind in ("backref_num", "backref_named"):
            feats.add("backref")
        if n.kind == "repeat" and n.flags == "+":
            feats.add("possessive")
        if n.kind == "zero_width" and n.value in ("\\A", "\\Z", "\\z"):
            feats.add("anchors_a_z")
        if n.kind == "zero_width" and n.value in ("\\b", "\\B"):
            feats.add("word_boundary")
        if n.kind == "esc_class" and n.value in ("d", "w", "s"):
            feats.add("digit_unicode")
        if n.kind == "anchor" and n.value == "$":
            feats.add("dollar_end")
        if n.kind == "anchor" and n.value == "^":
            feats.add("dollar_end")
        if n.kind == "quote":
            feats.add("quote_escape")
        if n.kind == "class":
            for it in n.value:
                if it["t"] == "posix":
                    feats.add("posix_class")
                if it["t"] == "esc_class" and it["c"] in ("d", "w", "s"):
                    feats.add("digit_unicode")
    return feats, kinds


def max_depth(node, d=0):
    best = d
    for c in node.children:
        best = max(best, max_depth(c, d + 1))
    return best


def score(pattern, feats, redos, kinds, captures, depth=0):
    ax = {}
    # 1. safety (35%)
    safety = 100
    for f in redos:
        safety -= {"critical": 45, "high": 25, "medium": 10}.get(f["severity"], 5)
    ax["safety"] = max(0, min(100, safety))
    # 2. portability (25%)
    engines_ok = 0
    matrix = {}
    for eid, _name, _ver in ENGINES:
        bad = 0
        diff = 0
        for f in sorted(feats):
            if f not in FEATURES:
                continue
            st = FEATURES[f].get(eid, ("yes", ""))[0]
            if st == "no":
                bad += 1
            elif st in ("partial", "diff"):
                diff += 1
        matrix[eid] = {"blocked": bad, "different": diff}
        if bad == 0:
            engines_ok += 1
    ax["portability"] = int(100 * engines_ok / len(ENGINES))
    # 3. readability (25%)
    read = 100
    if len(pattern) > 120:
        read -= 20
    elif len(pattern) > 60:
        read -= 10
    if captures > 6:
        read -= 15
    elif captures > 3:
        read -= 7
    if "inline_flags" in feats:
        read -= 5
    if depth > 6:
        read -= 10
    ax["readability"] = max(0, min(100, read))
    # 4. efficiency (15%)
    eff = 100
    for f in redos:
        eff -= {"critical": 40, "high": 20, "medium": 8}.get(f["severity"], 4)
    if kinds & {"backref_num", "backref_named"}:
        eff -= 10
    if "dot" in kinds and not redos:
        eff -= 3
    ax["efficiency"] = max(0, min(100, eff))
    total = (ax["safety"] * 0.35 + ax["portability"] * 0.25 +
             ax["readability"] * 0.25 + ax["efficiency"] * 0.15)
    worst = min([f["severity"] for f in redos], default=None)
    caps = {"critical": 34, "high": 58, "medium": 82}
    cap = caps.get(worst)
    if cap is not None and total > cap:
        total = cap
        blurb_note = (" Score is capped by the %s ReDoS finding: a pattern that can hang is never production "
                      "ready, however clean the rest of it looks." % worst)
    else:
        blurb_note = "" 
    bands = [(85, "production_ready", "safe to ship as written"),
             (70, "mostly_safe", "ship it, one caveat worth noting"),
             (55, "needs_review", "works, but read the warnings first"),
             (40, "fragile", "probably fine on curated input, risky on messy input"),
             (0, "dangerous", "will bite you in production")]
    verdict, blurb = next((v, b) for t, v, b in bands if total >= t)
    return {k: int(round(v)) for k, v in ax.items()}, int(round(total)), verdict, blurb + blurb_note




# ---------------------------------------------------------------- public API

def compile_flags(flags):
    f = 0
    for ch in flags or "":
        if ch in PY_FLAGS:
            f |= PY_FLAGS[ch]
    return f


def _escape_for_engine(pattern, eid):
    """Best-effort literal rewrite of a pattern into a target engine's syntax."""
    if eid in ("js", "go", "rust", "posix"):
        out = []
        i = 0
        while i < len(pattern):
            c = pattern[i]
            if c == "\\" and i + 1 < len(pattern):
                nxt = pattern[i + 1]
                if eid == "js" and nxt in "dDwWsSbBAZz":
                    out.append("\\" + nxt)
                elif eid == "js" and nxt == "Z":
                    out.append("$")
                else:
                    out.append(c + nxt)
                i += 2
                continue
            if c == "$" and eid == "js":
                out.append("$")
            i += 1
        return "".join(out)
    return pattern


def analyze(pattern, flags="", test_cases=None):
    pattern = pattern or ""
    flags = flags or ""
    result = {"pattern": pattern, "flags": flags, "valid": False}
    bad = [c for c in flags if c not in FLAG_ORDER]
    if bad:
        result["error"] = "unknown flag(s): %s" % ", ".join(bad)
        result["error_kind"] = "flags"
        return result
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            compiled = re.compile(pattern, compile_flags(flags))
        result["python_compiles"] = True
    except re.error as e:
        result["error"] = str(e)
        result["error_kind"] = "python_syntax"
        if "unknown extension" in str(e) and "(?<" in pattern:
            result["repair"] = ("This uses the JavaScript/.NET named-group syntax. "
                                "Python's re module wants (?P<name>...), Go and JavaScript want (?<name>...). "
                                "Swap it to (?P<name>...) or run the pattern on a JS engine instead.")
        return result
    try:
        root = RegexParser(pattern).parse()
    except ParseError as e:
        result["error"] = str(e)
        result["error_kind"] = "parse"
        result["python_compiles"] = True
        return result
    result["valid"] = True
    feats, kinds = detect_features(root)
    result["features"] = sorted(feats)
    redos = find_redos(root, pattern)
    result["redos"] = redos
    result["explanation"] = explain(root, pattern)
    captures = sorted([n for n in stack_inner(root) if n.kind == "group" and
                       (isinstance(n.value, int) or n.value in ("named", "named_py"))],
                      key=lambda n: n.start)
    result["captures"] = [
        {"index": n.value if isinstance(n.value, int) else None,
         "name": n.flags if n.value in ("named", "named_py") else None,
         "source": pattern[n.start:n.end]} for n in captures]
    result["pattern_length"] = len(pattern)
    depth = max_depth(root)
    if depth > 6:
        redos = redos + [{"severity": "medium", "kind": "deep_nesting", "where": [0, len(pattern)],
                          "snippet": pattern[:40], "attack": None,
                          "title": "Deeply nested groups",
                          "why": "%d levels of nesting is hard to read and hard to review." % depth,
                          "fix": "Flatten the alternation or split it into two patterns."}]
    ax, total, verdict, blurb = score(pattern, feats, redos, kinds, len(captures), depth)
    result["axes"] = ax
    result["score"] = total
    result["verdict"] = verdict
    result["verdict_blurb"] = blurb
    # engine matrix
    matrix = []
    for eid, ename, ever in ENGINES:
        blocked, different, notes = [], [], []
        for f in sorted(feats):
            if f not in FEATURES:
                continue
            st, note = FEATURES[f][eid]
            if st == "no":
                blocked.append(f)
            elif st in ("partial", "diff"):
                different.append(f)
                if note:
                    notes.append("%s: %s" % (f, note))
        fl = []
        for idx, fch in enumerate(FLAG_ORDER):
            if fch in flags:
                mapped = FLAG_MAP[eid][idx]
                fl.append(mapped if mapped else "?")
        matrix.append({
            "id": eid, "name": ename, "version": ever,
            "status": "no" if blocked else ("caution" if different else "ok"),
            "blocked": blocked, "different": different, "notes": notes,
            "flags": fl,
        })
    result["matrix"] = matrix
    # flags summary
    result["flag_notes"] = [{"flag": f, "label": FLAG_LABEL[f]} for f in FLAG_ORDER if f in flags]
    # sample strings
    result["samples"] = _samples(pattern, flags)
    # empirical timing
    result["timing"] = _timing(compiled, redos, root, pattern)
    if test_cases:
        result["tests"] = run_tests(pattern, flags, test_cases)
    return result


def _samples(pattern, flags):
    presets = {
        "email": ("user@example.com", "not-an-email@", "a.b+tag@mail.co.uk"),
        "phone": ("555-123-4567", "5551234567", "555-ABC-DEFG"),
        "date": ("2026-10-22", "22/10/2026", "2026-13-45"),
        "ipv4": ("192.168.1.1", "999.1.1.1", "1.2.3.4"),
        "url": ("https://example.com/path?x=1", "example.com", "ftp:/broken"),
        "uuid": ("123e4567-e89b-12d3-a456-426614174000", "123e4567e89b12d3a456426614174000", "nope"),
    }
    return [{"name": k, "strings": list(v)} for k, v in presets.items()]


def run_tests(pattern, flags, cases):
    rx = re.compile(pattern, compile_flags(flags))
    out = []
    for i, c in enumerate(cases):
        s = c.get("input", "")
        expect = c.get("expect", "match")
        try:
            m = rx.search(s)
            got = "match" if m else "no-match"
            groups = []
            if m:
                for gi in range(1, (rx.groups or 0) + 1):
                    try:
                        gv = m.group(gi)
                    except Exception:
                        gv = None
                    groups.append({"index": gi, "value": gv})
                gd = {}
                for k, v in (m.groupdict() or {}).items():
                    gd[k] = v
            else:
                gd = {}
            err = None
        except Exception as e:
            got, groups, gd, err = "error", [], {}, str(e)
        passed = (got == expect) if err is None else False
        out.append({"index": i, "input": s, "expect": expect, "got": got, "passed": passed,
                    "groups": groups, "named": gd, "error": err,
                    "span": _span(rx, s)})
    return out


def _span(rx, s):
    m = rx.search(s)
    if not m:
        return None
    return {"start": m.start(), "end": m.end(), "text": m.group(0)}


def _attack_candidates(root, pattern):
    """Plausible attack strings for this pattern, worst case first."""
    chars = set()
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        if n.kind == "literal":
            chars.add(n.value)
        elif n.kind == "esc_char":
            chars.add(n.value)
        elif n.kind == "esc_class":
            chars.add({"d": "1", "w": "a", "s": " ", "D": "a", "W": "!", "S": "a"}.get(n.value, "a"))
        elif n.kind == "class":
            for it in n.value:
                if it.get("t") == "char":
                    chars.add(it["c"])
    chars = [c for c in chars if c and c.isprintable() and c not in "()[]{}|?*+.\\^$-"]
    base = sorted(chars)[:3] or ["a"]
    out = []
    for c in base:
        for tail in ("!", " ", ".", "a"):
            out.append(c * 20 + tail)
            out.append((c + tail) * 10 + "!")
    seen, uniq = set(), []
    for a in out:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq[:6]


def _timing(compiled, redos, root=None, pattern=""):
    """Run each finding's pattern against several attack strings and keep the worst measured time."""
    rows = []
    cands = _attack_candidates(root, pattern) if root is not None else []
    for f in redos[:3]:
        best = None
        tested = []
        order = ([f["attack"]] if f.get("attack") else []) + cands
        for atk in order:
            if not atk or atk in tested:
                continue
            tested.append(atk)
            t = _time_match(compiled, atk, 1.0)
            if t == "timeout":
                rows.append({"kind": f["kind"], "attack": atk, "seconds": "timeout",
                             "tested": len(tested), "probe": "confirmed",
                             "probe_note": "Confirmed: a 20 character string did not finish inside 1 second."})
                best = "timeout"
                break
            if t is not None and (best is None or t > best[1]):
                best = (atk, t)
            if best and best[1] > 0.25:
                break
        if best is None:
            continue
        if best == "timeout":
            continue
        secs = round(best[1], 6)
        if secs > 0.25:
            pv = "confirmed"
            pn = ("Confirmed: %d characters of input already cost %sms. Extrapolate that and the "
                  "endpoint is down." % (len(best[0]), secs * 1000))
        elif secs > 0.01:
            pv = "noticeable"
            pn = ("Slow-ish: %d characters cost %sms. On a few hundred characters this is seconds."
                  % (len(best[0]), secs * 1000))
        else:
            pv = "not_reproduced"
            pn = ("Not reproduced on Python: the worst of %d attack strings still finished in under 1ms. "
                  "Python's engine skips literal prefixes like '.' before backtracking, so this exact "
                  "shape survives here. Engines without that optimizer (JavaScript, PCRE) can still fall "
                  "over, so treat it as a landmine you have not personally detonated." % len(tested))
        rows.append({"kind": f["kind"], "attack": best[0], "seconds": secs,
                     "tested": len(tested), "probe": pv, "probe_note": pn})
    return rows
