# Regex Workbench

Paste a regular expression. Get back three things you normally have to guess at:

1. **What it actually does**, in plain English, token by token.
2. **Whether it can hang**, with the backtracking pattern named, an attack string generated, and a real measured time from an actual engine run.
3. **Whether it will work somewhere else** - eight regex engines, checked against only the constructs your pattern really uses.

Local-first. No API keys, no network calls, no telemetry. Flask + SQLite + vanilla JS.

---

## Why this exists

Two regex failures cost real engineering time, and neither shows up in a unit test that only feeds valid input.

**It hangs.** A pattern like ^(a+)+$ matches "aaa" instantly and then takes exponential time on "aaaa...a". The input is 20 characters. It is not a bug you can reproduce by pasting the pattern into a search box, because the search box only ever tries matching input. The output depends on the engine: Python's optimizer skips literal prefixes, so some catastrophic-looking patterns survive there and fall over in JavaScript.

**It does not run where you need it.** (?&lt;name&gt;) is JavaScript and .NET. (a)\1 is banned outright in Go's RE2. [[:alpha:]] is POSIX and Python only. A pattern can be perfect on your laptop and throw a compile error in the service.

Regex Workbench answers both before you ship, and shows its work.

## Features

**Explain tab**
- Token-by-token table: position, token, plain-English description of what it does
- Greedy vs lazy vs possessive spelled out per quantifier ("take as much as possible and never give it back")
- Capture groups listed with index and name

**Backtracking risk tab**
- Static detection of three known-dangerous shapes:
  - nested unbounded quantifiers: (a+)+, ([\w.]+\.)*[\w]+
  - ambiguous alternation under a quantifier: (?:a|ab)+, (foo|foobar)+
  - quantifiers that can match the empty string: (?:a?)*
- Each finding gives the why, a concrete fix, and an attack string
- Then it runs the pattern against several generated attack strings **in a throwaway subprocess with a 1s hard timeout**, and reports the measured time. A server can never be wedged by analyzing a malicious pattern.
- Honest reporting: when static analysis flags a shape but the probe shows the engine is fine, the tool says so instead of crying wolf

**Engine matrix tab**
- Python re, JavaScript, Java, .NET, PCRE2, Go RE2, POSIX ERE, Rust regex
- Only the features your pattern uses are checked
- "caution" is not "no": it means the construct is supported but behaves differently (e.g. $\ in Python matches before a trailing newline, in JavaScript it does not; \d is Unicode in Python and ASCII in Go)
- Your flags are translated per engine, including cases with no equivalent (JavaScript has no verbose flag; POSIX ERE has no flags at all)

**Test bench tab**
- One case per line, prefix with ! to assert non-match
- Shows expected vs actual, match span, and every capture group by index and name

**Saved tab**
- SQLite log of patterns you analyzed, with a 1-5 star rating and notes
- Markdown and JSON export of any saved analysis

**Scoring**
0-100 across four axes (safety 35%, portability 25%, readability 25%, efficiency 15%), with a hard cap when a ReDoS finding is present: a pattern that can hang never scores above 34 regardless of how clean the rest of it is.

Verdict bands: production_ready >=85, mostly_safe >=70, needs_review >=55, fragile >=40, dangerous <40.

## Run it

    pip install -r requirements.txt
    python3 app.py

Then open <http://127.0.0.1:8765>.

    PORT=9000 python3 app.py      # different port
    python3 -m unittest discover -s tests   # 29 tests

## API

| Method | Path | What it does |
| --- | --- | --- |
| POST | /api/analyze | Full analysis. Body: pattern, flags, optional tests |
| POST | /api/run-tests | Run test cases. Body: pattern, flags, cases |
| GET | /api/samples | Built-in sample patterns |
| GET/POST | /api/sessions | List or create saved analyses |
| GET/PATCH | /api/sessions/&lt;id&gt; | Fetch or rate/note a saved analysis |
| GET | /api/export/&lt;id&gt;?fmt=md\|json | Download an export |
| GET | /api/health | Liveness |

Example:

    curl -s -X POST localhost:8765/api/analyze \
      -H 'Content-Type: application/json' \
      -d '{"pattern":"^([\\w.]+\\.)*[\\w]+@([\\w-]+\\.)+[a-z]{2,}$"}'

## How the analyzer works

analyzer.py has no dependencies beyond the standard library.

1. The pattern is parsed by a hand-written recursive-descent parser into an AST. It never executes the pattern to explain it.
2. Node types carry what they match, their source span, and enough structure to compute two properties used throughout: is this node *nullable* (can it match empty) and what is its *first set* (what characters can start a match). Those two facts are the whole basis of the backtracking analysis.
3. Dangerous shapes are found by walking the AST: a quantifier containing another unbounded quantifier, an alternation whose branches have overlapping first sets sitting under an unbounded quantifier, or a repeated expression that is nullable.
4. Portability comes from a hand-maintained feature matrix keyed on the constructs the AST actually contains.
5. The empirical probe forks a subprocess, runs the search, and kills it after one second.

If Python cannot compile the pattern, you get the compiler's own error message and position rather than a generic failure. For (?&lt;name&gt;) specifically, the tool adds the Python-syntax fix, since that is the most common thing people copy across a language boundary.

## Known limits

- The parser covers the common grammar. Conditionals (?(1)yes|no) are rejected with a clear message because Python's stdlib does not support them.
- Backtracking detection is structural, not a proof. It finds known-dangerous shapes; it cannot prove absence. The probe helps, but it only probes what it can generate.
- Probe timings are single-run on one machine. Treat them as an order of magnitude, not a benchmark.
- The engine matrix encodes documented behavior as of late 2026. Engines move; re-check before relying on a "differs subtly" note.

## Layout

    app.py                 Flask routes, SQLite session log, exports
    analyzer.py            parser, AST, ReDoS analysis, engine matrix, scoring
    templates/index.html   UI shell
    static/app.js          fetch/render layer
    static/style.css       dark theme
    tests/test_smoke.py    29 tests: parser, ReDoS, portability, API

MIT.
