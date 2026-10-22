"""Regex Workbench - Flask API + static server."""
import contextlib
import json
import os
import sqlite3
import re as _re
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request, Response

import analyzer

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("REGEX_WORKBENCH_DB", os.path.join(HERE, "sessions.db"))

app = Flask(__name__)

SAMPLES = [
    {"name": "Email (safe)", "pattern": r"^[\w.+-]+@[\w-]+\.[\w.]{2,}$", "flags": "",
     "note": "The shape most people actually want. Anchored, no nested quantifier."},
    {"name": "Email (ReDoS trap)", "pattern": r"^([\w.]+\.)*[\w]+@([\w-]+\.)+[a-z]{2,}$", "flags": "",
     "note": "A classic catastrophic pattern. Watch the probe time climb."},
    {"name": "Nested quantifier", "pattern": r"(a+)+$", "flags": "",
     "note": "Textbook nested quantifier: every 'a' can be split two ways."},
    {"name": "Ambiguous alternation", "pattern": r"^(?:a|ab)+c$", "flags": "",
     "note": "Branch 'a' is a prefix of branch 'ab', so a failing tail costs exponentially."},
    {"name": "Password policy", "pattern": r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?!.*\S?)\S{12,}$", "flags": "",
     "note": "Lookaheads everywhere: check what survives outside JavaScript."},
    {"name": "ISO date", "pattern": r"^(?<y>\d{4})-(?<m>\d{2})-(?<d>\d{2})$", "flags": "",
     "note": "Named groups: portable names, readable extraction."},
    {"name": "Log line", "pattern": r"^(\d{4}-\d{2}-\d{2})\s+(\w+)\s+level=(\w+)\s+(.*)$", "flags": "m",
     "note": "Multi-line log parsing with the multiline flag."},
    {"name": "HTML tag", "pattern": r"^<\s*([a-zA-Z][\w-]*)((?:\s+[\w-]+(?:=\S*)?)*)\s*/?>$", "flags": "",
     "note": "Realistic and hairy: find out what it costs."},
]


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextlib.contextmanager
def dbctx():
    conn = db()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db():
    with dbctx() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            pattern TEXT NOT NULL,
            flags TEXT NOT NULL DEFAULT '',
            score INTEGER,
            verdict TEXT,
            note TEXT,
            rating INTEGER DEFAULT 0,
            payload TEXT
        )""")


init_db()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    pattern = data.get("pattern", "")
    flags = data.get("flags", "")
    tests = data.get("tests") or None
    if len(pattern) > 2000:
        return jsonify({"error": "pattern is too long (max 2000 characters)"}), 400
    return jsonify(analyzer.analyze(pattern, flags, tests))


@app.route("/api/run-tests", methods=["POST"])
def api_run_tests():
    data = request.get_json(silent=True) or {}
    norm = []
    for c in (data.get("cases") or []):
        if isinstance(c, str):
            if c.startswith("!"):
                norm.append({"input": c[1:], "expect": "no-match"})
            else:
                norm.append({"input": c, "expect": "match"})
        else:
            norm.append(c)
    try:
        return jsonify({"tests": analyzer.run_tests(data.get("pattern", ""),
                                                   data.get("flags", ""), norm)})
    except _re.error as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/samples")
def api_samples():
    return jsonify({"samples": SAMPLES})


@app.route("/api/sessions", methods=["GET", "POST"])
def api_sessions():
    if request.method == "GET":
        with dbctx() as conn:
            rows = conn.execute(
                "SELECT id, created_at, pattern, flags, score, verdict, note, rating "
                "FROM sessions ORDER BY id DESC LIMIT 200").fetchall()
        return jsonify({"sessions": [dict(r) for r in rows]})
    data = request.get_json(silent=True) or {}
    if not data.get("pattern"):
        return jsonify({"error": "pattern is required"}), 400
    with dbctx() as conn:
        cur = conn.execute(
            "INSERT INTO sessions (created_at, pattern, flags, score, verdict, note, rating, payload) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), data["pattern"],
             data.get("flags", ""), data.get("score"), data.get("verdict"),
             data.get("note", ""), int(data.get("rating") or 0),
             json.dumps(data.get("payload") or {})))
        sid = cur.lastrowid
    return jsonify({"id": sid})


@app.route("/api/sessions/<int:sid>", methods=["GET", "PATCH"])
def api_session(sid):
    with dbctx() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        if request.method == "PATCH":
            data = request.get_json(silent=True) or {}
            conn.execute("UPDATE sessions SET note=?, rating=? WHERE id=?",
                         (data.get("note", row["note"]), int(data.get("rating", row["rating"])), sid))
            row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        item = dict(row)
        try:
            item["payload"] = json.loads(item.get("payload") or "{}")
        except Exception:
            item["payload"] = {}
    return jsonify({"session": item})


@app.route("/api/export/<int:sid>")
def api_export(sid):
    fmt = request.args.get("fmt", "md")
    with dbctx() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    item = dict(row)
    payload = json.loads(item.pop("payload") or "{}")
    base = "regex-workbench-session-%d" % sid
    if fmt == "json":
        body = json.dumps({"session": item, "analysis": payload}, indent=2)
        mime, ext = "application/json", "json"
    else:
        tick = chr(96)
        lines = ["# Regex Workbench - saved analysis", "",
                 "- Pattern: %s%s%s" % (tick, item["pattern"], tick),
                 "- Flags: %s%s%s" % (tick, item["flags"] or "(none)", tick),
                 "- Score: %s (%s)" % (item["score"], item["verdict"]),
                 "- Saved: %s" % item["created_at"], ""]
        if payload.get("verdict_blurb"):
            lines += [payload["verdict_blurb"], ""]
        axes = payload.get("axes") or {}
        if axes:
            lines.append("## Axes")
            lines += ["- %s: %s" % (k, v) for k, v in axes.items()]
            lines.append("")
        for f in payload.get("redos") or []:
            lines += ["## %s (%s)" % (f["title"], f["severity"]), "", f["why"], "",
                      "**Fix:** %s" % f["fix"], ""]
        for e in payload.get("matrix") or []:
            lines.append("- **%s** (%s): %s" % (e["name"], e["version"], e["status"]))
        lines.append("")
        if item.get("note"):
            lines += ["## Note", "", item["note"], ""]
        body = "\n".join(lines)
        mime, ext = "text/markdown", "md"
    return Response(body, mimetype=mime, headers={
        "Content-Disposition": 'attachment; filename="%s.%s"' % (base, ext)})


@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "engines": len(analyzer.ENGINES), "samples": len(SAMPLES)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8765")), debug=False)
