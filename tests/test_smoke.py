"""Smoke tests: analyzer logic + Flask API. Run: python3 tests/test_smoke.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analyzer  # noqa: E402
import app as web  # noqa: E402


class TestParsing(unittest.TestCase):
    def test_simple_pattern_is_valid(self):
        r = analyzer.analyze(r"^\d{3}-\d{2}$")
        self.assertTrue(r["valid"])
        self.assertEqual(r["verdict"], "production_ready")

    def test_bad_syntax_reports_error(self):
        r = analyzer.analyze("(unclosed")
        self.assertFalse(r["valid"])
        self.assertEqual(r["error_kind"], "python_syntax")

    def test_bad_flag_reports_error(self):
        r = analyzer.analyze("abc", flags="q")
        self.assertFalse(r["valid"])
        self.assertEqual(r["error_kind"], "flags")

    def test_named_groups_python_style(self):
        r = analyzer.analyze(r"(?P<year>\d{4})")
        self.assertTrue(r["valid"], r.get("error"))
        self.assertEqual(len(r["captures"]), 1)
        self.assertEqual(r["captures"][0]["name"], "year")

    def test_js_named_group_gets_repair_hint(self):
        r = analyzer.analyze(r"(?<year>\d{4})")
        self.assertFalse(r["valid"])
        self.assertIn("(?P<name>", r["repair"])

    def test_conditional_groups_rejected_clearly(self):
        r = analyzer.analyze("(a)(?(1)b|c)")
        self.assertFalse(r["valid"])
        self.assertIn("conditional", r["error"].lower())


class TestRedos(unittest.TestCase):
    def test_nested_quantifier_is_critical(self):
        r = analyzer.analyze(r"(a+)+$")
        kinds = [f["kind"] for f in r["redos"]]
        self.assertIn("nested_quantifier", kinds)
        self.assertEqual(r["redos"][0]["severity"], "critical")

    def test_critical_redos_caps_score(self):
        r = analyzer.analyze(r"(a+)+$")
        self.assertLessEqual(r["score"], 34)
        self.assertEqual(r["verdict"], "dangerous")

    def test_ambiguous_alternation_flagged(self):
        r = analyzer.analyze(r"^(?:a|ab)+c$")
        self.assertIn("ambiguous_alternation", [f["kind"] for f in r["redos"]])

    def test_nullable_repeat_flagged(self):
        r = analyzer.analyze(r"^(?:a?)*$")
        self.assertIn("nullable_loop", [f["kind"] for f in r["redos"]])

    def test_bounded_outer_repeat_is_only_medium(self):
        r = analyzer.analyze(r"(?:.*a){3}")
        sev = [f["severity"] for f in r["redos"]]
        self.assertNotIn("critical", sev)

    def test_safe_email_pattern_is_clean(self):
        r = analyzer.analyze(r"^[\w.+-]+@[\w-]+\.[\w.]{2,}$")
        self.assertEqual(r["redos"], [])

    def test_probe_returns_a_time(self):
        r = analyzer.analyze(r"(a+)+$")
        self.assertTrue(r["timing"])
        self.assertIsNotNone(r["timing"][0]["seconds"])


class TestPortability(unittest.TestCase):
    def test_eight_engines_reported(self):
        r = analyzer.analyze(r"^abc$")
        self.assertEqual(len(r["matrix"]), 8)

    def test_lookahead_blocks_posix_and_rust(self):
        r = analyzer.analyze(r"^(?=abc)a$")
        by = {e["id"]: e for e in r["matrix"]}
        self.assertIn("lookahead", by["posix"]["blocked"])
        self.assertIn("lookahead", by["rust"]["blocked"])

    def test_backreference_blocks_go(self):
        r = analyzer.analyze(r"^(a)\1$")
        by = {e["id"]: e for e in r["matrix"]}
        self.assertIn("backref", by["go"]["blocked"])
        self.assertNotIn("backref", by["python"]["blocked"])

    def test_flags_mapped_per_engine(self):
        r = analyzer.analyze("^abc$", flags="i")
        by = {e["id"]: e for e in r["matrix"]}
        self.assertEqual(by["python"]["flags"], ["re.I"])
        self.assertEqual(by["js"]["flags"], ["i"])
        self.assertEqual(by["posix"]["flags"], ["?"])


class TestExplain(unittest.TestCase):
    def test_every_token_has_a_note(self):
        r = analyzer.analyze(r"^(\w+)@\w+$")
        self.assertTrue(r["explanation"])
        for e in r["explanation"]:
            self.assertTrue(e["note"].strip(), e)

    def test_captures_listed(self):
        r = analyzer.analyze(r"^(\w+)@(\w+)\.com$")
        self.assertEqual(len(r["captures"]), 2)
        self.assertEqual(r["captures"][0]["index"], 1)

    def test_charclass_explained(self):
        r = analyzer.analyze(r"[a-z0-9_]+")
        joined = " ".join(e["note"] for e in r["explanation"])
        self.assertIn("set", joined)


class TestRunner(unittest.TestCase):
    def test_run_tests_reports_pass_and_fail(self):
        cases = [{"input": "abc", "expect": "match"}, {"input": "zzz", "expect": "no-match"}]
        out = analyzer.run_tests(r"^[a-c]+$", "", cases)
        self.assertTrue(out[0]["passed"])
        self.assertTrue(out[1]["passed"])

    def test_groups_returned(self):
        out = analyzer.run_tests(r"^(\w+)@(\w+)$", "", [{"input": "a@b", "expect": "match"}])
        self.assertEqual([g["value"] for g in out[0]["groups"]], ["a", "b"])


class TestApi(unittest.TestCase):
    def setUp(self):
        web.app.config["TESTING"] = True
        self.c = web.app.test_client()

    def test_health(self):
        self.assertEqual(self.c.get("/api/health").get_json()["status"], "ok")

    def test_index_serves(self):
        self.assertEqual(self.c.get("/").status_code, 200)

    def test_analyze_endpoint(self):
        r = self.c.post("/api/analyze", json={"pattern": r"(a+)+$", "flags": ""}).get_json()
        self.assertTrue(r["valid"])
        self.assertEqual(r["verdict"], "dangerous")

    def test_run_tests_endpoint(self):
        r = self.c.post("/api/run-tests", json={
            "pattern": r"^\d+$", "flags": "", "cases": ["123", "!abc"]}).get_json()
        self.assertEqual(len(r["tests"]), 2)
        self.assertTrue(all(t["passed"] for t in r["tests"]))

    def test_session_roundtrip_and_export(self):
        sid = self.c.post("/api/sessions", json={
            "pattern": r"^\w+$", "flags": "i", "score": 90, "verdict": "production_ready",
            "note": "used in signup form", "payload": {"axes": {"safety": 100}}}).get_json()["id"]
        got = self.c.get("/api/sessions/%d" % sid).get_json()["session"]
        self.assertEqual(got["note"], "used in signup form")
        self.c.patch("/api/sessions/%d" % sid, json={"rating": 5})
        self.assertEqual(self.c.get("/api/sessions/%d" % sid).get_json()["session"]["rating"], 5)
        md = self.c.get("/api/export/%d?fmt=md" % sid)
        self.assertEqual(md.status_code, 200)
        self.assertIn("Regex Workbench", md.get_data(as_text=True))
        js = self.c.get("/api/export/%d?fmt=json" % sid)
        self.assertIn("analysis", js.get_data(as_text=True))

    def test_samples_endpoint(self):
        self.assertGreaterEqual(len(self.c.get("/api/samples").get_json()["samples"]), 6)

    def test_long_pattern_rejected(self):
        self.assertEqual(self.c.post("/api/analyze", json={"pattern": "a" * 3000}).status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
