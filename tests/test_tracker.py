import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mfa_tracker import analyze, load_policy, load_signins, load_snapshots, parse_signins, parse_snapshots  # noqa: E402
from mfa_tracker.analysis import project  # noqa: E402
from mfa_tracker.cli import main  # noqa: E402
from mfa_tracker.loader import DataError  # noqa: E402
from mfa_tracker.reporting import WRITERS  # noqa: E402

S = ROOT / "samples"
POLICY = load_policy()
METHODS = POLICY["methods"]
HEAD = "snapshot_date,username,department,account_type,enabled,mfa_method\n"
SIGN_HEAD = "username,application,client_app,auth_requirement,status,count\n"


def snaps(rows: str):
    return parse_snapshots(HEAD + rows, METHODS)


def ids(result):
    return {(f.rule_id, f.account) for f in result.findings}


class TestLoader(unittest.TestCase):
    def test_parses_and_defaults(self):
        r = snaps("2026-09-30,a,,,,\n")[0]
        self.assertEqual((r.department, r.account_type, r.enabled, r.method), ("Unassigned", "user", True, "none"))

    def test_rejects_bad_input(self):
        with self.assertRaisesRegex(DataError, "snapshot_date"):
            snaps("30/09/2026,a,IT,user,true,none\n")
        with self.assertRaisesRegex(DataError, "unknown mfa_method"):
            snaps("2026-09-30,a,IT,user,true,carrier_pigeon\n")
        with self.assertRaisesRegex(DataError, "twice"):
            snaps("2026-09-30,a,IT,user,true,none\n2026-09-30,A,IT,user,true,sms\n")
        with self.assertRaisesRegex(DataError, "missing required"):
            parse_snapshots("username,mfa_method\na,none\n", METHODS)

    def test_signin_parsing(self):
        s = parse_signins(SIGN_HEAD + "a,M365,Browser,Multifactor authentication,success,5\n")[0]
        self.assertFalse(s.single_factor)
        self.assertEqual(s.count, 5)
        with self.assertRaisesRegex(DataError, "auth_requirement"):
            parse_signins(SIGN_HEAD + "a,M365,Browser,maybe,success,1\n")


class TestFindings(unittest.TestCase):
    def test_admin_and_user_gaps(self):
        r = analyze(snaps("2026-09-30,adm,IT,admin,true,none\n2026-09-30,adm2,IT,admin,true,app_push\n"
                          "2026-09-30,u,Ops,user,true,none\n2026-09-30,v,Ops,user,true,sms\n"))
        found = ids(r)
        self.assertIn(("MFA-01", "adm"), found)
        self.assertIn(("MFA-05", "adm2"), found)
        self.assertIn(("MFA-02", "u"), found)
        self.assertIn(("MFA-06", "v"), found)

    def test_persistent_non_enrollment_replaces_simple_gap(self):
        rows = "".join(f"2026-0{m}-28,u,Ops,user,true,none\n" for m in (6, 7, 8))
        found = ids(analyze(snaps(rows)))
        self.assertIn(("MFA-03", "u"), found)
        self.assertNotIn(("MFA-02", "u"), found)

    def test_regression_detected(self):
        r = analyze(snaps("2026-08-31,u,Ops,user,true,fido2\n2026-09-30,u,Ops,user,true,sms\n"))
        self.assertIn(("MFA-04", "u"), ids(r))

    def test_disabled_and_service_accounts_excluded(self):
        r = analyze(snaps("2026-09-30,svc,IT,service,true,none\n2026-09-30,old,IT,user,false,none\n"
                          "2026-09-30,u,IT,user,true,totp\n"))
        self.assertEqual(r.latest.accounts, 1)
        self.assertEqual(r.latest.mfa_pct, 100.0)

    def test_signin_bypass(self):
        regs = snaps("2026-09-30,u,Ops,user,true,totp\n")
        sign = parse_signins(SIGN_HEAD + "u,EXO,IMAP4,single_factor,success,10\n"
                                         "u,ERP,Browser,single_factor,success,5\n"
                                         "u,M365,Browser,multifactor,success,85\n"
                                         "x,EXO,POP3,single_factor,failure,50\n")
        r = analyze(regs, sign)
        rules = {f.rule_id for f in r.findings}
        self.assertTrue({"MFA-07", "MFA-08"} <= rules)
        self.assertEqual(r.signins["without_mfa_pct"], 15.0)
        self.assertEqual(r.signins["failed_legacy_sign_ins"], 50)


class TestProjection(unittest.TestCase):
    def test_on_track_off_track_achieved(self):
        target = date(2026, 12, 31)
        fast = [(date(2026, 7, 31), 70.0), (date(2026, 8, 31), 80.0), (date(2026, 9, 30), 90.0)]
        self.assertEqual(project(fast, 100, target, "x").status, "On track")
        slow = [(date(2026, 7, 31), 70.0), (date(2026, 8, 31), 71.0), (date(2026, 9, 30), 72.0)]
        self.assertEqual(project(slow, 100, target, "x").status, "Off track")
        flat = [(date(2026, 8, 31), 70.0), (date(2026, 9, 30), 70.0)]
        self.assertIsNone(project(flat, 100, target, "x").projected_date)
        self.assertEqual(project([(date(2026, 9, 30), 100.0)], 100, target, "x").status, "Achieved")
        self.assertEqual(project([(date(2026, 9, 30), 50.0)], 100, target, "x").status, "Insufficient data")


class TestSamples(unittest.TestCase):
    def test_riverbend_story(self):
        r = analyze(load_snapshots(S / "riverbend_mfa_snapshots.csv", METHODS),
                    load_signins(S / "riverbend_signins.csv"), "R", POLICY)
        self.assertGreater(r.latest.mfa_pct, r.first.mfa_pct)
        self.assertEqual({p.status for p in r.projections}, {"Off track"})
        self.assertIn("MFA-07", {f.rule_id for f in r.findings})
        self.assertEqual(r.departments[0]["department"], "Production")  # lowest coverage first

    def test_northfield_complete(self):
        r = analyze(load_snapshots(S / "northfield_mfa_snapshots.csv", METHODS),
                    load_signins(S / "northfield_signins.csv"), "N", POLICY)
        self.assertEqual(r.latest.mfa_pct, 100.0)
        self.assertEqual({p.status for p in r.projections}, {"Achieved"})
        self.assertEqual(r.signins["without_mfa"], 0)


class TestReportingAndCli(unittest.TestCase):
    def test_writers(self):
        r = analyze(load_snapshots(S / "riverbend_mfa_snapshots.csv", METHODS),
                    load_signins(S / "riverbend_signins.csv"), "<b>x</b>", POLICY)
        for fmt, writer in WRITERS.items():
            self.assertTrue(writer(r).strip(), fmt)
        html = WRITERS["html"](r)
        self.assertNotIn("<b>x</b>", html)
        self.assertIn("<svg", html)
        json.loads(WRITERS["json"](r))

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = main([str(S / "riverbend_mfa_snapshots.csv"), "--signins", str(S / "riverbend_signins.csv"),
                         "--out", tmp, "--fail-on", "high"])
            self.assertEqual(code, 2)
            self.assertTrue(any(Path(tmp).glob("*.html")))
            code = main([str(S / "northfield_mfa_snapshots.csv"), "--out", tmp, "--fail-on", "medium"])
            self.assertEqual(code, 0)
            bad = Path(tmp) / "bad.csv"
            bad.write_text("x\n1\n", encoding="utf-8")
            self.assertEqual(main([str(bad), "--out", tmp]), 1)


if __name__ == "__main__":
    unittest.main()
