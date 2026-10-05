"""Analyze MFA rollout progress across monthly snapshots."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .loader import HUMAN_TYPES, Registration, SignIn

DATA_DIR = Path(__file__).parent / "data"
TIERS = {0: "None", 1: "Weak (SMS or voice)", 2: "Standard (app or code)", 3: "Phishing-resistant"}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def load_policy(path: str | Path | None = None) -> dict:
    policy = json.loads((DATA_DIR / "policy.json").read_text(encoding="utf-8"))
    if path:
        policy.update(json.loads(Path(path).read_text(encoding="utf-8")))
    policy["methods"] = {k.lower(): int(v) for k, v in policy["methods"].items()}
    policy["legacy_client_apps"] = [c.lower() for c in policy["legacy_client_apps"]]
    policy["target_date"] = date.fromisoformat(str(policy["target_date"]))
    return policy


def _rules() -> dict[str, dict]:
    data = json.loads((DATA_DIR / "rules.json").read_text(encoding="utf-8"))
    return {r["id"]: r for r in data["rules"]}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    controls: list[str]
    account: str | None
    detail: str
    remediation: str


@dataclass
class SnapshotMetrics:
    snapshot: str
    accounts: int
    mfa_pct: float
    phishing_resistant_pct: float
    admins: int
    admin_mfa_pct: float | None
    admin_phishing_resistant_pct: float | None
    weak_count: int


@dataclass
class Projection:
    measure: str
    current_pct: float
    target_pct: float
    target_date: str
    projected_date: str | None
    status: str
    explanation: str


@dataclass
class TrackerResult:
    organization: str
    generated_at: str
    tool_version: str
    snapshots: list[SnapshotMetrics]
    departments: list[dict[str, Any]]
    method_mix: list[dict[str, Any]]
    signins: dict[str, Any]
    projections: list[Projection]
    findings: list[Finding] = field(default_factory=list)

    @property
    def latest(self) -> SnapshotMetrics:
        return self.snapshots[-1]

    @property
    def first(self) -> SnapshotMetrics:
        return self.snapshots[0]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _pct(num: int, den: int) -> float | None:
    return round(100 * num / den, 1) if den else None


def _in_scope(r: Registration) -> bool:
    return r.enabled and r.account_type in HUMAN_TYPES


def _metrics(snap: date, regs: list[Registration], strength: dict[str, int]) -> SnapshotMetrics:
    scope = [r for r in regs if _in_scope(r)]
    admins = [r for r in scope if r.account_type == "admin"]
    s = [strength[r.method] for r in scope]
    a = [strength[r.method] for r in admins]
    return SnapshotMetrics(
        snapshot=snap.isoformat(),
        accounts=len(scope),
        mfa_pct=_pct(sum(1 for x in s if x > 0), len(s)) or 0.0,
        phishing_resistant_pct=_pct(sum(1 for x in s if x == 3), len(s)) or 0.0,
        admins=len(admins),
        admin_mfa_pct=_pct(sum(1 for x in a if x > 0), len(a)),
        admin_phishing_resistant_pct=_pct(sum(1 for x in a if x == 3), len(a)),
        weak_count=sum(1 for x in s if x == 1),
    )


def project(points: list[tuple[date, float]], target: float, target_date: date, measure: str) -> Projection:
    """Least-squares trend over the three most recent snapshots, extended to the date the target is reached.

    Rollouts usually slow as the easy enrollments are done, so the recent pace predicts the finish better
    than the average pace since the start.
    """
    current = points[-1][1] if points else 0.0
    base = dict(measure=measure, current_pct=current, target_pct=float(target), target_date=target_date.isoformat())
    if points and current >= target:
        return Projection(**base, projected_date=points[-1][0].isoformat(), status="Achieved",
                          explanation="The target has been reached.")
    if len(points) < 2:
        return Projection(**base, projected_date=None, status="Insufficient data",
                          explanation="At least two snapshots are needed to project a trend.")
    pts = points[-3:]
    origin = pts[0][0]
    xs = [(d - origin).days for d, _ in pts]
    ys = [v for _, v in pts]
    n = len(pts)
    mx, my = sum(xs) / n, sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom if denom else 0.0
    per_month = slope * 30.4
    if slope <= 0:
        return Projection(**base, projected_date=None, status="Off track",
                          explanation="Coverage is flat or falling, so the target will not be reached at the current pace.")
    last_date = pts[-1][0]
    projected = last_date + timedelta(days=round((target - current) / slope))
    on_track = projected <= target_date
    return Projection(**base, projected_date=projected.isoformat(),
                      status="On track" if on_track else "Off track",
                      explanation=(f"Recent pace is about {per_month:.1f} percentage points per month, "
                                   f"which reaches {target:.0f}% around {projected:%B %Y}."))


def analyze(registrations: list[Registration], signins: list[SignIn] | None = None,
            organization: str = "Unnamed organization", policy: dict | None = None) -> TrackerResult:
    from . import __version__

    policy = policy or load_policy()
    strength = policy["methods"]
    rules = _rules()
    by_snap: dict[date, list[Registration]] = defaultdict(list)
    for r in registrations:
        by_snap[r.snapshot].append(r)
    if not by_snap:
        raise ValueError("No snapshot data supplied.")
    dates = sorted(by_snap)
    snapshots = [_metrics(d, by_snap[d], strength) for d in dates]
    latest_date = dates[-1]
    latest = [r for r in by_snap[latest_date] if _in_scope(r)]
    first_by_dept: dict[str, list[Registration]] = defaultdict(list)
    for r in by_snap[dates[0]]:
        if _in_scope(r):
            first_by_dept[r.department].append(r)

    findings: list[Finding] = []

    def add(rule_id: str, account: str | None, detail: str) -> None:
        m = rules[rule_id]
        findings.append(Finding(rule_id, m["title"], m["severity"], m["controls"], account, detail, m["remediation"]))

    # Consecutive snapshots without MFA, ending at the latest snapshot
    history: dict[str, list[int]] = defaultdict(list)
    for d in dates:
        for r in by_snap[d]:
            if _in_scope(r):
                history[r.username.lower()].append(strength[r.method])

    def streak(user: str) -> int:
        n = 0
        for v in reversed(history[user.lower()]):
            if v != 0:
                break
            n += 1
        return n

    need = policy["persistent_snapshots"]
    for r in sorted(latest, key=lambda x: x.username.lower()):
        s = strength[r.method]
        if r.account_type == "admin":
            if s == 0:
                add("MFA-01", r.username, f"{r.department}: no MFA method registered.")
            elif s < 3:
                add("MFA-05", r.username, f"{r.department}: uses {r.method}.")
        elif s == 0:
            months = streak(r.username)
            if months >= need:
                add("MFA-03", r.username, f"{r.department}: not enrolled in the last {months} snapshots.")
            else:
                add("MFA-02", r.username, f"{r.department}: no MFA method registered.")
        elif s == 1:
            add("MFA-06", r.username, f"{r.department}: uses {r.method}.")

    if len(dates) >= 2:
        prev = {r.username.lower(): r for r in by_snap[dates[-2]] if _in_scope(r)}
        for r in sorted(latest, key=lambda x: x.username.lower()):
            p = prev.get(r.username.lower())
            if p and strength[r.method] < strength[p.method]:
                add("MFA-04", r.username, f"Changed from {p.method} to {r.method} between {dates[-2]} and {latest_date}.")

    # Sign-ins
    legacy = set(policy["legacy_client_apps"])
    success = [s for s in (signins or []) if s.success]
    total = sum(s.count for s in success)
    groups: dict[tuple[str, str, bool], dict] = {}
    for s in success:
        is_legacy = s.client_app.lower() in legacy
        if not (is_legacy or s.single_factor):
            continue
        g = groups.setdefault((s.application, s.client_app, is_legacy), {"count": 0, "users": set()})
        g["count"] += s.count
        g["users"].add(s.username)
    bypass_rows = []
    for (app_name, client, is_legacy), g in sorted(groups.items(), key=lambda kv: -kv[1]["count"]):
        users = sorted(g["users"], key=str.lower)
        bypass_rows.append({"application": app_name, "client_app": client, "legacy": is_legacy,
                            "sign_ins": g["count"], "users": users})
        detail = (f"{client} to {app_name}: {g['count']} successful sign-ins by "
                  f"{len(users)} user{'s' if len(users) != 1 else ''} ({', '.join(users)}).")
        add("MFA-07" if is_legacy else "MFA-08", None, detail)
    single = sum(s.count for s in success if s.single_factor or s.client_app.lower() in legacy)
    failed_legacy = sum(s.count for s in (signins or []) if not s.success and s.client_app.lower() in legacy)
    signin_summary = {
        "provided": bool(signins),
        "successful_sign_ins": total,
        "without_mfa": single,
        "without_mfa_pct": _pct(single, total),
        "legacy_sign_ins": sum(r["sign_ins"] for r in bypass_rows if r["legacy"]),
        "failed_legacy_sign_ins": failed_legacy,
        "bypass": bypass_rows,
    }

    # Projections
    td = policy["target_date"]
    proj = [
        project([(date.fromisoformat(m.snapshot), m.mfa_pct) for m in snapshots],
                policy["coverage_target_pct"], td, "MFA coverage, all accounts"),
    ]
    admin_points = [(date.fromisoformat(m.snapshot), m.admin_phishing_resistant_pct)
                    for m in snapshots if m.admin_phishing_resistant_pct is not None]
    if admin_points:
        proj.append(project(admin_points, policy["admin_phishing_resistant_target_pct"], td,
                            "Phishing-resistant MFA, administrators"))
    for p, rule in zip(proj, ("MFA-09", "MFA-10")):
        if p.status == "Off track":
            add(rule, None, f"{p.measure}: {p.current_pct:.0f}% now, target {p.target_pct:.0f}% by "
                            f"{p.target_date}. {p.explanation}")

    # Departments and method mix (latest snapshot)
    dept_rows = []
    by_dept: dict[str, list[Registration]] = defaultdict(list)
    for r in latest:
        by_dept[r.department].append(r)
    for dept in sorted(by_dept):
        rs = by_dept[dept]
        mfa = _pct(sum(1 for r in rs if strength[r.method] > 0), len(rs))
        first = first_by_dept.get(dept, [])
        first_mfa = _pct(sum(1 for r in first if strength[r.method] > 0), len(first))
        dept_rows.append({
            "department": dept, "accounts": len(rs), "mfa_pct": mfa,
            "phishing_resistant_pct": _pct(sum(1 for r in rs if strength[r.method] == 3), len(rs)),
            "without_mfa": sum(1 for r in rs if strength[r.method] == 0),
            "change_pts": None if first_mfa is None else round(mfa - first_mfa, 1),
        })
    dept_rows.sort(key=lambda d: (d["mfa_pct"], d["department"]))

    mix = []
    for tier, label in TIERS.items():
        methods = sorted({r.method for r in latest if strength[r.method] == tier})
        count = sum(1 for r in latest if strength[r.method] == tier)
        mix.append({"tier": label, "accounts": count, "pct": _pct(count, len(latest)) or 0.0,
                    "methods": ", ".join(methods)})

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.rule_id, f.account or ""))
    return TrackerResult(
        organization=organization,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        tool_version=__version__,
        snapshots=snapshots,
        departments=dept_rows,
        method_mix=mix,
        signins=signin_summary,
        projections=proj,
        findings=findings,
    )
