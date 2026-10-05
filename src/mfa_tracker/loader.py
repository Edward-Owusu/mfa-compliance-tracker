"""Read MFA registration snapshots and sign-in summaries from CSV."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from datetime import date
from pathlib import Path

ACCOUNT_TYPES = ("user", "admin", "service", "guest")
HUMAN_TYPES = ("user", "admin", "guest")
_TRUE = {"true", "yes", "y", "1", "enabled"}
_FALSE = {"false", "no", "n", "0", "disabled"}


class DataError(ValueError):
    """Raised when an input file cannot be read."""


@dataclass(frozen=True)
class Registration:
    snapshot: date
    username: str
    department: str
    account_type: str
    enabled: bool
    method: str


@dataclass(frozen=True)
class SignIn:
    username: str
    application: str
    client_app: str
    single_factor: bool
    success: bool
    count: int


def _rows(text: str, required: tuple[str, ...]) -> list[tuple[int, dict]]:
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    fields = [f.strip().lower() for f in (reader.fieldnames or [])]
    missing = [c for c in required if c not in fields]
    if missing:
        raise DataError(f"The file is missing required column(s): {', '.join(missing)}.")
    out = []
    for i, raw in enumerate(reader, start=2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
        if any(row.values()):
            out.append((i, row))
    if not out:
        raise DataError("The file has a header but no data rows.")
    return out


def _bool(value: str, column: str, row: int, default: bool) -> bool:
    v = value.lower()
    if not v:
        return default
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise DataError(f"Row {row}: column '{column}' must be true or false, got '{value}'.")


def parse_snapshots(text: str, methods: dict[str, int]) -> list[Registration]:
    """One row per account per snapshot: snapshot_date, username, department, account_type, enabled, mfa_method."""
    regs: list[Registration] = []
    seen: set[tuple[date, str]] = set()
    for i, r in _rows(text, ("snapshot_date", "username", "mfa_method")):
        try:
            snap = date.fromisoformat(r["snapshot_date"])
        except ValueError as exc:
            raise DataError(f"Row {i}: snapshot_date must look like 2026-09-30, got '{r['snapshot_date']}'.") from exc
        user = r["username"]
        if not user:
            raise DataError(f"Row {i}: username is empty.")
        key = (snap, user.lower())
        if key in seen:
            raise DataError(f"Row {i}: '{user}' appears twice in the {snap} snapshot.")
        seen.add(key)
        acct = (r.get("account_type") or "user").lower()
        if acct not in ACCOUNT_TYPES:
            raise DataError(f"Row {i}: account_type must be one of {', '.join(ACCOUNT_TYPES)}, got '{acct}'.")
        method = (r["mfa_method"] or "none").lower()
        if method not in methods:
            raise DataError(f"Row {i}: unknown mfa_method '{method}'. Allowed: {', '.join(methods)}.")
        regs.append(Registration(snap, user, r.get("department") or "Unassigned", acct,
                                 _bool(r.get("enabled", ""), "enabled", i, True), method))
    return regs


def parse_signins(text: str) -> list[SignIn]:
    """Aggregated sign-ins: username, application, client_app, auth_requirement, status, count."""
    out: list[SignIn] = []
    for i, r in _rows(text, ("username", "client_app", "auth_requirement")):
        req = r["auth_requirement"].lower().replace("-", "_").replace(" ", "_")
        if req in ("single_factor", "singlefactor", "single_factor_authentication"):
            single = True
        elif req in ("multifactor", "multi_factor", "multifactor_authentication", "multi_factor_authentication"):
            single = False
        else:
            raise DataError(f"Row {i}: auth_requirement must be single_factor or multifactor, got '{r['auth_requirement']}'.")
        status = (r.get("status") or "success").lower()
        if status not in ("success", "failure"):
            raise DataError(f"Row {i}: status must be success or failure, got '{status}'.")
        try:
            count = int(r.get("count") or 1)
        except ValueError as exc:
            raise DataError(f"Row {i}: count must be a whole number.") from exc
        out.append(SignIn(r["username"], r.get("application") or "Unknown", r["client_app"],
                          single, status == "success", count))
    return out


def load_snapshots(path: str | Path, methods: dict[str, int]) -> list[Registration]:
    return parse_snapshots(Path(path).read_text(encoding="utf-8-sig"), methods)


def load_signins(path: str | Path) -> list[SignIn]:
    return parse_signins(Path(path).read_text(encoding="utf-8-sig"))
