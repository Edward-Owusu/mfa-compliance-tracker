"""Interactive dashboard for the MFA Compliance Tracker.

Run locally:   streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mfa_tracker import __version__, analyze, load_policy, parse_signins, parse_snapshots  # noqa: E402
from mfa_tracker.loader import DataError  # noqa: E402
from mfa_tracker.reporting import DISCLAIMER, grouped_findings, to_csv, to_html, to_json, to_markdown  # noqa: E402

S = ROOT / "samples"
SAMPLES = {
    "Small manufacturer mid-rollout (fictional)":
        ("Riverbend Components (fictional)", S / "riverbend_mfa_snapshots.csv", S / "riverbend_signins.csv"),
    "Cold storage warehouse, rollout complete (fictional)":
        ("Northfield Cold Logistics (fictional)", S / "northfield_mfa_snapshots.csv", S / "northfield_signins.csv"),
}
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

st.set_page_config(page_title="MFA Compliance Tracker", page_icon="📈", layout="wide")
st.title("MFA rollout tracker")
st.write(
    "Load monthly MFA registration snapshots to see whether your rollout is on pace, which teams are "
    "lagging, and where sign-ins still bypass MFA. Findings map to NIST SP 800-53 controls."
)

policy = load_policy()
with st.sidebar:
    st.header("1. Choose data")
    source = st.radio("Data", ["Use a sample", "Upload my own CSVs"], label_visibility="collapsed")
    snap_text = sign_text = None
    org = "My organization"
    if source == "Use a sample":
        org, sp, gp = SAMPLES[st.selectbox("Sample organization", list(SAMPLES))]
        snap_text, sign_text = sp.read_text(encoding="utf-8"), gp.read_text(encoding="utf-8")
    else:
        up1 = st.file_uploader("MFA snapshots (.csv)", type=["csv"])
        up2 = st.file_uploader("Sign-ins, optional (.csv)", type=["csv"])
        st.download_button("Snapshot template", (S / "snapshot_template.csv").read_bytes(),
                           "snapshot_template.csv", "text/csv")
        st.download_button("Sign-in template", (S / "signins_template.csv").read_bytes(),
                           "signins_template.csv", "text/csv")
        org = st.text_input("Organization name", "My organization")
        if up1:
            snap_text = up1.getvalue().decode("utf-8-sig", errors="replace")
        if up2:
            sign_text = up2.getvalue().decode("utf-8-sig", errors="replace")

    st.header("2. Set targets")
    policy["coverage_target_pct"] = st.slider("MFA coverage target (%)", 50, 100, int(policy["coverage_target_pct"]))
    policy["admin_phishing_resistant_target_pct"] = st.slider(
        "Admin phishing-resistant target (%)", 50, 100, int(policy["admin_phishing_resistant_target_pct"]))
    policy["target_date"] = st.date_input("Target date", policy["target_date"])
    st.caption(f"mfa_tracker {__version__}. Runs entirely in this session; uploaded files are not stored.")

if snap_text is None:
    st.info("Upload an MFA snapshot file in the sidebar, or switch to a sample, to see results.")
    st.stop()

try:
    regs = parse_snapshots(snap_text, policy["methods"])
    signins = parse_signins(sign_text) if sign_text else None
except DataError as exc:
    st.error(f"A file could not be read. {exc} Fix the file and upload it again.")
    st.stop()

result = analyze(regs, signins, org, policy)
L, F = result.latest, result.first


def pct(v):
    return "n/a" if v is None else f"{v:.0f}%"


st.subheader(result.organization)
st.caption(f"{len(result.snapshots)} snapshots, {F.snapshot} to {L.snapshot}. {L.accounts} accounts in the latest snapshot.")

c1, c2, c3, c4 = st.columns(4)
c1.metric("MFA coverage", pct(L.mfa_pct), f"{L.mfa_pct - F.mfa_pct:+.0f} pts since first")
c2.metric("Admins phishing-resistant", pct(L.admin_phishing_resistant_pct))
c3.metric("All accounts phishing-resistant", pct(L.phishing_resistant_pct))
c4.metric("Sign-ins without MFA", pct(result.signins["without_mfa_pct"]) if result.signins["provided"] else "n/a",
          delta_color="off")

st.markdown("#### Progress toward targets")
for p in result.projections:
    msg = f"**{p.measure}:** {p.current_pct:.0f}% now, target {p.target_pct:.0f}% by {p.target_date}. {p.explanation}"
    {"On track": st.success, "Achieved": st.success, "Off track": st.warning}.get(p.status, st.info)(
        f"{p.status}. {msg}")

st.markdown("#### Coverage over time")
trend = pd.DataFrame({
    "MFA coverage": [s.mfa_pct for s in result.snapshots],
    "Phishing-resistant, all": [s.phishing_resistant_pct for s in result.snapshots],
    "Phishing-resistant, admins": [s.admin_phishing_resistant_pct for s in result.snapshots],
}, index=pd.to_datetime([s.snapshot for s in result.snapshots]))
st.line_chart(trend, y_label="% of accounts", color=["#0F766E", "#B45309", "#475569"])

tab_f, tab_b, tab_d, tab_m = st.tabs(["Findings", "MFA bypass", "Departments", "Method strength"])
with tab_f:
    groups = grouped_findings(result)
    if not groups:
        st.success("No findings.")
    for g in groups:
        f = g["finding"]
        n = len(g["accounts"])
        label = f"{SEVERITY_ICON[f.severity]} {f.severity.title()}: {f.rule_id} {f.title}"
        if n:
            label += f" ({n} account{'s' if n != 1 else ''})"
        with st.expander(label):
            st.markdown(f"**Controls:** {', '.join(f.controls)}")
            for d in g["details"]:
                st.markdown(f"- {d}")
            st.markdown(f"**Remediation:** {f.remediation}")
with tab_b:
    sig = result.signins
    if not sig["provided"]:
        st.info("Upload a sign-in file to see where MFA is bypassed.")
    else:
        st.write(f"{sig['without_mfa']} of {sig['successful_sign_ins']} successful sign-ins completed without MFA, "
                 f"including {sig['legacy_sign_ins']} through legacy protocols that cannot perform MFA.")
        if sig["failed_legacy_sign_ins"]:
            st.warning(f"{sig['failed_legacy_sign_ins']} failed sign-in attempts used legacy protocols, a common "
                       "sign of password spraying.")
        if sig["bypass"]:
            st.dataframe(pd.DataFrame([{"Client": b["client_app"], "Application": b["application"],
                                        "Type": "Legacy protocol" if b["legacy"] else "Modern, single-factor",
                                        "Sign-ins": b["sign_ins"], "Users": ", ".join(b["users"])}
                                       for b in sig["bypass"]]), hide_index=True)
with tab_d:
    st.dataframe(pd.DataFrame([{"Department": d["department"], "Accounts": d["accounts"],
                                "MFA %": d["mfa_pct"], "Phishing-resistant %": d["phishing_resistant_pct"],
                                "Change (pts)": d["change_pts"], "Without MFA": d["without_mfa"]}
                               for d in result.departments]), hide_index=True)
with tab_m:
    mix = pd.DataFrame([{"Strength": m["tier"], "Accounts": m["accounts"]} for m in result.method_mix]).set_index("Strength")
    st.bar_chart(mix, color="#0F766E", horizontal=True)
    st.dataframe(pd.DataFrame([{"Strength": m["tier"], "Accounts": m["accounts"], "Share %": m["pct"],
                                "Methods": m["methods"]} for m in result.method_mix]), hide_index=True)

st.subheader("Download the report")
d1, d2, d3, d4 = st.columns(4)
d1.download_button("HTML report", to_html(result), "mfa_rollout_report.html", "text/html")
d2.download_button("Markdown", to_markdown(result), "mfa_rollout_report.md", "text/markdown")
d3.download_button("CSV findings", to_csv(result), "mfa_findings.csv", "text/csv")
d4.download_button("JSON results", to_json(result), "mfa_results.json", "application/json")
st.caption(DISCLAIMER)
