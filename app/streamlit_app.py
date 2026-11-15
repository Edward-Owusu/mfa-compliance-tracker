"""Interactive dashboard for the MFA Compliance Tracker.

Run locally:   streamlit run app/streamlit_app.py

Layout: no sidebar. The main screen is a rollout tracker: one progress track per target showing where
coverage is now, where it needs to be, and whether the current pace gets there by the deadline.
Data and targets sit in the top row.
"""

from __future__ import annotations

import sys
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ui  # noqa: E402
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
STATUS_COLOR = {"On track": "#0F766E", "Achieved": "#15803D", "Off track": "#B45309"}
TIER_COLOR = {"None": "#B42318", "Weak (SMS or voice)": "#D97706", "Standard (app or code)": "#0F766E",
              "Phishing-resistant": "#134E4A"}

PAL = ui.Palette(accent="#0F766E", band="#1F2933", band_text="#FFFFFF", band_sub="#B7C4C2",
                 card="#FFFFFF", line="#E2E2DA", ink="#1F2933", muted="#5F6B70")
ui.setup("MFA rollout tracker", "Identity · NIST SP 800-53 IA-2 · CISA phishing-resistant MFA",
         "Load monthly MFA registration snapshots to see whether your rollout is on pace, which teams are lagging, "
         "and where sign-ins still bypass MFA.", "📈", PAL)
st.markdown("""<style>
.track { background:#fff; border:1px solid #E2E2DA; border-radius:12px; padding:14px 18px 12px; margin-bottom:10px }
.track .t { display:flex; justify-content:space-between; font-weight:650; color:#1F2933 }
.rail { position:relative; height:16px; background:#ECEBE4; border-radius:9px; margin:12px 0 8px }
.rail i { position:absolute; left:0; top:0; bottom:0; border-radius:9px }
.rail b { position:absolute; top:-6px; bottom:-6px; width:3px; background:#1F2933; border-radius:2px }
.lb { display:grid; grid-template-columns: 150px 1fr 70px; gap:10px; align-items:center; margin:6px 0; font-size:13.5px }
.lb .bar2 { height:12px; background:#ECEBE4; border-radius:7px; overflow:hidden }
.lb .bar2 i { display:block; height:100% }
</style>""", unsafe_allow_html=True)

policy = load_policy()

# ---- Top row ----------------------------------------------------------------------------------------
t1, t2, t3 = st.columns([1.6, 2.8, 1.2], vertical_alignment="top")
snap_text = sign_text = None
org = "My organization"
with t1:
    st.caption("Data")
    source = ui.choose("Data", ["Use a sample", "Upload my own CSVs"], key="source", format_func=ui.source_label)
with t2:
    if source == "Use a sample":
        st.caption("Sample organization")
        org, sp, gp = SAMPLES[st.selectbox("Sample organization", list(SAMPLES), label_visibility="collapsed")]
        snap_text, sign_text = sp.read_text(encoding="utf-8"), gp.read_text(encoding="utf-8")
    else:
        a, b = st.columns(2)
        up1 = a.file_uploader("MFA snapshots (.csv)", type=["csv"])
        up2 = b.file_uploader("Sign-ins, optional (.csv)", type=["csv"])
        if up1:
            snap_text = up1.getvalue().decode("utf-8-sig", errors="replace")
        if up2:
            sign_text = up2.getvalue().decode("utf-8-sig", errors="replace")
with t3:
    st.caption("Targets")
    with st.popover("Set targets", use_container_width=True):
        policy["coverage_target_pct"] = st.slider("MFA coverage target (%)", 50, 100,
                                                  int(policy["coverage_target_pct"]))
        policy["admin_phishing_resistant_target_pct"] = st.slider(
            "Admin phishing-resistant target (%)", 50, 100, int(policy["admin_phishing_resistant_target_pct"]))
        policy["target_date"] = st.date_input("Target date", policy["target_date"])
        if source != "Use a sample":
            org = st.text_input("Organization name", "My organization")
        st.download_button("Snapshot template", (S / "snapshot_template.csv").read_bytes(),
                           "snapshot_template.csv", "text/csv")
        st.download_button("Sign-in template", (S / "signins_template.csv").read_bytes(),
                           "signins_template.csv", "text/csv")

if snap_text is None:
    st.info("Upload an MFA snapshot file above, or switch to a sample, to see the rollout. Templates and the "
            "organization name are under Set targets.")
    ui.footer("mfa_tracker", __version__, "mfa-compliance-tracker", DISCLAIMER)
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


st.markdown(f"<div class='g-sec'>{escape(result.organization)}</div>", unsafe_allow_html=True)
st.caption(f"{len(result.snapshots)} snapshots, {F.snapshot} to {L.snapshot}. {L.accounts} accounts in the latest "
           f"snapshot.")
ui.tiles([(pct(L.mfa_pct), f"MFA coverage · {L.mfa_pct - F.mfa_pct:+.0f} pts since first"),
          (pct(L.admin_phishing_resistant_pct), "Admins phishing-resistant", "#134E4A"),
          (pct(L.phishing_resistant_pct), "All accounts phishing-resistant", "#134E4A"),
          (pct(result.signins["without_mfa_pct"]) if result.signins["provided"] else "n/a",
           "Sign-ins without MFA", "#B42318")], PAL)

view = ui.choose("View", ["Rollout progress", "Departments", "MFA bypass", "Method strength", "Findings"], key="view")

if view == "Rollout progress":
    ui.section("Progress toward targets", "The bar is where you are now; the black marker is the target.")
    for p in result.projections:
        col = STATUS_COLOR.get(p.status, "#64748B")
        st.markdown(
            f"<div class='track'><div class='t'><span>{escape(p.measure)}</span>"
            f"{ui.pill(p.status, col)}</div><div class='rail'><i style='width:{min(p.current_pct, 100):.0f}%;"
            f"background:{col}'></i><b style='left:calc({min(p.target_pct, 100):.0f}% - 3px)'></b></div>"
            f"<div class='s' style='color:#5F6B70;font-size:13px'><b style='color:#1F2933'>{p.current_pct:.0f}% now"
            f"</b> · target {p.target_pct:.0f}% by {escape(str(p.target_date))}"
            f"{' · projected ' + escape(str(p.projected_date)) if getattr(p, 'projected_date', None) else ''}"
            f" · {escape(p.explanation)}</div></div>", unsafe_allow_html=True)
    ui.section("Coverage over time")
    trend = pd.DataFrame({
        "MFA coverage": [s.mfa_pct for s in result.snapshots],
        "Phishing-resistant, all": [s.phishing_resistant_pct for s in result.snapshots],
        "Phishing-resistant, admins": [s.admin_phishing_resistant_pct for s in result.snapshots],
    }, index=pd.to_datetime([s.snapshot for s in result.snapshots]))
    st.line_chart(trend, y_label="% of accounts", color=["#0F766E", "#B45309", "#475569"])

elif view == "Departments":
    ui.section("Department leaderboard", "Lowest MFA coverage first. The change column is since the first snapshot.")
    rows = []
    for d in sorted(result.departments, key=lambda d: d["mfa_pct"]):
        col = "#15803D" if d["mfa_pct"] >= 100 else "#0F766E" if d["mfa_pct"] >= 80 else "#B45309" \
            if d["mfa_pct"] >= 50 else "#B42318"
        rows.append(f"<div class='lb'><div><b>{escape(d['department'])}</b><br><span style='color:#5F6B70;"
                    f"font-size:12px'>{d['accounts']} accounts · {d['without_mfa']} without MFA</span></div>"
                    f"<div class='bar2'><i style='width:{d['mfa_pct']:.0f}%;background:{col}'></i></div>"
                    f"<div><b>{d['mfa_pct']:.0f}%</b><br><span style='color:#5F6B70;font-size:12px'>"
                    f"{d['change_pts']:+.0f} pts</span></div></div>")
    st.markdown(f"<div class='track'>{''.join(rows)}</div>", unsafe_allow_html=True)
    st.dataframe(pd.DataFrame([{"Department": d["department"], "Accounts": d["accounts"],
                                "MFA %": d["mfa_pct"], "Phishing-resistant %": d["phishing_resistant_pct"],
                                "Change (pts)": d["change_pts"], "Without MFA": d["without_mfa"]}
                               for d in result.departments]), hide_index=True, use_container_width=True)

elif view == "MFA bypass":
    sig = result.signins
    if not sig["provided"]:
        st.info("Upload a sign-in file to see where MFA is bypassed.")
    else:
        ui.section("Where sign-ins skip MFA")
        ui.tiles([(sig["without_mfa"], f"of {sig['successful_sign_ins']} successful sign-ins without MFA", "#B42318"),
                  (sig["legacy_sign_ins"], "through legacy protocols that cannot do MFA", "#B45309"),
                  (sig["failed_legacy_sign_ins"], "failed legacy attempts (possible password spraying)", "#7C2D12")],
                 PAL)
        for b in sig["bypass"]:
            ui.card(f"<div class='h'>{ui.pill('Legacy protocol' if b['legacy'] else 'Single-factor', '#B42318' if b['legacy'] else '#B45309')}"
                    f"{escape(b['client_app'])} → {escape(b['application'])}"
                    f"<span style='float:right'>{b['sign_ins']} sign-in(s)</span></div>",
                    f"<div class='s'>Users: {escape(', '.join(b['users']))}</div>",
                    accent="#B42318" if b["legacy"] else "#B45309")

elif view == "Method strength":
    ui.section("How strong is the MFA people actually use?")
    segs = "".join(f"<i style='display:inline-block;height:100%;width:{m['pct']}%;background:"
                   f"{TIER_COLOR.get(m['tier'], '#64748B')}' title='{escape(m['tier'])}'></i>"
                   for m in result.method_mix)
    st.markdown(f"<div style='height:26px;border-radius:8px;overflow:hidden;display:flex;margin:6px 0 12px'>{segs}"
                f"</div>", unsafe_allow_html=True)
    cols = st.columns(len(result.method_mix) or 1)
    for col, m in zip(cols, result.method_mix):
        col.markdown(f"<div class='g-tile' style='border-top-color:{TIER_COLOR.get(m['tier'], '#64748B')}'>"
                     f"<b>{m['pct']:.0f}%</b><span>{escape(m['tier'])} · {m['accounts']} accounts<br>"
                     f"{escape(m['methods'])}</span></div>", unsafe_allow_html=True)

else:
    groups = grouped_findings(result)
    if not groups:
        st.success("No findings.")
    for g in groups:
        f = g["finding"]
        n = len(g["accounts"])
        details = "".join(f"<li>{escape(d)}</li>" for d in g["details"])
        ui.card(f"<div class='h'>{ui.sev_pill(f.severity)}{escape(f.rule_id)} · {escape(f.title)}"
                f"<span class='s' style='float:right'>{n} account(s)</span></div>",
                f"<ul class='s' style='margin:4px 0 6px 18px;padding:0'>{details}</ul>"
                f"<div class='f'><b>Fix:</b> {escape(f.remediation)}</div>"
                f"<div class='s'>Controls {escape(', '.join(f.controls))}</div>", accent=ui.SEV_COLORS[f.severity])

ui.downloads([("HTML report", to_html(result), "mfa_rollout_report.html", "text/html"),
              ("Markdown", to_markdown(result), "mfa_rollout_report.md", "text/markdown"),
              ("CSV findings", to_csv(result), "mfa_findings.csv", "text/csv"),
              ("JSON results", to_json(result), "mfa_results.json", "application/json")])
ui.footer("mfa_tracker", __version__, "mfa-compliance-tracker", DISCLAIMER)
