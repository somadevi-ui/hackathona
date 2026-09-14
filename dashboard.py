import json
import hmac
import os
import time
from datetime import datetime, timezone

import pandas as pd
import streamlit as st
import plotly.graph_objects as go

from ai_agent import AIAgent

st.set_page_config(page_title="Nexus | Live SOC", page_icon="N", layout="wide", initial_sidebar_state="collapsed")

ARTIFACT_DIR = "artifacts"


@st.cache_data(ttl=2)
def load_log():
    try:
        rows = []
        with open(f"{ARTIFACT_DIR}/incident_log.jsonl", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    # The simulator may be writing this record during a refresh.
                    continue
        return pd.DataFrame(rows)
    except FileNotFoundError:
        return pd.DataFrame()


@st.cache_data
def load_metrics():
    try:
        with open(f"{ARTIFACT_DIR}/metrics.json") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


@st.cache_data(ttl=2)
def load_review_decisions():
    decisions = {}
    try:
        with open(f"{ARTIFACT_DIR}/review_decisions.jsonl", encoding="utf-8") as decision_file:
            for line in decision_file:
                line = line.strip()
                if not line:
                    continue
                try:
                    decision = json.loads(line)
                except json.JSONDecodeError:
                    continue
                decisions[decision["event_timestamp"]] = decision
    except FileNotFoundError:
        pass
    return decisions


def record_review_decision(event, decision):
    existing_decisions = load_review_decisions()
    event_timestamp = str(event["timestamp"])
    if event_timestamp in existing_decisions:
        return False
    malicious = str(event.get("verdict", "benign")) != "benign"
    review = {
        "event_timestamp": event_timestamp,
        "model_verdict": str(event.get("verdict", "unknown")),
        "model_confidence": float(event.get("confidence", 0)),
        "model_classification": "MALICIOUS" if malicious else "BENIGN",
        "decision": decision,
        "decided_at": datetime.now(timezone.utc).isoformat(),
        "decided_by": "Aniketdubey",
        "action": "ALLOW" if decision == "ALLOW" else "DENY_AND_CONTAIN" if malicious else "DENY_AND_LOG",
    }
    with open(f"{ARTIFACT_DIR}/review_decisions.jsonl", "a", encoding="utf-8") as decision_file:
        decision_file.write(json.dumps(review) + "\n")
    st.cache_data.clear()
    return True


def run_playbook(status, progress):
    steps = [
        "Validating incident confidence",
        "Blocking source address",
        "Isolating affected host",
        "Recording analyst evidence",
        "Containment verified",
    ]
    for index, step in enumerate(steps):
        status.info(f"PLAYBOOK // {step}")
        progress.progress((index + 1) / len(steps), text=f"{step} · {index + 1}/5")
        time.sleep(.55)
    st.session_state.playbook_state = "CONTAINED"
    status.success("Containment complete · simulated action recorded")


@st.fragment(run_every="2s")
def render_live_log_stream():
    live_logs = load_log()
    live_decisions = load_review_decisions()
    st.markdown(f'<div class="section">● Incoming telemetry</div><div class="panel"><div class="stream-banner"><span class="stream-dot"></span> Live log stream <span class="stream-count">{len(live_logs):,} events · auto-refresh 2s</span></div><div class="log-table">Every event is reloaded from the incident log, newest first.</div></div>', unsafe_allow_html=True)
    if live_logs.empty:
        st.info("Waiting for incoming telemetry from simulate_stream.py")
        return
    log_view = live_logs.sort_values("timestamp", ascending=False).copy()
    log_view["details"] = log_view["details"].apply(lambda value: json.dumps(value, separators=(",", ":")) if isinstance(value, dict) else str(value))
    log_view["analyst_decision"] = log_view["timestamp"].astype(str).map(lambda key: live_decisions.get(key, {}).get("decision", ""))
    log_view = log_view.reindex(columns=["timestamp", "verdict", "confidence", "severity", "action", "analyst_decision", "details"])
    st.dataframe(log_view, use_container_width=True, hide_index=True, height=390)


st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
:root { --ink:#edf4ff; --muted:#8495ad; --line:#203858; --panel:#101d33; --bg:#070f1d; --teal:#38d9e8; --amber:#f6bd55; --red:#ff6b7a; --blue:#5d9dff; --violet:#8b7bff; }
.stApp { background:radial-gradient(circle at 82% -10%, #203b68 0, #101d34 25%, var(--bg) 62%); color:var(--ink); font-family:'IBM Plex Mono',monospace; }
html, body, [data-testid="stAppViewContainer"] { overflow-x:hidden; } * { box-sizing:border-box; }
[data-testid="stHeader"] { background:transparent; } [data-testid="stSidebar"] { display:none; }
.block-container { width:100%; max-width:1540px; margin:0 auto; padding:1.15rem 1.45rem 2rem; }
[data-testid="stHorizontalBlock"] { align-items:stretch; gap:.65rem; } [data-testid="stColumn"] { min-width:0; }
.topbar { display:flex; align-items:center; gap:1.2rem; border-bottom:1px solid var(--line); padding:0 .2rem .9rem; }
.sigil { width:42px; height:40px; display:grid; place-items:center; border:1px solid var(--blue); color:var(--blue); font:700 .72rem 'IBM Plex Mono',monospace; letter-spacing:-.12em; background:linear-gradient(135deg,rgba(93,157,255,.16),rgba(56,217,232,.04)); clip-path:polygon(50% 0,94% 14%,88% 72%,50% 100%,12% 72%,6% 14%); box-shadow:0 0 18px rgba(93,157,255,.2),inset 0 0 12px rgba(56,217,232,.08); position:relative; }
.sigil::after { content:""; position:absolute; width:11px; height:7px; left:-5px; top:13px; border-top:1px solid var(--teal); border-radius:70% 0 0 0; transform:skewY(-24deg); }
.brand-name { color:var(--ink); font:700 1.32rem 'Barlow Condensed',sans-serif; letter-spacing:.09em; } .brand-name span { color:var(--blue); }
.brand-sub { color:var(--muted); font-size:.63rem; margin-top:.2rem; letter-spacing:.08em; }
.top-status { margin-left:auto; color:#7cf0c2; font-size:.66rem; text-align:right; letter-spacing:.08em; } .top-status span { color:var(--muted); } .top-status em { color:var(--blue); font-style:normal; font-size:.55rem; }
.nav { display:flex; gap:.5rem; padding:.72rem .2rem .85rem; color:var(--muted); font-size:.65rem; letter-spacing:.08em; text-transform:uppercase; } .nav span, .nav b { padding:.42rem .7rem; } .nav b { color:var(--ink); font-weight:500; background:rgba(93,157,255,.14); border-bottom:1px solid var(--blue); }
[data-testid="stHorizontalBlock"] .stButton button { min-height:2.15rem; }
.rail { background:rgba(10,23,42,.82); border:1px solid var(--line); padding:1rem .85rem; min-height:100%; box-shadow:0 12px 30px rgba(0,0,0,.16); } .rail-title { color:var(--ink); font:600 .86rem 'Barlow Condensed',sans-serif; text-transform:uppercase; letter-spacing:.1em; margin-bottom:1rem; }
.rail-label { color:var(--muted); font-size:.61rem; text-transform:uppercase; letter-spacing:.09em; margin-top:.8rem; } .rail-value { color:var(--ink); font-size:.72rem; border-bottom:1px solid var(--line); padding:.4rem 0 .5rem; }
.section { color:var(--muted); font-size:.63rem; letter-spacing:.14em; text-transform:uppercase; margin:1rem 0 .55rem; }
.panel { background:linear-gradient(145deg,rgba(16,29,51,.94),rgba(10,21,38,.9)); border:1px solid var(--line); padding:.9rem 1rem; min-height:100%; box-shadow:0 12px 30px rgba(0,0,0,.12); } .panel-title { color:var(--ink); font:600 .92rem 'Barlow Condensed',sans-serif; letter-spacing:.08em; text-transform:uppercase; } .panel-kicker { color:var(--muted); font-size:.62rem; margin-top:.2rem; }
.metric-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:.55rem; } .metric { background:linear-gradient(145deg,rgba(18,37,66,.92),rgba(10,22,40,.9)); border:1px solid var(--line); padding:.72rem .85rem; box-shadow:inset 0 1px rgba(255,255,255,.025); } .metric-label { color:var(--muted); font-size:.59rem; text-transform:uppercase; letter-spacing:.08em; } .metric-value { color:var(--ink); font:600 1.7rem 'Barlow Condensed',sans-serif; margin-top:.2rem; } .metric-delta { color:#7cf0c2; font-size:.58rem; } .metric-alert .metric-value { color:var(--red); }
.incident { display:grid; grid-template-columns:1fr .55fr 1.1fr; gap:.35rem; align-items:center; border-bottom:1px solid #1b3150; padding:.58rem 0; font-size:.65rem; } .incident:last-child { border-bottom:0; } .dot { font-size:.7rem; } .high { color:var(--red); } .medium { color:var(--amber); } .low { color:#f4dc61; } .confidence { color:var(--ink); } .action { color:var(--teal); text-align:right; font-size:.56rem; }
.threat-score { color:var(--amber); font:600 2.45rem 'Barlow Condensed',sans-serif; margin-top:.9rem; } .threat-label { color:var(--red); font-size:.68rem; letter-spacing:.1em; } .trend { color:#79f0b7; font-size:.62rem; }
.copilot { color:#c9d7ed; font-size:.68rem; line-height:1.65; margin:1rem 0; } .copilot strong { color:var(--teal); }
.distribution-row { display:grid; grid-template-columns:4rem 1fr 2rem; align-items:center; gap:.45rem; font-size:.62rem; margin:.63rem 0; } .bar { height:5px; background:#1a3151; } .bar i { display:block; height:100%; background:linear-gradient(90deg,var(--blue),var(--violet)); }
.response-row, .mitre-row { display:flex; justify-content:space-between; border-bottom:1px solid #1b3150; padding:.47rem 0; font-size:.63rem; } .response-row:last-child, .mitre-row:last-child { border-bottom:0; } .response-row b { color:var(--teal); font-weight:500; } .mitre-row span { color:var(--amber); } .muted { color:var(--muted); }
.review-card { border:1px solid rgba(246,189,85,.55); background:linear-gradient(145deg,rgba(72,53,23,.28),rgba(16,29,51,.8)); padding:.85rem 1rem; margin-top:.65rem; } .review-badge { color:var(--amber); font-size:.58rem; letter-spacing:.1em; text-transform:uppercase; } .review-status { color:#7cf0c2; font-size:.6rem; letter-spacing:.08em; }
.stButton button { background:linear-gradient(135deg,#174a70,#263b78); border:1px solid #397bc0; color:#d9f8ff; border-radius:3px; font-family:'IBM Plex Mono',monospace; font-size:.65rem; box-shadow:0 5px 15px rgba(40,111,188,.16); }
.topbar { animation:riseIn .55s ease-out both; } .top-status { animation:statusPulse 2.8s ease-in-out infinite; }
.rail, .metric, .panel { animation:riseIn .55s ease-out both; } .metric:nth-child(2) { animation-delay:.06s; } .metric:nth-child(3) { animation-delay:.12s; } .metric:nth-child(4) { animation-delay:.18s; } .metric:nth-child(5) { animation-delay:.24s; }
.panel:hover, .metric:hover { border-color:#397bc0; transform:translateY(-2px); transition:transform .2s ease,border-color .2s ease; }
.signal-field { position:relative; height:42px; margin-top:.9rem; overflow:hidden; border:1px solid #203858; background:linear-gradient(90deg,rgba(93,157,255,.03),rgba(56,217,232,.14),rgba(139,123,255,.03)); }
.signal-field::before { content:""; position:absolute; top:0; bottom:0; left:-12%; width:12%; background:linear-gradient(90deg,transparent,rgba(56,217,232,.8),transparent); animation:scan 3.2s linear infinite; }
.signal-field::after { content:""; position:absolute; inset:12px 5%; background:radial-gradient(circle,#7cf0c2 0 2px,transparent 3px) 0 50%/68px 100% repeat-x; opacity:.7; animation:signalDrift 4s linear infinite; }
.orbit { width:56px; height:56px; margin:1rem auto .7rem; border:1px solid rgba(93,157,255,.7); border-radius:50%; position:relative; animation:orbitSpin 7s linear infinite; box-shadow:0 0 20px rgba(93,157,255,.16); }
.orbit::before, .orbit::after { content:""; position:absolute; border:1px solid rgba(139,123,255,.55); border-radius:50%; inset:8px; } .orbit::after { inset:18px; background:var(--teal); box-shadow:0 0 14px var(--teal); }
.sim-label { color:var(--muted); font-size:.58rem; letter-spacing:.1em; text-transform:uppercase; margin:.7rem 0 .35rem; }
.response-chain { display:grid; grid-template-columns:repeat(5,1fr); gap:.35rem; margin-top:.85rem; } .chain-step { border-top:2px solid var(--blue); padding:.45rem .35rem 0; color:var(--muted); font-size:.56rem; } .chain-step b { display:block; color:var(--ink); font-size:.62rem; margin-bottom:.2rem; }
.map-canvas { position:relative; height:150px; margin-top:.8rem; border:1px solid var(--line); overflow:hidden; background:radial-gradient(circle at 50% 50%,rgba(93,157,255,.15),transparent 35%),linear-gradient(135deg,#0b192d,#0a1425); }
.map-canvas::before { content:""; position:absolute; top:50%; left:18%; right:18%; border-top:1px dashed rgba(93,157,255,.55); transform:rotate(-12deg); animation:pathPulse 1.8s ease-in-out infinite; }
.map-node { position:absolute; display:grid; place-items:center; width:42px; height:42px; border:1px solid var(--blue); border-radius:50%; color:var(--blue); font-size:.48rem; text-align:center; background:#0c1c32; box-shadow:0 0 15px rgba(93,157,255,.28); animation:nodePulse 2s ease-in-out infinite; } .map-node.source { left:8%; top:58%; } .map-node.category { left:44%; top:25%; border-color:var(--amber); color:var(--amber); animation-delay:.35s; } .map-node.target { right:8%; top:48%; border-color:var(--red); color:var(--red); animation-delay:.7s; }
.health-grid, .impact-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:.45rem; margin-top:.8rem; } .health-value, .impact-value { color:var(--ink); font:600 1.35rem 'Barlow Condensed',sans-serif; } .health-label, .impact-label { color:var(--muted); font-size:.53rem; text-transform:uppercase; letter-spacing:.08em; }
.stream-banner { display:flex; align-items:center; gap:.55rem; color:var(--teal); font-size:.6rem; letter-spacing:.1em; text-transform:uppercase; } .stream-dot { width:7px; height:7px; border-radius:50%; background:var(--teal); box-shadow:0 0 0 0 rgba(56,217,232,.7); animation:streamPulse 1.7s infinite; } .stream-count { margin-left:auto; color:var(--muted); font-size:.56rem; }
.log-table { border-top:1px solid var(--line); margin-top:.65rem; padding-top:.2rem; animation:riseIn .5s ease-out both; }
.login-shell { position:relative; max-width:430px; margin:11vh auto 0; padding:1rem 1.5rem; text-align:center; animation:riseIn .5s ease-out both; }
.login-shell::before, .login-shell::after { display:none; } .login-shell > * { position:relative; z-index:1; } .login-shell::marker { display:none; }
.login-shell [data-testid="stForm"] { border:0; padding:0; } .login-shell input { background:transparent; border:0; border-bottom:1px solid #526884; border-radius:0; color:var(--ink); padding-left:0; } .login-shell input:focus { border-bottom-color:var(--teal); box-shadow:0 1px 0 var(--teal); }
.login-mark { position:relative; z-index:1; width:72px; height:78px; display:grid; place-items:center; border:1px solid var(--teal); color:var(--teal); font:700 1rem 'IBM Plex Mono',monospace; letter-spacing:-.15em; background:linear-gradient(145deg,rgba(56,217,232,.12),rgba(93,157,255,.06)); clip-path:polygon(50% 0,94% 14%,88% 72%,50% 100%,12% 72%,6% 14%); box-shadow:0 0 22px rgba(56,217,232,.18); animation:loginPulse 2.4s ease-in-out infinite; }
.login-mark > span:last-child { position:relative; z-index:2; }
.wing-mark { position:absolute; left:9px; top:29px; width:20px; height:16px; border-top:1px solid var(--teal); border-radius:80% 0 0 0; transform:skewY(-24deg) rotate(-8deg); opacity:.9; }
.wing-mark::before, .wing-mark::after { content:""; position:absolute; left:2px; width:16px; border-top:1px solid var(--blue); border-radius:80% 0 0 0; }
.wing-mark::before { top:5px; transform:rotate(8deg); } .wing-mark::after { top:10px; width:11px; transform:rotate(16deg); }
.login-title { position:relative; z-index:1; color:var(--ink); font:600 2rem 'Barlow Condensed',sans-serif; letter-spacing:.06em; margin:.7rem 0 .2rem; } .login-title span { color:var(--blue); } .login-subtitle { position:relative; z-index:1; color:var(--muted); font-size:.65rem; line-height:1.6; margin-bottom:1.2rem; }
.login-meta { display:flex; justify-content:center; gap:.8rem; flex-wrap:wrap; margin:1rem 0 1.35rem; } .login-meta span { color:var(--muted); font-size:.52rem; letter-spacing:.07em; text-transform:uppercase; } .login-meta span:first-child { color:#7cf0c2; }
.login-shell [data-testid="stForm"] label { text-align:left; } .login-shell [data-testid="stFormSubmitButton"] button { margin-top:.45rem; }
.login-note { color:var(--muted); font-size:.58rem; margin-top:1rem; text-align:center; }
.logout-row { display:flex; justify-content:flex-end; margin-top:.45rem; } .logout-row .stButton button { width:auto; padding:.25rem .7rem; font-size:.58rem; }
@keyframes pathPulse { 0%,100% { opacity:.35; } 50% { opacity:1; border-color:var(--red); } } @keyframes nodePulse { 0%,100% { transform:scale(1); } 50% { transform:scale(1.08); } }
@keyframes streamPulse { 0% { box-shadow:0 0 0 0 rgba(56,217,232,.7); } 70% { box-shadow:0 0 0 8px rgba(56,217,232,0); } 100% { box-shadow:0 0 0 0 rgba(56,217,232,0); } }
@keyframes loginScan { 0%,20% { transform:translateX(-100%); } 55%,100% { transform:translateX(100%); } } @keyframes loginOrbit { to { transform:rotate(360deg); } } @keyframes loginPulse { 0%,100% { box-shadow:0 0 18px rgba(56,217,232,.18); } 50% { box-shadow:0 0 30px rgba(56,217,232,.42); } }
@keyframes scan { from { left:-12%; } to { left:110%; } } @keyframes signalDrift { from { transform:translateX(0); } to { transform:translateX(68px); } } @keyframes orbitSpin { to { transform:rotate(360deg); } }
@media (prefers-reduced-motion:reduce) { *, *::before, *::after { animation-duration:.01ms !important; animation-iteration-count:1 !important; } }
@keyframes riseIn { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }
@keyframes statusPulse { 0%,100% { opacity:1; } 50% { opacity:.62; } }
@media (max-width:1200px) { .metric-grid { grid-template-columns:repeat(3,1fr); } }
@media (max-width:900px) { .metric-grid { grid-template-columns:repeat(2,1fr); } .nav { overflow:auto; white-space:nowrap; } .block-container { padding:1rem; } }
@media (max-width:640px) { .block-container { padding:.75rem; } .topbar { gap:.7rem; } .top-status { font-size:.55rem; } .top-status em { font-size:.48rem; } .metric-grid, .health-grid, .impact-grid { grid-template-columns:1fr 1fr; } .response-chain { grid-template-columns:1fr 1fr; } .nav { gap:.15rem; } .nav span, .nav b { padding:.35rem .45rem; font-size:.55rem; } .login-shell { margin:7vh auto 0; padding:1rem .5rem; } }
</style>
""", unsafe_allow_html=True)

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "ai_agent" not in st.session_state:
    st.session_state.ai_agent = AIAgent(
        "Nexus Copilot",
        api_url=os.getenv("FREE_AI_API_URL"),
        api_model=os.getenv("FREE_AI_API_MODEL", "google/flan-t5-small"),
    )
if "ai_response" not in st.session_state:
    st.session_state.ai_response = ""

if not st.session_state.authenticated:
    st.markdown('<div class="login-shell"><div class="login-mark"><span class="wing-mark"></span><span>NX</span></div><div class="login-title">NEXUS <span>// ACCESS</span></div><div class="login-subtitle">Secure operator sign-in for the live security operations console.</div><div class="login-meta"><span>● Channel encrypted</span><span>Local operator mode</span><span>Audit ready</span></div>', unsafe_allow_html=True)
    with st.form("login_form"):
        username = st.text_input("Operator ID", placeholder="Enter operator ID")
        password = st.text_input("Passphrase", type="password", placeholder="Enter passphrase")
        submitted = st.form_submit_button("Sign in to SOC", use_container_width=True)
        if submitted:
            expected_username = "Aniketdubey"
            expected_password = "123456789"
            if hmac.compare_digest(username, expected_username) and hmac.compare_digest(password, expected_password):
                st.session_state.authenticated = True
                st.rerun()
            st.error("Access denied. Check your operator ID and passphrase.")
    st.markdown('<div class="login-note">Demo access is local-only. Response actions remain simulated.</div></div>', unsafe_allow_html=True)
    st.stop()

df = load_log()
total = len(df)
attacks = int((df["verdict"] != "benign").sum()) if total else 0
auto = int(df["action"].fillna("").str.startswith("AUTO_").sum()) if total else 0
blocked = int(df["action"].fillna("").str.contains("BLOCK", case=False).sum()) if total else 0
last_event = "No events yet"
seconds_ago = None
if total:
    last_timestamp = pd.to_datetime(df["timestamp"], utc=True).max()
    seconds_ago = max(0, int((datetime.now(timezone.utc) - last_timestamp.to_pydatetime()).total_seconds()))
    last_event = f"{seconds_ago} sec ago"
stream_state = "LIVE INGEST" if total and seconds_ago < 15 else "READY / AWAITING FEED"
workspace_incident = None
if total and (df["verdict"] != "benign").any():
    workspace_incident = df[df["verdict"] != "benign"].sort_values("timestamp", ascending=False).iloc[0]
review_decisions = load_review_decisions()

st.markdown(f"""
<div class="topbar"><div class="sigil">NX</div><div><div class="brand-name">NEXUS <span>// LIVE SOC</span></div><div class="brand-sub">AI CYBER DEFENSE PLATFORM</div></div><div class="top-status">● SYSTEM ONLINE<br><em>{stream_state}</em><br><span>Last event: {last_event}</span></div></div>
""", unsafe_allow_html=True)

st.markdown('<div class="logout-row">', unsafe_allow_html=True)
if st.button("Sign out", key="logout"):
    st.session_state.authenticated = False
    st.rerun()
st.markdown('</div>', unsafe_allow_html=True)

if "active_view" not in st.session_state:
    st.session_state.active_view = "Overview"
nav_items = [("🏠  Overview", "Overview"), ("⚠  Incident queue", "Incident queue"), ("🗺  Threat map", "Threat map"), ("▶  Response playbooks", "Response playbooks"), ("◈  Model health", "Model health")]
nav_cols = st.columns(len(nav_items))
for nav_col, (nav_label, nav_value) in zip(nav_cols, nav_items):
    with nav_col:
        if st.button(nav_label, key=f"nav_{nav_value}", use_container_width=True):
            st.session_state.active_view = nav_value
            st.rerun()

active_view = st.session_state.active_view
if active_view != "Overview":
    st.markdown(f'<div class="section">Workspace / {active_view}</div>', unsafe_allow_html=True)
    if active_view == "Incident queue":
        queue_count = int((df["verdict"] != "benign").sum()) if len(df) else 0
        incident_name = str(workspace_incident.get("verdict", "unknown")).upper() if workspace_incident is not None else "NONE"
        st.markdown(f'<div class="panel"><div class="panel-title">Incident queue</div><div class="panel-kicker">Prioritized detections awaiting analyst attention</div><div class="signal-field"></div><div class="copilot"><strong>{queue_count}</strong> incidents are currently visible in the filtered feed. High-confidence attacks are ranked first for response review.</div><div class="response-chain"><div class="chain-step"><b>DETECTION</b>{incident_name}</div><div class="chain-step"><b>CONFIDENCE</b>{float(workspace_incident.get("confidence", 0)):.0%}</div><div class="chain-step"><b>SEVERITY</b>{str(workspace_incident.get("severity", "none")).upper()}</div><div class="chain-step"><b>ACTION</b>RECOMMEND</div><div class="chain-step"><b>STATE</b>{st.session_state.get("playbook_state", "READY")}</div></div></div>', unsafe_allow_html=True)
        if queue_count:
            queue_view = df[df["verdict"] != "benign"].sort_values(["severity", "timestamp"], ascending=[True, False]).copy()
            queue_view["review_state"] = queue_view["timestamp"].astype(str).map(lambda key: review_decisions.get(key, {}).get("decision", "PENDING"))
            queue_view = queue_view[["timestamp", "verdict", "confidence", "severity", "action", "review_state"]]
            st.dataframe(queue_view, use_container_width=True, hide_index=True, height=300)
    elif active_view == "Threat map":
        map_details = workspace_incident.get("details", {}) if workspace_incident is not None else {}
        map_category = str(workspace_incident.get("verdict", "normal")).upper() if workspace_incident is not None else "NORMAL"
        st.markdown(f'<div class="panel"><div class="panel-title">Threat map</div><div class="panel-kicker">Live signal topology across the current detection window</div><div class="map-canvas"><div class="map-node source">{map_details.get("src_ip", "SOURCE")}</div><div class="map-node category">{map_category}</div><div class="map-node target">{map_details.get("target_host", "TARGET")}</div></div><div class="copilot">Animated path: <strong>{map_details.get("src_ip", "source")}</strong> → <strong>{map_category}</strong> → <strong>{map_details.get("target_host", "target")}</strong>. Red marks active threats; amber marks suspicious categories; blue marks normal traffic.</div></div>', unsafe_allow_html=True)
    elif active_view == "Response playbooks":
        st.markdown('<div class="panel"><div class="panel-title">Response playbooks</div><div class="panel-kicker">Choose a safe simulated response for the latest detected incident</div><div class="response-row"><span>Contain source</span><b>READY</b></div><div class="response-row"><span>Isolate host</span><b>READY</b></div><div class="response-row"><span>Flag analyst review</span><b>READY</b></div><div class="signal-field"></div><div class="copilot">Actions are simulated and safe. No firewall, host, or account is modified by this demo.</div></div>', unsafe_allow_html=True)
        playbook_action = st.selectbox("Playbook action", ["Rate-limit and block source", "Isolate affected host", "Flag for analyst review"], key="workspace_playbook_action")
        playbook_progress = st.empty()
        playbook_status = st.empty()
        if st.button("Run selected playbook", key="workspace_run_playbook", use_container_width=True):
            run_playbook(playbook_status, playbook_progress)
    else:
        model_status = "Healthy" if total else "Waiting"
        health_metrics = load_metrics()
        st.markdown(f'<div class="panel"><div class="panel-title">Model health</div><div class="panel-kicker">Detection service telemetry</div><div class="orbit"></div><div class="threat-label">{model_status.upper()}</div><div class="health-grid"><div><div class="health-label">Precision</div><div class="health-value">{health_metrics.get("precision", 0):.3f}</div></div><div><div class="health-label">Recall</div><div class="health-value">{health_metrics.get("recall", 0):.3f}</div></div><div><div class="health-label">F1 score</div><div class="health-value">{health_metrics.get("f1_score", 0):.3f}</div></div><div><div class="health-label">Accuracy</div><div class="health-value">{health_metrics.get("accuracy", 0):.3f}</div></div></div><div class="copilot">Random Forest inference is serving the live feed. The system combines supervised detection with human review. Response actions are simulated and safe.</div></div>', unsafe_allow_html=True)
        if os.path.exists(f"{ARTIFACT_DIR}/confusion_matrix.png"):
            st.image(f"{ARTIFACT_DIR}/confusion_matrix.png", caption="Confusion matrix from held-out evaluation")

left, main = st.columns([.72, 3.6], gap="small")
with left:
    st.markdown('<div class="rail"><div class="rail-title">Filter feed</div><div class="rail-label">Window</div><div class="rail-value">Live / latest 300</div>', unsafe_allow_html=True)
    severity_options = ["All severities"] + sorted(df["severity"].dropna().astype(str).unique().tolist()) if "severity" in df else ["All severities"]
    verdict_options = ["All detections"] + sorted(df["verdict"].dropna().astype(str).unique().tolist()) if "verdict" in df else ["All detections"]
    action_options = ["All responses"] + sorted(df["action"].dropna().astype(str).unique().tolist()) if "action" in df else ["All responses"]
    selected_severity = st.selectbox("Severity", severity_options)
    selected_verdict = st.selectbox("Verdict", verdict_options)
    selected_action = st.selectbox("Action", action_options)
    filtered_df = df.copy()
    if selected_severity != "All severities":
        filtered_df = filtered_df[filtered_df["severity"].astype(str) == selected_severity]
    if selected_verdict != "All detections":
        filtered_df = filtered_df[filtered_df["verdict"].astype(str) == selected_verdict]
    if selected_action != "All responses":
        filtered_df = filtered_df[filtered_df["action"].astype(str) == selected_action]
    if st.button("Apply filters", use_container_width=True):
        st.toast(f"Showing {len(filtered_df):,} matching events")
    st.download_button("Export filtered feed", filtered_df.to_csv(index=False), "nexus-feed.csv", "text/csv", use_container_width=True)
    st.markdown('<div style="height:.4rem"></div>', unsafe_allow_html=True)
    if st.button("Refresh feed", use_container_width=True):
        st.cache_data.clear(); st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)
df = filtered_df
total = len(df)
attacks = int((df["verdict"] != "benign").sum()) if total else 0
auto = int(df["action"].fillna("").str.startswith("AUTO_").sum()) if total else 0
blocked = int(df["action"].fillna("").str.contains("BLOCK", case=False).sum()) if total else 0
latest_incident = None
if total and (df["verdict"] != "benign").any():
    latest_incident = df[df["verdict"] != "benign"].sort_values("timestamp", ascending=False).iloc[0]
review_queue = df.sort_values("timestamp", ascending=False) if total else pd.DataFrame()
if "baseline_attacks" not in st.session_state:
    st.session_state.baseline_attacks = attacks
if "playbook_state" not in st.session_state:
    st.session_state.playbook_state = "READY"
with main:
    st.markdown('<div class="section">◈ Operational overview</div>', unsafe_allow_html=True)
    high_risk = int((df.get('severity', pd.Series(dtype=str)) == 'high').sum())
    st.markdown(f'''<div class="metric-grid"><div class="metric"><div class="metric-label">Events processed</div><div class="metric-value">{total:,}</div><div class="metric-delta">+ live feed</div></div><div class="metric metric-alert"><div class="metric-label">Threats detected</div><div class="metric-value">{attacks:,}</div><div class="metric-delta">▲ current window</div></div><div class="metric metric-alert"><div class="metric-label">High risk</div><div class="metric-value">{high_risk:,}</div><div class="metric-delta">requires attention</div></div><div class="metric"><div class="metric-label">Auto actions</div><div class="metric-value">{auto:,}</div><div class="metric-delta">simulated response</div></div><div class="metric"><div class="metric-label">Blocked</div><div class="metric-value">{blocked:,}</div><div class="metric-delta">containment actions</div></div></div>''', unsafe_allow_html=True)

    workload_reduction = round((auto / attacks) * 100) if attacks else 0
    st.markdown(f'<div class="section">Before vs after</div><div class="panel"><div class="panel-title">Business impact</div><div class="panel-kicker">The value of explainable automation in the current rehearsal</div><div class="impact-grid"><div><div class="impact-label">Threats detected</div><div class="impact-value">{attacks:,}</div></div><div><div class="impact-label">Response time</div><div class="impact-value">&lt; 1 sec</div></div><div><div class="impact-label">Auto-contained</div><div class="impact-value">{auto:,}</div></div><div><div class="impact-label">Analyst workload</div><div class="impact-value">-{workload_reduction}%</div></div></div></div>', unsafe_allow_html=True)

    st.markdown('<div class="section">⌁ Signal intelligence</div>', unsafe_allow_html=True)
    activity_col, level_col = st.columns([1.65, 1])
    with activity_col:
        st.markdown('<div class="panel"><div class="panel-title">Threat activity</div><div class="panel-kicker">Events over the latest feed window</div>', unsafe_allow_html=True)
        if total:
            timeline = pd.to_datetime(df["timestamp"], utc=True).dt.floor("10min").value_counts().sort_index()
            fig = go.Figure(go.Scatter(x=timeline.index, y=timeline.values, mode="lines", line=dict(color="#5d9dff", width=2), fill="tozeroy", fillcolor="rgba(93,157,255,.14)"))
            fig.update_layout(height=135, margin=dict(l=0, r=0, t=18, b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#8495ad", family="IBM Plex Mono"), xaxis=dict(showgrid=False, fixedrange=True), yaxis=dict(showgrid=False, fixedrange=True))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.markdown('<div class="muted" style="padding:3rem 0">Waiting for incident telemetry...</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    with level_col:
        threat_level = min(100, round((attacks / total) * 100)) if total else 0
        st.markdown(f'<div class="panel"><div class="panel-title">Threat level</div><div class="threat-score">{threat_level} / 100</div><div class="threat-label">{"HIGH" if threat_level >= 60 else "ELEVATED" if threat_level >= 25 else "LOW"}</div><div class="trend">▲ live feed signal</div></div>', unsafe_allow_html=True)

    st.markdown('<div class="section">▶ Active response</div>', unsafe_allow_html=True)
    incident_col, copilot_col = st.columns([1.65, 1])
    with incident_col:
        rows = []
        if total:
            for _, row in df[df["verdict"] != "benign"].sort_values("timestamp", ascending=False).head(4).iterrows():
                category = str(row["verdict"]).upper()
                severity = str(row.get("severity", "low"))
                action = str(row["action"]).replace("AUTO_", "").replace("_", " ")
                rows.append(f'<div class="incident"><span class="{severity}"><span class="dot">●</span> {category}</span><span class="confidence">{float(row["confidence"]):.0%}</span><span class="action">{action}</span></div>')
        incident_html = "".join(rows) or '<div class="muted" style="padding:1.4rem 0">No active incidents in the current feed.</div>'
        st.markdown(f'<div class="panel"><div class="panel-title">Live incidents</div><div class="panel-kicker">Most recent high-signal detections</div>{incident_html}</div>', unsafe_allow_html=True)
        if latest_incident is not None:
            latest_details = latest_incident.get("details", {})
            feature_keys = ["src_bytes", "protocol", "dst_host_count", "service", "flag"]
            feature_html = "".join(f'<div class="response-row"><span>{feature_key}</span><b>{latest_details.get(feature_key, "n/a")}</b></div>' for feature_key in feature_keys)
            st.markdown(f'<div class="panel"><div class="panel-title">Explainable AI</div><div class="panel-kicker">Top contributing network features for the selected incident</div>{feature_html}</div>', unsafe_allow_html=True)
        if not review_queue.empty:
            review_options = {}
            for review_index, review_row in review_queue.iterrows():
                review_key = str(review_row["timestamp"])
                review_state = review_decisions.get(review_key, {}).get("decision", "PENDING")
                classification = "MALICIOUS" if str(review_row["verdict"]) != "benign" else "BENIGN"
                label = f'{classification} · {str(review_row["verdict"]).upper()} · {float(review_row["confidence"]):.0%} · {review_state} · {review_key[-15:]} · row {review_index}'
                review_options[label] = review_index
            st.markdown(f'<div class="review-card"><div class="review-badge">◉ Review every event</div><div class="copilot">The AI classification is checked before your decision. <strong>{len(review_queue):,}</strong> events are available in the current filtered feed.</div></div>', unsafe_allow_html=True)
            selected_review_label = st.selectbox("Select event to review", list(review_options), key="review_incident")
            selected_review = review_queue.loc[review_options[selected_review_label]]
            selected_review_key = str(selected_review["timestamp"])
            selected_state = review_decisions.get(selected_review_key, {}).get("decision", "PENDING")
            selected_malicious = str(selected_review.get("verdict", "benign")) != "benign"
            classification = "MALICIOUS" if selected_malicious else "BENIGN"
            classification_color = "var(--red)" if selected_malicious else "#7cf0c2"
            deny_action = "DENY_AND_CONTAIN" if selected_malicious else "DENY_AND_LOG"
            st.markdown(f'<div class="review-card"><div class="review-badge">● AI safety check</div><div class="copilot"><strong style="color:{classification_color}">{classification}</strong> · Model verdict: {str(selected_review["verdict"]).upper()}<br>Confidence: {float(selected_review["confidence"]):.0%} · Severity: {str(selected_review.get("severity", "none")).upper()}<br>Recommended action: <strong>{str(selected_review["action"]).replace("_", " ")}</strong><br>Analyst state: <span class="review-status">{selected_state}</span></div></div>', unsafe_allow_html=True)
            review_allow, review_deny = st.columns(2)
            review_widget_key = "_".join(character for character in selected_review_key if character.isalnum())[-24:]
            with review_allow:
                if st.button("✓ Allow this event", key=f"allow_review_{review_widget_key}", use_container_width=True, disabled=selected_state != "PENDING"):
                    recorded = record_review_decision(selected_review, "ALLOW")
                    st.session_state.review_notice = "Analyst decision recorded: ALLOW" if recorded else "This event was already reviewed."
                    st.rerun()
            with review_deny:
                if st.button(f"✕ Deny: {deny_action}", key=f"deny_review_{review_widget_key}", use_container_width=True, disabled=selected_state != "PENDING"):
                    recorded = record_review_decision(selected_review, "DENY")
                    st.session_state.review_notice = f"Analyst decision recorded: {deny_action}" if recorded else "This event was already reviewed."
                    st.rerun()
            if st.session_state.get("review_notice"):
                st.success(st.session_state.pop("review_notice"))
    with copilot_col:
        st.markdown(f'<div class="panel"><div class="panel-title">AI security copilot</div><div class="copilot">"<strong>{high_risk} high-risk incidents</strong><br>detected in the current feed.<br>Response actions are simulated."</div>', unsafe_allow_html=True)

        default_prompt = (
            "Summarize this SOC incident in plain English and recommend the next safe analyst action."
            if latest_incident is not None
            else "Explain how the SOC should prioritize the current threat feed."
        )
        copilot_context = {
            "incident": latest_incident.to_dict() if latest_incident is not None else None,
            "feed": {"event_count": total, "threat_count": attacks},
        }

        with st.form("ai_copilot_form"):
            ai_prompt = st.text_area("Ask the copilot", value=default_prompt, height=120)
            submitted_ai = st.form_submit_button("Generate guidance", use_container_width=True)

        if submitted_ai:
            try:
                response = st.session_state.ai_agent.respond(ai_prompt, context=copilot_context)
                st.session_state.ai_response = response
            except Exception as exc:
                st.session_state.ai_response = f"AI copilot fallback: {exc}"

        if st.session_state.ai_response:
            st.markdown(f"<div class='review-card'><div class='review-badge'>AI OUTPUT</div><div class='copilot'>{st.session_state.ai_response}</div></div>", unsafe_allow_html=True)

        if st.button("Analyze incident", use_container_width=True):
            try:
                st.session_state.ai_response = st.session_state.ai_agent.respond(
                    default_prompt,
                    context=copilot_context,
                )
            except Exception as exc:
                st.session_state.ai_response = f"AI copilot fallback: {exc}"
            st.rerun()
        if latest_incident is not None:
            playbook_progress = st.empty()
            playbook_status = st.empty()
            if st.button("Run playbook", use_container_width=True):
                run_playbook(playbook_status, playbook_progress)
            st.markdown(f'<div class="response-chain"><div class="chain-step"><b>DETECTION</b>{str(latest_incident.get("verdict", "unknown")).upper()}</div><div class="chain-step"><b>CONFIDENCE</b>{float(latest_incident.get("confidence", 0)):.0%}</div><div class="chain-step"><b>SEVERITY</b>{str(latest_incident.get("severity", "none")).upper()}</div><div class="chain-step"><b>RECOMMENDED ACTION</b>{str(latest_incident.get("action", "review")).replace("AUTO_", "").replace("_", " ")}</div><div class="chain-step"><b>CONTAINMENT</b>{st.session_state.playbook_state}</div></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    render_live_log_stream()

    st.markdown('<div class="section">◇ Response intelligence</div>', unsafe_allow_html=True)
    distribution_col, response_col, mitre_col = st.columns([1.2, 1, 1.2])
    counts = df["verdict"].value_counts() if total else pd.Series(dtype=int)
    with distribution_col:
        dist_rows = []
        for name in ["dos", "probe", "r2l", "u2r"]:
            value = int(counts.get(name, 0)); percent = round(value / attacks * 100) if attacks else 0
            dist_rows.append(f'<div class="distribution-row"><span>{name.upper()}</span><span class="bar"><i style="width:{percent}%"></i></span><span>{percent}%</span></div>')
        st.markdown(f'<div class="panel"><div class="panel-title">Attack distribution</div>{"".join(dist_rows)}</div>', unsafe_allow_html=True)
    with response_col:
        action_counts = df["action"].value_counts() if total else pd.Series(dtype=int)
        action_rows = [("Block", int(action_counts[action_counts.index.to_series().str.contains("BLOCK", case=False)].sum())), ("Quarantine", int(action_counts[action_counts.index.to_series().str.contains("ISOLATE|QUARANTINE", case=False, regex=True)].sum())), ("Review", int(action_counts.get("FLAG_FOR_ANALYST_REVIEW", 0))), ("Logged", int(action_counts[action_counts.index.to_series().str.contains("LOG|ALLOW", case=False)].sum()))]
        response_html = "".join(f'<div class="response-row"><span>{label}</span><b>{value}</b></div>' for label, value in action_rows)
        st.markdown(f'<div class="panel"><div class="panel-title">Response activity</div>{response_html}</div>', unsafe_allow_html=True)
    with mitre_col:
        mitre_rows = '<div class="mitre-row"><span>T1498</span><label>Network DoS</label></div><div class="mitre-row"><span>T1110</span><label>Brute Force</label></div><div class="mitre-row"><span>T1046</span><label>Scanning</label></div>'
        st.markdown(f'<div class="panel"><div class="panel-title">MITRE ATT&CK</div>{mitre_rows}</div>', unsafe_allow_html=True)

