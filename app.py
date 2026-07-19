import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pandas as pd
import psutil
import streamlit as st

from utils.security import REQUESTS_TOTAL, SecurityGuard, start_metrics_server

start_metrics_server(port=8000)

guard = SecurityGuard()

# Page Configuration
st.set_page_config(
    page_title="MHcheck Stress Tester Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Dark Futuristic Theme with Crimson Accents)
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@500;600;700&display=swap');

/* Base layout settings */
.stApp {
    background-color: #0b0c10;
    color: #c5c6c7;
}

/* Custom header */
.custom-header {
    background: linear-gradient(135deg, #1f2833 0%, #0b0c10 100%);
    padding: 1.5rem;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(255, 75, 75, 0.15);
    border: 1px solid rgba(255, 75, 75, 0.3);
    text-align: center;
    margin-bottom: 2rem;
}

.custom-header h1 {
    font-family: 'Orbitron', sans-serif;
    color: #ff4c4c;
    font-weight: 900;
    letter-spacing: 2px;
    margin: 0;
    text-shadow: 0 0 10px rgba(255, 76, 76, 0.4);
}

.custom-header p {
    font-family: 'Rajdhani', sans-serif;
    color: #66fcf1;
    font-size: 1.1rem;
    margin-top: 0.5rem;
    margin-bottom: 0;
    font-weight: 600;
    letter-spacing: 1px;
}

/* Custom card wrapper */
.glass-card {
    background: rgba(31, 41, 55, 0.4);
    border-radius: 12px;
    padding: 1.5rem;
    border: 1px solid rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(10px);
    margin-bottom: 1.5rem;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
}

/* Metrics widgets */
.metric-row {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.metric-col {
    flex: 1;
    background: rgba(26, 30, 40, 0.85);
    border-radius: 10px;
    padding: 1rem;
    border: 1px solid rgba(255, 76, 76, 0.25);
    box-shadow: 0 0 15px rgba(255, 76, 76, 0.05);
    text-align: center;
}

.metric-lbl {
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.9rem;
    color: #8b9bb4;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.metric-val {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.6rem;
    color: #ff4c4c;
    font-weight: 700;
    margin-top: 0.3rem;
    text-shadow: 0 0 8px rgba(255, 76, 76, 0.4);
}

.metric-val-cyan {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.6rem;
    color: #66fcf1;
    font-weight: 700;
    margin-top: 0.3rem;
    text-shadow: 0 0 8px rgba(102, 252, 241, 0.4);
}

.status-indicator {
    font-weight: bold;
    padding: 4px 10px;
    border-radius: 4px;
    text-transform: uppercase;
}

.status-active {
    background-color: rgba(255, 76, 76, 0.2);
    color: #ff4c4c;
    border: 1px solid #ff4c4c;
}

.status-idle {
    background-color: rgba(102, 252, 241, 0.2);
    color: #66fcf1;
    border: 1px solid #66fcf1;
}

/* Sidebar adjustments */
[data-testid="stSidebar"] {
    background-color: #1f2833;
    border-right: 1px solid rgba(255, 76, 76, 0.2);
}

/* Tab design styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 24px;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.1rem;
    font-weight: bold;
    color: #c5c6c7 !important;
}
.stTabs [aria-selected="true"] {
    color: #ff4c4c !important;
    border-bottom-color: #ff4c4c !important;
}
</style>
""", unsafe_allow_html=True)

# Header Section
st.markdown("""
<div class="custom-header">
    <h1>🛡️ MHCHECK STRESS TESTER</h1>
    <p>PREMIUM CONTROL DASHBOARD & REAL-TIME VISUALIZER</p>
</div>
""", unsafe_allow_html=True)

# Helper Class definitions in case direct imports fail
try:
    from start import Methods, ToolsConsole, ping
except ImportError:
    class Methods:
        LAYER7_METHODS = {
            "CFB", "BYPASS", "GET", "POST", "OVH", "STRESS", "DYN", "SLOW", "HEAD",
            "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB", "AVB", "CFBUAM",
            "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER", "TOR", "RHEX", "STOMP"
        }
        LAYER4_METHODS = {
            "MEM", "NTP", "DNS", "ARD", "CLDAP", "CHAR", "RDP",
            "TCP", "UDP", "SYN", "VSE", "MINECRAFT",
            "MCBOT", "CONNECTION", "CPS", "FIVEM", "FIVEM-TOKEN",
            "TS3", "MCPE", "ICMP", "OVH-UDP"
        }
        ALL_METHODS = LAYER7_METHODS.union(LAYER4_METHODS)
    ping = None
    ToolsConsole = None

# OSINT Wrappers
import os as _os

from utils import auth, storage
from utils.config_model import load_config
from utils.osint.cyber_analysis import CyberAnalysisAdapter
from utils.osint.nmap_wrapper import NmapAdapter
from utils.osint.shodan_client import ShodanAdapter
from utils.osint.theharvester_wrapper import TheHarvesterAdapter
from utils.osint.wpscan_wrapper import WPScanAdapter
from utils.scoring import score_findings


def _auth_gate():
    """Optional login wall. Active when MHCHECK_AUTH_ENABLED is truthy or users exist.

    In open mode (no users, flag unset) the dashboard behaves as before, so this
    never locks out an existing deployment until auth is intentionally enabled.
    """
    flag = _os.getenv("MHCHECK_AUTH_ENABLED", "").lower() in ("1", "true", "yes")
    auth.bootstrap_admin()
    enabled = flag or bool(auth.list_users())
    if not enabled:
        return None

    import extra_streamlit_components as stx
    if "cookie_manager" not in st.session_state:
        st.session_state["cookie_manager"] = stx.CookieManager()

    cookie_manager = st.session_state["cookie_manager"]
    cookie_token = cookie_manager.get(cookie="mhcheck_session")

    if st.session_state.get("auth_user"):
        user = st.session_state["auth_user"]
        signed_token = auth.sign_session(user["username"], user["tenant"], user["role"])
        if cookie_token != signed_token:
            cookie_manager.set(cookie="mhcheck_session", val=signed_token, key="set_cookie_session")
        with st.sidebar:
            st.caption(f"👤 {user['username']} ({user['role']} · {user['tenant']})")
            if st.button("Log out", key="logout_btn"):
                cookie_manager.delete(cookie="mhcheck_session", key="del_cookie_session")
                del st.session_state["auth_user"]
                st.rerun()
        return user

    if cookie_token:
        verified = auth.verify_session(cookie_token)
        if verified:
            st.session_state["auth_user"] = verified.model_dump()
            st.rerun()

    st.markdown("<h2 style='text-align:center;color:#66fcf1;'>🔐 MHcheck Audit Platform</h2>", unsafe_allow_html=True)
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        user = auth.authenticate(username, password)
        if user:
            st.session_state["auth_user"] = user.model_dump()
            signed_token = auth.sign_session(user.username, user.tenant, user.role)
            cookie_manager.set(cookie="mhcheck_session", val=signed_token, key="set_cookie_login")
            st.rerun()
        else:
            st.error("Invalid credentials.")
    st.stop()


_current_user = _auth_gate()

# Parsers to convert formatted strings back to float numbers
def parse_human_number(s):
    s = s.strip().lower()
    if not s:
        return 0.0
    multiplier = 1.0
    if s.endswith('k'):
        multiplier = 1000.0
        s = s[:-1]
    elif s.endswith('m'):
        multiplier = 1000000.0
        s = s[:-1]
    elif s.endswith('g'):
        multiplier = 1000000000.0
        s = s[:-1]
    try:
        return float(s) * multiplier
    except ValueError:
        return 0.0

def parse_human_bytes(s):
    s = s.strip().lower()
    if not s or s in ('-- b', '--', '0 b', '0'):
        return 0.0
    parts = s.split()
    if len(parts) < 2:
        match = re.match(r"([0-9.]+)\s*([a-z]+)", s)
        if match:
            val_str = match.group(1)
            unit_str = match.group(2)
        else:
            try:
                return float(s)
            except ValueError:
                return 0.0
    else:
        val_str, unit_str = parts[0], parts[1]

    try:
        val = float(val_str)
    except ValueError:
        return 0.0

    multiplier = 1.0
    if 'kb' in unit_str or 'k' == unit_str:
        multiplier = 1024.0
    elif 'mb' in unit_str or 'm' == unit_str:
        multiplier = 1024.0 * 1024.0
    elif 'gb' in unit_str or 'g' == unit_str:
        multiplier = 1024.0 * 1024.0 * 1024.0
    elif 'tb' in unit_str or 't' == unit_str:
        multiplier = 1024.0 * 1024.0 * 1024.0 * 1024.0

    return val * multiplier

# Thread-safe attack runner & status tracker class
class AttackState:
    def __init__(self):
        self.running = False
        self.process = None
        self.logs = []
        self.metrics_history = []
        self.current_metrics = {"pps": "0", "bps": "0 B", "progress": 0.0}
        self.target = ""
        self.method = ""
        self.duration = 60
        self.start_time = 0.0
        self.lock = threading.Lock()

    def reset(self):
        with self.lock:
            if self.process:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=1.0)
                except Exception:
                    try:
                        self.process.kill()
                    except Exception:
                        pass
            self.running = False
            self.process = None
            self.logs = []
            self.metrics_history = []
            self.current_metrics = {"pps": "0", "bps": "0 B", "progress": 0.0}
            self.target = ""
            self.method = ""
            self.duration = 60
            self.start_time = 0.0

# Initialize Session State
if "attack_state" not in st.session_state:
    st.session_state.attack_state = AttackState()

state = st.session_state.attack_state

def monitor_subprocess(process, state_obj):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    # Regex matching: Target: ..., Port: ..., Method: ... PPS: ..., BPS: ... / 12%
    metric_pattern = re.compile(
        r'Target:\s*(?P<target>.*?),\s*Port:\s*(?P<port>\d+),\s*Method:\s*(?P<method>\w+)\s*PPS:\s*(?P<pps>[^\s,]+),\s*BPS:\s*(?P<bps>[^\s,]+)\s*/\s*(?P<pct>\d+(?:\.\d+)?)%'
    )

    # Read output line by line
    for line in iter(process.stdout.readline, ''):
        if not line:
            break
        clean_line = ansi_escape.sub('', line).strip()
        if not clean_line:
            continue

        with state_obj.lock:
            state_obj.logs.append(clean_line)
            if len(state_obj.logs) > 500:
                state_obj.logs.pop(0)

            # Parse metrics
            match = metric_pattern.search(clean_line)
            if match:
                pps_str = match.group('pps')
                bps_str = match.group('bps')
                pct_val = float(match.group('pct'))

                pps_val = parse_human_number(pps_str)
                bps_val = parse_human_bytes(bps_str)

                elapsed = time.time() - state_obj.start_time
                state_obj.metrics_history.append({
                    "Elapsed (s)": round(elapsed, 1),
                    "PPS": pps_val,
                    "BPS (MB/s)": round(bps_val / (1024 * 1024), 2),
                    "Progress %": pct_val
                })
                state_obj.current_metrics = {
                    "pps": pps_str,
                    "bps": bps_str,
                    "progress": pct_val
                }

    process.wait()
    with state_obj.lock:
        state_obj.running = False
        state_obj.process = None
        state_obj.logs.append("--- Stress Test Execution Finished ---")

def launch_attack_process(cmd_args, target, method, duration):
    state.reset()

    # Detect the correct python executable from current virtual environment
    python_bin = sys.executable
    if not python_bin or "venv" not in python_bin:
        venv_py = Path(__file__).parent / "venv" / "bin" / "python"
        if venv_py.exists():
            python_bin = str(venv_py)
        else:
            python_bin = "python3"

    full_cmd = [python_bin, "start.py"] + cmd_args

    try:
        proc = subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        state.process = proc
        state.running = True
        state.target = target
        state.method = method
        state.duration = duration
        state.start_time = time.time()
        state.logs = [f"Launching subprocess: {' '.join(full_cmd)}"]

        t = threading.Thread(target=monitor_subprocess, args=(proc, state), daemon=True)
        t.start()
        return True
    except Exception as e:
        state.logs = [f"Failed to launch: {e}"]
        return False

# ================= SIDEBAR CONFIGURATION =================
st.sidebar.markdown("""
<div style="text-align: center; margin-bottom: 1rem;">
    <h3 style="color: #ff4c4c; font-family: 'Orbitron'; margin:0;">⚙️ OPTIONS</h3>
</div>
""", unsafe_allow_html=True)


PRESETS = {
    "None": {},
    "Layer 7 Bypass CF": {"layer": "Layer 7 (Application)", "method": "BYPASS", "duration": 120, "threads": 200, "socks_type": "5 - SOCKS5", "rpc": 50},
    "Layer 4 UDP Flood": {"layer": "Layer 4 (Transport / Network)", "method": "UDP", "duration": 300, "threads": 500, "l4_mode": "Direct (No Proxies / Reflector)"},
}

# Extract Preset if Selected
selected_preset = st.sidebar.selectbox('Load Preset (Optional)', list(PRESETS.keys()))
pz = PRESETS[selected_preset]

# Select layer
layer_index = 0 if pz.get("layer", "Layer 7 (Application)") == "Layer 7 (Application)" else 1
layer = st.sidebar.radio("Select Layer", ["Layer 7 (Application)", "Layer 4 (Transport / Network)"], index=layer_index)

# Dynamically populate methods
if layer == "Layer 7 (Application)":
    methods_list = sorted(list(Methods.LAYER7_METHODS))
else:
    methods_list = sorted(list(Methods.LAYER4_METHODS))

method_index = methods_list.index(pz["method"]) if "method" in pz and pz["method"] in methods_list else 0
method = st.sidebar.selectbox("Attack Method", methods_list, index=method_index)

# Inputs
target_input = st.sidebar.text_input("Target URL / Host", placeholder="http://example.com" if layer == "Layer 7 (Application)" else "1.1.1.1:80")
duration = st.sidebar.number_input("Duration (seconds)", min_value=10, max_value=86400, value=pz.get("duration", 60), step=10)
threads = st.sidebar.slider("Threads", min_value=1, max_value=2000, value=pz.get("threads", 100), step=10)

# Layer 7 settings
if layer == "Layer 7 (Application)":
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Layer 7 Parameters**")
    s_types = ["0 - ALL", "1 - HTTP", "4 - SOCKS4", "5 - SOCKS5", "6 - RANDOM"]
    socks_type = st.sidebar.selectbox("Socks Type", s_types, index=s_types.index(pz.get("socks_type", "5 - SOCKS5")))
    socks_val = socks_type.split(" - ")[0]

    proxy_file = st.sidebar.text_input("Proxy File Name", value="http.txt", placeholder="e.g. proxy.txt")
    rpc = st.sidebar.slider("RPC (Request Pre Connection)", min_value=1, max_value=150, value=1, step=1)

# Layer 4 settings
else:
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Layer 4 Parameters**")
    l4_mode = st.sidebar.selectbox(
        "Layer 4 Mode",
        ["Direct (No Proxies / Reflector)", "Proxied Attack", "Amplification (Reflector)"]
    )

    socks_val = "5" # default
    proxy_file = ""
    reflector_file = ""

    if l4_mode == "Proxied Attack":
        socks_type = st.sidebar.selectbox(
            "Socks Type",
            ["0 - ALL", "1 - HTTP", "4 - SOCKS4", "5 - SOCKS5", "6 - RANDOM"],
            index=3
        )
        socks_val = socks_type.split(" - ")[0]
        proxy_file = st.sidebar.text_input("Proxy File Name", value="proxy.txt")
    elif l4_mode == "Amplification (Reflector)":
        reflector_file = st.sidebar.text_input("Reflector File Name (in files/)", value="dns.txt")

# Prepare CLI arguments list based on input parameters
cmd_args = []
target_val = target_input.strip()

# Set up launching logic
start_disabled = not target_val or state.running

if st.sidebar.button("💥 LAUNCH STRESS TEST", use_container_width=True, disabled=start_disabled, type="primary"):
    # Target validation
    if layer == "Layer 7 (Application)":
        if not target_val.startswith("http"):
            target_val = "http://" + target_val
        cmd_args = [method, target_val, socks_val, str(threads), proxy_file, str(rpc), str(duration)]
    else:
        # L4 Target IP:Port format check
        if ":" not in target_val:
            st.error("Layer 4 targets require a Port specification. Format: IP:PORT (e.g. 1.1.1.1:80)")
        else:
            if not target_val.startswith("http"):
                # URL parsing in start.py parses from urlraw
                target_url_fmt = "http://" + target_val
            else:
                target_url_fmt = target_val

            if l4_mode == "Direct (No Proxies / Reflector)":
                cmd_args = [method, target_url_fmt, str(threads), str(duration)]
            elif l4_mode == "Proxied Attack":
                cmd_args = [method, target_url_fmt, str(threads), str(duration), socks_val, proxy_file]
            else:
                cmd_args = [method, target_url_fmt, str(threads), str(duration), reflector_file]

    if cmd_args:
        is_safe, reason = guard.check_safe_to_run(threads)
        if not is_safe:
            st.error(f"Security Alert: Cannot start test. {reason}")
        else:
            success = launch_attack_process(cmd_args, target_val, method, duration)
            if success:
                st.toast("Stress test launched successfully!", icon="🔥")

                # Simple heuristic metric tracking for demonstration
                from utils.common import Methods
                layer = "7" if method in Methods.LAYER7_METHODS else "4"
                REQUESTS_TOTAL.labels(method=method, layer=layer).inc()
            else:
                st.error("Failed to launch stress test subprocess.")

if state.running:
    if st.sidebar.button("🛑 STOP / ABORT TEST", use_container_width=True, type="secondary"):
        state.reset()
        st.toast("Stress test aborted!", icon="🛑")
        st.rerun()


# ================= MAIN PAGE LAYOUT =================
tab1, tab2, tab5, tab7, tab3, tab4, tab6 = st.tabs([
    "🖥️ Stress Tester",
    "🛠️ Network Utilities",
    "🔍 OSINT Tools",
    "📋 Assets & Fleet",
    "📋 Live Console Logs",
    "🛡️ Proxy Manager",
    "⚙️ Configuration"
])

with tab1:
    # Status card container
    status_label = "RUNNING" if state.running else "IDLE"
    status_class = "status-active" if state.running else "status-idle"

    st.markdown(f"""
    <div class="glass-card">
        <h3 style="margin-top:0; color:#fafafa; font-family:'Orbitron';">Execution Status: <span class="status-indicator {status_class}">{status_label}</span></h3>
        <p style="color:#a9b2c3; margin-bottom:0;">Configure parameters in the sidebar and trigger the stress test. Real-time parsed metrics and interactive charts will load below.</p>
    </div>
    """, unsafe_allow_html=True)


    # System Resource Monitor
    st.markdown("<h4 style='font-family: Orbitron; color: #ff4c4c; margin-top: 1.5rem;'>📠 HOST HEALTH</h4>", unsafe_allow_html=True)
    c_cpu, c_mem = st.columns(2)
    with c_cpu:
        st.metric(label="CPU Utilization", value=f"{psutil.cpu_percent()}%")
    with c_mem:
        st.metric(label="Memory Utilization", value=f"{psutil.virtual_memory().percent}%")

    # KPIs Grid
    c_tgt, c_mth, c_pps, c_bps, c_rem = st.columns(5)

    with c_tgt:
        st.markdown(f"""
        <div class="metric-col">
            <div class="metric-lbl">Target Host</div>
            <div class="metric-val-cyan" style="font-size:1.1rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="{state.target if state.target else 'N/A'}">
                {state.target if state.target else 'N/A'}
            </div>
        </div>
        """, unsafe_allow_html=True)

    with c_mth:
        st.markdown(f"""
        <div class="metric-col">
            <div class="metric-lbl">Method</div>
            <div class="metric-val-cyan">{state.method if state.method else 'N/A'}</div>
        </div>
        """, unsafe_allow_html=True)

    with c_pps:
        st.markdown(f"""
        <div class="metric-col">
            <div class="metric-lbl">Packets Per Sec</div>
            <div class="metric-val">{state.current_metrics['pps']}</div>
        </div>
        """, unsafe_allow_html=True)

    with c_bps:
        st.markdown(f"""
        <div class="metric-col">
            <div class="metric-lbl">Bandwidth / Sec</div>
            <div class="metric-val">{state.current_metrics['bps']}</div>
        </div>
        """, unsafe_allow_html=True)

    with c_rem:
        if state.running:
            remaining = max(0.0, state.duration - (time.time() - state.start_time))
            remaining_str = f"{int(remaining)}s"
        else:
            remaining_str = "0s"
        st.markdown(f"""
        <div class="metric-col">
            <div class="metric-lbl">Time Remaining</div>
            <div class="metric-val-cyan">{remaining_str}</div>
        </div>
        """, unsafe_allow_html=True)

    # Progress bar
    if state.running:
        pct = min(100.0, state.current_metrics['progress'])
        st.progress(pct / 100.0, text=f"Duration Progress: {pct}%")
    else:
        st.progress(0.0, text="Inactive")

    # Metrics Charts
    if state.metrics_history:
        st.markdown("<h4 style='font-family: Orbitron; color: #ff4c4c; margin-top: 1.5rem;'>📈 REAL-TIME PERFORMANCE LOGS</h4>", unsafe_allow_html=True)
        df = pd.DataFrame(state.metrics_history)

        col_chart1, col_chart2 = st.columns(2)
        with col_chart1:
            st.markdown("<p style='text-align:center; font-weight:bold; color:#ff4c4c;'>PPS (Packets / Requests Per Second)</p>", unsafe_allow_html=True)
            st.line_chart(df, x="Elapsed (s)", y="PPS", color="#ff4c4c", height=300)

        with col_chart2:
            st.markdown("<p style='text-align:center; font-weight:bold; color:#66fcf1;'>Bandwidth (MB/s)</p>", unsafe_allow_html=True)
            st.line_chart(df, x="Elapsed (s)", y="BPS (MB/s)", color="#66fcf1", height=300)

        st.markdown("<hr style='border: 1px solid #1f2833;'/>", unsafe_allow_html=True)
        col_exp1, col_exp2 = st.columns([1, 4])
        with col_exp1:
            csv = df.to_csv(index=False)
            st.download_button(label="📥 Export Stats (CSV)", data=csv, file_name='stress_test_stats.csv', mime='text/csv')


with tab2:
    st.markdown("<h3 style='font-family: Orbitron; color: #ff4c4c;'>🛠️ CORE NETWORK UTILITIES</h3>", unsafe_allow_html=True)

    u_tab1, u_tab2, u_tab3 = st.tabs(["🗺️ Geo IP / Host Lookup", "⚡ Ping Test", "🌐 DNS SRV Records"])

    with u_tab1:
        st.subheader("Host/IP Geolocation Lookup")
        lookup_host = st.text_input("Enter Domain or IP Address", placeholder="example.com or 8.8.8.8")
        if st.button("Query Geolocation", type="primary"):
            if lookup_host:
                with st.spinner("Quering host API..."):
                    cleaned_host = lookup_host.replace('https://', '').replace('http://', '')
                    if "/" in cleaned_host: cleaned_host = cleaned_host.split("/")[0]

                    # Call API endpoint
                    try:
                        import requests
                        res = requests.get(f"https://ipwhois.app/json/{cleaned_host}/", timeout=5)
                        if res.status_code == 200:
                            info = res.json()
                            if info.get("success", False):
                                # Display nicely
                                st.success(f"Host details for {cleaned_host}:")
                                data = {
                                    "Field": ["IP", "Country", "City", "ISP", "Organization", "Region", "Latitude/Longitude"],
                                    "Value": [
                                        info.get("ip", "N/A"),
                                        info.get("country", "N/A"),
                                        info.get("city", "N/A"),
                                        info.get("isp", "N/A"),
                                        info.get("org", "N/A"),
                                        info.get("region", "N/A"),
                                        f"{info.get('latitude', 'N/A')} / {info.get('longitude', 'N/A')}"
                                    ]
                                }
                                st.table(pd.DataFrame(data))
                            else:
                                st.error(f"Failed to query details: {info.get('message', 'Unknown API failure')}")
                        else:
                            st.error(f"API returned status code: {res.status_code}")
                    except Exception as e:
                        st.error(f"Lookup error: {e}")
            else:
                st.warning("Please enter a valid host address first.")

    with u_tab2:
        st.subheader("Ping Verification Tool")
        ping_host = st.text_input("Enter Host / IP for Ping Test", placeholder="e.g. google.com or 8.8.8.8", key="ping_in")
        if st.button("Execute Ping", type="primary"):
            if ping_host:
                with st.spinner("Pinging host, please wait..."):
                    cleaned_ping = ping_host.replace('https://', '').replace('http://', '')
                    if "/" in cleaned_ping: cleaned_ping = cleaned_ping.split("/")[0]

                    try:
                        # Attempt to use icmplib ping if available
                        if ping is not None:
                            r = ping(cleaned_ping, count=4, interval=0.2)
                            if r.is_alive:
                                st.success(f"ONLINE: Host {cleaned_ping} responded.")
                            else:
                                st.error(f"OFFLINE: Host {cleaned_ping} did not respond.")

                            ping_data = {
                                "Metric": ["IP Resolved Address", "Average Round Trip (ms)", "Packets Sent", "Packets Received", "Packet Loss"],
                                "Value": [
                                    r.address,
                                    f"{round(r.avg_rtt, 2)} ms",
                                    r.packets_sent,
                                    r.packets_received,
                                    f"{round(r.packet_loss * 100, 1)}%"
                                ]
                            }
                            st.table(pd.DataFrame(ping_data))
                        else:
                            # Subprocess ping fallback
                            plat_arg = "-c" if sys.platform != "win32" else "-n"
                            result = subprocess.run(["ping", plat_arg, "4", cleaned_ping], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
                            if result.returncode == 0:
                                st.success(f"ONLINE: Host {cleaned_ping} responded.")
                                st.code(result.stdout)
                            else:
                                st.error(f"Host {cleaned_ping} unreachable or ping command failed.")
                                st.code(result.stderr or result.stdout)
                    except Exception as e:
                        st.error(f"Ping execution error: {e}")
            else:
                st.warning("Please enter a valid host or IP address.")

    with u_tab3:
        st.subheader("DNS SRV Record Lookup")
        st.info("Find specific Minecraft (`_ts3._udp.`) or TS3 (`_tsdns._tcp.`) servers records bound to a domain.")
        srv_host = st.text_input("Enter Domain to Resolve SRV", placeholder="e.g. hypixel.net")
        if st.button("Query SRV Records", type="primary"):
            if srv_host:
                with st.spinner("Resolving DNS SRV records..."):
                    cleaned_srv = srv_host.replace('https://', '').replace('http://', '')
                    if "/" in cleaned_srv: cleaned_srv = cleaned_srv.split("/")[0]

                    records = ['_ts3._udp.', '_tsdns._tcp.']
                    resolved = {}

                    try:
                        from dns import resolver
                        dns_resolver = resolver.Resolver()
                        dns_resolver.timeout = 1.5
                        dns_resolver.lifetime = 1.5

                        for rec in records:
                            try:
                                srv_records = dns_resolver.resolve(rec + cleaned_srv, 'SRV')
                                for srv in srv_records:
                                    resolved[rec] = f"{str(srv.target).rstrip('.')}:{srv.port}"
                            except Exception:
                                resolved[rec] = "Not found"

                        st.write("### SRV Resolution Results:")
                        st.table(pd.DataFrame(list(resolved.items()), columns=["Service Record", "Target Server"]))
                    except Exception as e:
                        st.error(f"DNS resolver execution failure: {e}")
            else:
                st.warning("Please enter a domain name.")

def _grade_color(grade: str) -> str:
    return {"A": "#28c76f", "B": "#28c76f", "C": "#ff9f43", "D": "#ff9f43", "F": "#ea5455"}.get(grade, "#c5c6c7")


def render_posture_report(res, persist: bool = True):
    """Render a CyberAnalysisReport with a posture score and persist it for drift tracking."""
    posture = score_findings(res.findings)
    color = _grade_color(posture.grade)

    c_score, c_grade, c_count = st.columns(3)
    c_score.metric("Posture Score", f"{posture.score}/100")
    c_grade.markdown(
        f"<div style='text-align:center;'><span style='font-family:Orbitron; font-size:2.4rem; "
        f"font-weight:900; color:{color};'>{posture.grade}</span><br>"
        f"<span style='color:#a9b2c3;'>Grade</span></div>",
        unsafe_allow_html=True,
    )
    c_count.metric("Findings", posture.findings_total)

    if res.findings:
        st.dataframe(
            [
                {
                    "Severity": f.severity.upper(),
                    "Category": f.category,
                    "Detail": f.detail,
                    "Recommendation": f.recommendation or "",
                }
                for f in res.findings
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No issues detected for this asset.")

    if persist:
        try:
            storage.save_scan(
                target=res.target,
                source=res.metadata.source,
                score=posture.score,
                grade=posture.grade,
                findings=[f.model_dump() for f in res.findings],
                report=res.model_dump(mode="json"),
                run_id=res.metadata.run_id,
            )
            st.caption("✅ Saved to audit history — check the 📈 History & Drift tab to compare over time.")
        except Exception as exc:  # noqa: BLE001
            st.warning(f"Could not persist audit history: {exc}")

    with st.expander("View raw report JSON"):
        st.json(res.model_dump(mode="json"))


with tab5:
    st.markdown("<h3 style='font-family: Orbitron; color: #66fcf1;'>🧪 AUTHORIZED CYBER ANALYSIS</h3>", unsafe_allow_html=True)
    st.info("Passive checks for domains, web endpoints and TLS posture on assets you are authorized to assess.")

    c_tab1, c_tab2, c_tab3 = st.tabs(["🌐 Domain Posture", "🔐 Web / TLS Posture", "📈 History & Drift"])

    with c_tab1:
        st.markdown("#### Domain posture review")
        cyber_domain = st.text_input("Target domain:", placeholder="example.com", key="cy_domain")

        if st.button("🧪 Run Domain Analysis", key="cy_domain_run"):
            if not cyber_domain:
                st.warning("Please enter a domain.")
            else:
                with st.spinner(f"Analyzing {cyber_domain}..."):
                    adapter = CyberAnalysisAdapter()
                    res = adapter.analyze_domain(cyber_domain)
                st.success("Domain analysis complete.")
                render_posture_report(res)

    with c_tab2:
        st.markdown("#### Web / TLS posture review")
        cyber_url = st.text_input("Target URL:", placeholder="https://example.com", key="cy_url")

        if st.button("🔐 Run URL Analysis", key="cy_url_run"):
            if not cyber_url:
                st.warning("Please enter a URL.")
            else:
                with st.spinner(f"Inspecting {cyber_url}..."):
                    adapter = CyberAnalysisAdapter()
                    res = adapter.analyze_url(cyber_url)
                st.success("Web analysis complete.")
                render_posture_report(res)

    with c_tab3:
        st.markdown("#### Audit history & drift detection")
        targets = storage.list_targets()
        if not targets:
            st.info("No audits stored yet. Run a domain or URL analysis to start tracking posture over time.")
        else:
            st.markdown("**Audited assets (worst posture first):**")
            st.dataframe(
                [
                    {"Grade": t["grade"], "Score": t["score"], "Target": t["target"], "Last Audit": t["timestamp"]}
                    for t in targets
                ],
                use_container_width=True,
                hide_index=True,
            )

            target_names = [t["target"] for t in targets]
            selected = st.selectbox("Compare last two audits for:", target_names, key="cy_diff_target")

            col_drift, col_html, col_pdf = st.columns(3)
            run_drift = False
            with col_drift:
                if st.button("🔬 Show Drift", key="cy_diff_run"):
                    run_drift = True
            with col_html:
                from utils import reporting
                recent = storage.get_recent_scans(selected, limit=1)
                if recent:
                    report_data = recent[0]["report"]
                    from utils.scoring import score_findings
                    posture = score_findings(report_data.get("findings", []))
                    history = [s["score"] for s in reversed(storage.get_recent_scans(selected, limit=10))]
                    html_content = reporting.generate_html_report(report_data, posture, history)
                    st.download_button(
                        label="📥 Download HTML",
                        data=html_content,
                        file_name=f"audit_report_{selected}.html",
                        mime="text/html",
                        key="dl_html_btn"
                    )
            with col_pdf:
                if recent:
                    report_data = recent[0]["report"]
                    from utils.scoring import score_findings
                    posture = score_findings(report_data.get("findings", []))
                    history = [s["score"] for s in reversed(storage.get_recent_scans(selected, limit=10))]
                    import tempfile
                    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                        tmp_path = tmp.name
                    reporting.generate_pdf_report(report_data, posture, tmp_path, history)
                    with open(tmp_path, "rb") as f:
                        pdf_bytes = f.read()
                    st.download_button(
                        label="📥 Download PDF",
                        data=pdf_bytes,
                        file_name=f"audit_report_{selected}.pdf",
                        mime="application/pdf",
                        key="dl_pdf_btn"
                    )

            if run_drift:
                diff = storage.diff_scans(selected)
                if diff is None:
                    st.warning(f"Need at least two audits of '{selected}' to compare. Run it again to build history.")
                else:
                    delta = diff["score_delta"]
                    st.metric(
                        f"Score change since {diff['previous']['timestamp']}",
                        f"{diff['current']['score']}/100",
                        delta=delta,
                    )
                    if diff["new_findings"]:
                        st.markdown("**🔴 New issues:**")
                        st.dataframe(
                            [{"Severity": f.get("severity", "").upper(), "Category": f.get("category"), "Detail": f.get("detail")} for f in diff["new_findings"]],
                            use_container_width=True,
                            hide_index=True,
                        )
                    if diff["resolved_findings"]:
                        st.markdown("**🟢 Resolved issues:**")
                        st.dataframe(
                            [{"Severity": f.get("severity", "").upper(), "Category": f.get("category"), "Detail": f.get("detail")} for f in diff["resolved_findings"]],
                            use_container_width=True,
                            hide_index=True,
                        )
                    if not diff["new_findings"] and not diff["resolved_findings"]:
                        st.info("No change in findings between the last two audits.")

    st.markdown("<h3 style='font-family: Orbitron; color: #ff4c4c;'>🔍 OSINT TOOLS</h3>", unsafe_allow_html=True)
    st.info("Passive and Active Intelligence Gathering Modules.")

    o_tab1, o_tab2, o_tab3, o_tab4 = st.tabs(["🌐 theHarvester", "⚙️ Shodan", "🗺️ Nmap", "🐛 WPScan"])

    with o_tab1:
        st.markdown("#### The Harvester (Email, Subdomain & IP Lookup)")
        osint_domain = st.text_input("Target Domain (e.g. example.com):", key="th_domain")
        osint_sources = st.text_input("Sources (comma separated, default: 'all'):", value="all", key="th_sources")
        osint_limit = st.number_input("Limit Results:", min_value=10, max_value=5000, value=500, key="th_limit")

        if "th_result" not in st.session_state:
            st.session_state["th_result"] = None
        if "hibp_results" not in st.session_state:
            st.session_state["hibp_results"] = None

        if st.button("🚀 Run theHarvester", key="th_run"):
            if not osint_domain:
                st.warning("Please enter a target domain.")
            else:
                with st.spinner(f"Running theHarvester on {osint_domain}..."):
                    adapter = TheHarvesterAdapter()
                    result = adapter.search_domain(osint_domain, sources=osint_sources, limit=osint_limit)
                    st.session_state["th_result"] = result.model_dump()
                    st.session_state["hibp_results"] = None
                    st.success("Harvester scan complete!")

        th_res = st.session_state["th_result"]
        if th_res:
            st.markdown("### 📊 theHarvester Scan Results")

            domains_list = th_res.get("domains", [])
            if domains_list:
                for d in domains_list:
                    subdomains = d.get("subdomains", [])
                    ips = d.get("ips", [])
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**Subdomains Discovered ({len(subdomains)})**")
                        if subdomains:
                            st.dataframe(pd.DataFrame({"Subdomain": subdomains}), use_container_width=True, hide_index=True)
                        else:
                            st.info("No subdomains found.")
                    with col2:
                        st.markdown(f"**IP Addresses Discovered ({len(ips)})**")
                        if ips:
                            st.dataframe(pd.DataFrame({"IP Address": ips}), use_container_width=True, hide_index=True)
                        else:
                            st.info("No IPs found.")

            emails = th_res.get("emails", [])
            st.markdown(f"### 📧 Emails Found ({len(emails)})")
            if emails:
                email_addresses = [e.get("address") for e in emails]
                st.dataframe(pd.DataFrame({"Email Address": email_addresses}), use_container_width=True, hide_index=True)

                from utils.osint.hibp import HIBPAdapter
                hibp_adapter = HIBPAdapter()

                if not hibp_adapter.available:
                    st.warning("⚠️ HIBP API Key is not configured (set HIBP_API_KEY environment variable to enable HIBP lookup).")

                if st.button("🔍 Check HaveIBeenPwned for Breaches", key="hibp_check_btn"):
                    with st.spinner("Checking HaveIBeenPwned (respecting rate limits)..."):
                        hibp_res = hibp_adapter.check_accounts(email_addresses)
                        st.session_state["hibp_results"] = hibp_res

                hibp_data = st.session_state["hibp_results"]
                if hibp_data:
                    st.markdown("### 🔓 HIBP Breach Intelligence Results")
                    formatted_hibp = []
                    for item in hibp_data:
                        if item.get("skipped"):
                            formatted_hibp.append({
                                "Email": item["email"],
                                "Status": "SKIPPED",
                                "Breach Count": 0,
                                "Details": item.get("reason", "")
                            })
                        elif item.get("error"):
                            formatted_hibp.append({
                                "Email": item["email"],
                                "Status": "ERROR",
                                "Breach Count": 0,
                                "Details": item.get("error", "")
                            })
                        else:
                            breaches_summary = ", ".join([b["name"] for b in item.get("breaches", [])])
                            formatted_hibp.append({
                                "Email": item["email"],
                                "Status": "PWNED ❌" if item.get("breached") else "SECURE ✅",
                                "Breach Count": item.get("breach_count", 0),
                                "Details": breaches_summary or "No known leaks"
                            })
                    st.dataframe(pd.DataFrame(formatted_hibp), use_container_width=True, hide_index=True)
            else:
                st.info("No emails found.")

            with st.expander("View raw JSON"):
                st.json(th_res)

    with o_tab2:
        st.markdown("#### Shodan (IP Information & Discovery)")
        app_config = load_config()
        if not app_config or not app_config.shodan_api_key:
            st.warning("⚠️ Shodan API Key is not configured in `config.json` (`shodan_api_key`). Features may not work.", icon="⚠️")

        shodan_mode = st.radio("Mode:", ["IP Lookup", "Search Query"])
        shodan_query = st.text_input("IP or Query:", key="shodan_query")

        if st.button("🚀 Run Shodan", key="shodan_run"):
            if not shodan_query:
                st.warning("Please enter an IP or Search Query.")
            else:
                with st.spinner("Querying Shodan API..."):
                    adapter = ShodanAdapter(api_key=app_config.shodan_api_key if app_config else "")
                    if shodan_mode == "IP Lookup":
                        res = adapter.lookup_ip(shodan_query)
                        if res:
                            st.success(f"IP Lookup successful for {shodan_query}")
                            st.json(res.model_dump())
                        else:
                            st.error("No results or error from Shodan.")
                    else:
                        res = adapter.search(shodan_query)
                        st.json(res.model_dump())

    with o_tab3:
        st.markdown("#### Nmap (Network Mapper)")
        st.info("Port scanning and service detection.")
        nmap_target = st.text_input("Target IP/Domain:", key="nm_target")
        nmap_args = st.text_input("Arguments:", value="-sV -T4 -F", key="nm_args")

        if st.button("🚀 Run Nmap", key="nm_run"):
            if not nmap_target:
                st.warning("Please enter a target.")
            else:
                with st.spinner("Running Nmap scan..."):
                    adapter = NmapAdapter()
                    res = adapter.scan(nmap_target, nmap_args)
                    st.json(res.model_dump())

    with o_tab4:
        st.markdown("#### WPScan (WordPress Vulnerability Scanner)")
        st.info("Scanner for WordPress instances (Requires wpscan installed natively or API Token).")
        wps_target = st.text_input("Target URL (e.g. http://example.com):", key="wps_target")
        wps_token = st.text_input("WPScan API Token (optional):", type="password", key="wps_token")

        if st.button("🚀 Run WPScan", key="wps_run"):
            if not wps_target:
                st.warning("Please enter a target URL.")
            else:
                with st.spinner("Running WPScan..."):
                    adapter = WPScanAdapter(api_token=wps_token if wps_token else None)
                    res = adapter.scan(wps_target)
                    st.json(res.model_dump())

with tab7:
    st.markdown("<h3 style='font-family: Orbitron; color: #66fcf1;'>📋 ASSET INVENTORY & FLEET AUDIT</h3>", unsafe_allow_html=True)
    st.info("Manage inventory assets and trigger continuous posture audits for the entire fleet.")

    current_tenant = _current_user.get("tenant", "default") if _current_user else "default"
    is_admin_or_auditor = True
    if _current_user:
        is_admin_or_auditor = _current_user.get("role") in ("admin", "auditor")

    fleet_col1, fleet_col2 = st.columns([2, 1])

    with fleet_col1:
        st.markdown("#### Registered Assets")
        from utils import inventory
        assets = inventory.list_assets(tenant=current_tenant)
        if not assets:
            st.info("No assets registered for this tenant.")
        else:
            assets_df = []
            for a in assets:
                assets_df.append({
                    "ID": a["id"],
                    "Name": a["name"],
                    "Target": a["target"],
                    "Type": a["asset_type"],
                    "Group": a["asset_group"],
                    "Environment": a["environment"],
                    "Owner": a["owner"],
                })
            st.dataframe(pd.DataFrame(assets_df), use_container_width=True, hide_index=True)

            if is_admin_or_auditor:
                st.markdown("#### Remove Asset")
                remove_id = st.number_input("Asset ID to remove:", min_value=1, step=1, key="remove_asset_id")
                if st.button("❌ Remove Asset", key="remove_asset_btn"):
                    target_asset = inventory.get_asset(remove_id)
                    if target_asset and target_asset["tenant"] == current_tenant:
                        if inventory.delete_asset(remove_id):
                            st.success(f"Asset #{remove_id} removed successfully.")
                            st.rerun()
                        else:
                            st.error("Failed to remove asset.")
                    else:
                        st.error("Asset not found or unauthorized.")

    with fleet_col2:
        if is_admin_or_auditor:
            st.markdown("#### Register New Asset")
            with st.form("register_asset_form"):
                new_name = st.text_input("Friendly Name")
                new_target = st.text_input("Target (Domain/URL/Host)")
                new_type = st.selectbox("Asset Type", ["domain", "url", "host"])
                new_group = st.text_input("Asset Group", value="default")
                new_env = st.selectbox("Environment", ["production", "staging", "development"])
                new_owner = st.text_input("Owner Email/Name")
                new_tags = st.text_input("Tags (comma separated)")

                submitted = st.form_submit_button("➕ Register Asset")
                if submitted:
                    if not new_name or not new_target:
                        st.error("Name and Target are required.")
                    else:
                        tags_list = [t.strip() for t in new_tags.split(",") if t.strip()]
                        try:
                            asset_id = inventory.add_asset(
                                name=new_name,
                                target=new_target,
                                asset_type=new_type,
                                group=new_group,
                                tags=tags_list,
                                environment=new_env,
                                owner=new_owner,
                                tenant=current_tenant
                            )
                            st.success(f"Asset registered successfully (ID: {asset_id}).")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Error registering asset: {exc}")
        else:
            st.warning("You do not have permission to register or manage assets.")

    st.markdown("---")
    st.markdown("### 🚀 Fleet Audit Trigger")

    fleet_audit_col1, fleet_audit_col2 = st.columns([1, 2])
    with fleet_audit_col1:
        if st.button("⚡ Trigger Manual Fleet Audit", key="trigger_fleet_audit_btn"):
            with st.spinner("Auditing all fleet assets..."):
                from utils import scheduler
                results = scheduler.run_fleet_audit(tenant=current_tenant)
                st.session_state["fleet_audit_results"] = results
                st.success("Fleet audit completed!")

    with fleet_audit_col2:
        results = st.session_state.get("fleet_audit_results")
        if results:
            st.markdown("**Last Fleet Audit Results:**")
            formatted_results = []
            for r in results:
                if "error" in r:
                    formatted_results.append({
                        "Asset": r["asset"],
                        "Target": r["target"],
                        "Status": "FAILED ❌",
                        "Score": "N/A",
                        "Grade": "N/A",
                        "Details": r["error"]
                    })
                else:
                    formatted_results.append({
                        "Asset": r["asset"],
                        "Target": r["target"],
                        "Status": "COMPLETED ✅",
                        "Score": f"{r['score']}/100",
                        "Grade": r["grade"],
                        "Details": f"{len(r['alerts'])} alert(s) triggered"
                    })
            st.dataframe(pd.DataFrame(formatted_results), use_container_width=True, hide_index=True)

with tab3:
    st.markdown("<h3 style='font-family: Orbitron; color: #ff4c4c;'>📋 LIVE PROCESS OUTPUT</h3>", unsafe_allow_html=True)
    st.info("Direct log output stdout/stderr from the active start.py subprocess.")

    # Logs Text area
    if state.logs:
        log_text = "\n".join(state.logs)
        st.code(log_text, language="text", wrap_lines=True)
    else:
        st.code("No logs available. Trigger a stress test to view stdout here.", language="text")

with tab4:
    st.markdown("<h3 style='font-family: Orbitron; color: #ff4c4c;'>🛡️ PROXY MANAGER</h3>", unsafe_allow_html=True)
    st.info("Download and test proxies directly from providers configured in config.json.")

    col_p1, col_p2 = st.columns(2)
    with col_p1:
        proxy_type_sel = st.selectbox("Proxy Type to Download", ["0 - ALL", "1 - HTTP", "4 - SOCKS4", "5 - SOCKS5", "6 - RANDOM"])
    with col_p2:
        proxy_filename = st.text_input("Save As:", value="http.txt")

    if st.button("🚀 Download & Verify Proxies"):
        with st.spinner("Downloading and verifying..."):
            from utils.proxy import handleProxyList
            try:
                # Type from str
                ptype = proxy_type_sel.split(" - ")[0]
                ptype_int = int(ptype)
                res = handleProxyList({'__dir__': Path(__file__).parent}, proxy_filename, ptype_int)
                st.success(f"Operation completed! Saved to {proxy_filename}. Found proxies.")
            except Exception as e:
                st.error(f"Error handling proxy list: {e}")

with tab6:
    st.markdown("### ⚙️ System Configuration (config.json)")
    st.markdown("Edit the global settings and proxy lists directly. Ensure the file complies with standard JSON formatting.")

    import json
    config_path = Path("config.json")

    # Read current configuration
    if config_path.exists():
        with open(config_path, "r") as f:
            current_config = f.read()
    else:
        current_config = "{}"

    edited_config = st.text_area("JSON Configuration", value=current_config, height=400)

    if st.button("💾 Save Configuration", use_container_width=True):
        try:
            parsed = json.loads(edited_config)

            # Additional layer of validation via Pydantic model
            from utils.config_model import MHCheckConfig
            MHCheckConfig(**parsed)

            with open(config_path, "w") as f:
                json.dump(parsed, f, indent=4)
            st.success("Configuration validated and saved successfully!")

            time.sleep(1)
            st.rerun()
        except Exception as e:
            st.error(f"Validation Error: The provided JSON is invalid or missing fields. Details: {e}")


# Refresh the dashboard if the attack subprocess is actively running
if state.running:
    time.sleep(0.8)
    st.rerun()

