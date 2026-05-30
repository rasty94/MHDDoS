import streamlit as st
import subprocess
import time
import re
import sys
import os
import threading
from pathlib import Path
import pandas as pd

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

# Select layer
layer = st.sidebar.radio("Select Layer", ["Layer 7 (Application)", "Layer 4 (Transport / Network)"])

# Dynamically populate methods
if layer == "Layer 7 (Application)":
    methods_list = sorted(list(Methods.LAYER7_METHODS))
else:
    methods_list = sorted(list(Methods.LAYER4_METHODS))

method = st.sidebar.selectbox("Attack Method", methods_list)

# Inputs
target_input = st.sidebar.text_input("Target URL / Host", placeholder="http://example.com" if layer == "Layer 7 (Application)" else "1.1.1.1:80")
duration = st.sidebar.number_input("Duration (seconds)", min_value=10, max_value=86400, value=60, step=10)
threads = st.sidebar.slider("Threads", min_value=1, max_value=2000, value=100, step=10)

# Layer 7 settings
if layer == "Layer 7 (Application)":
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Layer 7 Parameters**")
    socks_type = st.sidebar.selectbox(
        "Socks Type",
        ["0 - ALL", "1 - HTTP", "4 - SOCKS4", "5 - SOCKS5", "6 - RANDOM"],
        index=3
    )
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
        success = launch_attack_process(cmd_args, target_val, method, duration)
        if success:
            st.toast("Stress test launched successfully!", icon="🔥")
        else:
            st.error("Failed to launch stress test subprocess.")

if state.running:
    if st.sidebar.button("🛑 STOP / ABORT TEST", use_container_width=True, type="secondary"):
        state.reset()
        st.toast("Stress test aborted!", icon="🛑")
        st.rerun()


# ================= MAIN PAGE LAYOUT =================
tab1, tab2, tab3 = st.tabs(["🖥️ Stress Tester", "🛠️ Network Utilities", "📋 Live Console Logs"])

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

with tab3:
    st.markdown("<h3 style='font-family: Orbitron; color: #ff4c4c;'>📋 LIVE PROCESS OUTPUT</h3>", unsafe_allow_html=True)
    st.info("Direct log output stdout/stderr from the active start.py subprocess.")
    
    # Logs Text area
    if state.logs:
        log_text = "\n".join(state.logs)
        st.code(log_text, language="text", wrap_lines=True)
    else:
        st.code("No logs available. Trigger a stress test to view stdout here.", language="text")

# Refresh the dashboard if the attack subprocess is actively running
if state.running:
    time.sleep(0.8)
    st.rerun()
