#!/usr/bin/env python3
import base64
import collections
import csv
import io
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 日志内存环形缓冲区 (保留最近 200 条日志供前端实时查看)
log_buffer = collections.deque(maxlen=200)

class BufferedLogHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = self.format(record)
            log_buffer.append(msg)
        except Exception:
            pass

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
root_logger.addHandler(console_handler)

mem_handler = BufferedLogHandler()
mem_handler.setFormatter(formatter)
root_logger.addHandler(mem_handler)

POOL_SIZE = int(os.environ.get("POOL_SIZE", 8))
BASE_PORT = int(os.environ.get("BASE_PORT", 10800))
HTTP_PORT = int(os.environ.get("HTTP_PORT", 28080))
REFRESH_INTERVAL = int(os.environ.get("REFRESH_INTERVAL", 120))
RUNTIME_DIR = os.environ.get("RUNTIME_DIR", "/var/run/vg2resin")
UP_HOOK = os.environ.get("UP_HOOK", "/app/up_hook.sh")
if not os.path.exists(UP_HOOK) and os.path.exists("/root/workspace/vg2resin/up_hook.sh"):
    UP_HOOK = "/root/workspace/vg2resin/up_hook.sh"

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
OPENVPN_BIN = shutil.which("openvpn") or "/usr/sbin/openvpn"

os.makedirs(RUNTIME_DIR, exist_ok=True)

lock = threading.Lock()
workers = {}
failed_ips = {}
scan_event = threading.Event()

# 资源消耗监控数据缓存
metrics_cache = {
    "app_rss_mb": 0.0,
    "app_proc_count": 0,
    "app_cpu_percent": 0.0,
    "sys_cpu_percent": 0.0,
    "sys_mem_used_mb": 0,
    "sys_mem_total_mb": 0,
    "sys_mem_percent": 0,
    "load_1m": 0.0,
    "load_5m": 0.0
}

def get_public_ip():
    env_ip = os.environ.get("SERVER_IP", "").strip()
    if env_ip:
        return env_ip
    try:
        req = urllib.request.Request("http://checkip.amazonaws.com", headers={"User-Agent": "curl/7.88.1"})
        with urllib.request.urlopen(req, timeout=4) as r:
            ip = r.read().decode().strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

PUBLIC_HOST = get_public_ip()
logging.info(f"Default public host for Resin subscription: {PUBLIC_HOST}")

def parse_iphone_csv(text):
    if "*vpn_servers" not in text:
        return []
    lines = [l for l in text.splitlines() if l and not l.startswith("*")]
    if len(lines) <= 1:
        return []
    lines[0] = lines[0].lstrip("#")
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    nodes = []
    for row in reader:
        b64 = row.get("OpenVPN_ConfigData_Base64", "")
        ip = row.get("IP", "")
        if b64 and ip:
            ovpn = base64.b64decode(b64).decode("utf-8", errors="ignore")
            if "proto tcp" in ovpn:
                nodes.append({
                    "ip": ip,
                    "country": row.get("CountryShort", "VG"),
                    "score": int(row.get("Score") or 0),
                    "ping": int(row.get("Ping") or 999),
                    "speed": int(row.get("Speed") or 0),
                    "ovpn": ovpn
                })
    nodes.sort(key=lambda x: (x["score"], x["speed"]), reverse=True)
    return nodes

def fetch_from_api():
    url = "http://www.vpngate.net/api/iphone/"
    with lock:
        active_ports = [w["port"] for w in workers.values()]
    for port in active_ports:
        try:
            out = subprocess.check_output(
                ["curl", "-sL", "--max-time", "12", "--socks5-hostname", f"127.0.0.1:{port}", url],
                stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore")
            nodes = parse_iphone_csv(out)
            if nodes:
                logging.info(f"Fetched {len(nodes)} nodes from /api/iphone/ via local SOCKS5 :{port}")
                return nodes
        except Exception:
            continue

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        nodes = parse_iphone_csv(text)
        if nodes:
            logging.info(f"Fetched {len(nodes)} nodes from /api/iphone/ directly")
            return nodes
    except Exception as e:
        logging.warning(f"Direct API fetch failed: {e}")
    return []

def fetch_from_html():
    url = "https://www.vpngate.net/en/"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        pattern = re.compile(
            r"\.\./images/flags/([A-Z]{2})\.png'[^>]*>.*?do_openvpn\.aspx\?fqdn=([^&'\"]+)&ip=([0-9.]+)&tcp=(\d+)&udp=(\d+)&sid=(\d+)&hid=(\d+)",
            re.S
        )
        matches = [m for m in pattern.findall(html) if int(m[3]) > 0]
        nodes = []
        for country, fqdn, ip, tcp, udp, sid, hid in matches[:POOL_SIZE * 4]:
            if ip in failed_ips and time.time() - failed_ips[ip] < 600:
                continue
            proto_flag = f"tcp=1&port={tcp}"
            dl_url = f"https://www.vpngate.net/common/openvpn_download.aspx?sid={sid}&{proto_flag}&host={ip}&hid={hid}&/vpngate_{ip}.ovpn"
            try:
                dl_req = urllib.request.Request(dl_url, headers=headers)
                with urllib.request.urlopen(dl_req, timeout=6, context=ctx) as r:
                    ovpn_text = r.read().decode("utf-8", errors="ignore")
                if "client" in ovpn_text and "<ca>" in ovpn_text:
                    nodes.append({
                        "ip": ip,
                        "country": country,
                        "score": 1000,
                        "ping": 100,
                        "speed": 10000000,
                        "ovpn": ovpn_text
                    })
                    if len(nodes) >= POOL_SIZE * 2:
                        break
            except Exception:
                continue
        return nodes
    except Exception as e:
        logging.warning(f"Fetch HTML fallback failed: {e}")
    return []

def get_candidate_nodes():
    nodes = fetch_from_api()
    if not nodes:
        logging.info("Falling back to HTML scraping from vpngate.net/en/...")
        nodes = fetch_from_html()
    return nodes

def get_proc_rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return 0

def clean_worker(idx):
    dev = f"tun_vg_{idx}"
    with lock:
        if idx in workers:
            w = workers.pop(idx)
            try:
                w["proc"].terminate()
                w["proc"].wait(timeout=2)
            except Exception:
                try:
                    w["proc"].kill()
                except Exception:
                    pass
    subprocess.run(f"pkill -9 -f 'tun_vg_{idx}' 2>/dev/null || true", shell=True)
    subprocess.run(f"pkill -9 -f 'microsocks -i 0.0.0.0 -p {BASE_PORT + idx} ' 2>/dev/null || true", shell=True)
    subprocess.run(f"ip rule del priority {1000 + idx} 2>/dev/null || true", shell=True)
    subprocess.run(f"ip route flush table {100 + idx} 2>/dev/null || true", shell=True)
    subprocess.run(f"ip link del {dev} 2>/dev/null || true", shell=True)
    status_file = os.path.join(RUNTIME_DIR, f"worker_{idx}.json")
    if os.path.exists(status_file):
        try:
            os.remove(status_file)
        except Exception:
            pass
    time.sleep(0.3)

def check_socks5_handshake(port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("127.0.0.1", port))
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        s.close()
        return resp == b"\x05\x00"
    except Exception:
        return False

def probe_socks5_egress(port, timeout=6):
    try:
        out = subprocess.check_output(
            ["curl", "-s", "--max-time", str(timeout), "--socks5-hostname", f"127.0.0.1:{port}", "http://checkip.amazonaws.com"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", out):
            return out
    except Exception:
        pass
    return None

def start_worker(idx, node):
    clean_worker(idx)
    port = BASE_PORT + idx
    dev = f"tun_vg_{idx}"
    ovpn_file = os.path.join(RUNTIME_DIR, f"client_{idx}.ovpn")
    log_file = os.path.join(RUNTIME_DIR, f"ovpn_{idx}.log")

    patched_ovpn = node["ovpn"] + "\n" + (
        "data-ciphers AES-128-CBC:AES-256-CBC:AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305\n"
        "data-ciphers-fallback AES-128-CBC\n"
        "tls-cipher \"DEFAULT:@SECLEVEL=0\"\n"
        "route-noexec\n"
        "script-security 2\n"
        f"up \"{UP_HOOK}\"\n"
        "connect-retry-max 1\n"
        "connect-timeout 8\n"
    )
    with open(ovpn_file, "w") as f:
        f.write(patched_ovpn)

    env = os.environ.copy()
    env["WORKER_IDX"] = str(idx)
    env["WORKER_PORT"] = str(port)
    env["RUNTIME_DIR"] = RUNTIME_DIR

    cmd = [
        OPENVPN_BIN,
        "--config", ovpn_file,
        "--dev-type", "tun",
        "--dev", dev,
        "--log", log_file
    ]
    proc = subprocess.Popen(cmd, env=env)

    ready = False
    ms_pid = None
    for _ in range(15):
        time.sleep(1)
        status_file = os.path.join(RUNTIME_DIR, f"worker_{idx}.json")
        if os.path.exists(status_file) and check_socks5_handshake(port):
            try:
                with open(status_file) as f:
                    sdata = json.load(f)
                    ms_pid = sdata.get("ms_pid")
            except Exception:
                pass
            ready = True
            break
        if proc.poll() is not None:
            break

    if ready:
        egress_ip = probe_socks5_egress(port, timeout=6)
        if egress_ip:
            logging.info(f"[Worker-{idx}] ONLINE -> SOCKS5 :{port} | Node: {node['country']}-{node['ip']} | Egress: {egress_ip}")
            with lock:
                workers[idx] = {
                    "proc": proc,
                    "ms_pid": ms_pid,
                    "node": node,
                    "port": port,
                    "dev": dev,
                    "egress_ip": egress_ip,
                    "ready_time": time.time()
                }
            return True

    failed_ips[node["ip"]] = time.time()
    logging.warning(f"[Worker-{idx}] Failed to verify tunnel to {node['country']}-{node['ip']}")
    clean_worker(idx)
    return False

# 后台资源消耗计算线程
def resource_monitor_loop():
    last_sys_total = 0
    last_sys_idle = 0
    last_app_ticks = 0
    last_time = time.time()

    while True:
        try:
            # 1. 宿主机内存
            mem = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        mem[parts[0].strip()] = int(parts[1].strip().split()[0])
            total_mem = mem.get("MemTotal", 1) // 1024
            avail_mem = mem.get("MemAvailable", 0) // 1024
            used_mem = total_mem - avail_mem
            mem_pct = round((used_mem / total_mem) * 100, 1) if total_mem else 0

            # 2. 系统 CPU
            with open("/proc/stat") as f:
                fields = [float(x) for x in f.readline().split()[1:8]]
                sys_total = sum(fields)
                sys_idle = fields[3]

            sys_cpu = 0.0
            diff_sys_total = sys_total - last_sys_total
            diff_sys_idle = sys_idle - last_sys_idle
            if last_sys_total > 0 and diff_sys_total > 0:
                sys_cpu = max(0.0, min(100.0, (1.0 - diff_sys_idle / diff_sys_total) * 100.0))

            # 3. 收集属于本服务及子进程的 PIDs
            my_pid = os.getpid()
            tracked_pids = {my_pid}
            with lock:
                for w in workers.values():
                    if w["proc"].poll() is None:
                        tracked_pids.add(w["proc"].pid)
                    if w.get("ms_pid"):
                        tracked_pids.add(w["ms_pid"])

            # 累加应用进程的 CPU ticks 和 RSS 内存
            total_rss_kb = 0
            app_ticks = 0
            valid_pids = 0
            for p in list(tracked_pids):
                try:
                    with open(f"/proc/{p}/stat") as f:
                        parts = f.read().split()
                        app_ticks += int(parts[13]) + int(parts[14])
                    rss = get_proc_rss_kb(p)
                    total_rss_kb += rss
                    valid_pids += 1
                except Exception:
                    pass

            app_cpu = 0.0
            now = time.time()
            elapsed = now - last_time
            if last_app_ticks > 0 and diff_sys_total > 0:
                # 换算为百分比
                diff_ticks = max(0, app_ticks - last_app_ticks)
                hz = os.sysconf(os.sysconf_names['SC_CLK_TCK']) if hasattr(os, 'sysconf') else 100
                cpu_cores = os.cpu_count() or 1
                app_cpu = min(100.0, (diff_ticks / hz / elapsed / cpu_cores) * 100.0) if elapsed > 0 else 0.0

            last_sys_total = sys_total
            last_sys_idle = sys_idle
            last_app_ticks = app_ticks
            last_time = now

            load1, load5, _ = os.getloadavg()

            metrics_cache.update({
                "app_rss_mb": round(total_rss_kb / 1024, 2),
                "app_proc_count": valid_pids,
                "app_cpu_percent": round(app_cpu, 1),
                "sys_cpu_percent": round(sys_cpu, 1),
                "sys_mem_used_mb": used_mem,
                "sys_mem_total_mb": total_mem,
                "sys_mem_percent": mem_pct,
                "load_1m": round(load1, 2),
                "load_5m": round(load5, 2)
            })
        except Exception:
            pass
        time.sleep(2.0)

def supervisor_loop():
    logging.info("Starting background supervisor...")
    while True:
        try:
            dead_slots = []
            for i in range(1, POOL_SIZE + 1):
                with lock:
                    w = workers.get(i)
                if not w or w["proc"].poll() is not None or not check_socks5_handshake(BASE_PORT + i):
                    dead_slots.append(i)
                else:
                    if not probe_socks5_egress(BASE_PORT + i, timeout=6):
                        dead_slots.append(i)

            if dead_slots:
                logging.info(f"Filling slots: {dead_slots}...")
                candidates = get_candidate_nodes()
                with lock:
                    active_ips = {w["node"]["ip"] for w in workers.values()}
                now = time.time()
                available = [
                    n for n in candidates
                    if n["ip"] not in active_ips and (n["ip"] not in failed_ips or now - failed_ips[n["ip"]] > 600)
                ]

                c_idx = 0
                for slot in dead_slots:
                    attempts = 0
                    while c_idx < len(available) and attempts < 4:
                        node = available[c_idx]
                        c_idx += 1
                        attempts += 1
                        if start_worker(slot, node):
                            break
        except Exception as e:
            logging.error(f"Supervisor loop error: {e}")
        scan_event.wait(timeout=REFRESH_INTERVAL)
        scan_event.clear()

class ResinSubHandler(BaseHTTPRequestHandler):
    def resolve_sub_host(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if "host" in qs and qs["host"][0].strip():
            return qs["host"][0].strip()
        host_hdr = self.headers.get("Host", "")
        if host_hdr:
            h = host_hdr.split(":")[0].strip()
            if h and h not in ("0.0.0.0", "localhost"):
                return h
        return PUBLIC_HOST

    def build_lines(self, sub_host):
        lines = []
        with lock:
            for idx, w in sorted(workers.items()):
                if w["proc"].poll() is None and check_socks5_handshake(w["port"]):
                    egress = w.get("egress_ip") or w["node"]["ip"]
                    tag = f"VG-{w['node']['country']}-{egress}-{idx}"
                    lines.append(f"socks5://{sub_host}:{w['port']}#{tag}")
        return lines

    def send_json(self, data, code=200):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/api/rotate":
            slot = int(qs.get("slot", [0])[0])
            if 1 <= slot <= POOL_SIZE:
                logging.info(f"Manual rotation requested for slot #{slot}")
                threading.Thread(target=clean_worker, args=(slot,), daemon=True).start()
                scan_event.set()
                self.send_json({"ok": True, "message": f"槽位 #{slot} 已触发重新换线"})
            else:
                self.send_json({"ok": False, "message": "无效的槽位编号"}, 400)
        elif parsed.path == "/api/rescan":
            logging.info("Manual rescan requested via WebUI")
            scan_event.set()
            self.send_json({"ok": True, "message": "已触发全量扫描补齐"})
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/index.html", "/ui"):
            index_path = os.path.join(TEMPLATE_DIR, "index.html")
            if os.path.exists(index_path):
                with open(index_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"vg2resin WebUI is starting up...")
        elif parsed.path == "/sub":
            sub_host = self.resolve_sub_host()
            lines = self.build_lines(sub_host)
            body = ("\n".join(lines) + "\n") if lines else ""
            raw = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        elif parsed.path == "/sub/base64":
            sub_host = self.resolve_sub_host()
            lines = self.build_lines(sub_host)
            raw = ("\n".join(lines) + "\n").encode("utf-8")
            b64 = base64.b64encode(raw)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(b64)))
            self.end_headers()
            self.wfile.write(b64)
        elif parsed.path in ("/healthz", "/status"):
            workers_data = []
            with lock:
                for idx, w in sorted(workers.items()):
                    w_rss = (get_proc_rss_kb(w["proc"].pid) + get_proc_rss_kb(w.get("ms_pid") or 0)) / 1024
                    workers_data.append({
                        "slot": idx,
                        "port": w["port"],
                        "country": w["node"]["country"],
                        "vpn_server_ip": w["node"]["ip"],
                        "egress_ip": w.get("egress_ip"),
                        "uptime_sec": int(time.time() - w["ready_time"]),
                        "rss_mb": round(w_rss, 1),
                        "alive": check_socks5_handshake(w["port"])
                    })
            status_data = {
                "pool_size": POOL_SIZE,
                "public_host": PUBLIC_HOST,
                "resources": metrics_cache,
                "workers": workers_data
            }
            self.send_json(status_data)
        elif parsed.path == "/api/logs":
            logs_text = "\n".join(list(log_buffer))
            raw = logs_text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

def run_server():
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), ResinSubHandler)
    logging.info(f"Resin subscription & WebUI listening on http://0.0.0.0:{HTTP_PORT}/")
    server.serve_forever()

if __name__ == "__main__":
    t_res = threading.Thread(target=resource_monitor_loop, daemon=True)
    t_res.start()
    t_sup = threading.Thread(target=supervisor_loop, daemon=True)
    t_sup.start()
    run_server()
