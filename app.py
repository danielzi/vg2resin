#!/usr/bin/env python3
import base64
import csv
import io
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

POOL_SIZE = int(os.environ.get("POOL_SIZE", 8))
BASE_PORT = int(os.environ.get("BASE_PORT", 10800))
HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))
REFRESH_INTERVAL = int(os.environ.get("REFRESH_INTERVAL", 120))
RUNTIME_DIR = os.environ.get("RUNTIME_DIR", "/var/run/vg2resin")
UP_HOOK = os.environ.get("UP_HOOK", "/root/workspace/vg2resin/up_hook.sh")
if not os.path.exists(UP_HOOK) and os.path.exists("/app/up_hook.sh"):
    UP_HOOK = "/app/up_hook.sh"

os.makedirs(RUNTIME_DIR, exist_ok=True)

lock = threading.Lock()
workers = {}
failed_ips = {}  # ip -> timestamp

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
    # 1. Try via an already-connected local SOCKS5 worker to bypass datacenter IP filter
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

    # 2. Try direct request
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

def clean_worker(idx):
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
    pkill_cmd = f"pkill -f 'microsocks -i 0.0.0.0 -p {BASE_PORT + idx} ' 2>/dev/null || true"
    subprocess.run(pkill_cmd, shell=True)
    subprocess.run(f"ip rule del priority {1000 + idx} 2>/dev/null || true", shell=True)
    subprocess.run(f"ip route flush table {100 + idx} 2>/dev/null || true", shell=True)
    subprocess.run(f"ip tuntap del mode tun dev tun{idx} 2>/dev/null || true", shell=True)
    status_file = os.path.join(RUNTIME_DIR, f"worker_{idx}.json")
    if os.path.exists(status_file):
        try:
            os.remove(status_file)
        except Exception:
            pass

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
    dev = f"tun{idx}"
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
        "connect-timeout 6\n"
        "ping 5\n"
        "ping-restart 20\n"
    )
    with open(ovpn_file, "w") as f:
        f.write(patched_ovpn)

    env = os.environ.copy()
    env["WORKER_IDX"] = str(idx)
    env["WORKER_PORT"] = str(port)
    env["RUNTIME_DIR"] = RUNTIME_DIR

    cmd = [
        "/usr/sbin/openvpn",
        "--config", ovpn_file,
        "--dev", dev,
        "--log", log_file
    ]
    proc = subprocess.Popen(cmd, env=env)

    ready = False
    for _ in range(10):
        time.sleep(1)
        status_file = os.path.join(RUNTIME_DIR, f"worker_{idx}.json")
        if os.path.exists(status_file) and check_socks5_handshake(port):
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
                    # Periodically verify egress traffic works
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
        time.sleep(REFRESH_INTERVAL)

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

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/sub":
            sub_host = self.resolve_sub_host()
            lines = self.build_lines(sub_host)
            body = ("\n".join(lines) + "\n") if lines else ""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
        elif parsed.path == "/sub/base64":
            sub_host = self.resolve_sub_host()
            lines = self.build_lines(sub_host)
            raw = ("\n".join(lines) + "\n").encode("utf-8")
            b64 = base64.b64encode(raw)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b64)
        elif parsed.path in ("/healthz", "/status"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            status_data = {"pool_size": POOL_SIZE, "public_host": PUBLIC_HOST, "workers": []}
            with lock:
                for idx, w in sorted(workers.items()):
                    status_data["workers"].append({
                        "slot": idx,
                        "port": w["port"],
                        "country": w["node"]["country"],
                        "vpn_server_ip": w["node"]["ip"],
                        "egress_ip": w.get("egress_ip"),
                        "uptime_sec": int(time.time() - w["ready_time"]),
                        "alive": check_socks5_handshake(w["port"])
                    })
            self.wfile.write(json.dumps(status_data, indent=2).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

def run_server():
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), ResinSubHandler)
    logging.info(f"Resin subscription HTTP server listening on http://0.0.0.0:{HTTP_PORT}/sub")
    server.serve_forever()

if __name__ == "__main__":
    t_sup = threading.Thread(target=supervisor_loop, daemon=True)
    t_sup.start()
    run_server()
