import time
import json
import argparse
import socket
import threading
from collections import defaultdict

try:
    import psutil
    import requests
except Exception:
    print("Missing dependency: pip install psutil requests")
    raise

SIGNATURES_PATH = "signatures/signatures.json"
DEFAULT_COOLDOWN = 60  # seconds between duplicate alerts per signature

# endpoints to try for updating alerts and live dashboard traffic
ENDPOINTS = ["/alerts", "/events", "/live", "/live/alerts"]

def load_signatures(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def resolve_host(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def match_signature(sig, proc_name, remote_host):
    pname = (proc_name or "").lower()
    rhost = (remote_host or "").lower()
    typ = sig.get("type", "domain")
    pats = [p.lower() for p in sig.get("patterns", [])]
    if typ in ("process", "hybrid"):
        for p in pats:
            if p in pname:
                return True
    if typ in ("domain", "hybrid"):
        for p in pats:
            if rhost.endswith(p) or p in rhost:
                return True
    return False

def post_to_endpoint(base, endpoint, headers, payload):
    url = base.rstrip("/") + endpoint
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=5)
        if 200 <= resp.status_code < 300:
            return True, resp.status_code
        return False, resp.status_code
    except Exception as e:
        return False, str(e)

def send_alerts_to_backend(backend, jwt, sig, src_ip, dst_ip, dst_host, proc_name, allow_demo=False):
    # If signature is a demo and demos are not allowed, skip sending
    if sig.get("demo", False) and not allow_demo:
        print(f"[skipped-demo] {sig.get('id')} (demo) not sent")
        return

    payload = {
        "type": "alert",
        "signature_id": sig.get("id"),
        "name": sig.get("name"),
        "severity": sig.get("severity"),
        "description": sig.get("description"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_host": dst_host,
        "process_name": proc_name,
        "timestamp": int(time.time()),
        # flag to indicate UI should show this in live traffic view
        "live_traffic": True,
        # explicit source so backend/UI can filter demo vs real
        "source": "realtime",
        # mirror signature demo flag for backend verification
        "demo": bool(sig.get("demo", False))
    }
    headers = {"Content-Type": "application/json", "X-Source": "realtime"}
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"

    # Try /alerts first, then fallbacks for live/dashboard
    results = []
    # primary attempt at /alerts
    success, info = post_to_endpoint(backend, "/alerts", headers, payload)
    results.append(("/alerts", success, info))
    # also try other common live endpoints so dashboard can show immediately
    for ep in ENDPOINTS:
        if ep == "/alerts":
            continue
        success, info = post_to_endpoint(backend, ep, headers, payload)
        results.append((ep, success, info))

    # logging summary
    sent = [r for r in results if r[1]]
    failed = [r for r in results if not r[1]]
    if sent:
        print(f"[alert-sent] {sig.get('id')} -> {dst_host or dst_ip} via {[s[0] for s in sent]}")
    else:
        print(f"[alert-failed] {sig.get('id')} -> {dst_host or dst_ip}; failures: {failed}")

def monitor_loop(signatures, backend, jwt, interval, cooldown, allow_demo):
    last_alert = defaultdict(lambda: 0)
    while True:
        try:
            conns = psutil.net_connections(kind='inet')
        except Exception as e:
            print("psutil.net_connections error:", e)
            time.sleep(interval)
            continue

        for c in conns:
            if not c.raddr:
                continue
            try:
                proc_name = None
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except Exception:
                        proc_name = None
                src_ip = c.laddr.ip if c.laddr else None
                dst_ip = c.raddr.ip
                dst_host = resolve_host(dst_ip) or ""
            except Exception:
                continue

            for sig in signatures:
                sid = sig.get("id")
                if time.time() - last_alert[sid] < cooldown:
                    continue
                # if signature is demo and demos not allowed, skip matching/sending
                if sig.get("demo", False) and not allow_demo:
                    continue
                if match_signature(sig, proc_name, dst_host):
                    # send alert without blocking monitoring loop
                    threading.Thread(target=send_alerts_to_backend, args=(backend, jwt, sig, src_ip, dst_ip, dst_host, proc_name, allow_demo), daemon=True).start()
                    last_alert[sid] = time.time()
        time.sleep(interval)

def main():
    parser = argparse.ArgumentParser(description="Signature-based monitor that updates alerts + live dashboard")
    parser.add_argument("--backend", required=True, help="Backend base URL, e.g. http://localhost:4000")
    parser.add_argument("--jwt-token", default=None, help="Optional JWT for Authorization header")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval seconds")
    parser.add_argument("--cooldown", type=int, default=DEFAULT_COOLDOWN, help="Cooldown seconds per signature")
    parser.add_argument("--allow-demo", action="store_true", help="Allow sending demo/test alerts (default: false)")
    args = parser.parse_args()

    try:
        sigs = load_signatures(SIGNATURES_PATH)
    except Exception as e:
        print("Failed to load signatures:", e)
        return

    print(f"Loaded {len(sigs)} signatures. Monitoring connections and processes... (allow_demo={args.allow_demo})")
    monitor_loop(sigs, args.backend, args.jwt_token, args.interval, args.cooldown, args.allow_demo)

if __name__ == "__main__":
    main()
