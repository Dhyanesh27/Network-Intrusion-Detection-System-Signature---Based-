import time
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
