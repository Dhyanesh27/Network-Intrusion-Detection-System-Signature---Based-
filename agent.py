"""
Simple agent demo (Python) — captures packets (requires scapy) and forwards events to backend.

This is a demo. Run with:

# using mTLS
python agent.py --mtls --backend https://localhost:4000

# using JWT
python agent.py --jwt-token <token> --backend http://localhost:4000

Requires: pip install scapy requests
"""
import argparse
import json
import threading
import time
import requests
import psutil
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import struct


def extract_sni_from_client_hello(raw_bytes):
    """Attempt to parse TLS ClientHello and extract SNI (server_name) if present.
    This is a best-effort parser and will return None on failure.
    """
    try:
        b = raw_bytes
        # Need at least TLS record header (5) + handshake header (4)
        if len(b) < 5 + 4:
            return None
        # TLS record header
        content_type = b[0]
        if content_type != 0x16:  # handshake
            return None
        # skip record header (5)
        # handshake message starts at 5
        hs_start = 5
        if len(b) < hs_start + 4:
            return None
        hs_type = b[hs_start]
        if hs_type != 0x01:  # ClientHello
            return None
        # handshake length (3 bytes)
        hs_len = struct.unpack('!I', b'\x00' + b[hs_start+1:hs_start+4])[0]
        if len(b) < hs_start + 4 + hs_len:
            # incomplete
            pass

        # move pointer into ClientHello body
        ptr = hs_start + 4
        # client_version (2) + random (32)
        ptr += 2 + 32
        if ptr >= len(b):
            return None
        # session id
        if ptr + 1 > len(b):
            return None
        session_id_len = b[ptr]
        ptr += 1 + session_id_len
        if ptr + 2 > len(b):
            return None
        # cipher suites
        cs_len = struct.unpack('!H', b[ptr:ptr+2])[0]
        ptr += 2 + cs_len
        if ptr + 1 > len(b):
            return None
        # compression methods
        comp_len = b[ptr]
        ptr += 1 + comp_len
        if ptr + 2 > len(b):
            return None
        # extensions length
        ext_total_len = struct.unpack('!H', b[ptr:ptr+2])[0]
        ptr += 2
        end_ext = ptr + ext_total_len
        while ptr + 4 <= end_ext and ptr + 4 <= len(b):
            ext_type = struct.unpack('!H', b[ptr:ptr+2])[0]
            ext_len = struct.unpack('!H', b[ptr+2:ptr+4])[0]
            ptr += 4
            if ext_type == 0x0000:  # server_name
                # server_name list length (2)
                if ptr + 2 > len(b):
                    return None
                list_len = struct.unpack('!H', b[ptr:ptr+2])[0]
                ptr += 2
                list_end = ptr + list_len
                while ptr + 3 <= list_end and ptr + 3 <= len(b):
                    name_type = b[ptr]
                    name_len = struct.unpack('!H', b[ptr+1:ptr+3])[0]
                    ptr += 3
                    if ptr + name_len > len(b):
                        return None
                    server_name = b[ptr:ptr+name_len].decode('utf-8', errors='ignore')
                    return server_name
            else:
                ptr += ext_len
        return None
    except Exception:
        return None


def send_event(url, data, mtls=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        if mtls:
            r = requests.post(url + '/api/agent/event', json=data, headers=headers, cert=(mtls['cert'], mtls['key']), verify=mtls.get('ca', True))
        else:
            r = requests.post(url + '/api/agent/event', json=data, headers=headers)
        print('sent', r.status_code)
    except Exception as e:
        print('error sending event', e)


def packet_handler(pkt, args, backend_url, mtls, token):
    if IP in pkt:
        ip = pkt[IP]
        proto = 'TCP' if TCP in pkt else ('UDP' if UDP in pkt else str(ip.proto))
        src_port = pkt.sport if hasattr(pkt, 'sport') else None
        dst_port = pkt.dport if hasattr(pkt, 'dport') else None
        data = {
            'time': time.strftime('%H:%M:%S'),
            'src': ip.src,
            'src_port': src_port,
            'dst': ip.dst,
            'dst_port': dst_port,
            'proto': proto,
            'size': len(pkt)
        }

        # Try to attribute to a local process using psutil (best-effort, requires privileges)
        try:
            now = time.time()
            # cached small window of connections to avoid heavy syscall on every packet
            if not hasattr(packet_handler, '_cache'):
                packet_handler._cache = {'ts': 0, 'conns': []}
            if now - packet_handler._cache['ts'] > 1.0:
                # refresh connection table
                try:
                    packet_handler._cache['conns'] = psutil.net_connections(kind='inet')
                except Exception:
                    packet_handler._cache['conns'] = []
                packet_handler._cache['ts'] = now

            matched = None
            for c in packet_handler._cache['conns']:
                # c.laddr and c.raddr are tuples (ip, port) when present
                try:
                    laddr = (c.laddr.ip, c.laddr.port) if hasattr(c, 'laddr') and c.laddr else (None, None)
                except Exception:
                    laddr = (None, None)
                try:
                    raddr = (c.raddr.ip, c.raddr.port) if hasattr(c, 'raddr') and c.raddr else (None, None)
                except Exception:
                    raddr = (None, None)

                # match either direction
                if (laddr[0] == ip.src and laddr[1] == src_port and raddr[0] == ip.dst and raddr[1] == dst_port) or (
                        laddr[0] == ip.dst and laddr[1] == dst_port and raddr[0] == ip.src and raddr[1] == src_port):
                    matched = c
                    break

            if matched and matched.pid:
                data['pid'] = matched.pid
                try:
                    p = psutil.Process(matched.pid)
                    data['proc_name'] = p.name()
                except Exception:
                    data['proc_name'] = None
        except Exception:
            # silently ignore attribution failures
            pass

        # extract DNS qname if present (helps detecting domain accesses)
        try:
            if pkt.haslayer(DNS) and hasattr(pkt, 'qd') and pkt.qd:
                try:
                    q = pkt.qd.qname.decode('utf-8') if isinstance(pkt.qd.qname, bytes) else str(pkt.qd.qname)
                    data['qname'] = q.rstrip('.')
                except Exception:
                    pass
        except Exception:
            pass

        # extract HTTP Host header from raw payload if present
        try:
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                if b'Host: ' in raw:
                    try:
                        start = raw.index(b'Host: ') + len(b'Host: ')
                        end = raw.index(b'\r\n', start)
                        host = raw[start:end].decode('utf-8', errors='ignore')
                        data['http_host'] = host
                    except Exception:
                        pass
        except Exception:
            pass

        # attempt extracting TLS SNI from ClientHello in Raw payload
        try:
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                sni = extract_sni_from_client_hello(raw)
                if sni:
                    data['sni'] = sni
        except Exception:
            pass

        # 🟩 ADD THIS LINE (pretty print to terminal)
        print(json.dumps(data, indent=2))

        threading.Thread(target=send_event, args=(backend_url, data, mtls, token)).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', required=True)
    parser.add_argument('--mtls', action='store_true')
    parser.add_argument('--mtls-cert')
    parser.add_argument('--mtls-key')
    parser.add_argument('--mtls-ca')
    parser.add_argument('--jwt-token')
    parser.add_argument('--iface', default=None)
    args = parser.parse_args()

    mtls = None
    if args.mtls:
        mtls = {'cert': args.mtls_cert or 'client.crt', 'key': args.mtls_key or 'client.key'}
        if args.mtls_ca:
            mtls['ca'] = args.mtls_ca

    print('Starting capture, backend:', args.backend)
    sniff(prn=lambda p: packet_handler(p, args, args.backend, mtls, args.jwt_token), iface=args.iface, store=0)


if __name__ == '__main__':
    main()
