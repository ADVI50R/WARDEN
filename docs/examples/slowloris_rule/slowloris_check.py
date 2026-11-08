#!/usr/bin/env python3
"""Slowloris (connection exhaustion) detector for Guardian script rules.

Slowloris opens many connections to a server and keeps each one alive by
sending a partial request very slowly, so the server runs out of connection
slots. It sends few packets, so packet-count rules usually miss it.

This script counts how many inbound TCP connections each remote IP is holding
open right now (ESTABLISHED or SYN_RECV to one of this server's listening
ports) by reading /proc/net/tcp and /proc/net/tcp6. It needs no root, no
network access and no external programs.

Output: one JSON line per suspicious IP, as Guardian expects:
    {"source": "192.168.56.20", "detail": "..."}

Options:
    --min-conn N   connections held by one IP to report it (default 20)
"""
import json
import socket
import struct
import sys

STATE_ESTABLISHED = "01"
STATE_SYN_RECV = "03"
STATE_LISTEN = "0A"


def parse_addr(hex_addr):
    """'0100007F:1F90' -> ('127.0.0.1', 8080). Handles IPv4 and IPv6 (v4-mapped -> IPv4)."""
    ip_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    raw = bytes.fromhex(ip_hex)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(ip_hex, 16))), port
    # /proc stores IPv6 as four little-endian 32-bit words
    words = struct.unpack("<4I", raw)
    ip6 = struct.pack(">4I", *words)
    if ip6[:12] == b"\x00" * 10 + b"\xff\xff":
        return socket.inet_ntop(socket.AF_INET, ip6[12:]), port
    return socket.inet_ntop(socket.AF_INET6, ip6), port


def read_table(path):
    rows = []
    try:
        with open(path) as f:
            next(f, None)  # header
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                try:
                    local, remote = parse_addr(parts[1]), parse_addr(parts[2])
                except (ValueError, OSError):
                    continue
                rows.append((local, remote, parts[3].upper()))
    except OSError:
        pass
    return rows


def main():
    min_conn = 20
    args = sys.argv[1:]
    if "--min-conn" in args:
        try:
            min_conn = max(2, int(args[args.index("--min-conn") + 1]))
        except (IndexError, ValueError):
            print("usage: slowloris_check.py [--min-conn N]", file=sys.stderr)
            return 2

    rows = read_table("/proc/net/tcp") + read_table("/proc/net/tcp6")
    listen_ports = {local[1] for local, _, st in rows if st == STATE_LISTEN}
    own_ips = {local[0] for local, _, _ in rows}

    per_ip = {}  # remote ip -> {local port: count}
    for local, remote, st in rows:
        if st not in (STATE_ESTABLISHED, STATE_SYN_RECV):
            continue
        if local[1] not in listen_ports:  # outbound connection made by this server
            continue
        ip = remote[0]
        if ip in own_ips or ip.startswith("127.") or ip == "::1":
            continue
        ports = per_ip.setdefault(ip, {})
        ports[local[1]] = ports.get(local[1], 0) + 1

    for ip, ports in sorted(per_ip.items()):
        total = sum(ports.values())
        if total < min_conn:
            continue
        by_port = ", ".join(f"{p}번 {n}개" for p, n in sorted(ports.items(), key=lambda x: -x[1]))
        print(json.dumps({
            "source": ip,
            "detail": f"연결 {total}개를 동시에 붙잡고 있음 ({by_port}, 기준 {min_conn}개) - Slowloris 같은 연결 고갈 공격 의심",
        }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
