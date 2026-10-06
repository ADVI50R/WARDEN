#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Guardian - 실습용 리눅스 네트워크 관제/방어 도구 (초안)

탐지: 포트 스캔, SYN 플러드, ICMP(핑) 플러드, SSH 무차별 대입, ARP 스푸핑, 대량 데이터 유출
대응: iptables 전용 체인(GUARDIAN)에 차단 규칙 추가 -> 일정 시간 후 자동 해제
연동: JSON Lines 로그 파일(logs/events.jsonl) + REST API (대시보드용)

실행: sudo python3 guardian.py
"""
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    from scapy.all import sniff, get_if_addr, get_if_hwaddr, IP, TCP, ICMP, ARP
except ImportError:
    sys.exit("[!] scapy 가 필요합니다: sudo apt install python3-scapy")

# ─────────────────────────── 설정 로드 ───────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "config.json"), encoding="utf-8") as f:
    CFG = json.load(f)

RULES = CFG["rules"]
IFACE = CFG["interface"]
DRY_RUN = CFG["dry_run"]
LOG_FILE = os.path.join(BASE_DIR, CFG["log_file"])
CHAIN = "GUARDIAN"

# 실제 값은 main() 의 init_network() 에서 채움 (테스트 스크립트에서 직접 지정 가능)
MY_IP = "0.0.0.0"
MY_MAC = "00:00:00:00:00:00"
WHITELIST = set()


def init_network():
    global MY_IP, MY_MAC, WHITELIST
    MY_IP = get_if_addr(IFACE)
    MY_MAC = get_if_hwaddr(IFACE).lower()
    WHITELIST = {x.lower() for x in CFG["whitelist"]} | {MY_IP, MY_MAC, "127.0.0.1"}

# ─────────────────────────── 공유 상태 ───────────────────────────
lock = threading.Lock()          # events / blocked / stats 보호
hist_lock = threading.Lock()     # history 보호
events = deque(maxlen=1000)      # 최근 이벤트 (API 로 제공)
blocked = {}                     # "1.2.3.4" 또는 "mac:aa:bb:.." -> 정보
stats = defaultdict(int)
last_alert = {}                  # (규칙, 출발지) -> 마지막 알림 시각 (알림 폭주 방지)
arp_table = {}                   # IP -> 처음 본 MAC
history = defaultdict(deque)     # (규칙, 출발지) -> deque[(시각, 값)]
START_TIME = time.time()

SEV_COLOR = {"info": "\033[36m", "warning": "\033[33m", "critical": "\033[31m"}
RESET = "\033[0m"


def now_iso(ts=None):
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).astimezone().isoformat(timespec="seconds")


# ─────────────────────────── 이벤트 기록 ───────────────────────────
def emit(ev_type, source, severity, detail, action="alert", cooldown=True):
    """이벤트를 메모리/파일/화면에 기록. 쿨다운 중이면 False 반환.
    cooldown=False: 차단 해제·수동 조작처럼 매번 남겨야 하는 기록용"""
    now = time.time()
    key = (ev_type, source)
    with lock:
        if cooldown:
            if now - last_alert.get(key, 0) < CFG["alert_cooldown_sec"]:
                return False
            last_alert[key] = now
        ev = {
            "id": uuid.uuid4().hex[:12],
            "timestamp": now_iso(now),
            "type": ev_type,
            "severity": severity,      # info / warning / critical
            "source": source,          # 공격 출발지 IP (ARP 는 MAC)
            "target": MY_IP,
            "detail": detail,
            "action": action,          # alert / block / block(dry-run) / unblock
        }
        events.append(ev)
        stats["events_total"] += 1
        stats[f"events_{ev_type}"] += 1
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    color = SEV_COLOR.get(severity, "")
    print(f"{color}[{ev['timestamp']}] [{severity.upper()}] {ev_type} | {source} | {detail} | {action}{RESET}")
    return True


# ─────────────────────────── 방화벽(iptables) ───────────────────────────
def iptables(*args):
    return subprocess.run(["iptables", *args], capture_output=True, text=True)


def iptables_checked(*args):
    """규칙 추가/삭제용: 실패하면 화면에 이유를 보여줌 (조용히 실패하면 '차단된 줄' 착각함)"""
    r = iptables(*args)
    if r.returncode != 0:
        print(f"[!] iptables {' '.join(args)} 실패: {r.stderr.strip()}")
    return r.returncode == 0


def setup_firewall():
    if DRY_RUN:
        return
    iptables("-N", CHAIN)            # 전용 체인 생성 (이미 있으면 무시됨)
    iptables("-F", CHAIN)            # 이전 실행에서 남은 규칙 비우기
    if iptables("-C", "INPUT", "-j", CHAIN).returncode != 0:
        iptables("-I", "INPUT", "1", "-j", CHAIN)
    if CFG.get("enable_syncookies"):
        subprocess.run(["sysctl", "-w", "net.ipv4.tcp_syncookies=1"], capture_output=True)


def cleanup_firewall():
    if DRY_RUN:
        return
    iptables("-D", "INPUT", "-j", CHAIN)
    iptables("-F", CHAIN)
    iptables("-X", CHAIN)


def _rule_args(target):
    if target.startswith("mac:"):
        return ["-m", "mac", "--mac-source", target[4:], "-j", "DROP"]
    return ["-s", target, "-j", "DROP"]


def is_whitelisted(target):
    t = target[4:] if target.startswith("mac:") else target
    return t.lower() in WHITELIST


def block(target, reason, duration=None):
    if is_whitelisted(target):
        print(f"[i] {target} 는 화이트리스트라 차단하지 않음")
        return False
    duration = duration or CFG["block_duration_sec"]
    with lock:
        if target in blocked:
            return False
        blocked[target] = {"since": time.time(), "until": time.time() + duration, "reason": reason}
        stats["blocks_total"] += 1
    if not DRY_RUN:
        iptables_checked("-A", CHAIN, *_rule_args(target))
    print(f"\033[41m[BLOCK]{RESET} {target} ({reason}) {duration}초 차단{' [dry-run]' if DRY_RUN else ''}")
    return True


def unblock(target):
    with lock:
        info = blocked.pop(target, None)
    if info is None:
        return False
    if not DRY_RUN:
        iptables_checked("-D", CHAIN, *_rule_args(target))
    emit("unblock", target, "info", f"차단 해제 (사유였던 규칙: {info['reason']})", "unblock", cooldown=False)
    return True


def maintenance_loop():
    """만료된 차단 해제 + 오래된 기록 정리 (5초마다)"""
    while True:
        time.sleep(5)
        now = time.time()
        with lock:
            expired = [k for k, v in blocked.items() if v["until"] <= now]
        for k in expired:
            unblock(k)
        with hist_lock:
            for k in [k for k, q in history.items() if not q or now - q[-1][0] > 300]:
                del history[k]


# ─────────────────────────── 탐지 로직 ───────────────────────────
def record(rule, key, value, window, now):
    """슬라이딩 윈도우: window 초 이내 기록만 남기고 복사본 반환"""
    with hist_lock:
        q = history[(rule, key)]
        q.append((now, value))
        while q and now - q[0][0] > window:
            q.popleft()
        return list(q)


def action_for(rule):
    if not RULES[rule].get("block"):
        return "alert"
    return "block(dry-run)" if DRY_RUN else "block"


def fire(rule, source, severity, detail, block_target=None):
    if emit(rule, source, severity, detail, action_for(rule)) and RULES[rule].get("block"):
        block(block_target or source, rule)


def check_port_scan(src, dport, now):
    r = RULES["port_scan"]
    if not r["enabled"]:
        return
    q = record("port_scan", src, dport, r["window_sec"], now)
    ports = {p for _, p in q}
    if len(ports) >= r["distinct_ports"]:
        fire("port_scan", src, "warning", f"{r['window_sec']}초 동안 서로 다른 포트 {len(ports)}개에 접속 시도")


def check_syn_flood(src, now):
    r = RULES["syn_flood"]
    if not r["enabled"]:
        return
    q = record("syn_flood", src, 1, r["window_sec"], now)
    if len(q) >= r["max_syn"]:
        fire("syn_flood", src, "critical", f"{r['window_sec']}초 동안 SYN {len(q)}개")
    # 출발지를 위조(랜덤)하는 공격 대비: 전체 SYN 양도 감시 (차단 대상이 없으므로 알림만)
    # 출발지가 여러 개일 때만 알림 -> IP 하나가 보내는 일반 SYN 플러드를 '위조'로 오인하지 않음
    total = record("syn_flood", "*", src, r["window_sec"], now)
    sources = len({s for _, s in total})
    if len(total) >= r["global_max_syn"] and sources >= r.get("global_min_sources", 10):
        emit("syn_flood_distributed", "*", "critical",
             f"{r['window_sec']}초 동안 출발지 {sources}곳에서 SYN {len(total)}개 "
             f"(출발지 위조 의심, syncookies 로 방어)", "alert")


def check_ssh(src, now):
    r = RULES["ssh_bruteforce"]
    if not r["enabled"]:
        return
    q = record("ssh_bruteforce", src, 1, r["window_sec"], now)
    if len(q) >= r["max_attempts"]:
        fire("ssh_bruteforce", src, "critical", f"{r['window_sec']}초 동안 SSH 접속 시도 {len(q)}회")


def check_icmp(src, now):
    r = RULES["icmp_flood"]
    if not r["enabled"]:
        return
    q = record("icmp_flood", src, 1, r["window_sec"], now)
    if len(q) >= r["max_packets"]:
        fire("icmp_flood", src, "warning", f"{r['window_sec']}초 동안 ping {len(q)}개")


def check_arp(pkt):
    ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc.lower()
    if ip == "0.0.0.0" or mac == MY_MAC:
        return
    old = arp_table.get(ip)
    if old is None:
        arp_table[ip] = mac          # 처음 본 IP-MAC 조합을 "정상"으로 기억
    elif old != mac:
        fire("arp_spoof", mac, "critical",
             f"{ip} 의 MAC 주소가 {old} -> {mac} 로 바뀜 (ARP 스푸핑 의심)", block_target=f"mac:{mac}")


def check_exfil(dst, size, now):
    r = RULES["exfiltration"]
    if not r["enabled"]:
        return
    q = record("exfiltration", dst, size, r["window_sec"], now)
    total = sum(v for _, v in q)
    if total >= r["max_bytes"]:
        emit("exfiltration", dst, "warning",
             f"{r['window_sec']}초 동안 {dst} 로 {total / 1_000_000:.1f}MB 전송 (유출 의심)", "alert")


def handle(pkt):
    try:
        _handle(pkt)
    except Exception as e:  # 패킷 하나 때문에 전체가 죽지 않도록
        print(f"[!] 패킷 처리 오류: {e}")


def _handle(pkt):
    now = time.time()
    stats["packets_total"] += 1

    if ARP in pkt:
        if RULES["arp_spoof"]["enabled"]:
            check_arp(pkt)
        return
    if IP not in pkt:
        return

    src, dst = pkt[IP].src, pkt[IP].dst
    if src == MY_IP:                      # 나가는 트래픽 -> 유출 감시
        check_exfil(dst, len(pkt), now)
        return
    if dst != MY_IP:                      # 나에게 온 게 아님
        return
    # 이미 차단한 IP 는 무시 (실제로는 iptables 가 버리고 있음).
    # 단, dry-run 에선 진짜로 막힌 게 아니므로 계속 탐지해야 다음 공격 테스트가 보임
    if src in blocked and not DRY_RUN:
        return

    if TCP in pkt:
        flags = int(pkt[TCP].flags)
        if flags & 0x02 and not flags & 0x10:   # SYN 만 있고 ACK 없음 = 새 연결 시도
            stats["syn_total"] += 1
            dport = pkt[TCP].dport
            check_port_scan(src, dport, now)
            check_syn_flood(src, now)
            if dport in RULES["ssh_bruteforce"]["ports"]:
                check_ssh(src, now)
    elif ICMP in pkt and pkt[ICMP].type == 8:   # echo request (ping)
        stats["icmp_total"] += 1
        check_icmp(src, now)


# ─────────────────────────── 대시보드용 REST API ───────────────────────────
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def normalize_target(text):
    """수동 차단/해제 대상 검사. 올바르면 정리된 문자열, 아니면 None.
    '0.0.0.0/0' 같은 범위를 막지 않으면 실수 한 번에 서버 전체가 차단될 수 있음"""
    t = text.strip().lower()
    if t.startswith("mac:"):
        return t if MAC_RE.match(t[4:]) else None
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        return None


class API(BaseHTTPRequestHandler):
    def _headers(self, code, length=0):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")   # 다른 포트의 대시보드에서 호출 허용
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", str(length))
        self.end_headers()

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._headers(code, len(body))
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        return body if isinstance(body, dict) else {}

    def do_OPTIONS(self):
        self._headers(204)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            limit = max(1, int(q.get("limit", ["50"])[0]))
        except ValueError:
            return self._send(400, {"error": "limit 은 숫자여야 합니다"})
        if u.path == "/api/status":
            with lock:
                self._send(200, {
                    "status": "running",
                    "uptime_sec": int(time.time() - START_TIME),
                    "interface": IFACE, "my_ip": MY_IP, "dry_run": DRY_RUN,
                    "blocked_count": len(blocked), "stats": dict(stats),
                })
        elif u.path == "/api/events":
            ev_type = q.get("type", [None])[0]
            with lock:
                data = [e for e in events if not ev_type or e["type"] == ev_type]
            self._send(200, {"events": list(reversed(data))[:limit]})   # 최신순
        elif u.path == "/api/blocked":
            with lock:
                data = [{"target": k, "reason": v["reason"], "since": now_iso(v["since"]),
                         "until": now_iso(v["until"]), "remaining_sec": int(v["until"] - time.time())}
                        for k, v in blocked.items()]
            self._send(200, {"blocked": data})
        elif u.path == "/api/rules":
            self._send(200, {"dry_run": DRY_RUN, "rules": RULES})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        body = self._body()
        target = normalize_target(str(body.get("target", "")))
        if not target:
            return self._send(400, {"error": "target 은 IP 하나 또는 'mac:aa:bb:cc:dd:ee:ff' 형식이어야 합니다 "
                                             "(예: {\"target\": \"192.168.56.20\"})"})
        if u.path == "/api/block":
            duration = body.get("duration_sec")
            if duration is not None and (not isinstance(duration, int) or duration <= 0):
                return self._send(400, {"error": "duration_sec 은 1 이상의 정수(초)여야 합니다"})
            if is_whitelisted(target):
                return self._send(200, {"ok": False, "reason": "화이트리스트 대상"})
            ok = block(target, str(body.get("reason", "manual")), duration)
            if ok:
                emit("manual_block", target, "info", "대시보드에서 수동 차단",
                     "block(dry-run)" if DRY_RUN else "block", cooldown=False)
            self._send(200, {"ok": ok} if ok else {"ok": False, "reason": "이미 차단 중"})
        elif u.path == "/api/unblock":
            ok = unblock(target)
            self._send(200, {"ok": ok} if ok else {"ok": False, "reason": "차단 목록에 없음"})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):   # 요청마다 찍히는 기본 로그 끄기
        pass


# ─────────────────────────── 실행 ───────────────────────────
def main():
    if os.geteuid() != 0:
        sys.exit("[!] root 권한이 필요합니다: sudo python3 guardian.py")
    init_network()
    if MY_IP == "0.0.0.0":
        sys.exit(f"[!] 인터페이스 '{IFACE}' 에 IP가 없습니다. 'ip a' 로 확인 후 config.json 을 고치세요.")

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    setup_firewall()
    threading.Thread(target=maintenance_loop, daemon=True).start()

    api = CFG["api"]
    if api["enabled"]:
        server = ThreadingHTTPServer((api["host"], api["port"]), API)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    print("=" * 60)
    print(f" Guardian 시작 | {IFACE} ({MY_IP})")
    print(f" 모드: {'DRY-RUN (탐지만, 실제 차단 안 함)' if DRY_RUN else '실제 차단 모드'}")
    if api["enabled"]:
        print(f" API : http://{api['host']}:{api['port']}/api/status")
    print(f" 로그: {LOG_FILE}")
    print(" 종료: Ctrl+C")
    print("=" * 60)

    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    try:
        sniff(iface=IFACE, prn=handle, store=False, filter="arp or ip")
    except KeyboardInterrupt:
        pass
    finally:
        cleanup_firewall()
        print("\n[i] 종료: 방화벽 규칙을 정리했습니다.")


if __name__ == "__main__":
    main()
