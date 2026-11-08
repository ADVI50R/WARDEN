#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WARDEN - 실습용 리눅스 네트워크 관제/방어 도구 (초안)

탐지: 포트 스캔, SYN 플러드, ICMP(핑) 플러드, SSH 무차별 대입, ARP 스푸핑, 대량 데이터 유출
대응: iptables 전용 체인(WARDEN)에 차단 규칙 추가 -> 일정 시간 후 자동 해제
연동: JSON Lines 로그 파일(logs/events.jsonl) + REST API (대시보드용)

실행: sudo python3 warden.py
"""
import ipaddress
import itertools
import json
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
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
    sys.exit("[!] scapy 가 필요합니다: sudo apt install python3-scapy "
             "(록키·RHEL: sudo dnf install epel-release && sudo dnf install python3-scapy) — 또는 sudo python3 setup.py")
try:
    from scapy.all import UDP
except ImportError:      # 자체 테스트용 가짜 scapy 에는 UDP 가 없을 수 있음
    UDP = None

# ─────────────────────────── 설정 로드 ───────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "config.json"), encoding="utf-8") as f:
    CFG = json.load(f)



class _Rules(dict):
    """기본 탐지기 설정(id -> 규칙). rules/ 에 파일이 없으면(삭제됨) 꺼진 규칙으로 취급"""
    def __missing__(self, key):
        return {"enabled": False, "block": False, "ports": []}


RULES = _Rules()
IFACE = CFG["interface"]
DRY_RUN = CFG["dry_run"]
LOG_FILE = os.path.join(BASE_DIR, CFG["log_file"])
CHAIN = "WARDEN"

# 실제 값은 main() 의 init_network() 에서 채움 (테스트 스크립트에서 직접 지정 가능)
MY_IP = "0.0.0.0"
MY_MAC = "00:00:00:00:00:00"
WHITELIST = set()
MY_IPS = set()                   # 이 서버의 모든 IPv4 (감시 인터페이스 말고 다른 어댑터의 주소도 포함)


def local_ipv4():
    """리눅스는 어느 어댑터로 들어온 패킷이든 서버 자신의 주소면 받아 준다 (관리망 IP 를 감시망 쪽으로 찔러도 닿음).
    그래서 감시 인터페이스의 주소 하나만 '나'로 보면 다른 주소로 오는 공격을 놓친다"""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True, timeout=5).stdout
        return set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", out))
    except (OSError, subprocess.SubprocessError):
        return set()


def is_me(ip):
    return ip == MY_IP or ip in MY_IPS


def init_network():
    global MY_IP, MY_MAC, WHITELIST, MY_IPS
    MY_IP = get_if_addr(IFACE)
    MY_MAC = get_if_hwaddr(IFACE).lower()
    MY_IPS = local_ipv4() | {MY_IP}
    apply_whitelist()


def fixed_whitelist():
    """화면에서 뺄 수 없는 주소: 서버 자신(어느 어댑터든)과 loopback. 빠지면 WARDEN 이 자기 자신을 차단할 수 있음"""
    return {MY_IP, MY_MAC, "127.0.0.1"} | MY_IPS


def apply_whitelist():
    """config.json 의 whitelist 에, 대시보드에서 바꾼 내용(logs/whitelist_extra.json 의 add / remove)을 반영한다.
    config.json 은 건드리지 않아서 코드만 갱신하는 복사로도 화면에서 정한 값이 지워지지 않는다"""
    global WHITELIST
    extra = _load_json("whitelist_extra.json", {})
    extra = extra if isinstance(extra, dict) else {}
    add = {str(x).lower() for x in extra.get("add", []) if isinstance(x, str)}
    rem = {str(x).lower() for x in extra.get("remove", []) if isinstance(x, str)}
    WHITELIST = (({x.lower() for x in CFG["whitelist"]} | add) - rem) | fixed_whitelist()

# ─────────────────────────── 공유 상태 ───────────────────────────
lock = threading.Lock()          # events / blocked / stats 보호
hist_lock = threading.Lock()     # history 보호
events = deque(maxlen=1000)      # 최근 이벤트 (API 로 제공)
blocked = {}                     # "1.2.3.4" 또는 "mac:aa:bb:.." -> 정보
stats = defaultdict(int)
last_alert = {}                  # (규칙, 출발지) -> 마지막 알림 시각 (알림 폭주 방지)
arp_table = {}                   # IP -> 처음 본 MAC
history = None                   # (규칙, 출발지) -> Window (아래 '탐지 로직'에서 만듦)
rule_hits = {}                   # 이벤트 유형 -> {"count", "last"} (규칙 카드의 탐지 횟수·마지막 탐지)
rules_all = {}                   # id -> 규칙 (rules/*.json 전부)
rule_errors = {}                 # 파일 이름 -> 불러오기 실패 이유
_rules_sig = None                # 폴더 내용이 바뀌었는지 확인용
SCRIPT_RULES = {}                # id -> 플러그인(스크립트) 방식 규칙 (detector == "script")
_script_last_run = {}            # 규칙 id -> 마지막으로 실행한 시각
_script_errors_seen = {}         # 규칙 id -> 마지막으로 찍은 오류 (같은 오류 반복 출력 방지)
_script_running = set()          # 지금 실행 중인 규칙 id (주기보다 오래 걸려도 겹쳐 돌지 않게)
rule_changes = deque(maxlen=200) # 규칙 변경 기록 (탐지 이벤트와 분리: 통계·공격 기록에 안 들어감)
notes = {}                       # 대상 -> 메모 (차단 기록마다 붙이는 설명)
attackers = {}                   # 출발지 -> 누적 공격 기록 (IP별 로그)
START_TIME = time.time()
NOTE_MAX = 200

# 패킷 보기용 링 버퍼 (와이어샤크처럼 지나가는 패킷의 헤더 요약만 보관, 내용(payload)은 저장하지 않음)
PV = {"enabled": True, "buffer": 2000, "max_per_sec": 1000}
PV.update({k: v for k, v in CFG.get("packet_view", {}).items() if k in PV})
packets = deque(maxlen=max(100, int(PV["buffer"])))
packet_seq = itertools.count(1)
_pv_budget = {"sec": 0, "used": 0}   # 초당 기록 한도 (플러드 때 기록 때문에 탐지가 느려지지 않도록)
ICMP_TYPES = {0: "Echo reply (ping 응답)", 3: "Destination unreachable", 8: "Echo request (ping 요청)",
              11: "Time exceeded"}
TCP_FLAG_NAMES = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")]

SEV_COLOR = {"info": "\033[36m", "warning": "\033[33m", "critical": "\033[31m"}
RESET = "\033[0m"


def now_iso(ts=None):
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).astimezone().isoformat(timespec="seconds")


# ─────────────────────────── IP별 공격 기록 · 메모 · 영구 차단 저장 ───────────────────────────
def _data_path(name):
    return os.path.join(os.path.dirname(LOG_FILE), name)


def _save_json(name, obj):
    path = _data_path(name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)               # 쓰다가 꺼져도 파일이 깨지지 않게 교체 방식으로 저장


def _load_json(name, default):
    try:
        with open(_data_path(name), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


ADMIN_EVENTS = {"unblock", "manual_block", "rule_toggle"}      # 공격 탐지가 아닌 관리 작업 기록
NOT_ATTACKS = ADMIN_EVENTS


def count_attack(ev):
    """이벤트 하나를 출발지별 누적 기록에 반영 (lock 을 잡은 상태에서 호출).
    차단 해제·규칙 켜기끄기(rule_toggle, source 가 IP 가 아니라 규칙 이름)·출발지가 없는('*') 이벤트는
    공격 기록이 아니므로 제외 (실시간 로그에는 그대로 남음)"""
    if ev["type"] in NOT_ATTACKS:
        return
    hit = rule_hits.setdefault(ev["type"], {"count": 0, "last": ev["timestamp"]})
    hit["count"] += 1
    hit["last"] = ev["timestamp"]
    if ev["source"] == "*":
        return
    a = attackers.setdefault(ev["source"], {"total": 0, "blocks": 0, "by_type": {},
                                            "first": ev["timestamp"], "last": ev["timestamp"]})
    a["total"] += 1
    a["by_type"][ev["type"]] = a["by_type"].get(ev["type"], 0) + 1
    if ev["action"].startswith("block"):
        a["blocks"] += 1
    a["last"] = ev["timestamp"]


def count_stats(ev):
    """'탐지된 위협' 숫자. 차단 해제·수동 차단 같은 관리 작업은 위협이 아니므로 세지 않음"""
    if ev["type"] not in ADMIN_EVENTS:
        stats["events_total"] += 1
        stats[f"events_{ev['type']}"] += 1


def load_persisted():
    """재시작해도 탐지 로그·누적 숫자·IP별 기록·메모가 남도록 로그 파일에서 다시 읽는다"""
    try:
        with open(LOG_FILE, encoding="utf-8") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                    count_attack(ev)
                    ev.setdefault("id", uuid.uuid4().hex[:12])         # 아주 옛날 기록에는 id 가 없음
                    events.append(ev)                                  # 최근 것만 남음 (deque 크기만큼)
                    count_stats(ev)
                    if ev.get("action") == "block":
                        stats["blocks_auto"] += ev["type"] not in ADMIN_EVENTS
                    elif ev.get("action") == "block(dry-run)":
                        stats["blocks_auto_sim"] += ev["type"] not in ADMIN_EVENTS
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
    except OSError:
        pass
    try:
        with open(_data_path("rule_changes.jsonl"), encoding="utf-8") as f:
            for line in f.readlines()[-rule_changes.maxlen:]:
                try:
                    rule_changes.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    saved = _load_json("notes.json", {})
    if isinstance(saved, dict):
        notes.update({k: str(v)[:NOTE_MAX] for k, v in saved.items()})


def log_rule_change(rule, detail):
    """규칙 변경(켜기/끄기·추가·삭제) 기록. 탐지 이벤트가 아니므로 events·통계에 넣지 않고 별도 파일에 남김"""
    ev = {"timestamp": now_iso(), "rule": rule, "detail": detail}
    with lock:
        rule_changes.append(ev)
        with open(_data_path("rule_changes.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"[규칙 변경] {rule} | {detail}")


def set_note(target, text):
    text = str(text).strip()[:NOTE_MAX]
    with lock:
        if text:
            notes[target] = text
        else:
            notes.pop(target, None)
        snapshot = dict(notes)
    _save_json("notes.json", snapshot)


def save_permanent():
    with lock:
        data = {k: {"reason": v["reason"], "since": v["since"]} for k, v in blocked.items() if v.get("permanent")}
    _save_json("permanent_blocks.json", data)


def restore_permanent():
    """영구 차단은 WARDEN 을 껐다 켜도 유지 (setup_firewall 이 체인을 비우므로 다시 적용)"""
    for target, info in _load_json("permanent_blocks.json", {}).items():
        if isinstance(info, dict) and normalize_target(target) == target:
            block(target, str(info.get("reason", "permanent")), permanent=True)


# ─────────────────────────── 이벤트 기록 ───────────────────────────
def emit(ev_type, source, severity, detail, action="alert", cooldown=True, meta=None):
    """이벤트를 메모리/파일/화면에 기록. 쿨다운 중이면 False 반환.
    cooldown=False: 차단 해제·수동 조작처럼 매번 남겨야 하는 기록용.
    meta: 탐지 근거 숫자(횟수·기준·기간 등). 대시보드 '정보' 분석(analyze_event)이 사용"""
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
        if meta:
            ev["meta"] = meta
        events.append(ev)
        count_attack(ev)
        count_stats(ev)
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


_firewall_ready = False          # setup_firewall() 이 실제로 체인을 만들었는지 (dry_run 을 왔다갔다해도 정리가 되도록)


def setup_firewall():
    global _firewall_ready
    if DRY_RUN:
        return
    iptables("-N", CHAIN)            # 전용 체인 생성 (이미 있으면 무시됨)
    iptables("-F", CHAIN)            # 이전 실행에서 남은 규칙 비우기
    if iptables("-C", "INPUT", "-j", CHAIN).returncode != 0:
        iptables("-I", "INPUT", "1", "-j", CHAIN)
    if CFG.get("enable_syncookies"):
        subprocess.run(["sysctl", "-w", "net.ipv4.tcp_syncookies=1"], capture_output=True)
    _firewall_ready = True


def cleanup_firewall():
    if not _firewall_ready:          # dry_run 상태로 끝나도, 실제 차단을 한 번이라도 켰었다면 정리
        return
    iptables("-D", "INPUT", "-j", CHAIN)
    iptables("-F", CHAIN)
    iptables("-X", CHAIN)


def sync_firewall():
    """대시보드에서 dry_run 을 바꾼 뒤 iptables 상태를 지금의 차단 목록에 맞춘다.
    실제 차단으로 바뀌면 체인을 만들고 추적 중인 대상 전부에 규칙을 다시 걸고, dry-run 으로 바뀌면
    규칙만 비운다 (추적 자체는 그대로 둬서 화면에는 계속 '차단 중'으로 보임)"""
    if DRY_RUN:
        iptables("-F", CHAIN)
        return
    setup_firewall()
    with lock:
        targets = list(blocked)
    for t in targets:
        iptables_checked("-A", CHAIN, *_rule_args(t))


def set_dry_run(value):
    """대시보드의 '실제 차단' 슬라이드. logs/dry_run_override.json 에 저장해 재시작 후에도 유지되고
    (config.json 은 건드리지 않음), 다음에 WARDEN 을 시작할 때 apply_dry_run_override() 가 이 값을 적용함"""
    global DRY_RUN
    value = bool(value)
    if value == DRY_RUN:
        return False
    DRY_RUN = value
    sync_firewall()
    _save_json("dry_run_override.json", {"dry_run": DRY_RUN})
    return True


def apply_dry_run_override():
    global DRY_RUN
    o = _load_json("dry_run_override.json", {})
    if isinstance(o, dict) and isinstance(o.get("dry_run"), bool):
        DRY_RUN = o["dry_run"]


def _rule_args(target):
    if target.startswith("mac:"):
        return ["-m", "mac", "--mac-source", target[4:], "-j", "DROP"]
    return ["-s", target, "-j", "DROP"]


def is_whitelisted(target):
    t = target[4:] if target.startswith("mac:") else target
    return t.lower() in WHITELIST


def set_whitelist(action, target):
    """대시보드의 화이트리스트 추가·삭제. 돌려주는 값: (성공 여부, 설명, 추가하면서 차단을 푼 대상이 있었는지).
    추가한 주소가 지금 차단 중이면 차단을 풀어 준다 (신뢰하는 주소로 정했는데 계속 막혀 있으면 안 되므로)"""
    t = (target[4:] if target.startswith("mac:") else target).lower()
    with lock:
        extra = _load_json("whitelist_extra.json", {})
        extra = extra if isinstance(extra, dict) else {}
        add = {str(x).lower() for x in extra.get("add", []) if isinstance(x, str)}
        rem = {str(x).lower() for x in extra.get("remove", []) if isinstance(x, str)}
        base = {x.lower() for x in CFG["whitelist"]}
        if action == "add":
            if t in WHITELIST:
                return False, "이미 화이트리스트에 있습니다", False
            rem.discard(t)
            add.add(t)
        else:
            if t in fixed_whitelist():
                return False, "서버 자신의 주소는 뺄 수 없습니다 (WARDEN 이 자기 자신을 차단하게 됩니다)", False
            if t not in WHITELIST:
                return False, "화이트리스트에 없습니다", False
            add.discard(t)
            if t in base:
                rem.add(t)
        _save_json("whitelist_extra.json", {"add": sorted(add), "remove": sorted(rem)})
        apply_whitelist()
    log_rule_change("whitelist", ("추가: " if action == "add" else "삭제: ") + target)
    freed = unblock(target) if action == "add" else False
    return True, "", freed


def block(target, reason, duration=None, permanent=False, overwrite=False):
    """permanent=True 면 자동 해제 없이 계속 차단 (수동으로 해제할 때까지).
    overwrite=True 면 이미 차단 중인 대상의 기간·이유를 새 값으로 덮어씀 (iptables 규칙은 그대로 두므로 중복되지 않음)"""
    if is_whitelisted(target):
        print(f"[i] {target} 는 화이트리스트라 차단하지 않음")
        return False
    duration = duration or CFG["block_duration_sec"]
    now = time.time()
    with lock:
        existing = blocked.get(target)
        if existing and not overwrite:
            return False
        blocked[target] = {"since": now, "until": None if permanent else now + duration,
                           "reason": reason, "permanent": permanent}
        if not existing:
            stats["blocks_total"] += 1
    if not existing and not DRY_RUN:
        iptables_checked("-A", CHAIN, *_rule_args(target))
    if permanent or (existing and existing.get("permanent")):
        save_permanent()
    span = "영구 차단" if permanent else f"{duration}초 차단"
    print(f"\033[41m[BLOCK]{RESET} {target} ({reason}) {span}{' (갱신)' if existing else ''}"
          f"{' [dry-run]' if DRY_RUN else ''}")
    return True


def unblock(target):
    with lock:
        info = blocked.pop(target, None)
    if info is None:
        return False
    if not DRY_RUN:
        iptables_checked("-D", CHAIN, *_rule_args(target))
    if info.get("permanent"):
        save_permanent()
    emit("unblock", target, "info", f"차단 해제 (사유였던 규칙: {info['reason']})", "unblock", cooldown=False)
    return True


def maintenance_loop():
    """만료된 차단 해제 + 오래된 기록 정리 (5초마다)"""
    while True:
        time.sleep(5)
        now = time.time()
        reload_rules()
        run_script_rules_tick()
        with lock:
            expired = [k for k, v in blocked.items() if v["until"] is not None and v["until"] <= now]
        for k in expired:
            unblock(k)
        with hist_lock:
            for k in [k for k, w in history.items() if now - w.last > w.window + 5]:
                del history[k]


# ─────────────────────────── 탐지 로직 ───────────────────────────
class Window:
    """슬라이딩 윈도우 하나: window 초 이내 기록의 개수·서로 다른 값·합계를 패킷마다 다시 세지 않고 이어서 계산한다.
    (예전에는 패킷마다 기록 전체를 복사·집계해서 플러드가 들어올수록 WARDEN 자신이 느려졌음)"""
    __slots__ = ("q", "counts", "total", "last", "window")

    def __init__(self):
        self.q, self.counts, self.total, self.last, self.window = deque(), {}, 0, 0, 0

    def __len__(self):
        return len(self.q)

    def add(self, now, value, window):
        self.window, self.last = window, now
        self.q.append((now, value))
        self.counts[value] = self.counts.get(value, 0) + 1
        if type(value) is int:
            self.total += value
        self.trim(now)

    def trim(self, now):
        while self.q and now - self.q[0][0] > self.window:
            _, old = self.q.popleft()
            left = self.counts[old] - 1
            if left:
                self.counts[old] = left
            else:
                del self.counts[old]
            if type(old) is int:
                self.total -= old


history = defaultdict(Window)


def record(rule, key, value, window, now):
    """기록을 더하고 그 윈도우를 돌려준다 (len = 개수, .counts = 서로 다른 값, .total = 합계)"""
    with hist_lock:
        w = history[(rule, key)]
        w.add(now, value, window)
        return w


def cooling(rule, source, now):
    """같은 알림을 다시 낼 수 없는 시간이면 True: 근거 숫자를 만들 필요가 없으니 플러드 때 일을 줄인다"""
    return now - last_alert.get((rule, source), 0) < CFG["alert_cooldown_sec"]


def _repeat_config():
    """누적 차단 설정 (config.json 의 repeat_block). 같은 대상이 window_sec 안에 다시 자동 차단되면 steps_sec 의 다음 단계 시간으로"""
    rc = {"enabled": True, "window_sec": 86400, "steps_sec": [300, 1800, 7200]}
    user = CFG.get("repeat_block")
    if isinstance(user, dict):
        if isinstance(user.get("enabled"), bool):
            rc["enabled"] = user["enabled"]
        if isinstance(user.get("window_sec"), int) and not isinstance(user["window_sec"], bool) and user["window_sec"] > 0:
            rc["window_sec"] = user["window_sec"]
        steps = user.get("steps_sec")
        if isinstance(steps, list) and steps and all(isinstance(s, int) and not isinstance(s, bool) and 0 < s <= 10 * 365 * 86400 for s in steps):
            rc["steps_sec"] = steps
    return rc


REPEAT = _repeat_config()
repeat_hist = {}                 # 대상 -> 최근 자동 차단 시각들 (logs/repeat_blocks.json 에 저장, 재시작해도 이어짐)


def load_repeat():
    data = _load_json("repeat_blocks.json", {})
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, list):
                repeat_hist[k] = [float(t) for t in v if isinstance(t, (int, float)) and not isinstance(t, bool)][-20:]


def repeat_level(target, now):
    """이번 자동 차단이 window_sec 안에서 몇 번째인지 (1부터)"""
    with lock:
        return 1 + sum(1 for t in repeat_hist.get(target, []) if now - t < REPEAT["window_sec"])


def note_repeat(target, now):
    with lock:
        for k in [k for k, v in repeat_hist.items() if not v or now - v[-1] >= REPEAT["window_sec"]]:
            del repeat_hist[k]                       # 기준 시간이 지난 대상은 1단계부터 다시
        repeat_hist[target] = ([t for t in repeat_hist.get(target, []) if now - t < REPEAT["window_sec"]] + [now])[-20:]
        data = {k: list(v) for k, v in repeat_hist.items()}
    _save_json("repeat_blocks.json", data)


def block_auto(target, reason, duration=None, permanent=False):
    """규칙이 자동으로 하는 차단. '자동 차단' 숫자는 실제 차단과 모의(dry-run)를 나눠 센다.
    누적 차단: 같은 대상이 기준 시간 안에 다시 걸리면 단계별로 더 길게 (규칙에 적힌 시간이 더 길면 그 값)"""
    now, level = time.time(), 0
    if REPEAT["enabled"] and not permanent:
        level = repeat_level(target, now)
        steps = REPEAT["steps_sec"]
        duration = max(duration or CFG["block_duration_sec"], steps[min(level, len(steps)) - 1])
    if block(target, reason, duration, permanent):
        stats["blocks_auto_sim" if DRY_RUN else "blocks_auto"] += 1
        if level:
            note_repeat(target, now)
            with lock:
                if target in blocked:
                    blocked[target]["repeat"] = level
            if level > 1:
                print(f"[i] {target} 는 {REPEAT['window_sec'] // 3600}시간 안에 {level}번째 자동 차단 -> {duration}초")


def action_for(rule):
    if not RULES[rule].get("block"):
        return "alert"
    return "block(dry-run)" if DRY_RUN else "block"


def fire(rule, source, severity, detail, block_target=None, meta=None):
    r = RULES[rule]
    severity = r.get("severity", severity)                  # 위험도는 rules/<id>.json 값이 우선
    if emit(rule, source, severity, detail, action_for(rule), meta=meta) and r.get("block"):
        block_auto(block_target or source, rule, r.get("block_duration_sec"), bool(r.get("block_permanent")))


def check_port_scan(src, dport, now, how="접속 시도", key="port_scan"):
    r = RULES["port_scan"]
    if not r["enabled"]:
        return
    ports = record(key, src, dport, r["window_sec"], now).counts
    if len(ports) >= r["distinct_ports"] and not cooling("port_scan", src, now):
        fire("port_scan", src, "warning", f"{r['window_sec']}초 동안 서로 다른 포트 {len(ports)}개에 {how}",
             meta={"count": len(ports), "threshold": r["distinct_ports"], "window_sec": r["window_sec"],
                   "ports": sorted(ports)[:30]})


def check_syn_flood(src, now):
    r = RULES["syn_flood"]
    if not r["enabled"]:
        return
    q = record("syn_flood", src, 1, r["window_sec"], now)
    if len(q) >= r["max_syn"] and not cooling("syn_flood", src, now):
        fire("syn_flood", src, "critical", f"{r['window_sec']}초 동안 SYN {len(q)}개",
             meta={"count": len(q), "threshold": r["max_syn"], "window_sec": r["window_sec"]})
    # 출발지를 위조(랜덤)하는 공격 대비: 전체 SYN 양도 감시 (차단 대상이 없으므로 알림만)
    # 출발지가 여러 개일 때만 알림 -> IP 하나가 보내는 일반 SYN 플러드를 '위조'로 오인하지 않음
    total = record("syn_flood", "*", src, r["window_sec"], now)
    sources = len(total.counts)
    if len(total) >= r["global_max_syn"] and sources >= r.get("global_min_sources", 10) and not cooling("syn_flood_distributed", "*", now):
        emit("syn_flood_distributed", "*", "critical",
             f"{r['window_sec']}초 동안 출발지 {sources}곳에서 SYN {len(total)}개 "
             f"(출발지 위조 의심, syncookies 로 방어)", "alert",
             meta={"count": len(total), "threshold": r["global_max_syn"], "window_sec": r["window_sec"],
                   "sources": sources})


def check_ssh(src, now):
    r = RULES["ssh_bruteforce"]
    if not r["enabled"]:
        return
    q = record("ssh_bruteforce", src, 1, r["window_sec"], now)
    if len(q) >= r["max_attempts"] and not cooling("ssh_bruteforce", src, now):
        fire("ssh_bruteforce", src, "critical", f"{r['window_sec']}초 동안 SSH 접속 시도 {len(q)}회",
             meta={"count": len(q), "threshold": r["max_attempts"], "window_sec": r["window_sec"],
                   "ports": list(r.get("ports", []))})


def check_icmp(src, now):
    r = RULES["icmp_flood"]
    if not r["enabled"]:
        return
    q = record("icmp_flood", src, 1, r["window_sec"], now)
    if len(q) >= r["max_packets"] and not cooling("icmp_flood", src, now):
        fire("icmp_flood", src, "warning", f"{r['window_sec']}초 동안 ping {len(q)}개",
             meta={"count": len(q), "threshold": r["max_packets"], "window_sec": r["window_sec"]})


def check_arp(pkt):
    ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc.lower()
    if ip == "0.0.0.0" or mac == MY_MAC:
        return
    old = arp_table.get(ip)
    if old is None:
        arp_table[ip] = mac          # 처음 본 IP-MAC 조합을 "정상"으로 기억
    elif old != mac:
        fire("arp_spoof", mac, "critical",
             f"{ip} 의 MAC 주소가 {old} -> {mac} 로 바뀜 (ARP 스푸핑 의심)", block_target=f"mac:{mac}",
             meta={"ip": ip, "old_mac": old, "new_mac": mac})


def check_exfil(dst, size, now):
    r = RULES["exfiltration"]
    if not r["enabled"]:
        return
    total = record("exfiltration", dst, size, r["window_sec"], now).total
    if total >= r["max_bytes"] and not cooling("exfiltration", dst, now):
        emit("exfiltration", dst, r.get("severity", "warning"),
             f"{r['window_sec']}초 동안 {dst} 로 {total / 1_000_000:.1f}MB 전송 (유출 의심)", "alert",
             meta={"bytes": total, "threshold": r["max_bytes"], "window_sec": r["window_sec"]})


pkt_lock = threading.Lock()      # packets 보호 (sniff 스레드가 쓰고 API 스레드가 읽음)


def _describe(pkt):
    """패킷 하나를 화면에 보여줄 요약(dict)으로 바꾼다. 대상이 아닌 패킷(IP·ARP 가 아님)은 None"""
    if ARP in pkt:
        a = pkt[ARP]
        psrc, pdst = str(getattr(a, "psrc", "")), str(getattr(a, "pdst", ""))
        info = f"Who has {pdst}? Tell {psrc}" if getattr(a, "op", 1) == 1 else f"{psrc} is at {getattr(a, 'hwsrc', '')}"
        return {"src": psrc, "dst": pdst, "proto": "ARP", "info": info,
                "dir": "out" if str(getattr(a, "hwsrc", "")).lower() == MY_MAC else "in"}
    if IP not in pkt:
        return None
    ip = pkt[IP]
    row = {"src": ip.src, "dst": ip.dst, "dir": "in" if is_me(ip.dst) else "out" if is_me(ip.src) else "other"}
    if TCP in pkt:
        t = pkt[TCP]
        names = ",".join(n for bit, n in TCP_FLAG_NAMES if int(getattr(t, "flags", 0)) & bit) or "-"
        sport, dport = getattr(t, "sport", None), getattr(t, "dport", None)
        row.update(proto="TCP", sport=sport, dport=dport, info=f"{sport} → {dport} [{names}]")
    elif ICMP in pkt:
        ic = pkt[ICMP]
        typ = int(getattr(ic, "type", -1))
        text = ICMP_TYPES.get(typ, f"ICMP type {typ}")
        if typ in (0, 8):
            text += f" id={getattr(ic, 'id', 0)} seq={getattr(ic, 'seq', 0)}"
        row.update(proto="ICMP", info=text)
    elif UDP is not None and UDP in pkt:
        u = pkt[UDP]
        sport, dport = getattr(u, "sport", None), getattr(u, "dport", None)
        row.update(proto="UDP", sport=sport, dport=dport, info=f"{sport} → {dport}")
    else:
        row.update(proto="IP", info=f"IP 프로토콜 {getattr(ip, 'proto', '?')}")
    return row


def record_packet(pkt, now):
    """지나가는 패킷의 요약을 링 버퍼에 남긴다 (대시보드 '패킷 보기'용). 실패해도 탐지에는 영향이 없다"""
    if not PV["enabled"]:
        return
    sec = int(now)
    if _pv_budget["sec"] != sec:
        _pv_budget["sec"], _pv_budget["used"] = sec, 0
    if _pv_budget["used"] >= PV["max_per_sec"]:
        stats["packets_unrecorded"] += 1          # 플러드 중에는 일부만 보관 (화면에 생략 개수 표시)
        return
    try:
        row = _describe(pkt)
        if row is None:
            return
        _pv_budget["used"] += 1
        row["time"] = round(now, 3)
        row["len"] = len(pkt)
        raw = _header_bytes(pkt)
        if raw:
            row["_raw"] = raw                     # PCAP 내보내기용 (헤더만, API 응답에는 넣지 않음)
        with pkt_lock:
            row["seq"] = next(packet_seq)
            packets.append(row)
    except Exception:
        pass


def _header_bytes(pkt):
    """이더넷 프레임에서 헤더(이더넷·IPv4·TCP/UDP/ICMP, 또는 ARP)까지만 잘라 돌려준다.
    패킷 보기와 같은 원칙으로 내용(payload)은 남기지 않는다. 해석할 수 없는 프레임이면 None"""
    try:
        raw = getattr(pkt, "original", None) or bytes(pkt)
    except Exception:
        return None
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 14:
        return None
    off = 12
    while raw[off:off + 2] == b"\x81\x00" and len(raw) >= off + 6:   # VLAN 태그
        off += 4
    etype, l3 = raw[off:off + 2], off + 2
    if etype == b"\x08\x06":                                       # ARP
        end = l3 + 28
    elif etype == b"\x08\x00" and len(raw) > l3 and raw[l3] >> 4 == 4:   # IPv4
        ihl = (raw[l3] & 0x0F) * 4
        proto, l4 = raw[l3 + 9] if len(raw) > l3 + 9 else None, l3 + ihl
        if proto == 6 and len(raw) > l4 + 12:                      # TCP: 데이터 오프셋까지
            end = l4 + (raw[l4 + 12] >> 4) * 4
        elif proto in (1, 17):                                     # ICMP·UDP: 8바이트 헤더
            end = l4 + 8
        else:
            end = l4
    else:
        return None
    return bytes(raw[:min(len(raw), end)])


PCAP_LINKTYPE_ETHERNET = 1


def build_pcap(rows):
    """패킷 기록을 Wireshark 로 열 수 있는 pcap(리틀 엔디언, 마이크로초) 바이트로 만든다.
    잘라 둔 헤더만 들어가므로 원래 길이(orig_len)는 실제 길이, 저장 길이(incl_len)는 헤더 길이"""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, PCAP_LINKTYPE_ETHERNET)]
    for p in rows:
        raw = p.get("_raw")
        if not raw:
            continue
        sec = int(p["time"])
        usec = int(round((p["time"] - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        out.append(struct.pack("<IIII", sec, usec, len(raw), max(len(raw), int(p.get("len") or 0))))
        out.append(raw)
    return b"".join(out)


def _packet_match(p, proto="", ip="", hide_ports=(), start=None, end=None):
    if proto and p["proto"] != proto:
        return False
    if ip and not (p["src"].startswith(ip) or p["dst"].startswith(ip)):
        return False
    if hide_ports and (p.get("sport") in hide_ports or p.get("dport") in hide_ports):
        return False
    if start is not None and p["time"] < start:
        return False
    if end is not None and p["time"] > end:
        return False
    return True


def query_packets(since=0, limit=200, proto="", ip="", hide_ports=()):
    """since 보다 새로운 패킷을 오래된 순으로 돌려준다 (조건에 맞는 것 중 최신 limit 개)"""
    with pkt_lock:
        snap = list(packets)
    last = snap[-1]["seq"] if snap else 0
    rows = [p for p in snap if p["seq"] > since and _packet_match(p, proto, ip, hide_ports)][-limit:]
    return [{k: v for k, v in p.items() if k != "_raw"} for p in rows], last


def _ts(iso):
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError):
        return None


def pcap_for(proto="", ip="", hide_ports=(), event_id=""):
    """PCAP 으로 내보낼 패킷 기록을 고른다. event_id 를 주면 그 이벤트의 출발지(ARP 는 ARP 전체)와
    탐지 직전 구간(규칙의 window_sec + 앞뒤 여유)만. 돌려주는 값: (rows, 설명) / 이벤트가 없으면 LookupError"""
    start = end = None
    if event_id:
        with lock:
            ev = next((dict(e) for e in events if e["id"] == event_id), None)
        if ev is None:
            raise LookupError("이벤트를 찾을 수 없습니다 (목록에서 이미 밀려났을 수 있습니다)")
        t = _ts(ev.get("timestamp"))
        if t is None:
            raise LookupError("이벤트 시각을 읽을 수 없습니다")
        window = (ev.get("meta") or {}).get("window_sec") or 60
        start, end = t - float(window) - 5, t + 5
        if ev["type"] == "arp_spoof":
            proto, ip = "ARP", ""
        elif _is_ip(ev["source"]):
            ip = ev["source"]
        else:
            raise LookupError("IP 출발지가 없는 이벤트라 관련 패킷을 고를 수 없습니다")
    with pkt_lock:
        snap = list(packets)
    rows = [p for p in snap if p.get("_raw") and _packet_match(p, proto, ip, hide_ports, start, end)]
    return rows, {"start": start, "end": end, "ip": ip, "proto": proto}


UDP_REPLY_PORTS = {53, 67, 68, 123, 137, 138, 5353}   # 이 출발 포트는 서비스의 응답이라 스캔으로 세지 않음


def handle(pkt):
    try:
        _handle(pkt)
    except Exception as e:  # 패킷 하나 때문에 전체가 죽지 않도록
        print(f"[!] 패킷 처리 오류: {e}")


def _handle(pkt):
    now = time.time()
    stats["packets_total"] += 1
    record_packet(pkt, now)

    if ARP in pkt:
        if RULES["arp_spoof"]["enabled"]:
            check_arp(pkt)
        return
    if IP not in pkt:
        return

    src, dst = pkt[IP].src, pkt[IP].dst
    if is_me(src):                        # 나가는 트래픽 -> 유출 감시
        check_exfil(dst, len(pkt), now)
        return
    if not is_me(dst):                    # 나에게 온 게 아님
        return
    # 이미 차단한 IP 는 무시 (실제로는 iptables 가 버리고 있음).
    # 단, dry-run 에선 진짜로 막힌 게 아니므로 계속 탐지해야 다음 공격 테스트가 보임
    if src in blocked and not DRY_RUN:
        return

    check_custom(pkt, src, now)

    if TCP in pkt:
        flags = int(pkt[TCP].flags)
        if flags & 0x02 and not flags & 0x10:   # SYN 만 있고 ACK 없음 = 새 연결 시도
            stats["syn_total"] += 1
            dport = pkt[TCP].dport
            check_port_scan(src, dport, now)
            check_syn_flood(src, now)
            if dport in RULES["ssh_bruteforce"]["ports"]:
                check_ssh(src, now)
        elif not flags & 0x16:                  # SYN·RST·ACK 모두 없음 = NULL / FIN / Xmas 스캔 (정상 통신에는 없음)
            check_port_scan(src, pkt[TCP].dport, now, "비정상 플래그(NULL·FIN·Xmas) 패킷")
    elif ICMP in pkt:
        if pkt[ICMP].type == 8:                 # echo request (ping)
            stats["icmp_total"] += 1
            check_icmp(src, now)
    elif UDP is not None and UDP in pkt and pkt[UDP].sport not in UDP_REPLY_PORTS:
        check_port_scan(src, pkt[UDP].dport, now, "UDP 패킷", key="port_scan_udp")


# ─────────────────────────── 탐지 규칙 파일 (rules/) ───────────────────────────
# 모든 규칙(기본·사용자 구분 없이)은 rules/<id>.json 한 파일씩. 파일을 넣거나 고치면 재시작 없이 5초 안에 적용됨.
# 'detector' 가 포트스캔 같은 이름이면 코드에 들어 있는 전용 탐지기의 설정값(임계값)이고,
# 'custom'(기본값)이면 조건 데이터만 담은 범용 규칙이다. 어느 쪽이든 코드가 아닌 데이터라서
# 파일을 잘못 써도 임의 코드가 실행되지 않음. 형식은 README.md 참고.
RULES_DIR = os.path.join(BASE_DIR, "rules")
LEGACY_CUSTOM_DIR = os.path.join(BASE_DIR, "custom_rules")      # 예전 위치 (시작할 때 rules/ 로 옮김)
ID_RE = re.compile(r"^[a-z0-9_]{1,40}$")
BUILTIN_ORDER = ["port_scan", "syn_flood", "icmp_flood", "ssh_bruteforce", "ssh_login_success", "arp_spoof", "exfiltration"]
# 전용 탐지기별로 파일에 들어 있어야 하는 숫자 설정 (이름: (최소, 최대))
BUILTIN_PARAMS = {
    "port_scan": {"window_sec": (1, 3600), "distinct_ports": (1, 65535)},
    "syn_flood": {"window_sec": (1, 3600), "max_syn": (1, 10**7), "global_max_syn": (1, 10**8),
                  "global_min_sources": (1, 10**6)},
    "icmp_flood": {"window_sec": (1, 3600), "max_packets": (1, 10**7)},
    "ssh_bruteforce": {"window_sec": (1, 3600), "max_attempts": (1, 10**6)},
    "ssh_login_success": {"window_sec": (1, 86400), "min_failures": (1, 10**6)},
    "arp_spoof": {},
    "exfiltration": {"window_sec": (1, 3600), "max_bytes": (1, 10**12)},
}
RESERVED_IDS = {"unblock", "manual_block", "syn_flood_distributed", "rule_toggle"}


TAG_RE = re.compile(r"^[\w-]{1,20}$")
SCRIPT_CMD_RE = re.compile(r"^\./[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _rule_tags(raw, strict):
    """대시보드 카드의 #태그 목록. 파일을 읽을 때(strict=False)는 이상한 값을 건너뛰고(규칙이 통째로 사라지면 안 되므로),
    화면·API 로 저장할 때(strict=True)는 이유를 알려 준다"""
    if raw is None:
        return []
    if not isinstance(raw, list):
        if strict:
            raise ValueError("'tags' 는 목록이어야 합니다")
        return []
    out = []
    for t in raw:
        t = t.strip().lstrip("#") if isinstance(t, str) else ""
        if not TAG_RE.match(t):
            if strict:
                raise ValueError("태그는 공백 없이 20자까지의 글자·숫자·'-'·'_' 만 쓸 수 있습니다")
            continue
        if t not in out:
            out.append(t)
    if strict and len(out) > 6:
        raise ValueError("태그는 6개까지 달 수 있습니다")
    return out[:6]


def _rule_notify(raw, strict):
    """대시보드 알림 설정 {"popup": bool, "sound": bool}. 둘 다 생략 가능하고, 없는 항목은 위험도의 기본값을 따른다
    (Critical = 팝업+소리, Medium = 팝업, Low = 없음). 파일을 읽을 때(strict=False)는 이상한 값을 건너뛴다"""
    if raw is None:
        return {}
    if not isinstance(raw, dict) or set(raw) - {"popup", "sound"} or not all(isinstance(v, bool) for v in raw.values()):
        if strict:
            raise ValueError("'notify' 는 {\"popup\": true/false, \"sound\": true/false} 형식이어야 합니다 (생략하면 위험도 기본값)")
        return {}
    return {k: raw[k] for k in ("popup", "sound") if k in raw}


def validate_rule(d, filename_id=None):
    """규칙 dict 를 검사해 정리된 규칙을 돌려준다. 이상하면 ValueError(이유)."""
    if not isinstance(d, dict):
        raise ValueError("JSON 객체여야 합니다")

    def num(key, lo, hi):
        v = d.get(key)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError(f"'{key}' 는 {lo}~{hi} 사이의 정수여야 합니다")
        return v

    rid = d.get("id")
    if not isinstance(rid, str) or not ID_RE.match(rid):
        raise ValueError("'id' 는 영소문자·숫자·밑줄 1~40자여야 합니다")
    if filename_id is not None and rid != filename_id:
        raise ValueError("'id' 는 파일 이름과 같아야 합니다")
    detector = d.get("detector", "custom")
    if detector not in ("custom", "script") and detector not in BUILTIN_PARAMS:
        raise ValueError("'detector' 는 custom / script 이거나 " + " / ".join(BUILTIN_PARAMS) + " 중 하나여야 합니다")
    if detector not in ("custom", "script") and rid != detector:
        raise ValueError(f"전용 탐지기 규칙은 'id' 가 '{detector}' 여야 합니다")
    if detector in ("custom", "script") and (rid in RESERVED_IDS or rid in BUILTIN_PARAMS):
        raise ValueError(f"'{rid}' 는 기본 탐지기가 쓰는 이름입니다")
    sev = d.get("severity", "warning")
    if sev not in SEV_COLOR:
        raise ValueError("'severity' 는 info / warning / critical 중 하나여야 합니다")
    rule = {
        "id": rid, "detector": detector, "name": str(d.get("name", rid))[:60],
        "description": str(d.get("description", ""))[:200], "enabled": d.get("enabled", True) is True,
        "severity": sev, "block": d.get("block", False) is True,
    }
    tags = _rule_tags(d.get("tags"), strict=filename_id is None)
    if tags:
        rule["tags"] = tags
    notify = _rule_notify(d.get("notify"), strict=filename_id is None)
    if notify:
        rule["notify"] = notify
    if detector == "custom":
        proto = d.get("protocol", "tcp")
        if proto not in ("tcp", "udp", "icmp", "any"):
            raise ValueError("'protocol' 은 tcp / udp / icmp / any 중 하나여야 합니다")
        ports = d.get("dst_ports", [])
        if (not isinstance(ports, list) or len(ports) > 50
                or any(isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535 for p in ports)):
            raise ValueError("'dst_ports' 는 1~65535 사이 숫자 목록(최대 50개)이어야 합니다")
        if d.get("tcp_flags", "any") not in ("syn", "any"):
            raise ValueError("'tcp_flags' 는 syn / any 중 하나여야 합니다")
        if d.get("distinct", "none") not in ("none", "dst_port"):
            raise ValueError("'distinct' 는 none / dst_port 중 하나여야 합니다")
        rule.update({"protocol": proto, "dst_ports": ports, "tcp_flags": d.get("tcp_flags", "any"),
                     "count": num("count", 1, 1_000_000), "window_sec": num("window_sec", 1, 3600),
                     "distinct": d.get("distinct", "none")})
    elif detector == "script":
        cmd = d.get("command")
        if not isinstance(cmd, list) or not 1 <= len(cmd) <= 6 or not all(isinstance(c, str) and 0 < len(c) <= 200 for c in cmd):
            raise ValueError("'command' 는 문자열 1~6개의 목록이어야 합니다")
        if not SCRIPT_CMD_RE.match(cmd[0]):      # './/bin/sh' 처럼 rules/ 밖을 가리키는 값을 막음
            raise ValueError("'command' 의 첫 항목은 './파일이름' 형식이어야 합니다 (rules/ 폴더 바로 안의 파일만)")
        if any(".." in part.split("/") for part in cmd):
            raise ValueError("'command' 에 '..' 는 쓸 수 없습니다")
        rule.update({"command": cmd, "interval_sec": num("interval_sec", 5, 3600),
                     "timeout_sec": num("timeout_sec", 1, 60) if "timeout_sec" in d else 10})
    else:
        for key, (lo, hi) in BUILTIN_PARAMS[detector].items():
            rule[key] = num(key, lo, hi)
        if detector == "ssh_bruteforce":
            ports = d.get("ports")
            if (not isinstance(ports, list) or not ports or len(ports) > 20
                    or any(isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535 for p in ports)):
                raise ValueError("'ports' 는 1~65535 사이 숫자 목록(최대 20개)이어야 합니다")
            rule["ports"] = ports
    if detector == "exfiltration":
        rule["block"] = False                 # 유출 탐지는 알림만: 의심 목적지는 공격자가 아니라 데이터가 가는 곳이라서
    if rule["block"]:                         # 차단을 켠 규칙만 차단 기간을 가짐 (없으면 config.json 의 기본 시간)
        if d.get("block_permanent") is True:
            rule["block_permanent"] = True    # 영구 차단이면 기간은 의미 없음
        elif "block_duration_sec" in d:
            rule["block_duration_sec"] = num("block_duration_sec", 1, 10 * 365 * 86400)
    return rule


def migrate_legacy():
    """예전 구조(custom_rules/ 폴더, logs/rule_overrides.json)를 rules/ 로 옮김 (한 번만 실행됨)"""
    os.makedirs(RULES_DIR, exist_ok=True)
    try:
        for n in os.listdir(LEGACY_CUSTOM_DIR):
            src, dst = os.path.join(LEGACY_CUSTOM_DIR, n), os.path.join(RULES_DIR, n)
            if n.endswith(".json") and not os.path.exists(dst):
                os.replace(src, dst)
                print(f"[i] 예전 규칙 파일을 rules/ 로 옮겼습니다: {n}")
        os.rmdir(LEGACY_CUSTOM_DIR)
    except OSError:
        pass
    old = _data_path("rule_overrides.json")
    if os.path.exists(old):
        for rid, enabled in _load_json("rule_overrides.json", {}).items():
            path = os.path.join(RULES_DIR, f"{rid}.json")
            if isinstance(enabled, bool) and ID_RE.match(str(rid)) and os.path.exists(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        data = json.load(f)
                    data["enabled"] = enabled
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                except (OSError, json.JSONDecodeError):
                    pass
        try:
            os.replace(old, old + ".migrated")
        except OSError:
            pass


def reload_rules(force=False):
    """rules/ 를 읽어 반영. 폴더가 바뀌지 않았으면 아무것도 하지 않음 (5초마다 호출)"""
    global _rules_sig
    try:
        names = sorted(n for n in os.listdir(RULES_DIR) if n.endswith(".json") and not n.startswith("_"))
    except OSError:
        names = []
    sig = tuple((n, os.stat(os.path.join(RULES_DIR, n)).st_mtime_ns) for n in names)
    if sig == _rules_sig and not force:
        return
    found, errors = {}, {}
    for n in names:
        try:
            with open(os.path.join(RULES_DIR, n), encoding="utf-8") as f:
                rule = validate_rule(json.load(f), n[:-5])
            found[rule["id"]] = rule
        except (OSError, ValueError, json.JSONDecodeError) as e:
            errors[n] = str(e)
            if rule_errors.get(n) != str(e):
                print(f"[!] 규칙 파일 '{n}' 불러오기 실패: {e}")
    with lock:
        added = set(found) - set(rules_all)
        rules_all.clear(); rules_all.update(found)
        rule_errors.clear(); rule_errors.update(errors)
        RULES.clear()
        RULES.update({r["id"]: r for r in found.values() if r["detector"] not in ("custom", "script")})
        SCRIPT_RULES.clear()
        SCRIPT_RULES.update({r["id"]: r for r in found.values() if r["detector"] == "script"})
    for rid in list(_script_last_run):
        if rid not in SCRIPT_RULES:
            _script_last_run.pop(rid, None)
            _script_errors_seen.pop(rid, None)
    _rules_sig = sig
    if added and rules_loaded_once():
        print(f"[i] 규칙 적용: {', '.join(sorted(added))}")


def rules_loaded_once():
    return _rules_sig is not None


def list_rules():
    """화면용 목록: 기본 탐지기 순서대로, 그 뒤에 나머지를 이름순"""
    with lock:
        rules = list(rules_all.values())
    rank = {n: i for i, n in enumerate(BUILTIN_ORDER)}
    return sorted(rules, key=lambda r: (rank.get(r["id"], len(rank)), r["id"]))


def _write_rule(rule):
    os.makedirs(RULES_DIR, exist_ok=True)
    path = os.path.join(RULES_DIR, rule["id"] + ".json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rule, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def save_rule(rule):
    _write_rule(rule)
    reload_rules(force=True)


def set_rule_enabled(rid, enabled):
    with lock:
        rule = dict(rules_all.get(rid) or {})
    if not rule:
        return False
    rule["enabled"] = bool(enabled)
    save_rule(validate_rule(rule))
    return True


def delete_rule(rid):
    """규칙 삭제. 켜져 있으면 먼저 메모리에서 꺼서(탐지 즉시 중단) 파일을 지운다 -> 삭제하는 중에 탐지가 겹치지 않음.
    돌려주는 값: None(없는 규칙) 또는 삭제 직전 켜져 있었는지(bool)"""
    if not ID_RE.match(rid):
        return None
    with lock:
        rule = rules_all.get(rid)
        if rule is None:
            return None
        was_enabled = rule["enabled"]
        rule["enabled"] = False              # RULES 안의 같은 객체이므로 탐지기도 바로 멈춤
    try:
        os.remove(os.path.join(RULES_DIR, rid + ".json"))
    except OSError:
        with lock:
            rule["enabled"] = was_enabled    # 못 지웠으면 원래대로
        raise
    reload_rules(force=True)
    return was_enabled


def update_rule(rid, data):
    """규칙 수정. 바뀐 값이 있으면 먼저 메모리에서 꺼서(탐지 즉시 중단) 새 값을 꺼진 상태로 저장한다 -> 수정 도중에 옛 조건과
    새 조건이 섞여 충돌하지 않음. 켜는 건 사용자가 확인한 뒤 직접 한다. id·detector 는 바꿀 수 없고, 바뀐 게 없으면 그대로 둔다.
    돌려주는 값: None(없는 규칙) 또는 {"changed": 바뀌었는지, "was_enabled": 수정 직전 켜져 있었는지}. 값이 잘못되면 ValueError"""
    if not ID_RE.match(rid):
        return None
    with lock:
        old = rules_all.get(rid)
    if old is None:
        return None
    data = data if isinstance(data, dict) else {}
    if old["detector"] == "script":                  # 무엇을 실행할지는 터미널 승인으로만 정해진다
        if "command" in data and data["command"] != old["command"]:
            raise ValueError("플러그인 방식 규칙의 실행 명령은 바꿀 수 없습니다 (새로 올려서 서버에서 승인하세요)")
        data = {**data, "command": old["command"]}
    if "notify" not in data and old.get("notify"):   # 알림 설정을 안 보낸 수정이 지정값을 지우지 않도록
        data = {**data, "notify": old["notify"]}
    if "tags" not in data and old.get("tags"):       # 태그를 안 보낸 수정(옛 화면·API)이 태그를 지우지 않도록
        data = {**data, "tags": old["tags"]}
    new = validate_rule({**data, "id": rid, "detector": old["detector"]})
    new["enabled"] = old["enabled"]
    if new == old:
        return {"changed": False, "was_enabled": old["enabled"]}
    if {k: v for k, v in new.items() if k != "notify"} == {k: v for k, v in old.items() if k != "notify"}:
        _write_rule(new)                              # 알림 설정만 바뀜: 탐지 조건은 그대로라 끄지 않는다
        reload_rules(force=True)
        return {"changed": True, "was_enabled": old["enabled"], "kept_enabled": True}
    was_enabled = old["enabled"]
    with lock:
        old["enabled"] = False               # RULES 안의 같은 객체이므로 탐지기도 바로 멈춤
    new["enabled"] = False
    try:
        _write_rule(new)
    except OSError:
        with lock:
            old["enabled"] = was_enabled
        raise
    reload_rules(force=True)
    return {"changed": True, "was_enabled": was_enabled}


def check_custom(pkt, src, now):
    with lock:
        rules = [r for r in rules_all.values() if r["detector"] == "custom" and r["enabled"]]
    if not rules:
        return
    if TCP in pkt:
        proto, dport, syn = "tcp", int(pkt[TCP].dport), (int(pkt[TCP].flags) & 0x12) == 0x02
    elif UDP is not None and UDP in pkt:
        proto, dport, syn = "udp", int(pkt[UDP].dport), False
    elif ICMP in pkt:
        proto, dport, syn = "icmp", None, False
    else:
        return
    for r in rules:
        if r["protocol"] not in ("any", proto):
            continue
        if r["dst_ports"] and dport not in r["dst_ports"]:
            continue
        if r["tcp_flags"] == "syn" and not syn:
            continue
        q = record("custom:" + r["id"], src, dport if r["distinct"] == "dst_port" else 1, r["window_sec"], now)
        hits = len(q.counts) if r["distinct"] == "dst_port" else len(q)
        if hits >= r["count"] and not cooling(r["id"], src, now):
            what = f"서로 다른 포트 {hits}개" if r["distinct"] == "dst_port" else f"{hits}회"
            action = ("block(dry-run)" if DRY_RUN else "block") if r["block"] else "alert"
            meta = {"count": hits, "threshold": r["count"], "window_sec": r["window_sec"], "protocol": r["protocol"],
                    "ports": list(r["dst_ports"]), "distinct": r["distinct"]}
            if emit(r["id"], src, r["severity"], f"[{r['name']}] {r['window_sec']}초 동안 {what} 일치", action, meta=meta) and r["block"]:
                block_auto(src, r["id"], r.get("block_duration_sec"), bool(r.get("block_permanent")))


# ─────────────────────────── 탐지 규칙 (플러그인 방식, detector == "script") ───────────────────────────
# 스크립트는 공격 여부를 '판정만' 한다 (한 줄에 하나씩 {"source": "IP", "detail": "..."} 를 표준출력으로).
# 화이트리스트 확인·차단·로그 기록은 전부 여기(WARDEN)가 하고, 스크립트가 직접 iptables 를 건드리지 않는다.
# 설계 문서: rules/SCRIPT_RULES_TODO.md
SCRIPT_MAX_OUTPUT_LINES = 200
SCRIPT_MAX_LINE_BYTES = 4096


def _script_child_setup():
    """스크립트 프로세스 안에서 실행 직전에 호출: 출력 파일 크기를 제한하고 rules/ 소유 계정 권한으로 낮춘다.
    낮추지 못하면 root 로 돌지 않도록 실행 자체를 포기한다"""
    try:
        import resource
        limit = SCRIPT_MAX_OUTPUT_LINES * SCRIPT_MAX_LINE_BYTES * 2
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        st = os.stat(BASE_DIR)
        if st.st_uid != os.getuid():
            os.setgroups([])
            os.setgid(st.st_gid)
            os.setuid(st.st_uid)
    except (OSError, ValueError):
        os._exit(126)


def _script_command(rule):
    """실행할 명령. 규칙 파일이 검사 뒤에 바뀌었거나 심볼릭 링크로 밖을 가리키는 경우도 있으니 실행 직전에 다시 확인한다"""
    cmd = list(rule["command"])
    if not SCRIPT_CMD_RE.match(cmd[0]):
        raise ValueError(f"잘못된 스크립트 경로: {cmd[0]}")
    root = os.path.realpath(RULES_DIR)
    full = os.path.realpath(os.path.join(root, cmd[0][2:]))
    if not full.startswith(root + os.sep):
        raise ValueError(f"스크립트가 rules/ 밖을 가리킵니다: {cmd[0]}")
    cmd[0] = full
    return cmd


def _script_env():
    """root 로 뜬 WARDEN 의 환경 변수를 스크립트에 물려주지 않는다"""
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
    try:
        import pwd
        env["HOME"] = pwd.getpwuid(os.stat(BASE_DIR).st_uid).pw_dir
    except (ImportError, KeyError, OSError):
        pass
    return env


def _exec_script(rule):
    """스크립트를 한 번 실행하고 (종료 코드, 표준출력, 표준오류) 를 돌려준다. 시간 제한을 넘으면 자식까지 프로세스 그룹째 끝낸다.
    출력은 임시 파일로 받아 WARDEN(root) 메모리에 얼마든지 쌓이지 않게 한다"""
    if os.getuid() == 0 and os.stat(BASE_DIR).st_uid == 0:
        raise OSError("WARDEN 폴더가 root 소유라 권한을 낮출 수 없어 실행하지 않습니다")
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(_script_command(rule), cwd=RULES_DIR, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                env=_script_env(), start_new_session=True, preexec_fn=_script_child_setup)
        try:
            rc = proc.wait(timeout=rule["timeout_sec"])
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)       # 시간 초과, 또는 백그라운드로 남겨 둔 자식 정리
            except OSError:
                pass
            proc.wait()
        out.seek(0)
        err.seek(0)
        return (rc, out.read(SCRIPT_MAX_OUTPUT_LINES * SCRIPT_MAX_LINE_BYTES).decode("utf-8", "replace"),
                err.read(400).decode("utf-8", "replace"))


def _script_error(rid, msg):
    if _script_errors_seen.get(rid) != msg:            # 같은 오류를 주기마다 찍지 않음
        _script_errors_seen[rid] = msg
        print(f"[!] 플러그인 방식 규칙 '{rid}' {msg}")


def run_script_rule(rule):
    """플러그인 방식 탐지 규칙 하나를 한 번 실행하고, 출력된 판정을 emit()/block() 으로 반영한다"""
    rid = rule["id"]
    try:
        try:
            rc, stdout, stderr = _exec_script(rule)
        except (OSError, ValueError, subprocess.TimeoutExpired) as e:
            return _script_error(rid, f"실행 실패: {e}")
        if rc != 0 and not stdout:
            return _script_error(rid, f"종료 코드 {rc}: {stderr.strip()[:200]}")
        _script_errors_seen.pop(rid, None)
        for line in stdout.splitlines()[:SCRIPT_MAX_OUTPUT_LINES]:
            line = line.strip()[:SCRIPT_MAX_LINE_BYTES]
            if not line:
                continue
            try:
                found = json.loads(line)
            except ValueError:
                continue
            if not isinstance(found, dict):
                continue
            target = normalize_target(str(found.get("source", "")))
            if not target:
                continue
            detail = str(found.get("detail", ""))[:200]
            action = ("block(dry-run)" if DRY_RUN else "block") if rule["block"] else "alert"
            meta = {"detail": detail, "command": " ".join(rule["command"])}
            if emit(rid, target, rule["severity"], f"[{rule['name']}] {detail}" if detail else f"[{rule['name']}] 탐지됨",
                    action, meta=meta) and rule["block"]:
                block_auto(target, rid, rule.get("block_duration_sec"), bool(rule.get("block_permanent")))
    finally:
        _script_running.discard(rid)


def run_script_rules_tick():
    """5초마다(maintenance_loop) 호출: 주기(interval_sec)가 된 플러그인 방식 규칙만 실행한다. 아직 도는 규칙은 겹쳐 돌리지 않음"""
    now = time.time()
    with lock:
        due = [r for r in SCRIPT_RULES.values() if r["enabled"] and r["id"] not in _script_running
               and now - _script_last_run.get(r["id"], 0) >= r["interval_sec"]]
    for r in due:
        _script_last_run[r["id"]] = now
        _script_running.add(r["id"])
        threading.Thread(target=run_script_rule, args=(r,), daemon=True).start()


# ─────────────────────────── SSH 로그인 성공 탐지 (sshd 로그) ───────────────────────────
# 패킷으로는 비밀번호가 맞았는지 알 수 없어서 sshd 의 로그를 읽는다. 이 서버에는 /var/log/auth.log 가 없으므로 journald 를 본다.
AUTH_ACCEPT_RE = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port")
AUTH_FAIL_RE = re.compile(r"Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port")


def process_auth_line(line, now):
    """sshd 로그 한 줄 처리. 실패가 쌓인(또는 무차별 대입으로 탐지된) IP 에서 로그인이 성공하면 최고 위험도로 알린다.
    실패가 없던 평범한 로그인(관리자의 키 로그인 등)은 알리지 않는다"""
    r = RULES["ssh_login_success"]
    if not r["enabled"]:
        return
    m = AUTH_FAIL_RE.search(line)
    if m:
        record("ssh_login_fail", m.group(3), 1, r["window_sec"], now)
        return
    m = AUTH_ACCEPT_RE.search(line)
    if not m:
        return
    method, user, ip = m.groups()
    with hist_lock:
        w = history.get(("ssh_login_fail", ip))
        if w:
            w.trim(now)
        fails = len(w) if w else 0
    brute = now - last_alert.get(("ssh_bruteforce", ip), 0) <= r["window_sec"]
    if fails >= r["min_failures"] or brute:
        why = f"로그인 실패 {fails}회 뒤" if fails else "무차별 대입 탐지 뒤"
        fire("ssh_login_success", ip, "critical", f"{why} '{user}' 계정 로그인 성공 ({method})",
             meta={"user": user, "method": method, "failures": fails, "window_sec": r["window_sec"]})


def auth_log_loop():
    """journald 의 sshd 기록을 따라 읽는다. journalctl 이 끝나면 잠시 뒤 다시 시작"""
    while True:
        try:
            proc = subprocess.Popen(["journalctl", "-f", "-n", "0", "-o", "cat", "-t", "sshd-session", "-t", "sshd"],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
            for line in proc.stdout:
                try:
                    process_auth_line(line, time.time())
                except Exception as e:      # 한 줄 때문에 감시 전체가 멈추지 않도록
                    print(f"[!] sshd 로그 처리 오류: {e}")
            proc.wait()
        except OSError as e:
            print(f"[!] journalctl 을 실행할 수 없어 SSH 로그인 성공 탐지가 멈췄습니다: {e}")
        time.sleep(10)


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


# ─────────────────────────── 침입 상세 분석 (대시보드 '정보' 버튼) ───────────────────────────
# 이벤트 하나를 "어디서 / 어떤 공격 / 서버에 준 영향 / 대응 결과 / 권고" 로 풀어 쓴다.
# 영향(램·CPU 부담)은 공격 종류와 '탐지 기준 대비 횟수'로 짐작한 값이지 실제로 잰 값이 아니다 (화면에도 그렇게 표시).
# 대응 결과와 '지금도 계속 오는지'는 조회하는 순간의 차단 목록과 패킷 기록(최근 10초)으로 판단한다.
LEVELS = ["낮음", "보통", "높음"]
UNITS = {"port_scan": "개 포트", "syn_flood": "개", "syn_flood_distributed": "개", "icmp_flood": "개"}
META_LABELS = {"count": "탐지 횟수 (기간 안)", "threshold": "탐지 기준", "window_sec": "관찰 기간 (초)", "sources": "출발지 수",
               "bytes": "전송량 (바이트)", "ip": "관련 IP", "old_mac": "원래 MAC", "new_mac": "바뀐 MAC",
               "ports": "대상 포트", "protocol": "프로토콜", "distinct": "세는 방법",
               "user": "로그인 계정", "method": "로그인 방식", "failures": "로그인 실패 횟수", "detail": "스크립트 판정", "command": "실행 명령"}
ATTACK_INFO = {
    "port_scan": {
        "name": "포트 스캔", "burden": 0, "scales": False,
        "what": ["서버에서 열려 있는 문(포트)을 찾으려고 여러 포트를 차례로 두드리는 정찰 행위입니다 (nmap 같은 도구).",
                 "본격적인 공격 전에 어떤 서비스가 열려 있는지 알아내는 사전 조사 단계입니다."],
        "impact": ["스캔 자체는 서버의 램·CPU 에 큰 부담을 주지 않습니다.",
                   "하지만 열려 있는 서비스(SSH, 웹 등)가 공격자에게 알려져 다음 공격의 표적이 됩니다."],
        "tips": ["이어서 SSH 무차별 대입 같은 다른 공격이 있었는지 'IP별 공격 기록'에서 확인하세요.",
                 "사용하지 않는 포트와 서비스는 닫아 두세요."]},
    "syn_flood": {
        "name": "SYN 플러드", "burden": 2, "scales": True,
        "what": ["연결을 시작하는 신호(SYN)를 한꺼번에 쏟아부어 서버의 연결 대기열을 가득 채우는 서비스 거부(DoS) 공격입니다."],
        "impact": ["막지 않으면 대기열과 메모리·CPU 를 계속 소모해 서버가 새 연결을 받지 못하고(서비스 마비) 느려질 수 있습니다.",
                   "램 부담이 큰 공격입니다."],
        "tips": ["syncookies 가 켜져 있으면(config.json 의 enable_syncookies) 대기열이 차도 정상 접속을 일부 지킬 수 있습니다.",
                 "공격이 이어지면 해당 IP 를 영구 차단하세요."]},
    "syn_flood_distributed": {
        "name": "출발지 위조 SYN 플러드", "burden": 2, "scales": True,
        "what": ["출발지 IP 를 계속 바꿔 가며(위조) SYN 을 보내는 공격입니다. 어느 한 IP 를 차단해도 소용이 없습니다."],
        "impact": ["차단할 단일 IP 가 없어 서버의 연결 대기열과 램을 계속 소모할 수 있습니다."],
        "tips": ["syncookies 가 켜져 있는지 확인하세요 (config.json 의 enable_syncookies).",
                 "서버 앞단(공유기·상위 방화벽)에서 거르는 것이 근본 대책입니다."]},
    "icmp_flood": {
        "name": "핑 플러드", "burden": 1, "scales": True,
        "what": ["ping(ICMP)을 대량으로 보내 네트워크 회선과 CPU 를 소모시키는 공격입니다."],
        "impact": ["램 부담은 비교적 작지만 회선과 CPU 를 채워 정상 통신이 느려질 수 있습니다.",
                   "서버가 모든 ping 에 응답하느라 응답 패킷도 함께 나갑니다."],
        "tips": ["ping 응답이 필요 없다면 서버가 응답하지 않게 설정할 수 있습니다 (net.ipv4.icmp_echo_ignore_all)."]},
    "ssh_bruteforce": {
        "name": "SSH 무차별 대입", "burden": 0, "scales": False,
        "what": ["SSH 로그인(보통 22번 포트)을 계속 시도하며 비밀번호를 하나씩 대입해 보는 공격입니다."],
        "impact": ["서버 부담보다 '계정 탈취' 위험이 큰 공격입니다. 비밀번호가 약하면 성공해서 서버를 장악당할 수 있습니다.",
                   "이 표시는 '접속 시도'를 센 것입니다. 로그인이 실제로 성공하면 'SSH 로그인 성공' 탐지가 따로 뜹니다."],
        "tips": ["비밀번호 로그인 대신 키 로그인을 쓰고, 강한 비밀번호를 쓰세요.", "시도가 이어지면 영구 차단을 추천합니다."]},
    "ssh_login_success": {
        "name": "SSH 로그인 성공 (공격 뒤)", "burden": 0, "scales": False,
        "what": ["로그인 실패가 반복되던 출발지에서 SSH 로그인이 성공했습니다. 비밀번호를 알아냈을 가능성이 큽니다."],
        "impact": ["공격자가 이 서버에 계정 권한으로 들어왔을 수 있습니다. 가장 위험한 상황입니다.",
                   "관리자 본인이 비밀번호를 여러 번 틀린 뒤 성공한 경우에도 뜰 수 있으니 먼저 확인하세요."],
        "tips": ["본인이 아니라면 바로 차단하고 해당 계정의 비밀번호를 바꾸세요.",
                 "서버에서 접속 기록을 확인하세요 (who, last, journalctl -t sshd-session).",
                 "비밀번호 로그인 대신 키 로그인을 쓰세요."]},
    "arp_spoof": {
        "name": "ARP 스푸핑", "burden": 0, "scales": False,
        "what": ["같은 IP 의 MAC 주소를 거짓으로 알려 같은 망의 통신을 가로채려는 공격(중간자 공격)입니다."],
        "impact": ["서버 성능 부담은 거의 없지만 통신 내용이 엿보이거나 변조될 수 있습니다.",
                   "이 MAC 을 차단해도 이미 속은 장비의 ARP 표는 바로 고쳐지지 않을 수 있습니다."],
        "tips": ["이 IP 의 진짜 MAC 이 무엇인지 확인하세요 (원래 MAC 과 바뀐 MAC 은 아래 근거에 있습니다).",
                 "중요한 장비는 정적 ARP 항목으로 고정하는 것을 고려하세요."]},
    "exfiltration": {
        "name": "대량 데이터 유출", "burden": 1, "scales": False,
        "what": ["서버에서 외부 한 곳으로 비정상적으로 많은 데이터가 나가고 있습니다.",
                 "여기서 '출발지' 로 표시된 주소는 공격자가 아니라 데이터가 도착한 곳입니다."],
        "impact": ["회선을 많이 쓰고, 중요한 자료가 밖으로 새고 있을 수 있습니다."],
        "tips": ["정상적인 백업·업데이트·파일 전송이 아닌지 먼저 확인하세요.",
                 "의심스러우면 서버에서 해당 주소로 나가는 연결을 확인하세요 (ss -tnp)."]},
}


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _server_now():
    """지금 서버의 메모리 사용률·부하 (리눅스가 아니면 None)"""
    try:
        mem = {}
        with open("/proc/meminfo", encoding="ascii") as f:
            for line in f:
                key, val = line.split(":", 1)
                if key in ("MemTotal", "MemAvailable"):
                    mem[key] = int(val.split()[0])
        return {"mem_percent": round(100 - mem["MemAvailable"] * 100 / mem["MemTotal"], 1),
                "load1": round(os.getloadavg()[0], 2), "cpus": os.cpu_count() or 1}
    except (OSError, KeyError, ValueError, AttributeError, ZeroDivisionError):
        return None


_pkt_base = None                 # WARDEN 시작 때의 인터페이스 패킷 수


def _iface_packets():
    try:
        total = 0
        for name in ("rx_packets", "tx_packets"):
            with open(f"/sys/class/net/{IFACE}/statistics/{name}", encoding="ascii") as f:
                total += int(f.read())
        return total
    except (OSError, ValueError):
        return None


def _missed_packets():
    """인터페이스가 주고받은 패킷 수와 WARDEN 이 처리한 수의 차이 (플러드 때 못 따라간 양. IPv6 등 감시 대상이 아닌 것도 조금 포함)"""
    cur = _iface_packets()
    if cur is None or _pkt_base is None:
        return None
    return max(0, cur - _pkt_base - stats["packets_total"])


def _recent_from(ev, window=10):
    """이 이벤트의 출발지가 최근 window 초 동안 보낸 패킷 수 (패킷 기록이 꺼졌거나 비어 있거나 ARP 면 None)"""
    if not PV["enabled"] or ev["type"] == "arp_spoof":
        return None
    ip = ev["source"]
    if not _is_ip(ip):
        return None
    now = time.time()
    with pkt_lock:
        snap = list(packets)
    if not snap:
        return None
    if ev["type"] == "exfiltration":
        return sum(1 for p in snap if p["dst"] == ip and p["dir"] == "out" and now - p["time"] <= window)
    return sum(1 for p in snap if p["src"] == ip and p["dir"] == "in" and now - p["time"] <= window)


def _where(ev, meta):
    src, kind, lines = ev["source"], ev["type"], []
    if kind == "arp_spoof":
        lines.append(f"MAC 주소 {src} 인 장비가 {meta.get('ip', '?')} 인 척 ARP 응답을 보냈습니다.")
    elif _is_ip(src):
        a = ipaddress.ip_address(src)
        label = "데이터가 나간 목적지" if kind == "exfiltration" else "출발지"
        lines.append(f"{label}: {src}")
        try:
            net = ipaddress.ip_network(f"{MY_IP}/24", strict=False)
        except ValueError:
            net = None
        if a.is_loopback:
            lines.append("서버 자기 자신(loopback)입니다.")
        elif net and a in net:
            lines.append(f"서버와 같은 내부망({net}) 안의 장비입니다.")
        elif a.is_private:
            lines.append("사설(내부) IP 대역입니다. 다른 내부망에서 온 장비입니다.")
        else:
            lines.append("인터넷(공인 IP) 쪽입니다. 위치 조회는 인터넷이 필요해 이 실습망에서는 제공하지 않습니다.")
        mac = arp_table.get(src)
        if mac:
            lines.append(f"MAC 주소: {mac} (ARP 로 확인)")
    else:
        lines.append(f"출발지: {src}")
    key = f"mac:{src}" if kind == "arp_spoof" else src
    if notes.get(key):
        lines.append(f"메모: {notes[key]}")
    if kind != "exfiltration":
        ports = meta.get("ports") or []
        lines.append(f"목표: 이 서버 {MY_IP}" + (f" (포트 {', '.join(map(str, ports[:12]))}{' …' if len(ports) > 12 else ''})" if ports else ""))
    with lock:
        a = attackers.get(src)
        a = dict(a, by_type=dict(a["by_type"])) if a else None
    if a:
        types = ", ".join(f"{k} {v}회" for k, v in a["by_type"].items())
        lines.append(f"이 출발지의 누적 탐지 {a['total']}회 (처음 {a['first'].replace('T', ' ')[:19]}, "
                     f"마지막 {a['last'].replace('T', ' ')[:19]}) — {types}")
    return lines, (a or {}).get("total", 0)


def analyze_event(ev):
    """이벤트 dict 하나를 사람이 읽을 분석(dict)으로 바꾼다. 대시보드 '정보' 버튼용"""
    kind, src, action = ev["type"], ev["source"], ev.get("action", "alert")
    meta = ev.get("meta") or {}
    evidence = [["이벤트 ID", ev["id"]], ["발생 시각", ev["timestamp"].replace("T", " ")[:19]], ["탐지 유형", kind],
                ["위험도", ev["severity"]], ["출발지", src], ["당시 조치", action], ["상세", ev["detail"]]]
    for k, v in meta.items():
        evidence.append([META_LABELS.get(k, k), ", ".join(map(str, v)) if isinstance(v, list) else str(v)])
    if kind in ADMIN_EVENTS:
        return {"event": ev, "name": "관리 작업", "evidence": evidence, "sections": [],
                "headline": {"level": "info", "text": "관리 작업 기록입니다. 공격이 아니라서 영향 분석은 없습니다."},
                "actions": {"can_block": False, "target": ""}, "server_now": None, "recent_packets": None, "burden": None}
    info = ATTACK_INFO.get(kind)
    if info is None:                          # 직접 만든 규칙(rules/<id>.json)
        with lock:
            r = rules_all.get(kind)
        name = r["name"] if r else kind
        info = {"name": f"사용자 규칙 '{name}'", "burden": 0, "scales": False,
                "what": [f"직접 만든 규칙 '{name}' 의 조건에 맞는 트래픽이 탐지됐습니다." + (f" ({r['description']})" if r and r.get("description") else "")],
                "impact": ["이 규칙이 무엇을 막으려는지(규칙 설명)에 따라 영향이 달라집니다. 서버 부담은 탐지 횟수로만 짐작할 수 있습니다."],
                "tips": ["조건(횟수·기간)이 실제 공격에 비해 너무 낮거나 높지 않은지 '탐지 규칙'에서 확인하세요."]}

    target_key = f"mac:{src}" if kind == "arp_spoof" else src
    recent = _recent_from(ev)
    active = bool(recent)
    with lock:
        blk = dict(blocked[target_key]) if target_key in blocked else None
    enforced = bool(blk) and not DRY_RUN
    whitelisted = kind != "exfiltration" and src != "*" and is_whitelisted(target_key)
    can_block = (_is_ip(src) or kind == "arp_spoof") and kind not in ("exfiltration", "syn_flood_distributed") and not whitelisted

    where, repeat = _where(ev, meta)

    cnt = meta.get("bytes", meta.get("count"))
    thr = meta.get("threshold")
    ratio = cnt / thr if isinstance(cnt, (int, float)) and isinstance(thr, (int, float)) and thr else None
    lvl = info["burden"]
    if info["scales"] and ratio is not None:
        lvl = max(0, lvl - 1) if ratio < 2 else lvl if ratio < 5 else min(2, lvl + 1)
    if info["scales"] and active and not enforced:
        lvl = min(2, lvl + 1)                  # 막지 못했는데 지금도 계속 오는 중
    impact = []
    if ratio is not None:
        unit = UNITS.get(kind, "회")
        got = f"{cnt / 1_000_000:.1f}MB" if "bytes" in meta else f"{cnt}{unit}"
        want = f"{thr / 1_000_000:.0f}MB" if "bytes" in meta else f"{thr}{unit}"
        impact.append(f"{meta.get('window_sec', '?')}초 동안 {got} (탐지 기준 {want}의 {ratio:.1f}배)")
    impact.append(f"서버 부담(램·CPU·회선) 추정: {LEVELS[lvl]} — 실제로 잰 값이 아니라 공격 종류와 횟수로 짐작한 값입니다.")
    impact += info["impact"]

    out = []
    if kind == "exfiltration":
        level, head = "warn", "알림만 하는 탐지입니다. 데이터가 실제로 나갔는지 직접 확인이 필요합니다."
        out.append("유출 탐지는 차단하지 않습니다 (목적지가 공격자가 아니라 데이터가 가는 곳이고, 정상 백업과 구분할 수 없어서).")
    elif kind == "syn_flood_distributed":
        level, head = "warn", "차단할 IP 가 없는 유형입니다. syncookies 가 방어하지만 서버 부담이 이어질 수 있습니다."
        out.append("출발지가 위조돼 있어 방화벽으로 막을 수 없고 알림만 합니다.")
    elif action == "block" and enforced:
        left = "영구 차단" if blk.get("permanent") else f"{max(0, int(blk['until'] - time.time()))}초 남음"
        level, head = "good", "성공적으로 막아냈습니다."
        out.append(f"방화벽(iptables)이 {src} 를 차단했습니다 ({left}).")
        if recent:
            out.append(f"차단 뒤에도 최근 10초 동안 {recent}개가 도착했지만 방화벽이 버렸습니다. 서버에는 전달되지 않아 부담은 거의 없습니다.")
        elif recent == 0:
            out.append("최근 10초 동안 이 출발지에서 온 패킷이 없습니다.")
    elif action == "block":
        out.append("당시에는 차단했지만 지금은 실제로 막고 있지 않습니다." + (" (지금은 dry-run 모드)" if blk and DRY_RUN else " (차단 기간이 끝났거나 직접 해제함)"))
        if active:
            level, head = "bad", "차단이 풀린 뒤 공격이 다시 들어오고 있습니다. 서버 부담이 이어질 수 있어 IP 차단을 추천합니다."
        else:
            level, head = "warn", "지금은 막고 있지 않지만 공격도 조용합니다. 같은 IP 가 다시 오면 영구 차단을 고려하세요."
    else:
        out.append("dry-run(탐지만) 모드라 실제로 막지 않았습니다. 이 공격은 그대로 서버에 들어왔습니다." if action == "block(dry-run)"
                   else "이 규칙은 알림만 하도록 설정돼 있어 막지 않았습니다. 공격은 그대로 서버에 들어왔습니다.")
        if active:
            level, head = "bad", "막지 못했고 공격이 계속되고 있습니다. 서버 부담이 이어질 수 있어 IP 차단을 추천합니다."
        elif recent == 0:
            level, head = "warn", "막지는 못했지만 지금은 공격이 멈춘 것으로 보입니다."
        else:
            level, head = "warn", "막지 못했습니다. 지금도 오는지는 패킷 기록이 없어 알 수 없습니다."
    if recent is not None and kind != "exfiltration":
        out.append(f"지금 상태: 최근 10초 동안 이 출발지에서 온 패킷 {recent}개" + (" (공격이 계속되는 중)" if recent and not enforced else ""))
    if whitelisted:
        out.append("이 출발지는 화이트리스트라 차단되지 않습니다. 관리 PC 의 시험이 아닌지 확인하세요.")

    rec = []
    if can_block and not enforced:
        strong = active or (ratio is not None and ratio >= 2) or repeat >= 3
        rec.append("🚫 이 IP 차단을 추천합니다 (아래 버튼 또는 '보안 정책 제어')." if strong
                   else "필요하면 이 IP 를 차단하세요 (아래 버튼 또는 '보안 정책 제어').")
    if can_block and repeat >= 3:
        rec.append(f"같은 출발지가 {repeat}번 탐지된 반복 공격자입니다. 영구 차단을 고려하세요.")
    if can_block and action == "alert":
        rec.append("탐지 규칙의 '방화벽 차단'을 켜 두면 다음부터 자동으로 막습니다 ('탐지 규칙'에서 수정).")
    if DRY_RUN and can_block:
        rec.append("지금은 dry-run(탐지만) 모드입니다. 실제로 막으려면 왼쪽 '개요' 메뉴의 '관제 서버 상태' 슬라이드를 '실제 차단'으로 바꾸세요.")
    rec += info["tips"]

    return {"event": ev, "name": info["name"], "headline": {"level": level, "text": head},
            "sections": [{"title": "📍 어디서 공격했나", "lines": where}, {"title": "⚔️ 어떤 공격인가", "lines": info["what"] + [ev["detail"]]},
                         {"title": "💥 서버에 준 영향", "lines": impact}, {"title": "🛡️ 대응 결과", "lines": out},
                         {"title": "✅ 권고", "lines": rec}],
            "evidence": evidence, "actions": {"can_block": can_block and not enforced, "target": target_key if can_block else ""},
            "server_now": _server_now(), "recent_packets": recent, "burden": LEVELS[lvl]}


class API(BaseHTTPRequestHandler):
    def _headers(self, code, length=0):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
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

    def _from_browser_page(self):
        """이 API 는 토큰이 없고 대시보드 서버(프록시)만 부른다. 서버 안의 브라우저로 연 웹페이지가 대신 부르지 못하게 막는다
        (웹페이지 요청에는 Origin 이 붙고, DNS 를 속이는 경우에는 Host 가 달라진다). 서버 안의 프로그램까지 막는 장치는 아니다"""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        if self.headers.get("Origin") or host not in ("127.0.0.1", "localhost"):
            self._send(403, {"error": "이 API 는 대시보드 서버를 통해서만 부를 수 있습니다"})
            return True
        return False

    def do_GET(self):
        if self._from_browser_page():
            return
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
                    "whitelist": sorted(WHITELIST), "whitelist_fixed": sorted(fixed_whitelist()), "utc_offset": now_iso()[-6:],
                    "server": _server_now(), "missed_packets": _missed_packets(),
                    "notes": dict(notes),
                })
        elif u.path == "/api/events":
            ev_type, source = q.get("type", [None])[0], q.get("source", [None])[0]
            with lock:
                data = [e for e in events if (not ev_type or e["type"] == ev_type) and (not source or e["source"] == source)]
            self._send(200, {"events": list(reversed(data))[:limit]})   # 최신순
        elif u.path == "/api/blocked":
            with lock:
                data = [{"target": k, "reason": v["reason"], "since": now_iso(v["since"]),
                         "permanent": bool(v.get("permanent")), "note": notes.get(k, ""), "repeat": v.get("repeat", 0),
                         "until": None if v["until"] is None else now_iso(v["until"]),
                         "remaining_sec": None if v["until"] is None else int(v["until"] - time.time())}
                        for k, v in blocked.items()]
            self._send(200, {"blocked": data, "simulated": DRY_RUN})     # dry-run 이면 목록은 '모의' (실제로 막고 있지 않음)
        elif u.path == "/api/event_analysis":
            eid = q.get("id", [""])[0]
            with lock:
                ev = next((dict(e) for e in events if e["id"] == eid), None)
            if ev is None:
                return self._send(404, {"error": "이벤트를 찾을 수 없습니다 (목록에서 이미 밀려났을 수 있습니다)"})
            self._send(200, analyze_event(ev))
        elif u.path == "/api/packets":
            try:
                since = max(0, int(q.get("since", ["0"])[0]))
            except ValueError:
                return self._send(400, {"error": "since 는 숫자여야 합니다"})
            proto = q.get("proto", [""])[0].upper()
            if proto not in ("", "TCP", "UDP", "ICMP", "ARP"):
                return self._send(400, {"error": "proto 는 TCP / UDP / ICMP / ARP 중 하나여야 합니다"})
            ip = q.get("ip", [""])[0].strip()
            if ip and not re.fullmatch(r"[0-9a-fA-F.:]{1,45}", ip):
                return self._send(400, {"error": "ip 는 숫자와 점으로만 쓰세요 (앞부분만 써도 됩니다)"})
            hide = {int(s) for s in q.get("hide_ports", [""])[0].split(",") if s.strip().isdigit() and int(s) <= 65535}
            rows, last = query_packets(since, min(limit, 1000), proto, ip, hide)
            self._send(200, {"enabled": PV["enabled"], "packets": rows, "last_seq": last, "buffer": packets.maxlen,
                             "unrecorded": stats.get("packets_unrecorded", 0), "my_ip": MY_IP})
        elif u.path == "/api/pcap":
            if not PV["enabled"]:
                return self._send(409, {"error": "패킷 기록이 꺼져 있어 PCAP 을 만들 수 없습니다 (config.json 의 packet_view.enabled)"})
            proto = q.get("proto", [""])[0].upper()
            if proto not in ("", "TCP", "UDP", "ICMP", "ARP"):
                return self._send(400, {"error": "proto 는 TCP / UDP / ICMP / ARP 중 하나여야 합니다"})
            ip = q.get("ip", [""])[0].strip()
            if ip and not re.fullmatch(r"[0-9a-fA-F.:]{1,45}", ip):
                return self._send(400, {"error": "ip 는 숫자와 점으로만 쓰세요 (앞부분만 써도 됩니다)"})
            hide = {int(s) for s in q.get("hide_ports", [""])[0].split(",") if s.strip().isdigit() and int(s) <= 65535}
            eid = q.get("event", [""])[0]
            if eid and not re.fullmatch(r"[0-9a-zA-Z_-]{1,64}", eid):
                return self._send(400, {"error": "event 값이 올바르지 않습니다"})
            try:
                rows, info = pcap_for(proto, ip, hide, eid)
            except LookupError as e:
                return self._send(404, {"error": str(e)})
            if not rows:
                return self._send(404, {"error": f"조건에 맞는 패킷이 기록에 없습니다 (최근 {packets.maxlen}개만 보관하므로 "
                                                 "오래된 공격이나 플러드 중 기록 한도를 넘은 패킷은 없을 수 있습니다)"})
            body = build_pcap(rows)
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Packet-Count", str(len(rows)))
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/api/rule_changes":
            with lock:
                data = list(rule_changes)
            self._send(200, {"changes": list(reversed(data))[:limit]})
        elif u.path == "/api/history":
            with lock:
                data = [{"source": k, "total": a["total"], "blocks": a["blocks"], "by_type": dict(a["by_type"]),
                         "first": a["first"], "last": a["last"], "note": notes.get(k, ""),
                         "blocked_now": k in blocked}
                        for k, a in attackers.items()]
            data.sort(key=lambda x: x["total"], reverse=True)
            self._send(200, {"history": data[:limit]})
        elif u.path == "/api/rules":
            reload_rules()
            with lock:
                errors = dict(rule_errors)
            with lock:
                hits = {k: dict(v) for k, v in rule_hits.items()}
            self._send(200, {"dry_run": DRY_RUN, "rules": list_rules(), "errors": errors, "hits": hits,
                             "default_block_sec": CFG["block_duration_sec"]})
        else:
            self._send(404, {"error": "not found"})

    def _rules_post(self, path, body):
        """규칙: 저장(/api/rules) · 수정(/update) · 켜기끄기(/enable) · 삭제(/delete)"""
        try:
            if path == "/api/rules":
                rule = validate_rule(body.get("rule"))
                if rule["detector"] == "script":     # 실행될 코드는 터미널 승인을 거쳐야 한다 (approve_plugin.py)
                    return self._send(403, {"error": "플러그인 방식 규칙은 올리기와 서버 터미널 승인으로만 추가할 수 있습니다"})
                if rule["id"] in rules_all:          # 수정은 /update 로: 조용히 덮어쓰면 '수정하면 꺼짐' 원칙을 건너뜀
                    return self._send(409, {"error": f"이미 있는 규칙 ID 입니다: {rule['id']}"})
                save_rule(rule)
                log_rule_change(rule["id"], "추가됨")
                return self._send(200, {"ok": True, "id": rule["id"]})
            rid = str(body.get("id", ""))
            if path == "/api/rules/update":
                res = update_rule(rid, body.get("rule"))
                if res is None:
                    return self._send(200, {"ok": False, "reason": "없는 규칙"})
                if res["changed"]:
                    log_rule_change(rid, "알림 설정 변경" if res.get("kept_enabled")
                                    else "수정됨 (자동으로 꺼짐)" if res["was_enabled"] else "수정됨 (꺼짐 상태 유지)")
                return self._send(200, {"ok": True, **res})
            if path == "/api/rules/delete":
                was_enabled = delete_rule(rid)
                if was_enabled is None:
                    return self._send(200, {"ok": False, "reason": "없는 규칙"})
                if was_enabled:
                    log_rule_change(rid, "꺼짐 (삭제 전 자동 비활성화)")
                log_rule_change(rid, "삭제됨")
                return self._send(200, {"ok": True, "was_enabled": was_enabled})
            if path == "/api/rules/enable":
                if not isinstance(body.get("enabled"), bool):
                    return self._send(400, {"error": "enabled 는 true / false 여야 합니다"})
                if not set_rule_enabled(rid, body["enabled"]):
                    return self._send(200, {"ok": False, "reason": "없는 규칙"})
                log_rule_change(rid, "켜짐" if body["enabled"] else "꺼짐")
                return self._send(200, {"ok": True})
        except (ValueError, OSError) as e:
            return self._send(400, {"error": str(e)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self._from_browser_page():
            return
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self._send(415, {"error": "Content-Type 은 application/json 이어야 합니다"})
        u = urlparse(self.path)
        body = self._body()
        if u.path == "/api/dry_run":
            if not isinstance(body.get("dry_run"), bool):
                return self._send(400, {"error": "dry_run 은 true / false 여야 합니다"})
            changed = set_dry_run(body["dry_run"])
            return self._send(200, {"ok": True, "dry_run": DRY_RUN, "changed": changed})
        if u.path.startswith("/api/rules"):
            return self._rules_post(u.path, body)
        target = normalize_target(str(body.get("target", "")))
        if not target:
            return self._send(400, {"error": "target 은 IP 하나 또는 'mac:aa:bb:cc:dd:ee:ff' 형식이어야 합니다 "
                                             "(예: {\"target\": \"192.168.56.20\"})"})
        if u.path == "/api/block":
            duration = body.get("duration_sec")
            permanent = body.get("permanent") is True
            if duration is not None and (isinstance(duration, bool) or not isinstance(duration, int)
                                         or not 0 < duration <= 10 * 365 * 86400):
                return self._send(400, {"error": "duration_sec 은 1 이상의 정수(초)여야 합니다 (최대 10년)"})
            if is_whitelisted(target):
                return self._send(200, {"ok": False, "reason": "화이트리스트 대상"})
            overwrite = body.get("overwrite") is True
            with lock:
                cur = blocked.get(target)
                current = cur and {"reason": cur["reason"], "since": now_iso(cur["since"]),
                                   "permanent": bool(cur.get("permanent")), "note": notes.get(target, ""),
                                   "remaining_sec": None if cur["until"] is None else int(cur["until"] - time.time())}
            if current and not overwrite:
                return self._send(200, {"ok": False, "exists": True, "reason": "이미 차단 중", "current": current})
            ok = block(target, str(body.get("reason", "manual"))[:100], duration, permanent, overwrite)
            if ok:
                if isinstance(body.get("note"), str) and body["note"].strip():
                    set_note(target, body["note"])
                emit("manual_block", target, "info",
                     "대시보드에서 수동 " + ("영구 차단" if permanent else "차단") + (" (기존 차단 덮어씀)" if current else ""),
                     "block(dry-run)" if DRY_RUN else "block", cooldown=False)
            self._send(200, {"ok": ok} if ok else {"ok": False, "reason": "차단할 수 없는 대상"})
        elif u.path == "/api/note":
            if not isinstance(body.get("note"), str):
                return self._send(400, {"error": "note 는 문자열이어야 합니다 (비우면 메모 삭제)"})
            set_note(target, body["note"])
            self._send(200, {"ok": True})
        elif u.path == "/api/unblock":
            ok = unblock(target)
            self._send(200, {"ok": ok} if ok else {"ok": False, "reason": "차단 목록에 없음"})
        elif u.path == "/api/whitelist":
            if body.get("action") not in ("add", "remove"):
                return self._send(400, {"error": "action 은 add / remove 여야 합니다"})
            ok, why, freed = set_whitelist(body["action"], target)
            self._send(200, {"ok": ok, "reason": why, "unblocked": freed, "whitelist": sorted(WHITELIST)})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):   # 요청마다 찍히는 기본 로그 끄기
        pass


# ─────────────────────────── 실행 ───────────────────────────
def main():
    global _pkt_base
    if os.geteuid() != 0:
        sys.exit("[!] root 권한이 필요합니다: sudo python3 warden.py")
    init_network()
    if MY_IP == "0.0.0.0":
        sys.exit(f"[!] 인터페이스 '{IFACE}' 에 IP가 없습니다. 'ip a' 로 확인 후 config.json 을 고치세요.")

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    apply_dry_run_override()         # 대시보드에서 꺼 둔 dry_run 을 시작부터 반영 (setup_firewall 보다 먼저)
    setup_firewall()
    load_persisted()
    migrate_legacy()
    reload_rules()
    load_repeat()
    restore_permanent()
    threading.Thread(target=maintenance_loop, daemon=True).start()
    threading.Thread(target=auth_log_loop, daemon=True).start()
    _pkt_base = _iface_packets()

    api = CFG["api"]
    if api["enabled"]:
        server = ThreadingHTTPServer((api["host"], api["port"]), API)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    print("=" * 60)
    print(f" WARDEN 시작 | {IFACE} ({MY_IP})")
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
