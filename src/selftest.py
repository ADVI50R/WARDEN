#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest.py - 실제 패킷/VM 없이 WARDEN 의 탐지 로직만 시험합니다.

가짜 패킷 객체를 만들어 warden._handle() 에 직접 넣고,
기대한 이벤트가 발생하는지 확인합니다.
scapy, Npcap, 관리자 권한 모두 필요 없습니다.

실행:  python selftest.py
"""
import sys
import time

# ── warden 을 '라이브러리처럼' 불러오기 위한 최소한의 가짜 scapy ──
# warden.py 는 맨 위에서 scapy 를 import 하므로, 진짜가 없으면 가짜를 넣어준다.
import types

try:
    import scapy.all  # noqa: F401  (있으면 그대로 사용)
except ImportError:
    fake = types.ModuleType("scapy.all")
    # warden 이 쓰는 이름들만 최소로 채운다
    fake.sniff = lambda *a, **k: None
    fake.get_if_addr = lambda i: "192.168.56.10"
    fake.get_if_hwaddr = lambda i: "aa:bb:cc:dd:ee:ff"

    class _Layer:  # IP/TCP/ICMP/ARP 자리표시자
        pass

    fake.IP = type("IP", (_Layer,), {})
    fake.TCP = type("TCP", (_Layer,), {})
    fake.ICMP = type("ICMP", (_Layer,), {})
    fake.ARP = type("ARP", (_Layer,), {})
    scapy_pkg = types.ModuleType("scapy")
    scapy_pkg.all = fake
    sys.modules["scapy"] = scapy_pkg
    sys.modules["scapy.all"] = fake

import warden as g  # noqa: E402

# 테스트 중엔 실제 방화벽/네트워크를 건드리지 않는다
g.DRY_RUN = True
g.MY_IP = "192.168.56.10"
g.MY_MAC = "aa:bb:cc:dd:ee:ff"
g.WHITELIST = {g.MY_IP, g.MY_MAC, "127.0.0.1"}

_ipt_calls = []


def _fake_iptables(*args):
    """실제 iptables 바이너리가 없는 환경(윈도우 등)에서도 dry_run 전환 시험이 되도록 호출만 기록"""
    _ipt_calls.append(args)

    class _R:
        returncode = 0
        stdout = ""
        stderr = ""
    return _R()


g.iptables = _fake_iptables
g.subprocess.run = lambda *a, **k: _fake_iptables("sysctl")      # setup_firewall() 의 sysctl 호출도 같은 이유로 가짜로
# 쿨다운(30초)은 실제와 같게 둔다 -> 항목마다 IP 가 달라 첫 알림은 항상 뜨고, 화면도 덜 복잡함
g.LOG_FILE = "logs/selftest.jsonl"
import os
os.makedirs("logs", exist_ok=True)
open(g.LOG_FILE, "w").close()          # 로그 초기화
import shutil, tempfile                  # 진짜 rules/ 는 건드리지 않도록 임시 복사본으로 시험
_real_rules = g.RULES_DIR
g.RULES_DIR = tempfile.mkdtemp()
shutil.copytree(_real_rules, g.RULES_DIR, dirs_exist_ok=True)
g.reload_rules(force=True)


# ── 가짜 패킷 만들기 ────────────────────────────────────────────
class FakePkt:
    """pkt[IP].src, IP in pkt, len(pkt) 같은 접근을 흉내 낸다."""
    def __init__(self, layers, length=100):
        self._layers = layers          # {클래스: 필드객체}
        self._len = length

    def __contains__(self, cls):       # 'IP in pkt'
        return cls in self._layers

    def __getitem__(self, cls):        # 'pkt[IP]'
        return self._layers[cls]

    def __len__(self):                 # 'len(pkt)'
        return self._len


class Fields:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def ip(src, dst=None):
    return Fields(src=src, dst=dst or g.MY_IP)


def tcp(dport, flags):
    return Fields(dport=dport, flags=flags)   # flags: SYN=0x02, ACK=0x10


def make_tcp_syn(src, dport):
    return FakePkt({g.IP: ip(src), g.TCP: tcp(dport, 0x02)})


def make_icmp(src):
    return FakePkt({g.IP: ip(src), g.ICMP: Fields(type=8)})


def make_arp(psrc, hwsrc):
    return FakePkt({g.ARP: Fields(psrc=psrc, hwsrc=hwsrc)})


def make_outgoing(dst, size):
    return FakePkt({g.IP: ip(g.MY_IP, dst)}, length=size)


# ── 이벤트 발생 여부 확인용 ──────────────────────────────────────
def count(ev_type):
    return sum(1 for e in g.events if e["type"] == ev_type)


def run(name, expect_type, action):
    before = count(expect_type)
    action()
    after = count(expect_type)
    ok = after > before
    mark = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
    print(f"  [{mark}] {name}  ->  '{expect_type}' 이벤트 {after - before}건")
    return ok


# ── 실제 테스트 ─────────────────────────────────────────────────
ATTACKER = "192.168.56.20"
results = []

print("=" * 64)
print(" WARDEN 자체 테스트 (가짜 패킷)")
print("=" * 64)

# 항목마다 다른 공격자 IP 를 쓴다.
# (한 IP 가 한 번 차단되면 그 IP 의 이후 패킷은 무시되는 것이 정상 동작이므로,
#  각 탐지 규칙을 독립적으로 확인하려면 IP 를 분리해야 한다.)

# 1) 포트 스캔: 서로 다른 포트 25개
def t_portscan():
    for port in range(1000, 1025):
        g._handle(make_tcp_syn("192.168.56.21", port))
results.append(run("포트 스캔 (포트 25개)", "port_scan", t_portscan))

# 2) SYN 플러드: 같은 포트로 SYN 250개
def t_syn():
    for _ in range(250):
        g._handle(make_tcp_syn("192.168.56.22", 80))
results.append(run("SYN 플러드 (SYN 250개)", "syn_flood", t_syn))

# 3) ICMP 플러드: ping 60개
def t_icmp():
    for _ in range(60):
        g._handle(make_icmp("192.168.56.23"))
results.append(run("핑 플러드 (ping 60개)", "icmp_flood", t_icmp))

# 4) SSH 무차별 대입: 22번 포트로 12회
def t_ssh():
    for _ in range(12):
        g._handle(make_tcp_syn("192.168.56.30", 22))
results.append(run("SSH 무차별 대입 (22번 12회)", "ssh_bruteforce", t_ssh))

# 5) ARP 스푸핑: 같은 IP 인데 MAC 이 바뀜
def t_arp():
    g._handle(make_arp("192.168.56.1", "11:11:11:11:11:11"))  # 정상 학습
    g._handle(make_arp("192.168.56.1", "22:22:22:22:22:22"))  # 변조!
results.append(run("ARP 스푸핑 (MAC 변경)", "arp_spoof", t_arp))

# 6) 데이터 유출: 밖으로 60MB 전송
def t_exfil():
    for _ in range(60):
        g._handle(make_outgoing("203.0.113.9", 1_000_000))
results.append(run("데이터 유출 (60MB 전송)", "exfiltration", t_exfil))

# 7) dry-run 에서 같은 IP 로 공격을 이어서 해도 계속 탐지되는지
#    (가이드 7-3 처럼 공격자 한 대로 ①→② 순서대로 테스트하는 상황)
def t_same_ip():
    for port in range(2000, 2025):
        g._handle(make_tcp_syn(ATTACKER, port))   # 포트 스캔 -> (dry-run) 차단 목록에 올라감
    for _ in range(60):
        g._handle(make_icmp(ATTACKER))            # 이어서 핑 플러드
results.append(run("dry-run: 같은 IP 로 연속 공격", "icmp_flood", t_same_ip))


# 8) 출발지 위조 SYN 플러드: IP 1개만으로는 '위조' 알림이 뜨면 안 되고, 여러 IP 면 떠야 함
def run_not(name, expect_type, action):
    before = count(expect_type)
    action()
    ok = count(expect_type) == before
    mark = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
    print(f"  [{mark}] {name}  ->  '{expect_type}' 이벤트 없어야 함")
    return ok


def t_single_flood():
    for _ in range(1200):
        g._handle(make_tcp_syn("192.168.56.40", 80))
results.append(run_not("SYN 플러드 IP 1개 (위조 오탐 없음)", "syn_flood_distributed", t_single_flood))


def t_spoofed_flood():
    for i in range(1200):
        g._handle(make_tcp_syn(f"10.0.{i // 250}.{i % 250 + 1}", 80))
results.append(run("출발지 위조 SYN 플러드 (IP 1200개)", "syn_flood_distributed", t_spoofed_flood))

# 9) API 수동 차단 대상 검사: 범위·이상한 값은 거부
cases = {"192.168.56.20": "192.168.56.20", " MAC:AA:BB:CC:DD:EE:01 ": "mac:aa:bb:cc:dd:ee:01",
         "0.0.0.0/0": None, "192.168.56.0/24": None, "hello": None, "mac:zz": None}
ok = all(g.normalize_target(k) == v for k, v in cases.items())
mark = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
print(f"  [{mark}] API 차단 대상 검사 (범위·잘못된 값 거부)")
results.append(ok)

# 10) 영구 차단: 만료 처리에서 제외되고, 파일에 저장되며, 해제하면 저장도 지워짐
def check(name, ok):
    mark = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
    print(f"  [{mark}] {name}")
    results.append(ok)


g.block("192.168.56.77", "manual", permanent=True)
g.block("192.168.56.78", "manual", duration=1)
perm = g.blocked["192.168.56.77"]
check("영구 차단 (until 없음, 저장 파일에 기록)",
      perm["permanent"] and perm["until"] is None
      and "192.168.56.77" in g._load_json("permanent_blocks.json", {}))
g.blocked["192.168.56.78"]["until"] = 0                       # 기간이 지난 것처럼 만듦
expired = [k for k, v in g.blocked.items() if v["until"] is not None and v["until"] <= time.time()]
check("만료 처리: 기간제만 해제 대상, 영구는 제외", expired == ["192.168.56.78"])
g.unblock("192.168.56.77")
check("영구 차단 해제 시 저장 파일에서도 삭제", "192.168.56.77" not in g._load_json("permanent_blocks.json", {}))

# 11) 메모 저장/삭제, IP별 공격 기록 집계
g.set_note("192.168.56.20", "시연용 공격자")
check("메모 저장 (파일 반영)", g._load_json("notes.json", {}).get("192.168.56.20") == "시연용 공격자")
g.set_note("192.168.56.20", "")
check("메모 비우면 삭제", "192.168.56.20" not in g._load_json("notes.json", {}))
a = g.attackers.get(ATTACKER)
check("IP별 공격 기록 (유형별 횟수·차단 횟수)",
      bool(a) and a["total"] >= 2 and a["blocks"] >= 2 and "port_scan" in a["by_type"] and "icmp_flood" in a["by_type"])

# 12) 이미 차단 중인 대상: 기본은 거부, overwrite 면 기간·이유 갱신 (통계 중복 증가 없음)
g.block("192.168.56.90", "port_scan", duration=60)
before = g.stats["blocks_total"]
refused = not g.block("192.168.56.90", "manual", permanent=True)
check("차단 중 대상 재차단은 기본 거부", refused and g.blocked["192.168.56.90"]["reason"] == "port_scan")
g.block("192.168.56.90", "manual", permanent=True, overwrite=True)
b = g.blocked["192.168.56.90"]
check("overwrite 로 기간·이유 갱신 (영구로 변경, 차단 통계 중복 없음)",
      b["permanent"] and b["reason"] == "manual" and g.stats["blocks_total"] == before)
g.unblock("192.168.56.90")

# 13) 사용자 정의 탐지 규칙: 검사, 폴더 자동 불러오기, 조건 일치 시 탐지, 꺼진 규칙은 무시
import json, shutil, tempfile
bad = [{}, {"id": "Bad ID"}, {"id": "port_scan", "count": 1, "window_sec": 1},
       {"id": "r1", "count": 0, "window_sec": 5}, {"id": "r1", "count": 3, "window_sec": 5, "dst_ports": [70000]},
       {"id": "r1", "count": 3, "window_sec": 5, "protocol": "sctp"}]
def rejects(d):
    try:
        g.validate_rule(d)
        return False
    except ValueError:
        return True
check("규칙 검사: 잘못된 id·예약어·범위·값 거부", all(rejects(d) for d in bad))

tmp = g.RULES_DIR
def put(name, rule):
    with open(os.path.join(tmp, name + ".json"), "w", encoding="utf-8") as f:
        json.dump(rule, f)
put("t_syn23", {"id": "t_syn23", "protocol": "tcp", "dst_ports": [23], "tcp_flags": "syn", "count": 5, "window_sec": 30})
put("t_ports", {"id": "t_ports", "protocol": "tcp", "count": 8, "window_sec": 30, "distinct": "dst_port",
                "severity": "critical", "block": True})
put("t_off", {"id": "t_off", "enabled": False, "protocol": "tcp", "dst_ports": [24], "count": 1, "window_sec": 5})
put("wrong_name", {"id": "other", "count": 1, "window_sec": 5})
g.reload_rules()
check("폴더에서 규칙 자동 불러오기 (id·파일 이름 불일치는 오류로 분리)",
      {"t_syn23", "t_ports", "t_off"} <= set(g.rules_all) and "other" not in g.rules_all
      and "wrong_name.json" in g.rule_errors and {"port_scan", "syn_flood"} <= set(g.RULES))

def t_custom_count():
    for _ in range(5):
        g._handle(make_tcp_syn("192.168.56.51", 23))
results.append(run("사용자 규칙: 23번 포트 SYN 5회", "t_syn23", t_custom_count))

def t_custom_distinct():
    for port in range(3000, 3010):
        g._handle(make_tcp_syn("192.168.56.52", port))
results.append(run("사용자 규칙: 서로 다른 포트 8개 + 차단", "t_ports", t_custom_distinct))
check("사용자 규칙 차단 연동", "192.168.56.52" in g.blocked)

def t_custom_off():
    for _ in range(3):
        g._handle(make_tcp_syn("192.168.56.53", 24))
results.append(run_not("꺼진 사용자 규칙은 탐지하지 않음", "t_off", t_custom_off))

for n in ("t_syn23", "t_ports", "t_off", "wrong_name"):
    os.remove(os.path.join(tmp, n + ".json"))
g.reload_rules()
check("파일을 지우면 규칙도 사라짐 (기본 규칙은 그대로)",
      not {"t_syn23", "t_ports", "t_off"} & set(g.rules_all) and "port_scan" in g.rules_all)

# 14) 기본 규칙 켜기/끄기: 끄면 탐지 안 하고, 파일에 저장되며, 다시 켜면 탐지
def t_off_scan():
    for port in range(4000, 4025):
        g._handle(make_tcp_syn("192.168.56.60", port))
g.set_rule_enabled("port_scan", False)
before = count("port_scan")
t_off_scan()
check("기본 규칙 끄기 -> 포트스캔 탐지 안 함", count("port_scan") == before
      and json.load(open(os.path.join(g.RULES_DIR, "port_scan.json"), encoding="utf-8"))["enabled"] is False)
g.set_rule_enabled("port_scan", True)
ev_before, total_before = len(g.events), g.stats["events_total"]
g.log_rule_change("port_scan", "켜짐")
check("규칙 변경은 별도 기록 (이벤트·누적 통계·IP별 기록에 안 들어감)",
      len(g.events) == ev_before and g.stats["events_total"] == total_before and "port_scan" not in g.attackers
      and g.rule_changes[-1]["rule"] == "port_scan" and os.path.exists("logs/rule_changes.jsonl"))
t_off_scan_on = lambda: [g._handle(make_tcp_syn("192.168.56.61", p)) for p in range(4000, 4025)]
t_off_scan_on()
check("기본 규칙 다시 켜기 -> 탐지", count("port_scan") == before + 1 and not g.set_rule_enabled("nope", True))

# 15) 규칙 삭제: 켜져 있는 규칙은 먼저 꺼서(탐지 중단) 삭제, 파일도 사라짐, 없는 규칙은 None
put("t_del", {"id": "t_del", "protocol": "tcp", "dst_ports": [25], "tcp_flags": "syn", "count": 2, "window_sec": 30})
g.reload_rules()
live = g.rules_all["t_del"]
was = g.delete_rule("t_del")
check("규칙 삭제: 켜져 있던 규칙은 꺼진 뒤 삭제 (was_enabled=True, 파일·목록에서 제거)",
      was is True and live["enabled"] is False and "t_del" not in g.rules_all
      and not os.path.exists(os.path.join(g.RULES_DIR, "t_del.json")) and g.delete_rule("t_del") is None)
g.delete_rule("exfiltration")
check("기본 탐지기 규칙을 지우면 그 탐지는 꺼짐 (오류 없이)", g.RULES["exfiltration"]["enabled"] is False)
check("전용 탐지기 규칙 검사 (id 불일치·범위·ports 누락 거부)",
      all(rejects(d) for d in [{"id": "x", "detector": "port_scan", "window_sec": 5, "distinct_ports": 5},
                               {"id": "port_scan", "detector": "port_scan", "window_sec": 0, "distinct_ports": 5},
                               {"id": "ssh_bruteforce", "detector": "ssh_bruteforce", "window_sec": 5, "max_attempts": 5}]))

# 15-2) 규칙 수정: 바뀌면 먼저 꺼서 저장, 변경 없으면 그대로, 잘못된 값은 거부, id·detector 는 못 바꿈
put("t_edit", {"id": "t_edit", "protocol": "tcp", "dst_ports": [26], "tcp_flags": "syn", "count": 3, "window_sec": 30})
g.reload_rules()
live = g.rules_all["t_edit"]
same = g.update_rule("t_edit", {k: v for k, v in live.items() if k not in ("id", "detector", "enabled")})
check("규칙 수정: 바뀐 게 없으면 그대로 (켜진 채 유지)", same == {"changed": False, "was_enabled": True} and g.rules_all["t_edit"]["enabled"])
res = g.update_rule("t_edit", {**live, "count": 9, "id": "hacked", "detector": "port_scan", "enabled": True})
saved = json.load(open(os.path.join(g.RULES_DIR, "t_edit.json"), encoding="utf-8"))
check("규칙 수정: 바뀌면 꺼진 상태로 저장 (id·detector·enabled 입력은 무시)",
      res == {"changed": True, "was_enabled": True} and live["enabled"] is False and saved["enabled"] is False
      and saved["count"] == 9 and saved["id"] == "t_edit" and saved["detector"] == "custom" and "hacked" not in g.rules_all)
try:
    g.update_rule("t_edit", {**live, "count": 0}); bad_ok = False
except ValueError:
    bad_ok = True
check("규칙 수정: 잘못된 값은 거부하고 기존 규칙 유지", bad_ok and g.rules_all["t_edit"]["count"] == 9 and g.update_rule("nope", {}) is None)
res = g.update_rule("syn_flood", {**g.rules_all["syn_flood"], "max_syn": 500})
check("기본 탐지기 규칙 수정 (임계값 변경, 꺼짐)", res["changed"] and g.RULES["syn_flood"]["max_syn"] == 500 and g.RULES["syn_flood"]["enabled"] is False)
g.delete_rule("t_edit")

# 15-3) 규칙별 차단 기간: 기간 지정 / 영구 / 차단 끔(기간 필드 제거) / 잘못된 값
base = {"id": "t_blk", "protocol": "tcp", "dst_ports": [27], "tcp_flags": "syn", "count": 2, "window_sec": 30, "block": True}
v1 = g.validate_rule({**base, "block_duration_sec": 36000})
v2 = g.validate_rule({**base, "block_permanent": True, "block_duration_sec": 60})
v3 = g.validate_rule({**base, "block": False, "block_duration_sec": 60, "block_permanent": True})
check("규칙 차단 기간 검사 (지정·영구·차단 꺼짐이면 제거)",
      v1["block_duration_sec"] == 36000 and "block_permanent" not in v1
      and v2.get("block_permanent") is True and "block_duration_sec" not in v2
      and "block_duration_sec" not in v3 and "block_permanent" not in v3
      and rejects({**base, "block_duration_sec": 0}) and rejects({**base, "block_duration_sec": "10"}))
put("t_blk10h", {**base, "id": "t_blk10h", "dst_ports": [27], "block_duration_sec": 36000})
put("t_blkperm", {**base, "id": "t_blkperm", "dst_ports": [28], "block_permanent": True})
g.reload_rules()
for src_ip, port in (("192.168.56.71", 27), ("192.168.56.72", 28)):
    for _ in range(2):
        g._handle(make_tcp_syn(src_ip, port))
b1, b2 = g.blocked.get("192.168.56.71"), g.blocked.get("192.168.56.72")
check("규칙의 차단 기간대로 차단 (10시간 / 영구)",
      bool(b1) and abs((b1["until"] - b1["since"]) - 36000) < 1 and not b1["permanent"]
      and bool(b2) and b2["permanent"] and b2["until"] is None)
g.unblock("192.168.56.71"); g.unblock("192.168.56.72")
g.delete_rule("t_blk10h"); g.delete_rule("t_blkperm")

# 15-4) 유출 규칙은 알림만: 파일에 block:true 가 있어도 차단 안 함 (목적지는 공격자가 아님)
shutil.copy(os.path.join(_real_rules, "exfiltration.json"), g.RULES_DIR)   # 위 삭제 시험에서 지웠으므로 복구
g.reload_rules(force=True)
ex = g.rules_all["exfiltration"]
forced = g.validate_rule({**ex, "block": True, "block_permanent": True})
check("유출 규칙은 알림만 (block 을 켜도 꺼지고 기간 필드도 제거)", forced["block"] is False and "block_permanent" not in forced)
before_blocks = len(g.blocked)
for _ in range(3):
    g._handle(make_outgoing("203.0.113.50", 20_000_000))
check("유출 탐지는 알림만 (목적지를 차단 목록에 올리지 않음)", count("exfiltration") >= 1 and len(g.blocked) == before_blocks)

# 15-5) 대시보드의 '실제 차단' 슬라이드 (dry_run 켜기/끄기)
g.blocked["192.168.56.81"] = {"since": time.time(), "until": time.time() + 100, "reason": "manual", "permanent": False}
_ipt_calls.clear()
changed = g.set_dry_run(False)                      # dry-run -> 실제 차단
check("dry_run 끄기: 체인 생성 + 추적 중인 차단에 규칙을 다시 걺",
      changed and g.DRY_RUN is False
      and any(c[:2] == ("-N", g.CHAIN) for c in _ipt_calls)
      and any(c[0] == "-A" and "192.168.56.81" in c for c in _ipt_calls))
check("같은 값으로 다시 호출하면 아무 일도 안 함", g.set_dry_run(False) is False)
_ipt_calls.clear()
changed2 = g.set_dry_run(True)                      # 실제 차단 -> dry-run
check("dry_run 켜기: 방화벽 규칙은 비우고 추적(차단 목록)은 그대로 유지, 파일에 저장",
      changed2 and g.DRY_RUN is True and ("-F", g.CHAIN) in _ipt_calls
      and "192.168.56.81" in g.blocked
      and g._load_json("dry_run_override.json", {}).get("dry_run") is True)
del g.blocked["192.168.56.81"]

g._save_json("dry_run_override.json", {"dry_run": False})
g.apply_dry_run_override()
check("시작할 때 저장된 dry_run 값을 적용", g.DRY_RUN is False)
g.DRY_RUN = True                                    # 이후 테스트에 영향 없도록 원래대로
g._save_json("dry_run_override.json", {"dry_run": True})

# 16) 예전 구조 이전: custom_rules/ 폴더와 rule_overrides.json 을 rules/ 로 옮김
shutil.rmtree(g.RULES_DIR); g.RULES_DIR = tempfile.mkdtemp(); shutil.copytree(_real_rules, g.RULES_DIR, dirs_exist_ok=True)
g.LEGACY_CUSTOM_DIR = tempfile.mkdtemp()
json.dump({"id": "old_rule", "protocol": "tcp", "count": 3, "window_sec": 10}, open(os.path.join(g.LEGACY_CUSTOM_DIR, "old_rule.json"), "w"))
json.dump({"icmp_flood": False}, open(g._data_path("rule_overrides.json"), "w"))
g.migrate_legacy(); g.reload_rules(force=True)
check("예전 custom_rules/·rule_overrides.json 이전", "old_rule" in g.rules_all and g.rules_all["icmp_flood"]["enabled"] is False
      and not os.path.exists(g._data_path("rule_overrides.json")))

# 17) 패킷 보기 (링 버퍼): 지나가는 패킷 요약 기록·조회·한도
def make_echo(src, dst, typ, pid, seq):
    return FakePkt({g.IP: ip(src, dst), g.ICMP: Fields(type=typ, id=pid, seq=seq)}, length=98)


def make_tcp_full(src, dst, sport, dport, flags):
    return FakePkt({g.IP: ip(src, dst), g.TCP: Fields(sport=sport, dport=dport, flags=flags)}, length=60)


def pv_reset(max_per_sec=1000):
    g.packets.clear()
    g._pv_budget.update(sec=0, used=0)
    g.PV["enabled"], g.PV["max_per_sec"] = True, max_per_sec


pv_reset()
g._handle(make_echo("192.168.56.60", g.MY_IP, 8, 0x1a2b, 1))          # 들어오는 ping 요청
g._handle(make_echo(g.MY_IP, "192.168.56.60", 0, 0x1a2b, 1))          # 서버가 보내는 ping 응답
g._handle(make_tcp_full("192.168.56.61", g.MY_IP, 41000, 22, 0x12))   # SYN+ACK
g._handle(make_tcp_full("192.168.56.61", g.MY_IP, 41001, 8080, 0x02)) # 관리 통신
g._handle(make_arp("192.168.56.62", "33:33:33:33:33:33"))
rows, last = g.query_packets()
check("패킷 보기: ping 요청과 응답이 방향(들어옴/나감)과 함께 둘 다 기록",
      [(r["proto"], r["dir"]) for r in rows[:2]] == [("ICMP", "in"), ("ICMP", "out")]
      and "Echo request" in rows[0]["info"] and "Echo reply" in rows[1]["info"] and "seq=1" in rows[0]["info"])
check("패킷 보기: TCP 플래그·포트와 ARP 기록", rows[2]["info"] == "41000 → 22 [SYN,ACK]" and rows[4]["proto"] == "ARP"
      and [r["seq"] for r in rows] == sorted(r["seq"] for r in rows) and last == rows[-1]["seq"])
check("패킷 보기: 프로토콜·IP 앞부분·숨길 포트·since 조건으로 걸러냄",
      [r["proto"] for r in g.query_packets(proto="ICMP")[0]] == ["ICMP", "ICMP"]
      and len(g.query_packets(ip="192.168.56.61")[0]) == 2
      and len(g.query_packets(hide_ports={8080})[0]) == 4
      and g.query_packets(since=last)[0] == []
      and len(g.query_packets(limit=2)[0]) == 2)
pv_reset(max_per_sec=5)
for _ in range(20):
    g._handle(make_echo("192.168.56.63", g.MY_IP, 8, 1, 1))
check("패킷 보기: 초당 기록 한도를 넘으면 보관 생략", len(g.packets) <= 10 and g.stats["packets_unrecorded"] >= 10)
pv_reset()
g.PV["enabled"] = False
g._handle(make_echo("192.168.56.64", g.MY_IP, 8, 1, 1))
check("패킷 보기: 끄면 기록 안 함", len(g.packets) == 0)
g.PV["enabled"] = True

# 18) 침입 상세 분석 ('정보' 버튼): 근거 저장 · 대응 결과 판단 · 권고
pv_reset()
for port in range(3000, 3025):
    g._handle(make_tcp_syn("192.168.56.90", port))
ev = next(e for e in reversed(g.events) if e["type"] == "port_scan" and e["source"] == "192.168.56.90")
an = g.analyze_event(ev)
check("침입 분석: 이벤트에 근거 숫자(meta) 저장, 5개 항목으로 풀어 씀",
      ev["meta"]["count"] >= ev["meta"]["threshold"] and ev["meta"]["ports"][0] == 3000
      and len(an["sections"]) == 5 and any("내부망" in l for l in an["sections"][0]["lines"]))
check("침입 분석: dry-run 이고 지금도 패킷이 오면 '막지 못함 + IP 차단 추천'",
      an["headline"]["level"] == "bad" and "IP 차단을 추천" in an["headline"]["text"]
      and an["actions"] == {"can_block": True, "target": "192.168.56.90"} and an["recent_packets"] >= 25)
g.DRY_RUN = False
g.block("192.168.56.91", "syn_flood")
ev2 = {"id": "t1", "timestamp": g.now_iso(), "type": "syn_flood", "severity": "critical", "source": "192.168.56.91",
       "target": g.MY_IP, "detail": "5초 동안 SYN 1000개", "action": "block",
       "meta": {"count": 1000, "threshold": 200, "window_sec": 5}}
an2 = g.analyze_event(ev2)
check("침입 분석: 실제 차단 중이면 '성공적으로 막아냄', 부담은 기준 5배라 높음, 차단 버튼 없음",
      an2["headline"]["level"] == "good" and "성공적으로" in an2["headline"]["text"] and an2["burden"] == "높음"
      and an2["actions"]["can_block"] is False)
g.unblock("192.168.56.91")
an3 = g.analyze_event(ev2)
check("침입 분석: 차단이 풀리면 '막고 있지 않음'으로 바뀜",
      an3["headline"]["level"] in ("warn", "bad") and any("풀렸" in l or "해제" in l for l in an3["sections"][3]["lines"]))
g.DRY_RUN = True
check("침입 분석: 관리 작업(차단 해제)은 공격 분석 대상이 아님",
      g.analyze_event({"id": "t2", "timestamp": g.now_iso(), "type": "unblock", "severity": "info", "source": "1.2.3.4",
                       "target": g.MY_IP, "detail": "x", "action": "unblock"})["headline"]["level"] == "info")
g._handle(make_arp("192.168.56.92", "44:44:44:44:44:44"))
g._handle(make_arp("192.168.56.92", "55:55:55:55:55:55"))
ev4 = next(e for e in reversed(g.events) if e["type"] == "arp_spoof" and e["source"] == "55:55:55:55:55:55")
an4 = g.analyze_event(ev4)
check("침입 분석: ARP 스푸핑은 MAC 로 설명하고 MAC 차단 대상 제시",
      an4["actions"]["target"] == "mac:55:55:55:55:55:55" and any("원래 MAC" in r[0] for r in an4["evidence"]))
old = {"id": "t3", "timestamp": g.now_iso(), "type": "telnet_probe", "severity": "warning", "source": "192.168.56.93",
       "target": g.MY_IP, "detail": "예전 이벤트(meta 없음)", "action": "alert"}
check("침입 분석: meta 없는 예전 이벤트·사용자 규칙도 오류 없이 분석",
      "텔넷" in g.analyze_event(old)["name"] and bool(g.analyze_event(dict(old, type="no_such_rule"))["headline"]["text"]))

# 19) 승인 우회 차단: 스크립트 경로 검사, API 로 스크립트 규칙을 만들거나 명령을 바꿀 수 없음
script_base = {"id": "t_sc", "detector": "script", "interval_sec": 5}
check("스크립트 경로 검사: rules/ 밖을 가리키는 값 거부",
      all(rejects({**script_base, "command": [c]}) for c in (".//bin/sh", "/bin/sh", "./../x", "./a/b", "./", "bash"))
      and g.validate_rule({**script_base, "command": ["./check.py", "20"]})["command"] == ["./check.py", "20"])
try:
    g._script_command({"command": [".//bin/sh"]}); run_guard = False
except ValueError:
    run_guard = True
check("스크립트 경로 검사: 실행 직전에도 한 번 더 막음", run_guard)
tmp = g.RULES_DIR                                     # 16번 시험에서 폴더가 바뀌었음
put("t_sc", {**script_base, "command": ["./check.py"]})
g.reload_rules()
try:
    g.update_rule("t_sc", {"command": [".//bin/sh"], "interval_sec": 5}); changed_cmd = True
except ValueError:
    changed_cmd = False
res = g.update_rule("t_sc", {"name": "새 이름", "interval_sec": 5})
check("플러그인 방식 규칙: 명령은 못 바꾸고 이름 등은 수정 가능",
      not changed_cmd and res["changed"] and g.rules_all["t_sc"]["command"] == ["./check.py"] and g.rules_all["t_sc"]["name"] == "새 이름")

# 플러그인 방식 규칙을 지우면 딸린 스크립트 파일도 함께 지워져 고아 파일이 남지 않는다
with open(os.path.join(tmp, "del_chk.py"), "w", encoding="utf-8") as f:
    f.write("#!/usr/bin/env python3\n")
put("t_scdel", {"id": "t_scdel", "detector": "script", "command": ["./del_chk.py"], "interval_sec": 5})
g.reload_rules()
g.delete_rule("t_scdel")
check("플러그인 방식 규칙 삭제: 딸린 스크립트 파일도 함께 삭제 (고아 파일 방지)",
      "t_scdel" not in g.rules_all and not os.path.exists(os.path.join(tmp, "del_chk.py")))

# 두 규칙이 같은 스크립트를 쓰면, 하나를 지워도 그 스크립트는 남겨 두고 마지막까지 지워야 치운다
with open(os.path.join(tmp, "shared_chk.py"), "w", encoding="utf-8") as f:
    f.write("#!/usr/bin/env python3\n")
put("t_sh1", {"id": "t_sh1", "detector": "script", "command": ["./shared_chk.py"], "interval_sec": 5})
put("t_sh2", {"id": "t_sh2", "detector": "script", "command": ["./shared_chk.py"], "interval_sec": 5})
g.reload_rules()
g.delete_rule("t_sh1")
check("플러그인 방식 규칙 삭제: 다른 규칙이 같은 스크립트를 쓰면 파일을 남긴다",
      "t_sh1" not in g.rules_all and "t_sh2" in g.rules_all and os.path.exists(os.path.join(tmp, "shared_chk.py")))
g.delete_rule("t_sh2")
check("공유 스크립트: 마지막 규칙까지 지우면 스크립트 파일도 삭제",
      "t_sh2" not in g.rules_all and not os.path.exists(os.path.join(tmp, "shared_chk.py")))

import threading, urllib.error, urllib.request
srv = g.ThreadingHTTPServer(("127.0.0.1", 0), g.API)
threading.Thread(target=srv.serve_forever, daemon=True).start()
def call(path, body=None, headers=None):
    hdr = {"Content-Type": "application/json"} if body is not None else {}
    hdr.update(headers or {})
    req = urllib.request.Request(f"http://127.0.0.1:{srv.server_port}{path}", headers=hdr,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read()), r.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), e.headers
new_rule = {"id": "t_api", "protocol": "tcp", "count": 3, "window_sec": 5}
check("API: 스크립트 규칙 만들기 거부, 파일도 안 생김",
      call("/api/rules", {"rule": {"id": "t_evil", "detector": "script", "command": ["./x"], "interval_sec": 5}})[0] == 403
      and "t_evil" not in g.rules_all)
check("API: 일반 규칙은 추가되고 같은 ID 는 덮어쓰지 않음",
      call("/api/rules", {"rule": new_rule})[0] == 200 and call("/api/rules", {"rule": {**new_rule, "count": 9}})[0] == 409
      and g.rules_all["t_api"]["count"] == 3)
status = call("/api/status")
check("API: CORS 를 허용하지 않고 웹페이지 요청(Origin)·다른 Host·JSON 이 아닌 POST 를 거부",
      status[0] == 200 and "Access-Control-Allow-Origin" not in status[2]
      and call("/api/status", headers={"Origin": "http://evil.example"})[0] == 403
      and call("/api/status", headers={"Host": "evil.example:8000"})[0] == 403
      and call("/api/dry_run", {"dry_run": False}, {"Content-Type": "text/plain"})[0] == 415 and g.DRY_RUN is True)
check("API: 상태에 화이트리스트·시간대, 규칙에 탐지 횟수 제공",
      g.MY_IP in status[1]["whitelist"] and status[1]["utc_offset"][0] in "+-" and "port_scan" in call("/api/rules")[1]["hits"])
srv.shutdown()
g.delete_rule("t_api"); g.delete_rule("t_sc")

# 20) 탐지 구멍: 두 번째 IP 로 오는 공격, NULL·FIN·Xmas·UDP 스캔
g.MY_IPS = {g.MY_IP, "192.168.57.10"}
def to_second_ip():
    for port in range(5000, 5025):
        g._handle(FakePkt({g.IP: ip("192.168.56.100", "192.168.57.10"), g.TCP: tcp(port, 0x02)}))
results.append(run("서버의 다른 IP(관리망 주소)로 오는 포트 스캔", "port_scan", to_second_ip))
for name, src, flags in (("NULL", "192.168.56.101", 0x00), ("FIN", "192.168.56.102", 0x01), ("Xmas", "192.168.56.103", 0x29)):
    results.append(run(f"{name} 스캔", "port_scan", lambda s=src, f=flags: [g._handle(FakePkt({g.IP: ip(s), g.TCP: tcp(p, f)})) for p in range(6000, 6025)]))
results.append(run_not("정상 통신(ACK·RST 패킷)은 스캔으로 안 셈", "port_scan",
                       lambda: [g._handle(FakePkt({g.IP: ip("192.168.56.104"), g.TCP: tcp(p, f)})) for p in range(7000, 7040) for f in (0x10, 0x04, 0x11)]))
g.UDP = type("UDP", (), {})
results.append(run("UDP 스캔", "port_scan", lambda: [g._handle(FakePkt({g.IP: ip("192.168.56.105"), g.UDP: Fields(sport=40000, dport=p)})) for p in range(8000, 8025)]))
results.append(run_not("서비스 응답(DNS 등)은 UDP 스캔으로 안 셈", "port_scan", lambda: [g._handle(FakePkt({g.IP: ip("192.168.56.106"), g.UDP: Fields(sport=53, dport=p)})) for p in range(8000, 8025)]))
g.UDP = None

# 21) 슬라이딩 윈도우: 기간이 지나면 빠지고, 개수·서로 다른 값·합계가 맞음
w = g.Window()
w.add(100, 5, 10); w.add(101, 5, 10); w.add(105, 7, 10)
ok1 = len(w) == 3 and len(w.counts) == 2 and w.total == 17
w.add(112, 9, 10)                                     # 100, 101 은 기간 밖
check("슬라이딩 윈도우: 개수·서로 다른 값·합계", ok1 and len(w) == 2 and set(w.counts) == {7, 9} and w.total == 16)

# 22) 숫자: 관리 작업은 위협이 아니고, 자동 차단은 실제·모의를 나눠 세고, 재시작해도 남음
for port in range(9000, 9025):
    g._handle(make_tcp_syn("192.168.56.110", port))
before_ev, before_sim = g.stats["events_total"], g.stats["blocks_auto_sim"]
g.unblock("192.168.56.110")
g.block("192.168.56.111", "manual"); g.emit("manual_block", "192.168.56.111", "info", "수동", "block(dry-run)", cooldown=False); g.unblock("192.168.56.111")
check("숫자: 차단 해제·수동 차단은 위협으로 안 셈", g.stats["events_total"] == before_ev and "192.168.56.111" not in g.attackers and before_sim >= 1)
total_ev, total_sim, hit_before = g.stats["events_total"], g.stats["blocks_auto_sim"], g.rule_hits["port_scan"]["count"]
kept_ids = {e["id"] for e in g.events}
g.events.clear(); g.stats.clear(); g.attackers.clear(); g.rule_hits.clear()
g.load_persisted()
check("재시작 뒤 복원: 탐지 로그·누적 숫자·규칙별 횟수", kept_ids <= {e["id"] for e in g.events} or len(g.events) == g.events.maxlen)
check("재시작 뒤 복원: 숫자가 파일 기록과 같음",
      g.stats["events_total"] >= total_ev and g.stats["blocks_auto_sim"] >= total_sim and g.rule_hits["port_scan"]["count"] >= hit_before)

# 23) SSH 로그인 성공: 실패가 쌓인 뒤 성공하면 탐지, 평범한 로그인은 조용
fail_line = "Failed password for {}kali from {} port 40000 ssh2\n"
ok_line = "Accepted {} for kali from {} port 40001 ssh2\n"
results.append(run_not("실패 없는 키 로그인(관리자)은 알리지 않음", "ssh_login_success",
                       lambda: g.process_auth_line(ok_line.format("publickey", "192.168.57.1"), time.time())))
results.append(run_not("실패가 기준보다 적으면 알리지 않음", "ssh_login_success",
                       lambda: [g.process_auth_line(fail_line.format("", "192.168.56.120"), time.time()) for _ in range(2)]
                       + [g.process_auth_line(ok_line.format("password", "192.168.56.120"), time.time())]))
def t_login():
    for i in range(6):
        g.process_auth_line(fail_line.format("invalid user " if i % 2 else "", "192.168.56.121"), time.time())
    g.process_auth_line(ok_line.format("password", "192.168.56.121"), time.time())
results.append(run("로그인 실패 6회 뒤 성공", "ssh_login_success", t_login))
ev5 = next(e for e in reversed(g.events) if e["type"] == "ssh_login_success")
check("SSH 로그인 성공: 최고 위험도, 근거에 계정·횟수, 분석 창 지원",
      ev5["severity"] == "critical" and ev5["meta"]["user"] == "kali" and ev5["meta"]["failures"] == 6
      and g.analyze_event(ev5)["name"].startswith("SSH 로그인 성공") and "192.168.56.121" in g.blocked)
results.append(run("패킷으로 무차별 대입이 탐지된 IP 의 성공도 탐지", "ssh_login_success",
                   lambda: [g._handle(make_tcp_syn("192.168.56.122", 22)) for _ in range(12)]
                   + [g.process_auth_line(ok_line.format("password", "192.168.56.122"), time.time())]))

# 24) 스크립트 실행 (리눅스에서만): 판정 반영, 시간 제한이 자식까지 끝냄, 겹쳐 돌지 않음
if os.name == "posix":
    def script(name, body):
        path = os.path.join(g.RULES_DIR, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n" + body + "\n")
        os.chmod(path, 0o755)
        return {"id": name.replace(".", "_"), "name": name, "command": ["./" + name], "timeout_sec": 2, "severity": "warning", "block": False}
    r_ok = script("t_ok.sh", """echo 'not json'; echo '{"source": "192.168.56.130", "detail": "판정"}'; echo '{"source": "0.0.0.0/0"}'""")
    g._script_running.add(r_ok["id"])
    g.run_script_rule(r_ok)
    check("스크립트 실행: 판정 한 줄만 반영하고 끝나면 실행 중 표시가 풀림",
          any(e["type"] == r_ok["id"] and e["source"] == "192.168.56.130" for e in g.events) and r_ok["id"] not in g._script_running)
    marker = "4242.5"
    r_slow = script("t_slow.sh", f"sleep {marker} & wait")
    t0 = time.time()
    g.run_script_rule(r_slow)
    time.sleep(0.2)
    alive = os.popen(f"pgrep -f '[s]leep {marker}' | wc -l").read().strip()
    check("스크립트 실행: 시간 제한이 되면 자식 프로세스까지 끝냄", time.time() - t0 < 4 and alive == "0")
    r_big = script("t_big.sh", "while :; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done")
    g.run_script_rule(r_big)
    check("스크립트 실행: 끝없이 출력해도 WARDEN 이 멈추지 않음", True)
    os.symlink("/bin/echo", os.path.join(g.RULES_DIR, "t_link"))
    try:
        g._script_command({"command": ["./t_link"]}); link_ok = False
    except ValueError:
        link_ok = True
    check("스크립트 실행: rules/ 밖을 가리키는 심볼릭 링크 거부", link_ok)

# 26) 규칙별 알림 설정(notify): 검사, 알림 설정만 바꾸면 켜진 채 유지, 안 보내면 그대로
nbase = {"id": "t_nt", "protocol": "tcp", "dst_ports": [29], "tcp_flags": "syn", "count": 3, "window_sec": 30}
check("알림 설정 검사: 올바른 값은 저장, 이상한 값은 거부, 파일에서는 건너뜀",
      g.validate_rule({**nbase, "notify": {"sound": False}})["notify"] == {"sound": False}
      and "notify" not in g.validate_rule({**nbase, "notify": {}})
      and rejects({**nbase, "notify": {"popup": "yes"}}) and rejects({**nbase, "notify": {"email": True}}) and rejects({**nbase, "notify": True})
      and "notify" not in g.validate_rule({**nbase, "notify": {"popup": "yes"}}, "t_nt"))
put("t_nt", nbase)
g.reload_rules()
live_nt = {k: v for k, v in g.rules_all["t_nt"].items() if k not in ("id", "detector", "enabled")}
r1 = g.update_rule("t_nt", {**live_nt, "notify": {"popup": False, "sound": True}})
check("알림 설정만 바꾸면 규칙은 켜진 채 유지되고 파일에 저장",
      r1 == {"changed": True, "was_enabled": True, "kept_enabled": True} and g.rules_all["t_nt"]["enabled"]
      and json.load(open(os.path.join(g.RULES_DIR, "t_nt.json"), encoding="utf-8"))["notify"] == {"popup": False, "sound": True})
r2 = g.update_rule("t_nt", {**live_nt, "count": 7})
check("알림 설정을 안 보낸 수정은 지정값을 지우지 않고, 조건을 바꾸면 꺼짐",
      r2["changed"] and not r2.get("kept_enabled") and g.rules_all["t_nt"]["notify"] == {"popup": False, "sound": True}
      and g.rules_all["t_nt"]["enabled"] is False)
r3 = g.update_rule("t_nt", {**live_nt, "count": 7, "notify": {}})
check("알림 설정을 비우면 기본값으로 돌아감", r3.get("kept_enabled") and "notify" not in g.rules_all["t_nt"])
g.delete_rule("t_nt")

# 25) 화이트리스트: 화면에서 추가·삭제, 서버 자신은 못 뺌, 저장되고 config.json 의 값과 합쳐짐
wl_file = g._data_path("whitelist_extra.json")
if os.path.exists(wl_file):
    os.remove(wl_file)
g.MY_IP, g.MY_IPS = "192.168.56.10", {"192.168.56.10", "192.168.57.10"}
g.apply_whitelist()
base_wl = set(g.WHITELIST)
check("화이트리스트: 시작 값 = config.json + 서버 자신의 모든 주소", {"192.168.57.1", "192.168.57.10", "127.0.0.1"} <= base_wl and "192.168.57.1" in g.CFG["whitelist"])
g.block("192.168.56.140", "port_scan", duration=60)
ok, why, freed = g.set_whitelist("add", "192.168.56.140")
check("화이트리스트 추가: 적용·저장되고, 차단 중이던 주소는 차단이 풀림",
      ok and freed and "192.168.56.140" in g.WHITELIST and "192.168.56.140" not in g.blocked
      and "192.168.56.140" in g._load_json("whitelist_extra.json", {})["add"])
check("화이트리스트 주소는 차단되지 않음", g.block("192.168.56.140", "port_scan") is False and "192.168.56.140" not in g.blocked)
check("화이트리스트: 이미 있는 것 추가·없는 것 삭제 거부", g.set_whitelist("add", "192.168.56.140")[0] is False and g.set_whitelist("remove", "9.9.9.9")[0] is False)
check("화이트리스트: 서버 자신의 주소·127.0.0.1 은 못 뺌",
      all(g.set_whitelist("remove", x)[0] is False for x in ("192.168.56.10", "192.168.57.10", "127.0.0.1")) and "192.168.57.10" in g.WHITELIST)
ok2, _, _ = g.set_whitelist("remove", "192.168.57.1")                    # config.json 에 있던 관리 PC
check("화이트리스트: config.json 에 있던 주소도 화면에서 뺄 수 있고 다시 시작해도 유지됨",
      ok2 and "192.168.57.1" not in g.WHITELIST and (g.apply_whitelist() or "192.168.57.1" not in g.WHITELIST))
g.set_whitelist("remove", "192.168.56.140"); g.set_whitelist("add", "192.168.57.1")
check("화이트리스트: 추가했다 뺀 주소는 원래대로", "192.168.56.140" not in g.WHITELIST and "192.168.57.1" in g.WHITELIST)
check("화이트리스트 변경은 규칙 변경 기록에 남음", any(c["rule"] == "whitelist" and "192.168.56.140" in c["detail"] for c in g.rule_changes))
srv2 = g.ThreadingHTTPServer(("127.0.0.1", 0), g.API)
threading.Thread(target=srv2.serve_forever, daemon=True).start()
def call2(path, body):
    req = urllib.request.Request(f"http://127.0.0.1:{srv2.server_port}{path}", headers={"Content-Type": "application/json"}, data=json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
check("API: 화이트리스트 추가·삭제, 잘못된 값 거부",
      call2("/api/whitelist", {"action": "add", "target": "192.168.56.141"})[1]["ok"] is True
      and call2("/api/whitelist", {"action": "add", "target": "10.0.0.0/8"})[0] == 400
      and call2("/api/whitelist", {"action": "drop", "target": "192.168.56.141"})[0] == 400
      and call2("/api/whitelist", {"action": "remove", "target": "127.0.0.1"})[1]["ok"] is False
      and call2("/api/whitelist", {"action": "remove", "target": "192.168.56.141"})[1]["ok"] is True)
srv2.shutdown()
os.remove(wl_file)
g.WHITELIST = {g.MY_IP, g.MY_MAC, "127.0.0.1"}

# 27) PCAP 내보내기: 헤더까지만 저장, Wireshark 형식, 이벤트 관련 패킷만 고르기, API
import socket, struct


class RawPkt(FakePkt):
    """sniff 로 받은 진짜 패킷처럼 원래 바이트(original)를 가진 가짜 패킷"""
    def __init__(self, layers, raw):
        super().__init__(layers, length=len(raw))
        self.original = raw


def eth(etype, src_mac=b"\x02\x00\x00\x00\x00\x14"):
    return b"\xaa\xbb\xcc\xdd\xee\xff" + src_mac + etype


def ipv4(src, dst, proto, rest):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(rest), 0, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + rest


def raw_syn(src, dport, payload=b"SECRET-PASSWORD"):
    tcp_hdr = struct.pack("!HHIIBBHHH", 40000, dport, 0, 0, 5 << 4, 0x02, 64240, 0, 0)
    raw = eth(b"\x08\x00") + ipv4(src, g.MY_IP, 6, tcp_hdr + payload)
    return RawPkt({g.IP: ip(src), g.TCP: Fields(sport=40000, dport=dport, flags=0x02)}, raw)


def raw_ping(src, payload=b"PING-DATA-0123456789"):
    raw = eth(b"\x08\x00") + ipv4(src, g.MY_IP, 1, struct.pack("!BBHHH", 8, 0, 0, 7, 1) + payload)
    return RawPkt({g.IP: ip(src), g.ICMP: Fields(type=8, id=7, seq=1)}, raw)


def raw_arp(psrc, hwsrc):
    raw = eth(b"\x08\x06") + bytes(28) + bytes(18)          # ARP 28바이트 + 이더넷 최소 길이 패딩
    return RawPkt({g.ARP: Fields(psrc=psrc, pdst=g.MY_IP, op=2, hwsrc=hwsrc)}, raw)


def read_pcap(data):
    magic, major, minor, _, _, snap, link = struct.unpack("<IHHiIII", data[:24])
    recs, i = [], 24
    while i < len(data):
        sec, usec, incl, orig = struct.unpack("<IIII", data[i:i + 16])
        recs.append((sec + usec / 1e6, incl, orig, data[i + 16:i + 16 + incl]))
        i += 16 + incl
    return (magic, major, minor, link), recs


pv_reset()
for port in range(9100, 9125):
    g._handle(raw_syn("192.168.56.150", port))
g._handle(raw_ping("192.168.56.151"))
g._handle(raw_arp("192.168.56.152", "66:66:66:66:66:66"))
g._handle(make_echo("192.168.56.153", g.MY_IP, 8, 1, 1))          # 원래 바이트가 없는 패킷
rows_all, _ = g.query_packets(limit=1000)
check("PCAP: 헤더만 잘라 보관 (TCP 54·ICMP 42·ARP 42바이트), 내용(payload)은 없음, API 응답에는 안 나감",
      all("_raw" not in r for r in rows_all)
      and {len(p["_raw"]) for p in g.packets if p["src"] == "192.168.56.150"} == {54}
      and all(b"SECRET" not in p.get("_raw", b"") and b"PING-DATA" not in p.get("_raw", b"") for p in g.packets)
      and [len(p["_raw"]) for p in g.packets if p["src"] in ("192.168.56.151", "192.168.56.152")] == [42, 42]
      and not any("_raw" in p for p in g.packets if p["src"] == "192.168.56.153"))
rows, _ = g.pcap_for(ip="192.168.56.150")
hdr, recs = read_pcap(g.build_pcap(rows))
check("PCAP: Wireshark 형식(매직·이더넷), 시각·저장 길이·원래 길이가 맞음",
      hdr == (0xA1B2C3D4, 2, 4, g.PCAP_LINKTYPE_ETHERNET) and len(recs) == 25
      and all(incl == 54 and orig == 54 + len(b"SECRET-PASSWORD") for _, incl, orig, _ in recs)
      and abs(recs[0][0] - rows[0]["time"]) < 0.001 and recs[3][3][36:38] == struct.pack("!H", 9103))
ev = next(e for e in reversed(g.events) if e["type"] == "port_scan" and e["source"] == "192.168.56.150")
next(p for p in g.packets if p["src"] == "192.168.56.150")["time"] -= 3600       # 탐지 구간보다 한참 전 패킷
ev_rows, info = g.pcap_for(event_id=ev["id"])
arp_ev = {"id": "pcaparp", "timestamp": g.now_iso(), "type": "arp_spoof", "severity": "critical",
          "source": "66:66:66:66:66:66", "target": g.MY_IP, "detail": "x", "action": "alert", "meta": {}}
g.events.append(arp_ev)
try:
    g.pcap_for(event_id="no-such-event"); missing = False
except LookupError:
    missing = True
check("PCAP: 이벤트를 고르면 그 출발지·탐지 구간만, ARP 이벤트는 ARP 만, 없는 이벤트는 거부",
      len(ev_rows) == 24 and {r["src"] for r in ev_rows} == {"192.168.56.150"} and info["ip"] == "192.168.56.150"
      and [r["proto"] for r in g.pcap_for(event_id="pcaparp")[0]] == ["ARP"] and missing)
srv3 = g.ThreadingHTTPServer(("127.0.0.1", 0), g.API)
threading.Thread(target=srv3.serve_forever, daemon=True).start()
def get3(path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{srv3.server_port}{path}", timeout=5) as r:
            return r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers
ok_res = get3("/api/pcap?ip=192.168.56.15&proto=TCP")
pk_res = get3("/api/packets?limit=1000")
check("API: /api/pcap 은 파일로, 조건에 없으면 404, 잘못된 값은 400, /api/packets 는 여전히 JSON",
      ok_res[0] == 200 and ok_res[2]["Content-Type"] == "application/vnd.tcpdump.pcap" and ok_res[2]["X-Packet-Count"] == "25"
      and len(read_pcap(ok_res[1])[1]) == 25
      and get3("/api/pcap?ip=10.9.9.9")[0] == 404 and get3("/api/pcap?event=x%2F..")[0] == 400
      and get3("/api/pcap?proto=HTTP")[0] == 400 and get3(f"/api/pcap?event={ev['id']}")[0] == 200
      and pk_res[0] == 200 and "_raw" not in pk_res[1].decode())
srv3.shutdown()
g.events.remove(arp_ev)

# 28) 누적 차단: 기준 시간 안에 다시 자동 차단되면 5분 -> 30분 -> 2시간, 수동·영구·화이트리스트는 세지 않음
g.REPEAT = {"enabled": True, "window_sec": 86400, "steps_sec": [300, 1800, 7200]}
g.repeat_hist.clear()
RB = "192.168.56.170"


def auto_span(target, duration=None, permanent=False):
    g.block_auto(target, "port_scan", duration, permanent)
    b = g.blocked.get(target)
    span = None if b is None else (None if b["until"] is None else round((b["until"] - b["since"]) / 60))
    lvl = b and b.get("repeat")
    g.unblock(target)
    return span, lvl


spans = [auto_span(RB) for _ in range(4)]
check("누적 차단: 같은 IP 가 다시 걸리면 5분 -> 30분 -> 2시간 -> 2시간(마지막 단계 유지), 차단 목록에 반복 횟수",
      spans == [(5, 1), (30, 2), (120, 3), (120, 4)])
check("누적 차단: 규칙에 적힌 시간이 더 길면 그 값 (1단계라도 10시간)", auto_span("192.168.56.171", 36000) == (600, 1))
g.repeat_hist["192.168.56.172"] = [time.time() - 90000, time.time() - 88000]
check("누적 차단: 기준 시간(24시간)이 지난 기록은 세지 않고 1단계부터", auto_span("192.168.56.172") == (5, 1))
g.WHITELIST.add("192.168.56.173")
g.block_auto("192.168.56.173", "port_scan")
g.WHITELIST.discard("192.168.56.173")
g.block("192.168.56.174", "manual"); g.unblock("192.168.56.174")
perm = auto_span("192.168.56.175", permanent=True)
check("누적 차단: 화이트리스트·수동 차단·영구 차단 규칙은 횟수에 안 들어감",
      "192.168.56.173" not in g.repeat_hist and "192.168.56.174" not in g.repeat_hist
      and "192.168.56.175" not in g.repeat_hist and perm == (None, None))
saved = g._load_json("repeat_blocks.json", {})
g.repeat_hist.clear(); g.load_repeat()
check("누적 차단: 기록이 logs/repeat_blocks.json 에 남아 재시작 뒤에도 이어짐",
      len(saved.get(RB, [])) == 4 and len(g.repeat_hist.get(RB, [])) == 4 and auto_span(RB)[0] == 120)
g.REPEAT["enabled"] = False
off = auto_span("192.168.56.176"), auto_span("192.168.56.176")
g.REPEAT["enabled"] = True
_old_cfg = g.CFG.get("repeat_block")
g.CFG["repeat_block"] = {"enabled": "yes", "window_sec": -5, "steps_sec": [300, "x"]}
bad = g._repeat_config()
g.CFG["repeat_block"] = {"window_sec": 3600, "steps_sec": [60, 120]}
good = g._repeat_config()
g.CFG.pop("repeat_block") if _old_cfg is None else g.CFG.__setitem__("repeat_block", _old_cfg)
check("누적 차단: 끄면 매번 기본 시간, 설정값이 잘못되면 기본값을 씀",
      off == ((5, None), (5, None)) and bad == {"enabled": True, "window_sec": 86400, "steps_sec": [300, 1800, 7200]}
      and good == {"enabled": True, "window_sec": 3600, "steps_sec": [60, 120]})
g.repeat_hist.clear()

# ── 결과 요약 ──────────────────────────────────────────────────
print("-" * 64)
passed = sum(results)
print(f" 결과: {passed}/{len(results)} 통과")
print(f" 총 이벤트 {len(g.events)}건 기록됨  (로그: {g.LOG_FILE})")
print("=" * 64)
sys.exit(0 if passed == len(results) else 1)
