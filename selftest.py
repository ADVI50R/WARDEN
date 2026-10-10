#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest.py - 실제 패킷/VM 없이 Guardian 의 탐지 로직만 시험합니다.

가짜 패킷 객체를 만들어 guardian._handle() 에 직접 넣고,
기대한 이벤트가 발생하는지 확인합니다.
scapy, Npcap, 관리자 권한 모두 필요 없습니다.

실행:  python selftest.py
"""
import sys
import time

# ── guardian 을 '라이브러리처럼' 불러오기 위한 최소한의 가짜 scapy ──
# guardian.py 는 맨 위에서 scapy 를 import 하므로, 진짜가 없으면 가짜를 넣어준다.
import types

try:
    import scapy.all  # noqa: F401  (있으면 그대로 사용)
except ImportError:
    fake = types.ModuleType("scapy.all")
    # guardian 이 쓰는 이름들만 최소로 채운다
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

import guardian as g  # noqa: E402

# 테스트 중엔 실제 방화벽/네트워크를 건드리지 않는다
g.DRY_RUN = True
g.MY_IP = "192.168.56.10"
g.MY_MAC = "aa:bb:cc:dd:ee:ff"
g.WHITELIST = {g.MY_IP, g.MY_MAC, "127.0.0.1"}
# 쿨다운(30초)은 실제와 같게 둔다 -> 항목마다 IP 가 달라 첫 알림은 항상 뜨고, 화면도 덜 복잡함
g.LOG_FILE = "logs/selftest.jsonl"
import os
os.makedirs("logs", exist_ok=True)
open(g.LOG_FILE, "w").close()          # 로그 초기화


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
print(" Guardian 자체 테스트 (가짜 패킷)")
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

# ── 결과 요약 ──────────────────────────────────────────────────
print("-" * 64)
passed = sum(results)
print(f" 결과: {passed}/{len(results)} 통과")
print(f" 총 이벤트 {len(g.events)}건 기록됨  (로그: {g.LOG_FILE})")
print("=" * 64)
sys.exit(0 if passed == len(results) else 1)
