#!/usr/bin/env python3
"""
Guardian 설치 도구 — 한 번 실행하면 보안 서버에 Guardian 과 대시보드를 구성합니다.

  sudo python3 setup.py            화면 모드: 진행 순서·필요한 프로그램·IP 구성을 확인하고 설정을 고른 뒤 설치
  sudo python3 setup.py --yes      화면 없이 자동으로 고른 기본값으로 바로 설치
  python3 setup.py --test-home DIR 연습 모드 (root 불필요): DIR 를 홈 폴더로 보고 설치. 패키지 설치·서비스 등록·실행은 건너뜀

지원 환경: 데비안 계열(칼리·데비안·우분투, apt) / 레드햇 계열(록키·RHEL·알마, dnf — python3-scapy 는 EPEL 저장소).
시작하면 배포판·파이썬 버전·WSL/가상 머신 여부·firewalld/UFW·SELinux 를 먼저 확인해 화면에 보여 줍니다.

설치하는 것
  1. 필요한 프로그램 확인 (없으면 apt/dnf 로 설치 — 인터넷이 필요하므로 먼저 화면에 목록을 보여 줌)
  2. 코드 복사 (rules/ · logs/ · 설치된 플러그인 · 대시보드 토큰은 덮어쓰지 않음)
  3. 설정 파일 (config.json: 감시 인터페이스·화이트리스트·dry-run / dashboard_config.json: 주소·포트·토큰)
  4. 파일 소유자·권한
  5. approve 단축 명령 (~/.zshrc, ~/.bashrc)
  6. (선택) systemd 자동 시작 서비스 — 기본은 끔
  7. 자가 시험 (임시 복사본에서 selftest.py)
  8. Guardian·대시보드 실행 (켜져 있으면 새 코드로 다시 시작)

방화벽(UFW)·sudoers 는 건드리지 않습니다. 화면에서 고르지 않은 항목은 기존 설정을 유지하고, 새로 설치할 때는 기본값을 씁니다.
"""
import argparse
import ipaddress
import json
import os
import pwd
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unicodedata

SRC = os.path.dirname(os.path.abspath(__file__))

# 필요한 프로그램: (확인할 명령 또는 파이썬 모듈, {배포판 계열: 패키지}, 설명)
DEPENDENCIES = [
    ("python3", {"debian": "python3", "rhel": "python3"}, "Guardian·대시보드 실행"),
    ("py:scapy", {"debian": "python3-scapy", "rhel": "python3-scapy"}, "패킷 감시"),
    ("iptables", {"debian": "iptables", "rhel": "iptables-nft"}, "방화벽 차단"),
    ("ss", {"debian": "iproute2", "rhel": "iproute"}, "연결·포트 확인"),
    ("ip", {"debian": "iproute2", "rhel": "iproute"}, "IP 구성 확인"),
    ("bwrap", {"debian": "bubblewrap", "rhel": "bubblewrap"}, "업로드된 플러그인 격리 시험(샌드박스)"),
    ("prlimit", {"debian": "util-linux", "rhel": "util-linux"}, "샌드박스 자원 제한"),
    ("runuser", {"debian": "util-linux", "rhel": "util-linux"}, "대시보드를 일반 계정으로 실행"),
    ("timeout", {"debian": "coreutils", "rhel": "coreutils"}, "스크립트 시간 제한"),
    ("journalctl", {"debian": "systemd", "rhel": "systemd"}, "SSH 로그인 기록 읽기"),
]
MIN_PYTHON = (3, 9)

# 배포판 계열: /etc/os-release 의 ID·ID_LIKE 로 판단
FAMILIES = {
    "debian": {"ids": {"debian", "ubuntu", "kali", "linuxmint", "raspbian"}, "label": "데비안 계열", "pm": "apt-get"},
    "rhel": {"ids": {"rhel", "rocky", "centos", "almalinux", "fedora", "ol"}, "label": "레드햇 계열", "pm": "dnf"},
}

# 덮어쓰지 않는 것 (사용 중에 생기는 데이터·비밀값)
NEVER_COPY = {"logs", "__pycache__", "plugins_pending", "audit.jsonl", ".git", "config.json", "setup_log.txt"}
NEVER_COPY_DASHBOARD = {"dashboard_config.json", "plugins_state.json", "__pycache__"}
MERGE_DIRS = {"rules", os.path.join("dashboard", "plugins")}     # 없는 파일만 추가 (있는 건 그대로)

# 개발·실습 준비용이라 서버 설치본에는 넣지 않는 것 (원본 폴더에는 그대로 남음)
DEV_ONLY = {
    "ROADMAP.md", "진행상황_및_계획.txt", "migration_guide.txt", "lab_setup_guide.txt",   # 프로젝트 관리·실습실 준비 문서
    "attack_auto.sh", "attack_test_guide.md",                                            # 공격자 VM 에서 쓰는 시험 도구
    "examples", "preview",                                                               # 예제 규칙, 서버 없이 보는 화면 미리보기
    os.path.join("dashboard", "example_upload"), os.path.join("dashboard", "guides"),    # 업로드 예제, 안내 PDF 의 원본 HTML
}

ALIAS_BEGIN = "# >>> guardian setup >>>"
ALIAS_END = "# <<< guardian setup <<<"


def alias_block(target):
    """셸 설정 파일에 넣을 단축 명령 (setup.py 가 넣고 uninstall.py 가 이 블록째 지움)"""
    ctl = f"python3 {target}/guardianctl.py"
    return (f"{ALIAS_BEGIN}\n"
            f"alias approve=\"python3 {target}/dashboard/approve_plugin.py\"   # 업로드된 플러그인 승인 화면\n"
            f"alias gstart=\"sudo {ctl} start\"       # Guardian·대시보드를 백그라운드로 켜기 (켜져 있으면 그대로)\n"
            f"alias gstop=\"sudo {ctl} stop\"         # 끄기\n"
            f"alias grestart=\"sudo {ctl} restart\"   # 새 코드로 다시 켜기\n"
            f"alias gstatus=\"{ctl} status\"          # 켜짐·꺼짐, 모드, 대시보드 주소\n"
            f"alias glog=\"sudo {ctl} log\"           # 최근 실행 기록 (glog dashboard 로 대시보드 기록)\n"
            f"alias gunblock=\"sudo {ctl} unblock-all\"   # 긴급 전체 해제 (목록 확인 후 yes 입력)\n"
            f"{ALIAS_END}\n")

UNIT_GUARDIAN = """[Unit]
Description=Guardian (packet monitoring and automatic blocking)
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory={target}
UMask=0077
ExecStart=/usr/bin/python3 {target}/guardian.py run
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

UNIT_DASHBOARD = """[Unit]
Description=Guardian web dashboard
After=guardian.service
Wants=guardian.service

[Service]
User={user}
WorkingDirectory={target}/dashboard
UMask=0077
ExecStart=/usr/bin/python3 {target}/dashboard/server.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


# ───────────────────────── 환경 살펴보기 ─────────────────────────

def run(cmd, timeout=20, **kw):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


def have(dep):
    if dep.startswith("py:"):
        code, _ = run([sys.executable, "-c", f"import {dep[3:]}"])
        return code == 0
    return shutil.which(dep) is not None


def interfaces():
    """[(이름, 'IP/접두어', 켜짐 여부)] — 루프백 제외"""
    out = []
    code, text = run(["ip", "-o", "-4", "addr", "show"])
    if code == 0:
        for line in text.splitlines():
            m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\S+)", line)
            if m and m.group(1) != "lo":
                out.append((m.group(1), m.group(2)))
    up = set()
    code, text = run(["ip", "-o", "link", "show", "up"])
    if code == 0:
        up = {m.group(1).split("@")[0] for m in re.finditer(r"^\d+:\s+([^:]+):", text, re.M)}
    return [(n, a, n in up) for n, a in out]


def listening_ports():
    code, text = run(["ss", "-Htln"])
    ports = set()
    for line in text.splitlines() if code == 0 else []:
        parts = line.split()
        if len(parts) >= 4 and ":" in parts[3]:
            try:
                ports.add(int(parts[3].rsplit(":", 1)[1]))
            except ValueError:
                pass
    return ports


def os_release():
    info = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                if k:
                    info[k] = v.strip().strip('"')
    except OSError:
        pass
    return info


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


class Platform:
    """설치 도구가 돌고 있는 환경: 배포판·패키지 관리자·방화벽·SELinux·WSL·가상화"""

    def __init__(self):
        osr = os_release()
        ids = {osr.get("ID", "").lower()} | set(osr.get("ID_LIKE", "").lower().split())
        self.name = osr.get("PRETTY_NAME") or osr.get("NAME") or "알 수 없는 리눅스"
        self.family = next((f for f, d in FAMILIES.items() if ids & d["ids"]), None)
        pm = FAMILIES[self.family]["pm"] if self.family else None
        if pm == "dnf" and not shutil.which("dnf") and shutil.which("yum"):
            pm = "yum"
        self.pm = pm if pm and shutil.which(pm) else None
        self.major = osr.get("VERSION_ID", "").split(".")[0]
        self.python = sys.version_info[:3]
        self.wsl = "microsoft" in read_text("/proc/version").lower()
        code, out = run(["systemd-detect-virt"]) if shutil.which("systemd-detect-virt") else (1, "")
        self.virt = out.strip() if code == 0 else ("none" if out.strip() == "none" else "")
        self.systemd = shutil.which("systemctl") is not None and os.path.isdir("/run/systemd/system")
        self.firewalld = self._active("firewalld")
        self.ufw = self._active("ufw") and "Status: active" in run(["ufw", "status"])[1] if shutil.which("ufw") else False
        self.selinux = run(["getenforce"])[1].strip() if shutil.which("getenforce") else ""
        code, out = run(["iptables", "-V"]) if shutil.which("iptables") else (1, "")
        self.iptables = out.strip() if code == 0 else ""

    def _active(self, unit):
        if not self.systemd:
            return False
        return run(["systemctl", "is-active", unit])[1].strip() == "active"

    def checks(self):
        """(종류, 글) 목록 — 설치 화면의 '환경' 칸"""
        out = []
        fam = FAMILIES.get(self.family)
        if fam:
            out.append(("ok", f"{self.name} — {fam['label']}, 패키지 설치는 {self.pm or fam['pm'] + ' (없음!)'}"))
        else:
            out.append(("warn", f"{self.name} — 지원 목록(데비안·칼리·우분투 / 록키·RHEL·알마) 밖의 배포판. 필요한 프로그램은 직접 설치하세요"))
        py = ".".join(map(str, self.python))
        if self.python < MIN_PYTHON:
            out.append(("bad", f"파이썬 {py} — {'.'.join(map(str, MIN_PYTHON))} 이상이 필요합니다"))
        else:
            out.append(("ok", f"파이썬 {py}"))
        where = "WSL (윈도우 안의 리눅스)" if self.wsl else {"": "확인 못 함", "none": "실제 컴퓨터"}.get(self.virt, f"가상 머신 ({self.virt})")
        out.append(("warn" if self.wsl else "ok", f"실행 위치: {where}" + (" — 실습망이 없어 동작 확인용으로만 쓰세요" if self.wsl else "")))
        if not self.systemd:
            out.append(("warn", "systemd 가 없어 자동 시작 서비스는 쓸 수 없습니다" + (" (WSL 은 /etc/wsl.conf 에서 켤 수 있음)" if self.wsl else "")))
        if self.firewalld:
            out.append(("warn", "firewalld 가 켜져 있습니다. firewalld 를 다시 읽으면(reload) Guardian 의 차단 규칙이 지워질 수 있습니다 "
                                "— 설치 도구는 방화벽을 건드리지 않으니, 시연 중에는 firewalld 를 reload 하지 마세요"))
        if self.ufw:
            out.append(("warn", "UFW 가 켜져 있습니다. Guardian 의 GUARDIAN 체인과 결과가 섞여 헷갈릴 수 있습니다 (이 프로젝트는 UFW 를 쓰지 않음)"))
        if self.selinux == "Enforcing":
            out.append(("warn", "SELinux 가 Enforcing 입니다. 서비스가 막히면 'sudo ausearch -m avc -ts recent' 로 거부 기록을 확인하세요"))
        if self.iptables:
            out.append(("ok", f"방화벽 도구: {self.iptables}"))
        return out

    def epel_needed(self, missing):
        """록키·RHEL 에서 python3-scapy 는 EPEL 저장소에 있다"""
        if self.family != "rhel" or "python3-scapy" not in missing or "fedora" in self.name.lower():
            return False
        return run(["rpm", "-q", "epel-release"])[0] != 0


class Env:
    def __init__(self, test_home=None):
        self.test = test_home is not None
        if self.test:
            self.user = pwd.getpwuid(os.getuid()).pw_name
            self.home = os.path.abspath(test_home)
            os.makedirs(self.home, exist_ok=True)
        else:
            self.user = os.environ.get("SUDO_USER", "")
            self.home = pwd.getpwnam(self.user).pw_dir if self.user else ""
        self.plat = Platform()
        self.deps = [(cmd, pkgs, why, have(cmd)) for cmd, pkgs, why in DEPENDENCIES]
        self.ifaces = interfaces()
        self.ports = listening_ports()
        self.systemd = self.plat.systemd
        try:
            self.shell = pwd.getpwnam(self.user).pw_shell if self.user else ""
        except KeyError:
            self.shell = ""

    def missing_packages(self):
        fam = self.plat.family or "debian"
        return sorted({pkgs[fam] for _, pkgs, _, ok in self.deps if not ok})

    def missing_commands(self):
        return [cmd.replace("py:", "") for cmd, _, _, ok in self.deps if not ok]

    def download_plan(self):
        """외부에서 받을 것 (화면 표시용): 저장소 추가 + 패키지"""
        missing = self.missing_packages()
        plan = []
        if self.plat.epel_needed(missing):
            plan.append("epel-release (EPEL 저장소: python3-scapy 가 여기 있음)")
        plan += missing
        return plan


def default_settings(env):
    target = os.path.join(env.home, "guardian")
    old_cfg = load_json(os.path.join(target, "config.json"), {})
    old_dash = load_json(os.path.join(target, "dashboard", "dashboard_config.json"), {})
    names = [n for n, _, _ in env.ifaces]
    ip_of = {n: a.split("/")[0] for n, a, _ in env.ifaces}
    # 감시 인터페이스: 기존 설정 → 실습 감시망(192.168.56.x) → 첫 인터페이스
    mon = old_cfg.get("interface") if old_cfg.get("interface") in names else None
    mon = mon or next((n for n, a, _ in env.ifaces if a.startswith("192.168.56.")), None) or (names[0] if names else "eth0")
    # 대시보드 주소: 기존 설정 → 감시망이 아닌 다른 인터페이스(관리망) → 감시 인터페이스 IP
    host = old_dash.get("host")
    if host not in list(ip_of.values()) + ["0.0.0.0", "127.0.0.1"]:
        host = next((ip for n, ip in ip_of.items() if n != mon), None) or ip_of.get(mon, "127.0.0.1")
    # 관리 PC: 기존 화이트리스트에서 127.0.0.1 이 아닌 첫 주소 → 대시보드 네트워크의 .1
    admin = next((w for w in old_cfg.get("whitelist", []) if w != "127.0.0.1"), None)
    if not admin:
        net = next((a for n, a, _ in env.ifaces if a.split("/")[0] == host), None)
        admin = str(next(ipaddress.ip_interface(net).network.hosts())) if net else ""
    return {
        "target": target,
        "interface": mon,
        "host": host,
        "port": str(old_dash.get("port", 8080)),
        "admin_ip": admin,
        "dry_run": old_cfg.get("dry_run", True),
        "alias": True,
        "systemd": False,
        "selftest": True,
        "start": True,
    }


def network_checks(env, s):
    """(종류, 글) 목록 — 종류: ok / warn / bad"""
    out = []
    ip_of = {n: a for n, a, _ in env.ifaces}
    up = {n for n, _, u in env.ifaces if u}
    if not env.ifaces:
        return [("bad", "IP 가 붙은 인터페이스가 없습니다 (ip addr 로 확인하세요)")]
    for n, a, u in env.ifaces:
        role = []
        if n == s["interface"]:
            role.append("감시")
        if a.split("/")[0] == s["host"]:
            role.append("대시보드")
        out.append(("ok" if u else "warn", f"{n:<8} {a:<20} {'켜짐' if u else '꺼짐(DOWN)'}" + (f"   <- {'·'.join(role)}" if role else "")))
    if s["interface"] not in ip_of:
        out.append(("bad", f"감시 인터페이스 '{s['interface']}' 에 IP 가 없습니다"))
    elif s["interface"] not in up:
        out.append(("warn", f"감시 인터페이스 '{s['interface']}' 가 꺼져 있습니다"))
    host_net = next((a for a in ip_of.values() if a.split("/")[0] == s["host"]), None)
    if s["host"] == "0.0.0.0":
        out.append(("warn", "대시보드가 모든 주소(0.0.0.0)에 열립니다. 감시망에서도 접속될 수 있으니 관리망 IP 를 권장합니다"))
    elif s["host"] == "127.0.0.1":
        out.append(("warn", "대시보드가 서버 안(127.0.0.1)에서만 열립니다. 다른 PC 에서는 접속할 수 없습니다"))
    elif not host_net:
        out.append(("bad", f"대시보드 주소 {s['host']} 는 이 서버의 IP 가 아닙니다"))
    elif ip_of.get(s["interface"], "").split("/")[0] == s["host"]:
        out.append(("warn", "대시보드가 감시망과 같은 주소에 열립니다 (공격자 VM 에서도 접속 화면이 보임). 관리망 분리를 권장합니다"))
    else:
        out.append(("ok", "감시망과 대시보드(관리망)가 다른 인터페이스로 분리되어 있습니다"))
    try:
        if s["admin_ip"]:
            adm = ipaddress.ip_address(s["admin_ip"])
            if host_net and adm not in ipaddress.ip_interface(host_net).network:
                out.append(("warn", f"관리 PC {s['admin_ip']} 가 대시보드 네트워크({ipaddress.ip_interface(host_net).network})에 없습니다"))
            else:
                out.append(("ok", f"관리 PC {s['admin_ip']} 를 화이트리스트에 넣습니다 (차단되지 않음)"))
        else:
            out.append(("warn", "관리 PC IP 가 비어 있습니다. 실제 차단 때 대시보드 접속이 막힐 수 있습니다"))
    except ValueError:
        out.append(("bad", f"관리 PC IP '{s['admin_ip']}' 가 올바른 주소가 아닙니다"))
    for port, name in ((8000, "Guardian API"), (int(s["port"]) if s["port"].isdigit() else 0, "대시보드")):
        if port in env.ports:
            out.append(("warn", f"{port}번 포트가 이미 사용 중입니다 ({name}) — 기존 Guardian 이면 설치 뒤 새 코드로 다시 시작합니다"))
    return out


# ───────────────────────── 설치 단계 ─────────────────────────

def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data, mode=None):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


class Installer:
    def __init__(self, env, s, log):
        self.env, self.s, self.log = env, s, log
        self.target = os.path.abspath(s["target"])
        self.user = env.user
        pw = pwd.getpwnam(self.user)
        self.uid, self.gid = pw.pw_uid, pw.pw_gid

    def steps(self):
        st = [("필요한 프로그램 확인", self.step_deps),
              ("코드 복사", self.step_copy),
              ("설정 파일 작성", self.step_config),
              ("소유자·권한 정리", self.step_perms)]
        if self.s["alias"]:
            st.append(("단축 명령 등록 (approve·gstart 등)", self.step_alias))
        if self.s["systemd"]:
            st.append(("자동 시작 서비스(systemd) 등록", self.step_systemd))
        if self.s["selftest"]:
            st.append(("자가 시험 (selftest.py)", self.step_selftest))
        if self.s["start"] or self.s["systemd"]:
            st.append(("Guardian·대시보드 실행", self.step_start))
        return st

    # 1
    def step_deps(self):
        plat = self.env.plat
        self.log(f"환경: {plat.name}, 파이썬 {'.'.join(map(str, plat.python))}")
        missing = self.env.missing_packages()
        if not missing:
            self.log("필요한 프로그램이 모두 있습니다 (외부에서 받을 것 없음)")
            return True
        if self.env.test:
            self.log(f"연습 모드라 설치하지 않음. 없는 패키지: {' '.join(missing)}")
            return True
        if not plat.pm:
            self.log(f"이 배포판의 패키지 관리자를 몰라 자동 설치할 수 없습니다. 직접 설치하세요: {' '.join(self.env.missing_commands())}")
            return False
        envv = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        cmds = []
        if plat.pm == "apt-get":
            cmds.append(["apt-get", "install", "-y", *missing])
        else:
            if plat.epel_needed(missing):
                cmds.append([plat.pm, "install", "-y", "epel-release"])
                if plat.major in ("8", "9", "10") and shutil.which("crb"):
                    cmds.append(["crb", "enable"])              # EPEL 의 일부 패키지가 CRB 저장소를 필요로 함
            cmds.append([plat.pm, "install", "-y", *missing])
        for cmd in cmds:
            self.log(f"실행: {' '.join(cmd)} (인터넷 필요)")
            code, out = run(cmd, timeout=900, env=envv)
            if code != 0 and cmd[0] == "apt-get":                  # 패키지 목록이 오래되면 한 번 갱신하고 다시
                self.log("목록을 갱신하고 다시 시도: apt-get update")
                run(["apt-get", "update"], timeout=600, env=envv)
                code, out = run(cmd, timeout=900, env=envv)
            for line in out.strip().splitlines()[-3:]:
                self.log("  " + line)
            if code != 0:
                self.log("설치하지 못했습니다. 인터넷 연결을 확인하거나 패키지를 직접 설치한 뒤 다시 실행하세요")
                return False
        still = [c for c, _, _, _ in self.env.deps if not have(c)]
        if still:
            self.log("설치했지만 아직 없는 것: " + ", ".join(s.replace("py:", "") for s in still))
            return False
        return True

    # 2
    def step_copy(self):
        if os.path.realpath(SRC) == os.path.realpath(self.target):
            self.log("이미 설치 위치에서 실행 중이라 복사하지 않습니다")
            return True
        os.makedirs(self.target, exist_ok=True)
        copied = kept = 0
        for root, dirs, files in os.walk(SRC):
            rel = os.path.relpath(root, SRC)
            rel = "" if rel == "." else rel
            top = rel.split(os.sep)[0] if rel else ""
            if top in NEVER_COPY or "__pycache__" in rel.split(os.sep):
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if not (rel == "" and d in NEVER_COPY) and d != "__pycache__"
                       and os.path.join(rel, d) not in DEV_ONLY]
            merge = any(rel == m or rel.startswith(m + os.sep) for m in MERGE_DIRS)
            os.makedirs(os.path.join(self.target, rel), exist_ok=True)
            for name in files:
                if (rel == "" and name in NEVER_COPY) or os.path.join(rel, name) in DEV_ONLY:
                    continue
                if rel == "dashboard" and name in NEVER_COPY_DASHBOARD:
                    continue
                src, dst = os.path.join(root, name), os.path.join(self.target, rel, name)
                if merge and os.path.exists(dst):
                    kept += 1
                    continue
                shutil.copyfile(src, dst)
                copied += 1
        os.makedirs(os.path.join(self.target, "logs"), exist_ok=True)
        self.log(f"{copied}개 복사 -> {self.target}")
        if kept:
            self.log(f"이미 있던 규칙·플러그인 {kept}개는 그대로 둠 (대시보드에서 바꾼 상태 유지)")
        return True

    # 3
    def step_config(self):
        path = os.path.join(self.target, "config.json")
        existed = os.path.exists(path)
        cfg = load_json(path, None) if existed else None
        if cfg is None:
            cfg = load_json(os.path.join(SRC, "config.json"), {})
        cfg["interface"] = self.s["interface"]
        cfg["dry_run"] = bool(self.s["dry_run"])
        wl = [w for w in cfg.get("whitelist", []) if isinstance(w, str)]
        for w in ("127.0.0.1", self.s["admin_ip"]):
            if w and w not in wl:
                wl.append(w)
        cfg["whitelist"] = wl
        write_json(path, cfg)
        self.log(f"config.json {'갱신' if existed else '새로 만듦'}: 감시 {cfg['interface']}, "
                 f"{'탐지만(dry-run)' if cfg['dry_run'] else '실제 차단'}, 화이트리스트 {', '.join(wl)}")
        override = os.path.join(self.target, "logs", "dry_run_override.json")
        if os.path.exists(override):
            try:
                os.remove(override)
                self.log("대시보드 슬라이드로 바꿔 둔 모드 기록을 지워 위 모드로 시작합니다")
            except OSError as e:
                self.log(f"모드 기록을 지우지 못함 ({e}) — 대시보드 슬라이드 값이 우선합니다")

        dpath = os.path.join(self.target, "dashboard", "dashboard_config.json")
        dash = load_json(dpath, {})
        new_token = not dash.get("token")
        dash.update({"host": self.s["host"], "port": int(self.s["port"]),
                     "guardian_url": dash.get("guardian_url", "http://127.0.0.1:8000")})
        if new_token:
            dash["token"] = secrets.token_urlsafe(12)
        write_json(dpath, dash, 0o600)
        self.log(f"dashboard_config.json: http://{dash['host']}:{dash['port']}  (로그인 토큰 {'새로 만듦' if new_token else '기존 것 유지'}, 권한 600)")
        return True

    # 4
    def step_perms(self):
        if self.env.test:
            self.log("연습 모드라 소유자는 바꾸지 않음")
        else:
            for root, dirs, files in os.walk(self.target):
                for n in [root] + [os.path.join(root, f) for f in files]:
                    try:
                        os.chown(n, self.uid, self.gid, follow_symlinks=False)
                    except OSError:
                        pass
            self.log(f"{self.target} 의 소유자를 {self.user} 로 맞춤 (탐지 스크립트는 root 소유 폴더에서 실행되지 않음)")
        os.chmod(self.target, 0o770)
        for root, dirs, files in os.walk(self.target):
            for f in files:
                p = os.path.join(root, f)
                if os.path.islink(p):
                    continue
                rel = os.path.relpath(p, self.target).split(os.sep)
                if rel[0] == "logs":
                    continue                       # Guardian 이 만든 기록의 권한은 그대로
                if f.endswith((".py", ".sh")):
                    # 탐지 스크립트·플러그인은 실행 권한이 필요 (Guardian·대시보드가 직접 실행)
                    os.chmod(p, 0o755 if rel[0] == "rules" or rel[:2] == ["dashboard", "plugins"] else 0o750)
                elif f in ("dashboard_config.json", "audit.jsonl", "setup_log.txt"):
                    os.chmod(p, 0o600)
                else:
                    os.chmod(p, 0o640)
        self.log("실행 파일 755/750, 설정·문서 640, 토큰 파일 600")
        return True

    # 5
    def step_alias(self):
        block = alias_block(self.target)
        done = []
        rcs = [".bashrc"]
        if self.env.shell.endswith("zsh") or os.path.exists(os.path.join(self.env.home, ".zshrc")):
            rcs.insert(0, ".zshrc")              # 칼리는 zsh, 록키는 bash 가 기본
        for rc in rcs:
            path = os.path.join(self.env.home, rc)
            text = ""
            if os.path.exists(path):
                with open(path, encoding="utf-8", errors="replace") as f:
                    text = f.read()
            text = re.sub(re.escape(ALIAS_BEGIN) + r".*?" + re.escape(ALIAS_END) + r"\n?", "", text, flags=re.S)
            text = re.sub(r"(?m)^# Guardian: plugin approval screen\nalias approve=.*\n?", "", text)   # 손으로 넣었던 옛 줄
            if text and not text.endswith("\n"):
                text += "\n"
            with open(path, "w", encoding="utf-8") as f:
                f.write(text + block)
            if not self.env.test:
                os.chown(path, self.uid, self.gid)
            done.append(rc)
        self.log(f"단축 명령(approve·gstart·gstop·grestart·gstatus·glog·gunblock)을 {', '.join(done)} 에 넣음 "
                 f"(새 터미널부터, 지금 창은 source ~/{done[0]})")
        return True

    # 6
    def step_systemd(self):
        if self.env.test or not self.env.systemd:
            self.log("연습 모드이거나 systemd 가 없어 건너뜀")
            return True
        kill_matching(self.target, self.log)
        for name, text in (("guardian.service", UNIT_GUARDIAN), ("guardian-dashboard.service", UNIT_DASHBOARD)):
            with open(f"/etc/systemd/system/{name}", "w", encoding="utf-8") as f:
                f.write(text.format(target=self.target, user=self.user))
        run(["systemctl", "daemon-reload"])
        code, out = run(["systemctl", "enable", "--now", "guardian.service", "guardian-dashboard.service"], timeout=60)
        if code != 0:
            self.log("서비스를 켜지 못했습니다: " + out.strip()[-300:])
            return False
        run(["systemctl", "restart", "guardian.service", "guardian-dashboard.service"], timeout=60)
        self.log("guardian.service · guardian-dashboard.service 등록 (부팅 때 자동 시작)")
        self.log("다시 시작: sudo systemctl restart guardian   /   상태: systemctl status guardian")
        return True

    # 7
    def step_selftest(self):
        tmp = tempfile.mkdtemp(prefix="guardian_setup_test_")
        try:
            for name in os.listdir(self.target):
                if name in ("logs", "plugins_pending", "__pycache__", "audit.jsonl"):
                    continue
                src = os.path.join(self.target, name)
                if os.path.isdir(src):
                    shutil.copytree(src, os.path.join(tmp, name),
                                    ignore=shutil.ignore_patterns("dashboard_config.json", "__pycache__"))   # 토큰은 복사하지 않음
                else:
                    shutil.copyfile(src, os.path.join(tmp, name))
            os.makedirs(os.path.join(tmp, "logs"))
            # 시험은 설치본의 '기본 규칙'으로 한다: 대시보드에서 꺼 둔 규칙 때문에 시험이 실패하지 않도록 임시 복사본에서만 모두 켬
            shutil.rmtree(os.path.join(tmp, "rules"), ignore_errors=True)
            shutil.copytree(os.path.join(SRC, "rules"), os.path.join(tmp, "rules"),
                            ignore=shutil.ignore_patterns("__pycache__"))
            for name in os.listdir(os.path.join(tmp, "rules")):
                if name.endswith(".json"):
                    p = os.path.join(tmp, "rules", name)
                    r = load_json(p, None)
                    if isinstance(r, dict):
                        r["enabled"] = True
                        write_json(p, r)
            cmd = [sys.executable, "selftest.py"]
            if not self.env.test:
                for root, dirs, files in os.walk(tmp):
                    for n in [root] + [os.path.join(root, f) for f in files]:
                        os.chown(n, self.uid, self.gid)
                cmd = ["runuser", "-u", self.user, "--"] + cmd
            code, out = run(cmd, timeout=600, cwd=tmp)
            m = re.search(r"결과:\s*(\d+)/(\d+)", out)
            if m:
                self.log(f"selftest {m.group(1)}/{m.group(2)} 통과")
                return m.group(1) == m.group(2)
            self.log("selftest 결과를 읽지 못했습니다: " + out.strip()[-300:])
            return False
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # 8
    def step_start(self):
        if self.env.test:
            self.log("연습 모드라 실행하지 않음")
            return True
        if self.s["systemd"] and self.env.systemd:
            ok = wait_ports([8000, int(self.s["port"])], self.log)
            return ok
        kill_matching(self.target, self.log)
        launch(self.target, self.user, ("guardian", "dashboard"), self.log)
        return wait_ports([8000, int(self.s["port"])], self.log)


SCRIPTS = {"guardian": "guardian.py", "dashboard": os.path.join("dashboard", "server.py")}


def find_pids(target, which=("guardian", "dashboard")):
    """설치 위치의 guardian.py / dashboard/server.py 를 돌리는 파이썬 프로세스 {pid: 이름} (/proc 를 직접 읽음)"""
    want = {os.path.join(target, SCRIPTS[w]): w for w in which}
    found = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        if int(pid) == os.getpid():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = [a.decode(errors="replace") for a in f.read().split(b"\0") if a]
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            continue
        if len(argv) < 2 or not os.path.basename(argv[0]).startswith("python"):
            continue
        script = os.path.normpath(argv[1] if os.path.isabs(argv[1]) else os.path.join(cwd, argv[1]))
        if script in want:
            found[int(pid)] = want[script]
    return found


def launch(target, user, which, log):
    """Guardian(root)·대시보드(일반 계정)를 터미널과 떨어진 백그라운드로 켠다. 출력은 logs/*.out (600)"""
    old_umask = os.umask(0o077)
    try:
        for name in which:
            out = os.path.join(target, "logs", f"{name}.out")      # 대시보드는 시작할 때 토큰을 찍으므로 600
            if os.path.lexists(out):
                os.unlink(out)
            with open(out, "w") as fh:
                if name == "guardian":
                    cmd, cwd = [sys.executable, os.path.join(target, "guardian.py"), "run"], target
                else:
                    pw = pwd.getpwnam(user)
                    os.chown(out, pw.pw_uid, pw.pw_gid)
                    cmd = ["runuser", "-u", user, "--", sys.executable, os.path.join(target, "dashboard", "server.py")]
                    cwd = os.path.join(target, "dashboard")
                subprocess.Popen(cmd, cwd=cwd, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                                 start_new_session=True)
            log(f"{'Guardian' if name == 'guardian' else '대시보드'} 켜는 중 (기록: {out})")
    finally:
        os.umask(old_umask)


def kill_matching(target, log, which=("guardian", "dashboard")):
    """설치 위치의 guardian.py run / dashboard/server.py 프로세스를 끝낸다 (자기 자신은 제외)"""
    victims = list(find_pids(target, which))
    for pid in victims:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    if victims:
        log(f"켜져 있던 {'·'.join('Guardian' if w == 'guardian' else '대시보드' for w in which)} 프로세스 {len(victims)}개를 끝냄")
    deadline = time.time() + 8
    while victims and time.time() < deadline:
        victims = [p for p in victims if os.path.exists(f"/proc/{p}")]
        time.sleep(0.3)
    for pid in victims:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    time.sleep(1)       # 포트가 풀릴 시간


def wait_ports(ports, log, limit=180):
    start = time.time()
    while time.time() - start < limit:
        up = listening_ports()
        if all(p in up for p in ports):
            log(f"실행 확인: Guardian(8000)·대시보드({ports[1]}) 응답 ({int(time.time() - start)}초)")
            return True
        time.sleep(2)
    up = listening_ports()
    log("시간 안에 뜨지 않았습니다: " + ", ".join(f"{p}={'up' if p in up else 'down'}" for p in ports)
        + "  (설치 위치의 logs/guardian.out, logs/dashboard.out 확인)")
    return False


# ───────────────────────── 화면 (curses) ─────────────────────────

def _cw(ch):
    return 2 if unicodedata.east_asian_width(ch) in "WF" else 1


def _pad(text, width):
    """한글(두 칸) 너비를 고려해 오른쪽을 공백으로 채움"""
    return text + " " * max(0, width - sum(_cw(ch) for ch in text))


def _clip(text, width):
    out, used = [], 0
    for ch in text:
        w = _cw(ch)
        if used + w > width:
            break
        out.append(ch)
        used += w
    return "".join(out)


SETTINGS = [
    # (키, 이름, 종류, 설명)
    ("target", "설치 위치", "text", "코드를 둘 폴더. rules/·logs/ 는 덮어쓰지 않음"),
    ("interface", "감시 인터페이스", "iface", "공격을 감시할 네트워크 (실습 감시망)"),
    ("host", "대시보드 주소", "host", "대시보드를 열 IP (관리망 권장)"),
    ("port", "대시보드 포트", "text", "기본 8080"),
    ("admin_ip", "관리 PC IP", "text", "화이트리스트에 넣어 절대 차단하지 않을 주소"),
    ("dry_run", "시작 모드", "bool", "켜기 = 탐지만(dry-run), 끄기 = 실제 차단. 대시보드 슬라이드로 언제든 바꿈"),
    ("alias", "approve 단축 명령", "bool", "셸에 approve 명령 추가"),
    ("systemd", "자동 시작 서비스", "bool", "systemd 에 등록해 부팅 때 켜짐 (켜면 sudo systemctl restart guardian 으로 재시작)"),
    ("selftest", "설치 후 자가 시험", "bool", "임시 복사본에서 selftest.py 실행"),
    ("start", "설치 후 실행", "bool", "Guardian·대시보드 켜기 (이미 켜져 있으면 새 코드로 다시 시작)"),
]
BOOL_TEXT = {"dry_run": ("탐지만 (dry-run)", "실제 차단"), }


def show_value(key, v):
    if isinstance(v, bool):
        on, off = BOOL_TEXT.get(key, ("켜기", "끄기"))
        return on if v else off
    return str(v) or "(비어 있음)"


class SetupTui:
    def __init__(self, scr, env, s):
        import curses
        self.c, self.scr, self.env, self.s = curses, scr, env, s
        curses.curs_set(0)
        scr.keypad(True)
        self.attr = {"": 0, "head": curses.A_BOLD, "dim": curses.A_DIM, "ok": curses.A_BOLD, "warn": curses.A_BOLD,
                     "bad": curses.A_BOLD | curses.A_REVERSE}
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            for n, fg in ((1, curses.COLOR_YELLOW), (2, curses.COLOR_RED), (3, curses.COLOR_CYAN), (4, curses.COLOR_GREEN)):
                curses.init_pair(n, fg, -1)
            self.attr.update(warn=curses.color_pair(1) | curses.A_BOLD, bad=curses.color_pair(2) | curses.A_BOLD,
                             head=curses.color_pair(3) | curses.A_BOLD, ok=curses.color_pair(4) | curses.A_BOLD)

    def put(self, y, x, text, kind=""):
        h, w = self.scr.getmaxyx()
        if 0 <= y < h and x < w - 1:
            try:
                self.scr.addstr(y, x, _clip(text, w - 1 - x), kind if isinstance(kind, int) else self.attr.get(kind, 0))
            except self.c.error:
                pass

    def footer(self, text):
        h, _ = self.scr.getmaxyx()
        self.put(h - 1, 0, text, self.c.A_REVERSE)

    def edit_text(self, y, label, value):
        typed = value
        self.c.curs_set(1)
        try:
            while True:
                self.put(y, 0, " " * 300)
                self.put(y, 2, f"{label}: {typed}", "warn")
                self.scr.refresh()
                k = self.scr.getch()
                if k == 27:
                    return value
                if k in (10, 13, self.c.KEY_ENTER):
                    return typed.strip()
                if k in (self.c.KEY_BACKSPACE, 127, 8):
                    typed = typed[:-1]
                elif 32 <= k < 127 and len(typed) < 200:
                    typed += chr(k)
        finally:
            self.c.curs_set(0)

    def change(self, idx, y):
        key, label, kind, _ = SETTINGS[idx]
        if kind == "bool":
            self.s[key] = not self.s[key]
        elif kind == "iface":
            names = [n for n, _, _ in self.env.ifaces] or [self.s[key]]
            self.s[key] = names[(names.index(self.s[key]) + 1) % len(names)] if self.s[key] in names else names[0]
        elif kind == "host":
            opts = [a.split("/")[0] for _, a, _ in self.env.ifaces] + ["0.0.0.0", "127.0.0.1"]
            self.s[key] = opts[(opts.index(self.s[key]) + 1) % len(opts)] if self.s[key] in opts else opts[0]
        else:
            v = self.edit_text(y, label, str(self.s[key]))
            if key == "port" and not (v.isdigit() and 1 <= int(v) <= 65535 and int(v) != 8000):
                return "포트는 1~65535 의 숫자여야 하고 8000(Guardian API)은 쓸 수 없습니다"
            if key == "admin_ip" and v:
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    return f"'{v}' 는 올바른 IP 가 아닙니다"
            if key == "target" and not os.path.isabs(v):
                return "설치 위치는 / 로 시작하는 절대 경로여야 합니다"
            self.s[key] = v
        return ""

    def overview_lines(self, sel):
        """화면에 그릴 줄: (들여쓰기, 글, 종류, 설정 번호 또는 None)"""
        L = []
        mark = {"ok": "O", "warn": "!", "bad": "X"}
        L.append((1, "진행 순서", "head", None))
        order = ["필요한 프로그램 확인", "코드 복사", "설정 파일", "권한", "approve 명령", "systemd(선택)", "자가 시험", "실행"]
        L.append((3, " > ".join(f"{i}.{t}" for i, t in enumerate(order, 1)), "dim", None))
        L.append((0, "", "", None))
        L.append((1, "이 컴퓨터 환경", "head", None))
        for kind, text in self.env.plat.checks():
            L.append((3, f"{mark[kind]} {text}", kind if kind != "ok" else "", None))
        L.append((0, "", "", None))
        plan = self.env.download_plan()
        L.append((1, "외부에서 받을 파일", "head", None))
        if plan:
            pm = self.env.plat.pm or "패키지 관리자"
            L.append((3, f"! {pm} 로 설치 예정 (인터넷 필요): {', '.join(plan)}", "warn", None))
        else:
            ok_list = " ".join(c.replace("py:", "") for c, _, _, _ in self.env.deps)
            L.append((3, f"O 없음 — 필요한 프로그램이 모두 있음 ({ok_list})", "", None))
        L.append((0, "", "", None))
        L.append((1, "IP 구성 확인", "head", None))
        for kind, text in network_checks(self.env, self.s):
            L.append((3, f"{mark[kind]} {text}", kind if kind != "ok" else "", None))
        L.append((0, "", "", None))
        L.append((1, "설정 (위/아래 키로 고르고 Enter 로 바꾸기)", "head", None))
        for i, (key, label, kind, desc) in enumerate(SETTINGS):
            text = f"{'❯' if i == sel else ' '} {_pad(label, 18)} {show_value(key, self.s[key])}"
            if key == "systemd" and not self.env.systemd:
                text += "   (systemd 없음 — 켜도 건너뜀)"
            L.append((2, text, "sel" if i == sel else "", i))
        return L

    def blocking_problems(self):
        return [t for k, t in self.env.plat.checks() + network_checks(self.env, self.s) if k == "bad"]

    def overview(self):
        sel, note, top = 0, "", 0
        while True:
            self.scr.erase()
            h, w = self.scr.getmaxyx()
            self.put(0, 0, " Guardian 설치", "head")
            self.put(0, 22, f"설치 계정: {self.env.user}" + ("   [연습 모드: 패키지·서비스·실행은 건너뜀]" if self.env.test else ""), "dim")
            lines = self.overview_lines(sel)
            room = max(3, h - 4)                     # 제목 1줄 + 빈 줄 + 아래 안내 2줄
            sel_row = next(r for r, ln in enumerate(lines) if ln[3] == sel)
            top = min(top, sel_row)
            if sel_row >= top + room:
                top = sel_row - room + 1
            if sel == 0 and top > 0 and sel_row < room:      # 맨 위 설정으로 돌아오면 화면 처음부터
                top = 0
            for r, (x, text, kind, idx) in enumerate(lines[top:top + room]):
                y = 2 + r
                if kind == "sel":
                    self.put(y, x, text, self.c.A_REVERSE)
                    self.put(y, x + sum(_cw(ch) for ch in text) + 3, SETTINGS[idx][3], "dim")
                else:
                    self.put(y, x, text, kind)
            for flag, y, text in ((top > 0, 1, "^ 위에 더 있음"), (top + room < len(lines), h - 3, "v 아래에 더 있음 (아래 키 또는 PgDn)")):
                if flag:
                    self.put(y, max(0, w - 2 - sum(_cw(ch) for ch in text)), text, "dim")
            if note:
                self.put(h - 2, 2, note, "warn")
            self.footer(" 위/아래 고르기   Enter 바꾸기   i 설치 시작   q 끝내기 ")
            self.scr.refresh()
            k = self.scr.getch()
            note = ""
            if k in (ord("q"), ord("Q")):
                return False
            if k in (self.c.KEY_UP, ord("k")):
                sel = (sel - 1) % len(SETTINGS)
            elif k in (self.c.KEY_DOWN, ord("j")):
                sel = (sel + 1) % len(SETTINGS)
            elif k in (10, 13, self.c.KEY_ENTER, ord(" ")):
                note = self.change(sel, h - 2)
            elif k in (self.c.KEY_PPAGE,):
                top = max(0, top - 5)
            elif k in (self.c.KEY_NPAGE,):
                top += 5
            elif k in (ord("i"), ord("I")):
                bad = self.blocking_problems()
                if bad:
                    note = "먼저 고쳐야 할 것: " + bad[0]
                    continue
                if self.confirm():
                    return True

    def confirm(self):
        h, _ = self.scr.getmaxyx()
        self.put(h - 2, 0, " " * 300)
        self.put(h - 2, 2, "위 설정으로 설치를 시작할까요?  (y = 예 / 그 밖의 키 = 아니오)", "warn")
        self.scr.refresh()
        return self.scr.getch() in (ord("y"), ord("Y"))

    def progress(self, installer):
        steps = installer.steps()
        state = ["…"] * len(steps)
        logs = []

        def draw():
            self.scr.erase()
            h, _ = self.scr.getmaxyx()
            self.put(0, 0, " Guardian 설치 중", "head")
            for i, (name, _) in enumerate(steps):
                mark = {"…": "  ", "▶": "> ", "✔": "O ", "✘": "X ", "-": "- "}[state[i]]
                kind = {"✔": "ok", "✘": "bad", "▶": "warn"}.get(state[i], "dim")
                self.put(2 + i, 2, f"{mark}{i + 1}. {name}", kind)
            top = 3 + len(steps)
            self.put(top, 1, "기록", "head")
            room = h - top - 3
            for j, line in enumerate(logs[-room:] if room > 0 else []):
                self.put(top + 1 + j, 3, line, "dim")
            self.scr.refresh()

        def log(text):
            logs.append(text)
            draw()

        installer.log = log
        ok_all = True
        for i, (name, fn) in enumerate(steps):
            state[i] = "▶"
            log(f"[{name}]")
            try:
                ok = fn()
            except Exception as e:        # 한 단계가 터져도 화면은 끝까지 보여 줌
                log(f"오류: {e}")
                ok = False
            state[i] = "✔" if ok else "✘"
            draw()
            if not ok:
                ok_all = False
                if name in ("필요한 프로그램 확인", "코드 복사", "설정 파일 작성"):
                    for k in range(i + 1, len(steps)):
                        state[k] = "-"
                    log("앞 단계가 실패해서 나머지는 건너뜁니다")
                    break
        draw()
        return ok_all, logs

    def done(self, ok_all, lines, title=None):
        """결과 화면. 토큰처럼 꼭 읽어야 할 내용이 있으므로 yes 를 입력해야만 닫힌다
        (설치 중에 눌러 둔 키가 남아 있으면 바로 닫히는 일이 없도록 입력 버퍼도 비움)"""
        self.c.flushinp()
        title = title or (" 설치 완료" if ok_all else " 설치가 끝났지만 실패한 단계가 있습니다")
        typed, warn = "", ""
        while True:
            self.scr.erase()
            h, _ = self.scr.getmaxyx()
            self.put(0, 0, title, "ok" if ok_all else "bad")
            y = 2
            for text, kind in lines:
                self.put(y, 2, text, kind)
                y += 1
            if warn:
                self.put(h - 3, 2, warn, "warn")
            self.put(h - 2, 2, f"위 내용을 확인했으면 yes 를 입력하고 Enter: {typed}_", "warn")
            self.footer(" yes 를 입력해야 닫힙니다 (Enter·다른 키·시간이 지나도 닫히지 않음) ")
            self.scr.refresh()
            k = self.scr.getch()
            if k in (10, 13, self.c.KEY_ENTER):
                if typed.strip().lower() == "yes":
                    return
                typed, warn = "", "yes 를 입력해야 닫힙니다. 토큰·주소를 적어 두었는지 확인하세요."
            elif k in (self.c.KEY_BACKSPACE, 127, 8):
                typed = typed[:-1]
            elif 32 <= k < 127 and len(typed) < 10:
                typed += chr(k)


def summary_lines(env, s, ok_all):
    target = os.path.abspath(s["target"])
    dash = load_json(os.path.join(target, "dashboard", "dashboard_config.json"), {})
    out = [(f"대시보드     http://{dash.get('host', s['host'])}:{dash.get('port', s['port'])}", "head"),
           (f"로그인 토큰  {dash.get('token', '(없음)')}", "warn"),
           (f"             (이 화면에만 표시. 다시 보려면: cat {target}/dashboard/dashboard_config.json)", "dim"),
           ("", ""),
           (f"모드         {'탐지만 (dry-run)' if s['dry_run'] else '실제 차단'} — 대시보드 '관제 서버 상태' 슬라이드로 바꿈", ""),
           (f"화이트리스트 127.0.0.1, {s['admin_ip'] or '(관리 PC 없음)'}", "")]
    if s["alias"]:
        rc = "~/.zshrc" if env.shell.endswith("zsh") else "~/.bashrc"
        out.append((f"승인 화면    approve   (지금 창에서는 먼저 source {rc})", ""))
    if s["systemd"]:
        out.append(("다시 시작    sudo systemctl restart guardian guardian-dashboard", ""))
    else:
        out.append(("다시 시작    sudo python3 setup.py 를 다시 실행하거나, 기존 방식(startlab)으로", ""))
    out.append((f"설치 기록    {target}/setup_log.txt", "dim"))
    out.append(("그 밖의 값(차단 시간 300초, 알림 간격 30초, 패킷 보기 등)은 기본값 그대로입니다 (config.json).", "dim"))
    return out


def save_log(env, s, lines):
    path = os.path.join(os.path.abspath(s["target"]), "setup_log.txt")
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S %z')} ===\n")
            f.write("설정: " + json.dumps({k: v for k, v in s.items()}, ensure_ascii=False) + "\n")
            f.write("\n".join(lines) + "\n")
        os.chmod(path, 0o600)
        if not env.test:
            pw = pwd.getpwnam(env.user)
            os.chown(path, pw.pw_uid, pw.pw_gid)
    except OSError:
        pass


# ───────────────────────── 시작 ─────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Guardian 설치 도구 (sudo 로 실행)")
    ap.add_argument("--yes", action="store_true", help="화면 없이 기본값으로 설치")
    ap.add_argument("--test-home", metavar="DIR", help="연습 모드: root 없이 DIR 를 홈 폴더로 보고 설치 (패키지·서비스·실행 건너뜀)")
    a = ap.parse_args()

    if a.test_home is None:
        if os.geteuid() != 0:
            sys.exit("이 설치 도구는 관리자 권한이 필요합니다. 이렇게 실행하세요:\n\n    sudo python3 " + os.path.abspath(__file__) + "\n")
        if not os.environ.get("SUDO_USER") or os.environ["SUDO_USER"] == "root":
            sys.exit("root 계정으로 직접 실행하지 말고, 일반 계정(예: kali)에서 sudo 로 실행하세요.\n"
                     "(설치 폴더와 대시보드를 그 계정 소유로 만들기 위해 필요합니다)")
    env = Env(a.test_home)
    s = default_settings(env)

    if a.yes or not (sys.stdin.isatty() and sys.stdout.isatty()):
        if not a.yes:
            sys.exit("터미널이 아니면 --yes 를 붙여 실행하세요.")
        print("환경:")
        for kind, text in env.plat.checks():
            print(f"  {'O' if kind == 'ok' else '!' if kind == 'warn' else 'X'} {text}")
        plan = env.download_plan()
        print("외부에서 받을 파일: " + (", ".join(plan) if plan else "없음"))
        bad = [t for k, t in env.plat.checks() + network_checks(env, s) if k == "bad"]
        if bad:
            sys.exit("설치할 수 없습니다: " + bad[0])
        lines = []

        def log(t):
            lines.append(t)
            print("  " + t, flush=True)
        inst = Installer(env, s, log)
        ok_all = True
        for name, fn in inst.steps():
            print(f"[{name}]", flush=True)
            if not fn():
                ok_all = False
                print("  X 실패", flush=True)
                if name in ("필요한 프로그램 확인", "코드 복사", "설정 파일 작성"):
                    break
        save_log(env, s, lines)
        print("\n설치 완료" if ok_all else "\n실패한 단계가 있습니다")
        for text, _ in summary_lines(env, s, ok_all):
            if not text.startswith("로그인 토큰"):       # 화면 없는 실행은 기록에 남을 수 있어 토큰을 찍지 않음
                print("  " + text)
        print(f"  로그인 토큰: cat {os.path.abspath(s['target'])}/dashboard/dashboard_config.json")
        sys.exit(0 if ok_all else 1)

    import curses
    import locale
    locale.setlocale(locale.LC_ALL, "")
    os.environ.setdefault("ESCDELAY", "25")

    def ui(scr):
        t = SetupTui(scr, env, s)
        if not t.overview():
            return None
        inst = Installer(env, s, lambda _x: None)
        ok_all, logs = t.progress(inst)
        save_log(env, s, logs)
        t.done(ok_all, summary_lines(env, s, ok_all))
        return ok_all

    try:
        res = curses.wrapper(ui)
    except KeyboardInterrupt:
        res = None
    if res is None:
        print("설치하지 않고 끝냈습니다.")
    else:
        # 화면이 닫힌 뒤에도 다시 볼 수 있게 남김 (토큰 자체는 터미널 기록에 남지 않도록 보는 방법만)
        target = os.path.abspath(s["target"])
        dash = load_json(os.path.join(target, "dashboard", "dashboard_config.json"), {})
        print("설치 완료" if res else "설치가 끝났지만 실패한 단계가 있습니다 (" + os.path.join(target, "setup_log.txt") + " 참고)")
        print(f"  대시보드: http://{dash.get('host', s['host'])}:{dash.get('port', s['port'])}")
        print(f"  로그인 토큰 다시 보기: sudo cat {target}/dashboard/dashboard_config.json")
    sys.exit(0 if res in (None, True) else 1)


if __name__ == "__main__":
    main()
