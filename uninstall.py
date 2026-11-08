#!/usr/bin/env python3
"""
WARDEN 제거 도구 — setup.py 로 구성한 것을 되돌립니다.

  sudo python3 uninstall.py             화면 모드: 지울 것을 보여 주고 고른 뒤 yes 를 입력하면 제거
  sudo python3 uninstall.py --yes       화면 없이 기본 선택대로 제거 (백업은 만듦)
  python3 uninstall.py --test-home DIR  연습 모드 (root 불필요): DIR 를 홈 폴더로 보고 제거. 프로세스·방화벽·서비스는 건드리지 않음

되돌리는 것 (화면에서 하나씩 켜고 끌 수 있음)
  1. 실행 중인 WARDEN·대시보드 끄기
  2. 자동 시작 서비스(systemd) 삭제 — setup.py 로 등록한 경우
  3. 방화벽에 남은 WARDEN 전용 체인(WARDEN) 정리 — 다른 방화벽 규칙은 건드리지 않음
  4. approve 단축 명령 삭제 (~/.zshrc, ~/.bashrc 의 warden setup 블록)
  5. 백업 (탐지 기록·규칙·설정·설치된 플러그인 → ~/warden_backup_날짜.tar.gz, 권한 600)
  6. 설치 폴더 삭제

남겨 두는 것: 설치했던 패키지(scapy 등 — 다른 프로그램도 쓸 수 있음), sudoers 같은 보안 설정(직접 지우도록 안내만 함).
"""
import argparse
import os
import pwd
import re
import shutil
import sys
import tarfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import setup as S        # 같은 폴더의 setup.py 에 있는 도구(환경 확인·프로세스 끄기·화면 그리기)를 같이 씀

UNITS = ("warden.service", "warden-dashboard.service")
BACKUP_ITEMS = ("logs", "rules", "config.json", "audit.jsonl", "plugins_pending",
                os.path.join("dashboard", "plugins"), os.path.join("dashboard", "dashboard_config.json"),
                os.path.join("dashboard", "plugins_state.json"), "setup_log.txt")
SUDOERS_HINTS = ("/etc/sudoers.d/warden-lab", "/etc/sudoers.d/warden")


# ───────────────────────── 무엇이 남아 있는지 찾기 ─────────────────────────

def looks_like_install(path):
    return os.path.isfile(os.path.join(path, "warden.py")) and os.path.isfile(os.path.join(path, "dashboard", "server.py"))


def target_problem(path):
    """지우면 안 되는 폴더면 이유를 돌려준다"""
    real = os.path.realpath(path)
    if not os.path.isabs(path):
        return "설치 위치는 / 로 시작하는 절대 경로여야 합니다"
    if real in ("/", "/home", "/root", "/usr", "/etc", "/var", "/opt", "/tmp") or real == os.path.realpath(os.path.expanduser("~")):
        return f"{real} 는 지울 수 없는 위치입니다"
    if real.startswith(("/media/", "/mnt/")):
        return f"{real} 는 공유·외부 폴더(원본일 수 있음)라 지우지 않습니다. 설치본(예: ~/warden)을 지정하세요"
    if os.path.islink(path):
        return f"{path} 는 다른 곳을 가리키는 링크라 지우지 않습니다"
    if os.path.exists(path) and not looks_like_install(path):
        return f"{path} 에 warden.py·dashboard/server.py 가 없어 WARDEN 설치 폴더로 보이지 않습니다"
    return ""


def rc_files_with_block(home):
    out = []
    for rc in (".zshrc", ".bashrc"):
        p = os.path.join(home, rc)
        text = S.read_text(p)
        if S.ALIAS_BEGIN in text or re.search(r"(?m)^alias approve=.*approve_plugin\.py", text):
            out.append(p)
    return out


def running_pids(target):
    pids = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = [a.decode(errors="replace") for a in f.read().split(b"\0") if a]
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            continue
        if len(argv) >= 2 and os.path.basename(argv[0]).startswith("python"):
            script = os.path.normpath(argv[1] if os.path.isabs(argv[1]) else os.path.join(cwd, argv[1]))
            if script in (os.path.join(target, "warden.py"), os.path.join(target, "dashboard", "server.py")):
                pids.append(int(pid))
    return pids


class Found:
    def __init__(self, env, target):
        self.env, self.target = env, os.path.abspath(target)
        self.exists = os.path.isdir(self.target)
        self.problem = target_problem(self.target)
        self.size = self._size() if self.exists and not self.problem else 0
        self.pids = [] if env.test else running_pids(self.target)
        self.units = [u for u in UNITS if os.path.exists(f"/etc/systemd/system/{u}")] if not env.test else []
        self.chain = False
        if not env.test and shutil.which("iptables"):
            self.chain = S.run(["iptables", "-n", "-L", "WARDEN"])[0] == 0
        self.rcs = rc_files_with_block(env.home)
        self.sudoers = [p for p in SUDOERS_HINTS if os.path.exists(p)]

    def _size(self):
        total = 0
        for root, _, files in os.walk(self.target):
            for f in files:
                try:
                    total += os.lstat(os.path.join(root, f)).st_size
                except OSError:
                    pass
        return total


def default_choices(found):
    return {
        "stop": bool(found.pids),
        "systemd": bool(found.units),
        "firewall": found.chain,
        "alias": bool(found.rcs),
        "backup": found.exists and not found.problem,
        "delete": found.exists and not found.problem,
    }


CHOICES = [
    ("stop", "실행 중인 WARDEN·대시보드 끄기"),
    ("systemd", "자동 시작 서비스(systemd) 삭제"),
    ("firewall", "방화벽의 WARDEN 체인 정리"),
    ("alias", "approve 단축 명령 삭제"),
    ("backup", "지우기 전에 백업 만들기"),
    ("delete", "설치 폴더 삭제"),
]


def describe(found):
    """(종류, 글) 목록: 지금 남아 있는 것"""
    mb = found.size / 1024 / 1024
    out = []
    if found.problem:
        out.append(("bad", found.problem))
    elif found.exists:
        out.append(("warn", f"설치 폴더: {found.target} ({mb:.1f}MB)"))
    else:
        out.append(("ok", f"설치 폴더 없음: {found.target}"))
    out.append(("warn" if found.pids else "ok", f"실행 중: {len(found.pids)}개" if found.pids else "실행 중인 WARDEN·대시보드 없음"))
    out.append(("warn" if found.units else "ok", "systemd 서비스: " + ", ".join(found.units) if found.units else "systemd 서비스 없음"))
    out.append(("warn" if found.chain else "ok", "방화벽에 WARDEN 체인이 남아 있음" if found.chain else "방화벽에 남은 WARDEN 체인 없음"))
    out.append(("warn" if found.rcs else "ok", "approve 단축 명령: " + ", ".join(found.rcs) if found.rcs else "approve 단축 명령 없음"))
    for p in found.sudoers:
        out.append(("warn", f"보안 설정 {p} 가 있습니다 — 자동으로 지우지 않습니다. 필요 없으면 직접: sudo rm {p}"))
    if found.env.test:
        out.append(("warn", "연습 모드: 프로세스·서비스·방화벽은 확인도, 변경도 하지 않습니다"))
    return out


# ───────────────────────── 제거 단계 ─────────────────────────

class Remover:
    def __init__(self, env, found, ch, log):
        self.env, self.f, self.ch, self.log = env, found, ch, log
        self.backup_path = ""

    def steps(self):
        st = []
        if self.ch["stop"]:
            st.append(("WARDEN·대시보드 끄기", self.stop))
        if self.ch["systemd"]:
            st.append(("systemd 서비스 삭제", self.systemd))
        if self.ch["firewall"]:
            st.append(("WARDEN 체인 정리", self.firewall))
        if self.ch["alias"]:
            st.append(("approve 단축 명령 삭제", self.alias))
        if self.ch["backup"]:
            st.append(("백업 만들기", self.backup))
        if self.ch["delete"]:
            st.append(("설치 폴더 삭제", self.delete))
        return st

    def stop(self):
        if self.env.test:
            self.log("연습 모드라 건너뜀")
            return True
        S.kill_matching(self.f.target, self.log)         # WARDEN 은 정상 종료하면서 자기 방화벽 체인을 스스로 지움
        left = running_pids(self.f.target)
        if left:
            self.log(f"아직 실행 중: {left}")
            return False
        self.log("꺼짐 확인")
        return True

    def systemd(self):
        if self.env.test:
            self.log("연습 모드라 건너뜀")
            return True
        S.run(["systemctl", "disable", "--now", *self.f.units], timeout=60)
        for u in self.f.units:
            try:
                os.remove(f"/etc/systemd/system/{u}")
                self.log(f"삭제: /etc/systemd/system/{u}")
            except OSError as e:
                self.log(f"지우지 못함: {u} ({e})")
                return False
        S.run(["systemctl", "daemon-reload"])
        return True

    def firewall(self):
        if self.env.test:
            self.log("연습 모드라 건너뜀")
            return True
        if S.run(["iptables", "-n", "-L", "WARDEN"])[0] != 0:
            self.log("이미 정리되어 있음 (WARDEN 이 끝나면서 지웠음)")
            return True
        for _ in range(10):                               # INPUT 에서 WARDEN 으로 가는 줄을 모두 뺌 (여러 번 들어갔을 수 있음)
            if S.run(["iptables", "-D", "INPUT", "-j", "WARDEN"])[0] != 0:
                break
        S.run(["iptables", "-F", "WARDEN"])
        code, out = S.run(["iptables", "-X", "WARDEN"])
        if code != 0:
            self.log("체인을 지우지 못했습니다: " + out.strip())
            return False
        self.log("WARDEN 체인과 INPUT 의 연결을 지움 (다른 규칙은 그대로)")
        return True

    def alias(self):
        for p in self.f.rcs:
            text = S.read_text(p)
            new = re.sub(re.escape(S.ALIAS_BEGIN) + r".*?" + re.escape(S.ALIAS_END) + r"\n?", "", text, flags=re.S)
            new = re.sub(r"(?m)^# WARDEN: plugin approval screen\n", "", new)
            new = re.sub(r"(?m)^alias approve=.*approve_plugin\.py\"?\n?", "", new)
            st = os.stat(p)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(new)
            if not self.env.test:
                os.chown(p, st.st_uid, st.st_gid)
            self.log(f"정리: {p}")
        return True

    def backup(self):
        stamp = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.env.home, f"warden_backup_{stamp}.tar.gz")
        old = os.umask(0o077)
        try:
            with tarfile.open(path, "w:gz") as tar:
                n = 0
                for item in BACKUP_ITEMS:
                    src = os.path.join(self.f.target, item)
                    if os.path.lexists(src):
                        tar.add(src, arcname=os.path.join("warden", item))
                        n += 1
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        if not self.env.test:
            pw = pwd.getpwnam(self.env.user)
            os.chown(path, pw.pw_uid, pw.pw_gid)
        self.backup_path = path
        self.log(f"{n}개 항목 → {path} (권한 600, 대시보드 토큰 포함이니 공유하지 마세요)")
        self.log(f"되살리기: tar -xzf {path} -C ~  (setup.py 로 다시 설치하기 전에)")
        return True

    def delete(self):
        problem = target_problem(self.f.target)
        if problem:
            self.log(problem)
            return False
        if self.ch["backup"] and not self.backup_path:
            self.log("백업이 만들어지지 않아 지우지 않습니다")
            return False
        shutil.rmtree(self.f.target)
        self.log(f"삭제: {self.f.target}")
        return True


# ───────────────────────── 화면 ─────────────────────────

class UninstallTui(S.SetupTui):
    def __init__(self, scr, env, found, ch):
        super().__init__(scr, env, {})
        self.found, self.ch = found, ch

    def overview(self):
        sel, note = 0, ""
        mark = {"ok": "O", "warn": "!", "bad": "X"}
        while True:
            self.scr.erase()
            h, w = self.scr.getmaxyx()
            self.put(0, 0, " WARDEN 제거", "head")
            self.put(0, 18, f"계정: {self.env.user}   설치 위치: {self.found.target}", "dim")
            y = 2
            self.put(y, 1, "지금 남아 있는 것", "head")
            y += 1
            for kind, text in describe(self.found):
                self.put(y, 3, f"{mark[kind]} {text}", kind if kind != "ok" else "")
                y += 1
            y += 1
            self.put(y, 1, "할 일 (위/아래 키로 고르고 Enter 로 켜기·끄기)", "head")
            y += 1
            for i, (key, label) in enumerate(CHOICES):
                text = f"{'❯' if i == sel else ' '} [{'v' if self.ch[key] else ' '}] {label}"
                self.put(y, 2, text, self.c.A_REVERSE if i == sel else ("" if self.ch[key] else "dim"))
                y += 1
            y += 1
            self.put(y, 1, "남겨 두는 것: 설치했던 패키지(scapy 등), sudoers 같은 보안 설정", "dim")
            if self.ch["delete"] and not self.ch["backup"]:
                self.put(y + 1, 1, "! 백업 없이 폴더를 지우면 탐지 기록·규칙·토큰을 되살릴 수 없습니다", "warn")
            if note:
                self.put(h - 2, 2, note, "warn")
            self.footer(" 위/아래 고르기   Enter 켜기·끄기   d 제거 시작   q 끝내기 ")
            self.scr.refresh()
            k = self.scr.getch()
            note = ""
            if k in (ord("q"), ord("Q")):
                return False
            if k in (self.c.KEY_UP, ord("k")):
                sel = (sel - 1) % len(CHOICES)
            elif k in (self.c.KEY_DOWN, ord("j")):
                sel = (sel + 1) % len(CHOICES)
            elif k in (10, 13, self.c.KEY_ENTER, ord(" ")):
                key = CHOICES[sel][0]
                if key in ("backup", "delete") and self.found.problem:
                    note = self.found.problem
                else:
                    self.ch[key] = not self.ch[key]
            elif k in (ord("d"), ord("D")):
                if not any(self.ch.values()):
                    note = "고른 일이 없습니다"
                elif self.ask_yes():
                    return True
                else:
                    note = "취소했습니다 (yes 를 정확히 입력해야 진행합니다)"

    def ask_yes(self):
        typed = ""
        while True:
            h, _ = self.scr.getmaxyx()
            self.put(h - 2, 0, " " * 300)
            self.put(h - 2, 2, f"고른 것을 제거합니다. 계속하려면 yes 를 입력하고 Enter (취소: Esc): {typed}_", "warn")
            self.scr.refresh()
            k = self.scr.getch()
            if k == 27:
                return False
            if k in (10, 13, self.c.KEY_ENTER):
                return typed.strip().lower() == "yes"
            if k in (self.c.KEY_BACKSPACE, 127, 8):
                typed = typed[:-1]
            elif 32 <= k < 127 and len(typed) < 10:
                typed += chr(k)

    def run_steps(self, remover):
        steps = remover.steps()
        state = [" "] * len(steps)
        logs = []

        def draw():
            self.scr.erase()
            h, _ = self.scr.getmaxyx()
            self.put(0, 0, " WARDEN 제거 중", "head")
            for i, (name, _) in enumerate(steps):
                kind = {"O": "ok", "X": "bad", ">": "warn"}.get(state[i], "dim")
                self.put(2 + i, 2, f"{state[i]} {i + 1}. {name}", kind)
            top = 3 + len(steps)
            self.put(top, 1, "기록", "head")
            room = h - top - 3
            for j, line in enumerate(logs[-room:] if room > 0 else []):
                self.put(top + 1 + j, 3, line, "dim")
            self.scr.refresh()

        def log(text):
            logs.append(text)
            draw()

        remover.log = log
        ok_all = execute(steps, log, lambda i, s: (state.__setitem__(i, s), draw()))
        return ok_all, logs


def execute(steps, log, mark):
    ok_all = True
    for i, (name, fn) in enumerate(steps):
        mark(i, ">")
        log(f"[{name}]")
        try:
            ok = fn()
        except Exception as e:
            log(f"오류: {e}")
            ok = False
        mark(i, "O" if ok else "X")
        if not ok:
            ok_all = False
            if name == "WARDEN·대시보드 끄기" or name == "백업 만들기":
                log("이 단계가 실패해서 폴더 삭제는 하지 않습니다")
                steps[:] = [s for s in steps if s[0] != "설치 폴더 삭제"]
    return ok_all


def finish_lines(found, remover, ok_all):
    out = [("제거 완료" if ok_all else "끝났지만 실패한 단계가 있습니다", "ok" if ok_all else "bad"), ("", "")]
    if remover.backup_path:
        out.append((f"백업: {remover.backup_path}", "head"))
    out.append(("남겨 둔 것: 설치했던 패키지(scapy·bubblewrap 등). 필요 없으면 apt/dnf 로 직접 지우세요", "dim"))
    for p in found.sudoers:
        out.append((f"남겨 둔 보안 설정: {p} (필요 없으면 sudo rm {p})", "warn"))
    out.append(("다른 컴퓨터에서 이 서버의 자동 시작을 걸어 두었다면(예: 윈도우 작업 스케줄러) 그것도 꺼 주세요", "dim"))
    out.append(("열려 있는 터미널에는 approve 명령이 남아 있을 수 있습니다 (새 터미널부터 사라짐)", "dim"))
    return out


# ───────────────────────── 시작 ─────────────────────────

def main():
    ap = argparse.ArgumentParser(description="WARDEN 제거 도구 (sudo 로 실행)")
    ap.add_argument("--yes", action="store_true", help="화면 없이 기본 선택대로 제거 (백업 포함)")
    ap.add_argument("--target", help="설치 위치 (기본: ~/warden)")
    ap.add_argument("--test-home", metavar="DIR", help="연습 모드: root 없이 DIR 를 홈 폴더로 보고 제거")
    a = ap.parse_args()

    if a.test_home is None:
        if os.geteuid() != 0:
            sys.exit("이 제거 도구는 관리자 권한이 필요합니다. 이렇게 실행하세요:\n\n    sudo python3 " + os.path.abspath(__file__) + "\n")
        if not os.environ.get("SUDO_USER") or os.environ["SUDO_USER"] == "root":
            sys.exit("root 계정으로 직접 실행하지 말고, 설치한 일반 계정(예: kali)에서 sudo 로 실행하세요.")
    env = S.Env(a.test_home)
    target = a.target or os.path.join(env.home, "warden")
    found = Found(env, target)
    ch = default_choices(found)

    if a.yes or not (sys.stdin.isatty() and sys.stdout.isatty()):
        if not a.yes:
            sys.exit("터미널이 아니면 --yes 를 붙여 실행하세요.")
        for kind, text in describe(found):
            print(f"  {'O' if kind == 'ok' else '!' if kind == 'warn' else 'X'} {text}")
        if not any(ch.values()):
            print("지울 것이 없습니다.")
            return
        lines = []

        def log(t):
            lines.append(t)
            print("  " + t, flush=True)
        rem = Remover(env, found, ch, log)
        steps = rem.steps()
        ok_all = execute(steps, log, lambda i, s: print(f"[{s}] {steps[i][0]}", flush=True) if s != ">" else None)
        for text, _ in finish_lines(found, rem, ok_all):
            print(text)
        sys.exit(0 if ok_all else 1)

    import curses
    import locale
    locale.setlocale(locale.LC_ALL, "")
    os.environ.setdefault("ESCDELAY", "25")

    def ui(scr):
        t = UninstallTui(scr, env, found, ch)
        if not t.overview():
            return None
        rem = Remover(env, found, ch, lambda _x: None)
        ok_all, _ = t.run_steps(rem)
        t.done(ok_all, finish_lines(found, rem, ok_all)[2:],
               title=" 제거 완료" if ok_all else " 제거가 끝났지만 실패한 단계가 있습니다")
        return ok_all

    try:
        res = curses.wrapper(ui)
    except KeyboardInterrupt:
        res = None
    if res is None:
        print("아무것도 지우지 않고 끝냈습니다.")
    sys.exit(0 if res in (None, True) else 1)


if __name__ == "__main__":
    main()
