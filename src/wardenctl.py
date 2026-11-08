#!/usr/bin/env python3
"""
WARDEN·대시보드 켜기/끄기 도구 (setup.py 가 단축 명령으로 등록)

  sudo python3 wardenctl.py start   [warden|dashboard]   백그라운드로 켜기 (이미 켜져 있으면 그대로 둠)
  sudo python3 wardenctl.py stop    [warden|dashboard]   끄기
  sudo python3 wardenctl.py restart [warden|dashboard]   끄고 다시 켜기 (코드를 바꾼 뒤)
       python3 wardenctl.py status                         켜짐·꺼짐, 모드, 대시보드 주소 (sudo 불필요)
  sudo python3 wardenctl.py log     [warden|dashboard]   최근 실행 기록 40줄
  sudo python3 wardenctl.py unblock-all                    긴급 전체 해제 (목록을 보여 주고 yes 를 입력해야 실행)

단축 명령: wstart / wstop / wrestart / wstatus / wlog / wunblock
긴급 전체 해제는 일부러 대시보드에 넣지 않았습니다 (토큰이 새도 한 번에 방어를 다 풀 수 없게, 서버 터미널에서만).
systemd 서비스(setup.py 에서 선택)로 설치했으면 systemctl 로 대신 처리합니다.
터미널을 닫아도 계속 돌고, 출력은 설치 위치의 logs/warden.out, logs/dashboard.out 에 남습니다.
"""
import json
import os
import sys
import time
import urllib.request

TARGET = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TARGET)
import setup as S          # 같은 폴더의 setup.py 에 있는 켜기·끄기 도구를 같이 씀

NAMES = {"warden": "WARDEN", "dashboard": "대시보드"}
UNITS = {"warden": "warden.service", "dashboard": "warden-dashboard.service"}


def dash_config():
    return S.load_json(os.path.join(TARGET, "dashboard", "dashboard_config.json"), {})


def owner():
    """대시보드를 돌릴 일반 계정: sudo 를 부른 계정 → 설치 폴더 주인"""
    import pwd
    user = os.environ.get("SUDO_USER")
    if user and user != "root":
        return user
    return pwd.getpwuid(os.stat(TARGET).st_uid).pw_name


def use_systemd():
    return all(os.path.exists(f"/etc/systemd/system/{u}") for u in UNITS.values()) and os.path.isdir("/run/systemd/system")


def ports():
    return {"warden": 8000, "dashboard": int(dash_config().get("port", 8080))}


def need_root():
    if os.geteuid() != 0:
        sys.exit("관리자 권한이 필요합니다: sudo python3 " + os.path.abspath(__file__) + " " + " ".join(sys.argv[1:])
                 + "\n(단축 명령 wstart·wstop·wrestart·wlog·wunblock 은 sudo 가 이미 붙어 있습니다)")


def say(text):
    print("  " + text, flush=True)


def start(which):
    need_root()
    up = S.listening_ports()
    p = ports()
    todo = [w for w in which if p[w] not in up]
    for w in which:
        if w not in todo:
            say(f"{NAMES[w]}: 이미 켜져 있음 (포트 {p[w]})")
    if not todo:
        return True
    if use_systemd():
        S.run(["systemctl", "start", *[UNITS[w] for w in todo]], timeout=60)
        say("systemd 로 켜는 중: " + ", ".join(UNITS[w] for w in todo))
    else:
        S.kill_matching(TARGET, say, tuple(todo))     # 포트는 안 열렸지만 프로세스가 남아 있으면(시작 중 멈춤 등) 정리
        S.launch(TARGET, owner(), tuple(todo), say)
    return S.wait_ports([p[w] for w in which], say) if len(which) == 2 else wait_one(p[which[0]], NAMES[which[0]])


def wait_one(port, name, limit=180):
    import time
    t0 = time.time()
    while time.time() - t0 < limit:
        if port in S.listening_ports():
            say(f"실행 확인: {name} (포트 {port}, {int(time.time() - t0)}초)")
            return True
        time.sleep(2)
    say(f"{limit}초 안에 뜨지 않았습니다. wlog 로 기록을 확인하세요")
    return False


def stop(which):
    need_root()
    if use_systemd():
        S.run(["systemctl", "stop", *[UNITS[w] for w in which]], timeout=60)
        say("systemd 로 끔: " + ", ".join(UNITS[w] for w in which))
    before = S.find_pids(TARGET, which)
    S.kill_matching(TARGET, say, tuple(which))
    left = S.find_pids(TARGET, which)
    if left:
        say(f"아직 남아 있음: {left}")
        return False
    if not before and not use_systemd():
        say("켜져 있던 것이 없습니다")
    else:
        say("꺼짐 확인")
    return True


def status():
    up = S.listening_ports()
    p = ports()
    pids = S.find_pids(TARGET) if os.access("/proc/1/cwd", os.R_OK) else None
    print(f"설치 위치: {TARGET}" + ("   (systemd 서비스로 관리)" if use_systemd() else ""))
    for w in ("warden", "dashboard"):
        on = p[w] in up
        mine = [pid for pid, n in (pids or {}).items() if n == w]
        extra = f", pid {', '.join(map(str, mine))}" if mine else ""
        print(f"  {S._pad(NAMES[w], 9)}{'켜짐' if on else '꺼짐'} (포트 {p[w]}{extra})")
    if p["warden"] in up:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/api/status", timeout=3) as r:
                st = json.load(r)
            print(f"  {S._pad('모드', 9)}{'탐지만 (dry-run)' if st.get('dry_run') else '실제 차단'} · 감시 {st.get('interface')} · "
                  f"차단 중 {st.get('blocked_count', 0)}건 · 켜진 지 {int(st.get('uptime_sec', 0)) // 60}분")
        except (OSError, ValueError):
            print("  모드     (WARDEN API 가 아직 응답하지 않음 — 막 켠 경우 잠시 뒤 다시)")
    d = dash_config()
    if d:
        print(f"  {S._pad('주소', 9)}http://{d.get('host')}:{d.get('port')}")
    if not (p["warden"] in up and p["dashboard"] in up):
        print("  켜기: wstart")
    return True


def log(which):
    need_root()
    for w in which:
        path = os.path.join(TARGET, "logs", f"{w}.out")
        print(f"── {NAMES[w]} ({path})")
        if not os.path.exists(path):
            print("  기록 없음 (wstart 로 켠 적이 없거나 다른 방법으로 켬)")
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()[-40:]
        token = dash_config().get("token")
        for line in lines:
            print(line.replace(token, "********") if token else line)    # 토큰은 가려서 보여 줌
    return True


WARDEN_API = "http://127.0.0.1:8000"
CHAIN = "WARDEN"


def api(path, body=None):
    req = urllib.request.Request(WARDEN_API + path, method="GET" if body is None else "POST",
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)


def write_audit(action, detail):
    """대시보드와 같은 감사 기록(audit.jsonl)에 남김. 파일을 새로 만들면 주인을 설치 폴더 주인으로 맞춤
    (root 소유가 되면 대시보드가 더 이상 기록하지 못함)"""
    path = os.path.join(TARGET, "audit.jsonl")
    existed = os.path.exists(path)
    entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "ip": "서버 터미널", "action": action, "detail": detail, "code": 200}
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        if not existed:
            st = os.stat(TARGET)
            os.chown(path, st.st_uid, st.st_gid)
    except OSError as e:
        say(f"(감사 기록을 남기지 못함: {e})")


def ask_yes(question, read=input):
    """yes 를 그대로 입력해야만 진행 (엔터·y 는 취소)"""
    try:
        return read(f"\n{question}\n진행하려면 yes 를 입력하세요 (그 밖에는 취소): ").strip() == "yes"
    except EOFError:
        return False


def _left(item):
    if item.get("permanent"):
        return "영구"
    sec = max(0, int(item.get("remaining_sec") or 0))
    return f"{sec // 60}분 {sec % 60}초 남음"


def unblock_all(read=input):
    """긴급 전체 해제. WARDEN 이 응답하면 API 로 하나씩 풀고(목록·영구 차단 파일·탐지 로그가 같이 정리됨),
    응답하지 않으면 방화벽 WARDEN 체인을 직접 비운다"""
    need_root()
    try:
        data = api("/api/blocked")
    except (OSError, ValueError):
        data = None
    if data is not None:
        items, sim = data.get("blocked", []), bool(data.get("simulated"))
        if not items:
            say("차단 중인 대상이 없습니다")
            return True
        print(f"지금 차단 중 {len(items)}개" + (" (탐지만(dry-run) 모드라 모의 목록입니다. 해제하면 목록만 비워집니다)" if sim else "") + ":")
        for it in items:
            note = f" · 메모: {it['note']}" if it.get("note") else ""
            print(f"  {S._pad(it['target'], 24)}{S._pad(str(it.get('reason', '')), 18)}{_left(it)}{note}")
        if not ask_yes(f"위 {len(items)}개를 모두 해제합니다. 공격이 계속되면 규칙에 따라 다시 차단될 수 있습니다.", read):
            say("취소했습니다 (아무것도 바꾸지 않음)")
            return True
        done, failed = [], []
        for it in items:
            try:
                (done if api("/api/unblock", {"target": it["target"]}).get("ok") else failed).append(it["target"])
            except (OSError, ValueError):
                failed.append(it["target"])
        say(f"해제함 {len(done)}개" + (f", 실패 {len(failed)}개: {', '.join(failed)}" if failed else ""))
        write_audit("unblock_all", {"via": "api", "dry_run": sim, "count": len(done), "targets": done, "failed": failed})
        return not failed
    # WARDEN 이 꺼졌거나 멈춤: 방화벽에 남은 규칙을 직접 비움
    say("WARDEN API 가 응답하지 않습니다 (꺼졌거나 멈춤). 방화벽의 WARDEN 체인을 직접 확인합니다")
    code, text = S.run(["iptables", "-S", CHAIN])
    if code != 0:
        say(f"WARDEN 체인이 없습니다 (차단 규칙 없음): {text.strip()}")
        return True
    rules = [l for l in text.splitlines() if l.startswith(f"-A {CHAIN} ")]
    if not rules:
        say("WARDEN 체인이 비어 있습니다 (차단 규칙 없음)")
        return True
    print(f"방화벽 WARDEN 체인의 규칙 {len(rules)}개:")
    for l in rules:
        print("  " + l)
    if not ask_yes(f"방화벽 규칙 {len(rules)}개를 모두 지웁니다 (iptables -F {CHAIN}).", read):
        say("취소했습니다 (아무것도 바꾸지 않음)")
        return True
    code, text = S.run(["iptables", "-F", CHAIN])
    if code != 0:
        say(f"실패: {text.strip()}")
        return False
    say(f"WARDEN 체인을 비웠습니다 ({len(rules)}개)")
    perm = os.path.join(TARGET, "logs", "permanent_blocks.json")
    if S.load_json(perm, {}):
        say(f"주의: 영구 차단 기록({perm})은 그대로라 WARDEN 을 다시 켜면 그 대상은 다시 차단됩니다.")
        say("      다시 켠 뒤 wunblock 을 한 번 더 하면 기록까지 정리됩니다")
    write_audit("unblock_all", {"via": "iptables", "count": len(rules)})
    return True


def main():
    args = sys.argv[1:]
    if args and args[0] == "unblock-all":
        sys.exit(0 if unblock_all() else 1)
    if not args or args[0] not in ("start", "stop", "restart", "status", "log"):
        print(__doc__.strip())
        sys.exit(2)
    cmd = args[0]
    which = ("warden", "dashboard")
    if len(args) > 1:
        if args[1] not in NAMES:
            sys.exit("대상은 warden 또는 dashboard 입니다")
        which = (args[1],)
    if cmd == "start":
        ok = start(which)
    elif cmd == "stop":
        ok = stop(which)
    elif cmd == "restart":
        ok = stop(which) and start(which)
    elif cmd == "status":
        ok = status()
    else:
        ok = log(which)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
