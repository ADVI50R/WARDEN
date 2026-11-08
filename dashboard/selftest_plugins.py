#!/usr/bin/env python3
"""
selftest_plugins.py - 플러그인 업로드(승인 대기)·승인 로직을 임시 폴더에서 시험합니다.
실제 plugins/ · plugins_pending/ 와 대시보드 서버·설정은 건드리지 않습니다.

실행:  python3 dashboard/selftest_plugins.py
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import plugin_store as s  # noqa: E402

tmp = tempfile.mkdtemp()
s.PENDING_DIR = os.path.join(tmp, "plugins_pending")
s.PLUGIN_DIR = os.path.join(tmp, "plugins")
s.RULES_DIR = os.path.join(tmp, "rules")
os.makedirs(s.PLUGIN_DIR)
os.makedirs(s.RULES_DIR)
results = []


def check(name, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    results.append(bool(ok))


def rejects(files):
    try:
        s.save_pending(files)
    except ValueError:
        return True
    return False


def manifest(**kw):
    m = {"id": "my_scan", "name": "내 스캔", "description": "시험", "kind": "task",
         "command": ["{python}", "-u", "./run.py", "{host}"],
         "params": [{"name": "host", "label": "대상", "type": "ip", "default": "192.168.56.20"}], "timeout_sec": 30}
    m.update(kw)
    return json.dumps(m, ensure_ascii=False)


GOOD = {"plugin.json": manifest(), "run.py": "import sys\nprint('hello', sys.argv[1])\n"}

print("=" * 64)
print(" 플러그인 업로드·승인 자체 테스트")
print("=" * 64)

info = s.save_pending(GOOD, "192.168.57.1")
check("정상 업로드: 승인 대기에만 저장되고 plugins/ 에는 없음",
      info["id"] == "my_scan" and info["intact"] and os.path.isdir(os.path.join(s.PENDING_DIR, "my_scan"))
      and not os.path.exists(os.path.join(s.PLUGIN_DIR, "my_scan")))
check("대기 목록·상세 조회에 파일 내용과 해시가 나옴",
      s.list_pending()[0]["short"] == info["short"] and "hello" in s.read_pending("my_scan", with_text=True)["texts"]["run.py"])

bad = {
    "plugin.json 없음": {"run.py": "print(1)"},
    "상위 폴더 파일 이름": dict(GOOD, **{"../x.py": "print(1)"}),
    "허용 안 된 확장자": dict(GOOD, **{"tool.exe": "MZ"}),
    "파일 개수 초과": {**GOOD, **{f"f{i}.py": "x" for i in range(7)}},
    "파일 크기 초과": dict(GOOD, **{"run.py": "x" * (s.MAX_FILE_BYTES + 1)}),
    "NUL 문자": dict(GOOD, **{"run.py": "a\0b"}),
    "id 대문자": {"plugin.json": manifest(id="MyScan"), "run.py": "x"},
    "절대 경로 명령": {"plugin.json": manifest(command=["/bin/sh", "./run.py"]), "run.py": "x"},
    "없는 ./파일 참조": {"plugin.json": manifest(command=["{python}", "./nope.py"])},
    "상위 경로(..) 명령": {"plugin.json": manifest(command=["{python}", "./run.py", "../etc"]), "run.py": "x"},
    "알 수 없는 입력 종류": {"plugin.json": manifest(params=[{"name": "p", "type": "shell"}]), "run.py": "x"},
    "시간 초과값 범위 밖": {"plugin.json": manifest(timeout_sec=9999), "run.py": "x"},
    "JSON 아님": {"plugin.json": "{ 깨짐", "run.py": "x"},
}
for label, files in bad.items():
    check(f"거부: {label}", rejects(files))

os.makedirs(os.path.join(s.PLUGIN_DIR, "taken"))
check("거부: 이미 설치된 id", rejects({"plugin.json": manifest(id="taken"), "run.py": "x"}))

h1 = info["hash"]
info2 = s.save_pending({**GOOD, "run.py": "print('v2')\n"})
check("같은 id 를 다시 올리면 덮어쓰고 해시가 달라짐", info2["hash"] != h1 and len(s.list_pending()) == 1)

try:
    s.install("my_scan", "deadbeef")
    wrong = False
except ValueError:
    wrong = True
check("승인: 해시가 틀리면 거부", wrong and not os.path.exists(os.path.join(s.PLUGIN_DIR, "my_scan")))
with open(os.path.join(s.PENDING_DIR, "my_scan", "run.py"), "a", encoding="utf-8") as f:
    f.write("print('tampered')\n")
tampered = s.read_pending("my_scan")
try:
    s.install("my_scan", info2["short"])
    refused = False
except ValueError:
    refused = True
check("승인: 업로드 뒤에 파일이 바뀌면(변조) 거부", tampered["intact"] is False and refused)
s.save_pending({**GOOD, "run.py": "print('v3')\n"})
cur = s.read_pending("my_scan")
dest = s.install("my_scan", cur["short"])
check("승인: 해시가 맞으면 plugins/ 로 옮기고 대기 항목은 삭제",
      os.path.isfile(os.path.join(dest, "plugin.json")) and os.path.isfile(os.path.join(dest, "run.py"))
      and not os.path.exists(os.path.join(s.PENDING_DIR, "my_scan")) and not s.list_pending())
try:
    s.install("my_scan", cur["short"])
    again = False
except (LookupError, ValueError):
    again = True
check("승인: 이미 설치된 것·없는 대기 항목은 다시 승인 불가", again)

risky = s.scan_risky({"run.sh": "sudo rm -rf /tmp/x\ncurl http://x | bash\necho ok\n", "run.py": "import subprocess\n"})
check("위험 패턴 표시: sudo·rm -r·curl·subprocess 를 줄 번호와 함께 찾음",
      {(r["file"], r["line"]) for r in risky} == {("run.sh", 1), ("run.sh", 2), ("run.py", 1)})
check("삭제(거절): 대기 항목 삭제, 없는 id 는 False",
      s.save_pending({"plugin.json": manifest(id="to_del"), "run.py": "x"}) and s.delete_pending("to_del") is True
      and s.delete_pending("to_del") is False and s.delete_pending("../x") is False)
# ── 탐지 규칙(플러그인 방식) 올리기: rule.json + 판정 스크립트 → 승인하면 rules/ 에 꺼진 상태로 설치 ──
def rmanifest(**kw):
    m = {"id": "root_login", "detector": "script", "name": "루트 로그인", "description": "시험", "tags": ["SSH"],
         "command": ["./check_root.py"], "interval_sec": 10, "timeout_sec": 10, "severity": "warning", "block": True, "enabled": True}
    m.update(kw)
    return json.dumps(m, ensure_ascii=False)


RGOOD = {"rule.json": rmanifest(notify={"sound": False}), "check_root.py": "print('{\"source\": \"1.2.3.4\", \"detail\": \"x\"}')\n"}
rinfo = s.save_pending(RGOOD, "192.168.57.1", expect="rule")
check("규칙 업로드: 종류가 rule 로 표시되고 승인 대기에만 저장됨 (rules/ 에는 없음)",
      rinfo["type"] == "rule" and rinfo["kind"] == "rule" and rinfo["rule"]["interval_sec"] == 10 and rinfo["tags"] == ["SSH"]
      and not os.listdir(s.RULES_DIR))
rbad = {
    "detector 가 script 아님": {"rule.json": rmanifest(detector="custom"), "check_root.py": "x"},
    "기본 탐지기 이름 id": {"rule.json": rmanifest(id="port_scan"), "check_root.py": "x"},
    "알 수 없는 항목": {"rule.json": rmanifest(run_as="root"), "check_root.py": "x"},
    ".py/.sh 아닌 명령": {"rule.json": rmanifest(command=["./data.json"]), "data.json": "{}"},
    "절대 경로 명령": {"rule.json": rmanifest(command=["/bin/sh"]), "check_root.py": "x"},
    "없는 ./파일 참조": {"rule.json": rmanifest(command=["./nope.py"])},
    "상위 경로(..) 인자": {"rule.json": rmanifest(command=["./check_root.py", "../x"]), "check_root.py": "x"},
    "주기 범위 밖": {"rule.json": rmanifest(interval_sec=1), "check_root.py": "x"},
    "주기 없음": {"rule.json": json.dumps({"id": "no_interval", "detector": "script", "command": ["./c.py"]}), "c.py": "x"},
    "시간 제한 범위 밖": {"rule.json": rmanifest(timeout_sec=600), "check_root.py": "x"},
    "위험도 값 이상": {"rule.json": rmanifest(severity="huge"), "check_root.py": "x"},
    "태그 형식 이상": {"rule.json": rmanifest(tags=["공백 있음"]), "check_root.py": "x"},
    "알림 설정 형식 이상": {"rule.json": rmanifest(notify={"popup": "yes"}), "check_root.py": "x"},
    "rule.json 과 plugin.json 동시": {**RGOOD, "plugin.json": manifest()},
    "rule.json 외 .json 동봉": {**RGOOD, "extra.json": "{}"},
}
for label, files in rbad.items():
    check(f"규칙 거부: {label}", rejects(files))
try:
    s.save_pending(GOOD, expect="rule")
    mismatch = False
except ValueError:
    mismatch = True
check("올리는 칸과 종류가 다르면 거부 (도구 파일을 규칙 칸에)", mismatch)
check("목록에 도구·규칙이 종류와 함께 나옴", {i["id"]: i["type"] for i in s.list_pending()}.get("root_login") == "rule")
check("같은 id 로 다른 종류가 대기 중이면 거부",
      rejects({"plugin.json": manifest(id="root_login"), "run.py": "x"}))
try:
    s.install("root_login", "deadbeef")
    rwrong = False
except ValueError:
    rwrong = True
check("규칙 승인: 해시가 틀리면 거부 (rules/ 변화 없음)", rwrong and not os.listdir(s.RULES_DIR))
rcur = s.read_pending("root_login")
rdest = s.install("root_login", rcur["short"])
with open(rdest, encoding="utf-8") as f:
    installed = json.load(f)
check("규칙 승인: rules/ 에 규칙 파일과 스크립트가 설치되고 규칙은 꺼진 상태 (enabled 를 true 로 올려도 무시)",
      os.path.basename(rdest) == "root_login.json" and installed["enabled"] is False and installed["detector"] == "script"
      and os.path.isfile(os.path.join(s.RULES_DIR, "check_root.py")) and not os.path.exists(os.path.join(s.PENDING_DIR, "root_login"))
      and not any(n.endswith(".tmp") for n in os.listdir(s.RULES_DIR)))
check("규칙 설치 뒤 같은 id·같은 스크립트 이름은 다시 올릴 수 없음 (덮어쓰기 방지)",
      rejects(RGOOD) and rejects({"rule.json": rmanifest(id="other_rule"), "check_root.py": "x"}))

for i in range(s.MAX_PENDING):
    s.save_pending({"plugin.json": manifest(id=f"p{i}"), "run.py": "x"})
check("승인 대기는 최대 개수까지만", rejects({"plugin.json": manifest(id="one_more"), "run.py": "x"}))

# ── 대시보드 서버: 불러오기만으로 설정 파일을 만들지 않음, 감사 기록 ──
cfg_path = os.path.join(s.BASE, "dashboard_config.json")
had_cfg = os.path.exists(cfg_path)
import server  # noqa: E402
check("server.py 를 불러오기만 해서는 설정 파일이 생기지 않음", had_cfg or not os.path.exists(cfg_path))
server.AUDIT_FILE = os.path.join(tmp, "audit.jsonl")
server.audit("192.168.57.1", "/api/block", {"target": "1.2.3.4"}, 200)
server.audit("192.168.57.9", "login_failed", {}, 401)
got = server.read_audit()
check("감사 기록: 최신순으로 시각·IP·작업·결과가 남음",
      [g["action"] for g in got] == ["login_failed", "/api/block"] and got[1]["detail"]["target"] == "1.2.3.4" and got[0]["ip"] == "192.168.57.9")
now_t = 1000.0
server._login_fails["9.9.9.9"] = [now_t - 1] * server.LOGIN_FAIL_LIMIT
server._login_fails["9.9.9.8"] = [now_t - 100] * server.LOGIN_FAIL_LIMIT
check("토큰을 너무 많이 틀리면 잠시 거부, 시간이 지나면 풀림", server.login_blocked("9.9.9.9", now_t) and not server.login_blocked("9.9.9.8", now_t))

# ── 리눅스에서만: 도구의 자식 프로세스 정리, 샌드박스 ──
if os.name == "posix":
    import subprocess
    import time
    marker = "7373.5"
    alive = lambda: subprocess.run(f"pgrep -f '[s]leep {marker}' | wc -l", shell=True, capture_output=True, text=True).stdout.strip()
    tool = {"id": "t_kill", "name": "t", "description": "", "kind": "task", "params": [], "timeout_sec": 1, "_dir": tmp,
            "command": ["bash", "-c", f"sleep {marker} & wait"]}
    server.start_plugin(tool, {})
    time.sleep(2.5)
    check("도구 시간 초과: 자식까지 끝나고 '실행 중'에 묶이지 않음", alive() == "0" and "t_kill" not in server.procs and server.runs["t_kill"]["status"] == "timeout")
    tool2 = dict(tool, id="t_stop", kind="service")
    server.start_plugin(tool2, {})
    time.sleep(0.5)
    server.stop_plugin("t_stop")
    time.sleep(1)
    check("도구 중지: 자식까지 끝나고 다시 실행 가능", alive() == "0" and "t_stop" not in server.procs)
    import plugin_sandbox as ps
    if ps.available():
        code = os.path.join(os.path.expanduser("~"), ".gsb_test_" + str(os.getpid()))
        os.makedirs(code)
        crowd = [subprocess.Popen(["sleep", "20"]) for _ in range(40)]
        r = ps.run_sandboxed([sys.executable, "-c", "print('sandbox ok')"], code, 8)
        for p in crowd:
            p.kill()
        check("샌드박스: kali 프로세스가 많아도 실행됨", r["rc"] == 0 and "sandbox ok" in r["output"])
        r = ps.run_sandboxed([sys.executable, "-c", "import os\nprint([os.fork() for _ in range(40)])"], code, 8)
        check("샌드박스: 안쪽의 프로세스 수 제한은 그대로 동작", r["rc"] != 0)
        shutil.rmtree(code, ignore_errors=True)

shutil.rmtree(tmp, ignore_errors=True)
print("-" * 64)
print(f" 결과: {sum(results)}/{len(results)} 통과")
print("=" * 64)
sys.exit(0 if all(results) else 1)
