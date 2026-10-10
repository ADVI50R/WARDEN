#!/usr/bin/env python3
"""
Guardian 관제 대시보드 서버 (파이썬 표준 라이브러리만 사용 -> 인터넷 없이 실행 가능)

역할
  1) static/ 의 웹페이지(HTML/JS/CSS)를 보여준다
  2) Guardian REST API(127.0.0.1:8000)를 대신 호출해 준다 (프록시)
     -> Guardian API 는 계속 127.0.0.1 에만 열어 두면 되므로 더 안전
  3) plugins/ 폴더의 플러그인(보안 스크립트)을 목록/실행/중지/켜기끄기 한다

실행:  python3 server.py            (설정은 dashboard_config.json, 처음 실행 시 자동 생성)
"""
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
PLUGIN_DIR = os.path.join(BASE, "plugins")
CONFIG_FILE = os.path.join(BASE, "dashboard_config.json")
STATE_FILE = os.path.join(BASE, "plugins_state.json")

DEFAULT_CONFIG = {
    "host": "0.0.0.0",                       # 다른 PC(윈도우 10)에서 접속하려면 0.0.0.0 또는 관리망 IP
    "port": 8080,
    "guardian_url": "http://127.0.0.1:8000",
    "token": "",                             # 비어 있으면 처음 실행 때 자동 생성
}

# 대시보드가 Guardian 에 전달해도 되는 경로만 허용
GUARDIAN_GET = {"/api/status", "/api/events", "/api/blocked", "/api/rules"}
GUARDIAN_POST = {"/api/block", "/api/unblock"}

MAX_OUTPUT_LINES = 500


# ─────────────────────────── 설정 ───────────────────────────
def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg.update(json.load(f))
    if not cfg.get("token"):
        cfg["token"] = secrets.token_urlsafe(12)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.chmod(CONFIG_FILE, 0o600)
    return cfg


CFG = load_config()


# ─────────────────────────── 플러그인 ───────────────────────────
# 플러그인 = plugins/<id>/plugin.json (+ 필요하면 스크립트). 형식은 dashboard/README.md 참고.
PARAM_PATTERNS = {
    "text": re.compile(r"^[\w .:/@,=-]{0,100}$"),
}
state_lock = threading.Lock()
runs = {}          # plugin_id -> 마지막 실행 정보
procs = {}         # plugin_id -> 실행 중인 Popen


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def load_plugins():
    """plugins/ 를 매번 새로 읽는다 -> 폴더만 추가하면 서버 재시작 없이 목록에 나타남."""
    found = {}
    if not os.path.isdir(PLUGIN_DIR):
        return found
    for name in sorted(os.listdir(PLUGIN_DIR)):
        mf = os.path.join(PLUGIN_DIR, name, "plugin.json")
        if not os.path.isfile(mf):
            continue
        try:
            with open(mf, encoding="utf-8") as f:
                m = json.load(f)
            if m.get("id") != name:
                raise ValueError("id 는 폴더 이름과 같아야 합니다")
            if not isinstance(m.get("command"), list) or not m["command"]:
                raise ValueError("command 는 비어 있지 않은 목록이어야 합니다")
            m.setdefault("name", name)
            m.setdefault("description", "")
            m.setdefault("kind", "task")
            m.setdefault("params", [])
            m.setdefault("timeout_sec", 30)
            m["_dir"] = os.path.join(PLUGIN_DIR, name)
            found[name] = m
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"[!] 플러그인 '{name}' 불러오기 실패: {e}")
    return found


def validate_param(spec, value):
    """사용자가 입력한 값을 검사해 문자열로 돌려준다. 이상하면 ValueError."""
    t = spec.get("type", "text")
    if value is None or value == "":
        value = spec.get("default", "")
    value = str(value)
    if t == "ip":
        return str(ipaddress.ip_address(value))
    if t == "int":
        n = int(value)
        if not spec.get("min", -2**31) <= n <= spec.get("max", 2**31):
            raise ValueError("범위를 벗어난 숫자")
        return str(n)
    if t == "choice":
        if value not in spec.get("choices", []):
            raise ValueError("허용되지 않은 선택지")
        return value
    if t == "text":
        if value.startswith("-") or not PARAM_PATTERNS["text"].match(value):
            raise ValueError("허용되지 않은 문자")
        return value
    raise ValueError(f"알 수 없는 type: {t}")


def build_command(plugin, params):
    values = {}
    for spec in plugin["params"]:
        try:
            values[spec["name"]] = validate_param(spec, params.get(spec["name"]))
        except (ValueError, TypeError) as e:
            raise ValueError(f"'{spec.get('label', spec['name'])}': {e}")
    cmd = []
    for part in plugin["command"]:
        part = str(part).replace("{python}", sys.executable)
        for k, v in values.items():
            part = part.replace("{" + k + "}", v)
        cmd.append(part)
    if cmd[0].startswith("./"):                  # 플러그인 폴더 안의 스크립트
        cmd[0] = os.path.join(plugin["_dir"], cmd[0][2:])
    return cmd


def _reader(pid, proc, run):
    for line in proc.stdout:
        with state_lock:
            run["output"].append(line.rstrip("\n"))
            del run["output"][:-MAX_OUTPUT_LINES]
    rc = proc.wait()
    with state_lock:
        if run["status"] == "running":
            run["status"] = "done" if rc == 0 else "failed"
        run["rc"], run["ended"] = rc, time.time()
        procs.pop(pid, None)


def _watchdog(pid, proc, timeout):
    time.sleep(timeout)
    if proc.poll() is None:
        with state_lock:
            if pid in runs:
                runs[pid]["status"] = "timeout"
        proc.kill()


def start_plugin(plugin, params):
    pid = plugin["id"]
    with state_lock:
        if pid in procs:
            raise RuntimeError("이미 실행 중입니다")
    cmd = build_command(plugin, params)
    try:
        proc = subprocess.Popen(cmd, cwd=plugin["_dir"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, text=True, bufsize=1)
    except OSError as e:
        raise RuntimeError(f"실행 실패: {e}")
    run = {"status": "running", "started": time.time(), "ended": None, "rc": None,
           "command": " ".join(cmd), "output": []}
    with state_lock:
        runs[pid] = run
        procs[pid] = proc
    threading.Thread(target=_reader, args=(pid, proc, run), daemon=True).start()
    if plugin["kind"] == "task":                 # service 는 사용자가 중지할 때까지 계속 실행
        threading.Thread(target=_watchdog, args=(pid, proc, plugin["timeout_sec"]), daemon=True).start()
    return run


def stop_plugin(pid):
    with state_lock:
        proc = procs.get(pid)
        if not proc:
            return False
        runs[pid]["status"] = "stopped"
    proc.terminate()
    return True


def describe(plugin, state):
    pid = plugin["id"]
    with state_lock:
        run = runs.get(pid)
        info = None
        if run:
            info = {k: run[k] for k in ("status", "started", "ended", "rc", "command")}
            info["output"] = run["output"][-MAX_OUTPUT_LINES:]
    return {
        "id": pid, "name": plugin["name"], "description": plugin["description"],
        "kind": plugin["kind"], "params": plugin["params"],
        "enabled": state.get(pid, {}).get("enabled", True),
        "running": pid in procs, "last_run": info,
    }


# ─────────────────────────── HTTP ───────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "GuardianDash"

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        given = self.headers.get("X-Token", "")
        return hmac.compare_digest(given.encode(), CFG["token"].encode())

    def _body(self):
        try:
            n = min(int(self.headers.get("Content-Length", 0)), 100_000)
            body = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, UnicodeDecodeError):
            return {}
        return body if isinstance(body, dict) else {}

    # ── 정적 파일 ──
    def _static(self, path):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        full = os.path.realpath(os.path.join(STATIC, rel))
        if not full.startswith(os.path.realpath(STATIC) + os.sep) or not os.path.isfile(full):
            return self._json(404, {"error": "not found"})
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", (mimetypes.guess_type(full)[0] or "application/octet-stream")
                         + ("; charset=utf-8" if full.endswith((".html", ".js", ".css")) else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    # ── Guardian 프록시 ──
    def _proxy(self, path_with_query, method, body=None):
        url = CFG["guardian_url"].rstrip("/") + path_with_query
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return self._json(r.status, json.loads(r.read()))
        except urllib.error.HTTPError as e:
            try:
                return self._json(e.code, json.loads(e.read()))
            except ValueError:
                return self._json(e.code, {"error": "Guardian 오류"})
        except (urllib.error.URLError, OSError, ValueError):
            return self._json(502, {"error": "Guardian 에 연결할 수 없습니다 (guardian.py 가 실행 중인지, "
                                             "config.json 의 api.enabled / port 를 확인하세요)"})

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/health":
            return self._json(200, {"ok": True})
        if not u.path.startswith("/api/"):
            return self._static(u.path)
        if not self._authed():
            return self._json(401, {"error": "토큰이 필요합니다"})
        if u.path in GUARDIAN_GET:
            return self._proxy(u.path + (f"?{u.query}" if u.query else ""), "GET")
        if u.path == "/api/plugins":
            state = load_state()
            return self._json(200, {"plugins": [describe(p, state) for p in load_plugins().values()]})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if not self._authed():
            return self._json(401, {"error": "토큰이 필요합니다"})
        body = self._body()
        if u.path in GUARDIAN_POST:
            return self._proxy(u.path, "POST", body)
        m = re.fullmatch(r"/api/plugins/([\w-]+)/(run|stop|enable)", u.path)
        if not m:
            return self._json(404, {"error": "not found"})
        pid, action = m.groups()
        plugin = load_plugins().get(pid)
        if not plugin:
            return self._json(404, {"error": "없는 플러그인"})
        if action == "enable":
            with state_lock:
                state = load_state()
                state.setdefault(pid, {})["enabled"] = bool(body.get("enabled", True))
                save_state(state)
            if not state[pid]["enabled"]:
                stop_plugin(pid)
            return self._json(200, {"ok": True})
        if action == "stop":
            return self._json(200, {"ok": stop_plugin(pid)})
        if not load_state().get(pid, {}).get("enabled", True):
            return self._json(409, {"error": "비활성화된 플러그인입니다"})
        try:
            start_plugin(plugin, body.get("params") or {})
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        except RuntimeError as e:
            return self._json(409, {"error": str(e)})
        self._json(200, {"ok": True})

    def log_message(self, *args):
        pass


def main():
    server = ThreadingHTTPServer((CFG["host"], CFG["port"]), Handler)
    print("=" * 60)
    print(f" 대시보드 : http://{CFG['host']}:{CFG['port']}/   (브라우저에서 접속)")
    print(f" 로그인 토큰 : {CFG['token']}")
    print(f" Guardian : {CFG['guardian_url']}")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for pid in list(procs):
            stop_plugin(pid)


if __name__ == "__main__":
    main()
