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
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import plugin_sandbox
import plugin_store

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
PLUGIN_DIR = os.path.join(BASE, "plugins")
CONFIG_FILE = os.path.join(BASE, "dashboard_config.json")

DEFAULT_CONFIG = {
    "host": "0.0.0.0",                       # 다른 PC(윈도우 10)에서 접속하려면 0.0.0.0 또는 관리망 IP
    "port": 8080,
    "guardian_url": "http://127.0.0.1:8000",
    "token": "",                             # 비어 있으면 처음 실행 때 자동 생성
}

# 대시보드가 Guardian 에 전달해도 되는 경로만 허용
GUARDIAN_GET = {"/api/status", "/api/events", "/api/blocked", "/api/rules", "/api/history", "/api/rule_changes",
                "/api/packets", "/api/event_analysis"}
GUARDIAN_POST = {"/api/block", "/api/unblock", "/api/note", "/api/rules", "/api/rules/update", "/api/rules/enable",
                 "/api/rules/delete", "/api/dry_run", "/api/whitelist"}

MAX_OUTPUT_LINES = 500
UPLOAD_MAX_BODY = 600_000        # 플러그인 업로드 한 번의 최대 크기 (바이트)


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


CFG = dict(DEFAULT_CONFIG)        # 실제 값은 main() 에서 읽는다 (불러오기만 해도 설정 파일이 생기면 시험하다 진짜 설정을 덮어쓸 수 있음)


# ─────────────────────────── 감사 기록 ───────────────────────────
# 토큰 하나로 모든 조작이 되므로 "언제, 어느 IP 에서, 무엇을" 했는지 남긴다 (조회는 기록하지 않음). 로그인 실패도 남긴다.
AUDIT_FILE = os.path.join(os.path.dirname(BASE), "audit.jsonl")
AUDIT_MAX_BYTES = 1_000_000
AUDIT_KEYS = ("target", "id", "dry_run", "enabled", "permanent", "duration_sec", "overwrite", "action")
audit_lock = threading.Lock()
LOGIN_FAIL_LIMIT, LOGIN_FAIL_WINDOW = 10, 60
_login_fails = {}                  # IP -> 최근 실패 시각들


def audit(ip, action, detail, code):
    entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "ip": ip, "action": action, "detail": detail, "code": code}
    with audit_lock:
        try:
            if os.path.exists(AUDIT_FILE) and os.path.getsize(AUDIT_FILE) > AUDIT_MAX_BYTES:
                os.replace(AUDIT_FILE, AUDIT_FILE + ".old")
            fd = os.open(AUDIT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as e:
            print(f"[!] 감사 기록 실패: {e}")


def read_audit(limit=200):
    with audit_lock:
        try:
            with open(AUDIT_FILE, encoding="utf-8") as f:
                lines = f.readlines()[-limit:]
        except OSError:
            return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def login_blocked(ip, now):
    """짧은 시간에 토큰을 너무 많이 틀린 IP 인지"""
    recent = [t for t in _login_fails.get(ip, []) if now - t < LOGIN_FAIL_WINDOW]
    if recent:
        _login_fails[ip] = recent
    else:
        _login_fails.pop(ip, None)
    return len(recent) >= LOGIN_FAIL_LIMIT


# ─────────────────────────── 플러그인 ───────────────────────────
# 플러그인 = plugins/<id>/plugin.json (+ 필요하면 스크립트). 형식은 dashboard/README.md 참고.
PARAM_PATTERNS = {
    "text": re.compile(r"^[\w .:/@,=-]{0,100}$"),
}
state_lock = threading.Lock()
runs = {}          # plugin_id -> 마지막 실행 정보
procs = {}         # plugin_id -> 실행 중인 Popen
plugin_errors = {}  # 폴더 이름 -> 불러오기 실패 이유 (화면에 표시)
_seen_errors = {}


def load_plugins():
    """plugins/ 를 매번 새로 읽는다 -> 폴더만 추가하면 서버 재시작 없이 목록에 나타남."""
    found = {}
    plugin_errors.clear()
    if not os.path.isdir(PLUGIN_DIR):
        return found
    for name in sorted(os.listdir(PLUGIN_DIR)):
        if name.startswith((".", "_")) or not os.path.isdir(os.path.join(PLUGIN_DIR, name)):
            continue
        mf = os.path.join(PLUGIN_DIR, name, "plugin.json")
        if not os.path.isfile(mf):
            plugin_errors[name] = "plugin.json 파일이 없습니다"
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
            m["tags"] = plugin_store.normalize_tags(m.get("tags"))
            m.setdefault("params", [])
            m.setdefault("timeout_sec", 30)
            m["_dir"] = os.path.join(PLUGIN_DIR, name)
            found[name] = m
        except (OSError, ValueError, json.JSONDecodeError) as e:
            if _seen_errors.get(name) != str(e):      # 같은 오류를 3초마다 반복 출력하지 않음
                print(f"[!] 플러그인 '{name}' 불러오기 실패: {e}")
            plugin_errors[name] = _seen_errors[name] = str(e)
    for name in [n for n in _seen_errors if n not in plugin_errors]:
        del _seen_errors[name]               # 고쳐진 뒤 다시 깨지면 새로 알려줌
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


def _kill_group(proc, sig):
    """플러그인과 그 자식 프로세스까지 끝낸다 (플러그인마다 자기 프로세스 그룹으로 실행함).
    스크립트만 끝내면 자식이 출력 파이프를 잡고 있어서 '실행 중'에 묶이고 자식은 계속 돈다"""
    try:
        os.killpg(proc.pid, sig)
    except OSError:
        pass


def _watchdog(pid, proc, timeout):
    time.sleep(timeout)
    if proc.poll() is None:
        with state_lock:
            if pid in runs:
                runs[pid]["status"] = "timeout"
    _kill_group(proc, signal.SIGKILL)         # 스크립트가 끝났어도 남은 자식이 있으면 정리


def start_plugin(plugin, params):
    pid = plugin["id"]
    with state_lock:
        if pid in procs:
            raise RuntimeError("이미 실행 중입니다")
    cmd = build_command(plugin, params)
    try:
        proc = subprocess.Popen(cmd, cwd=plugin["_dir"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, text=True, errors="replace", bufsize=1, start_new_session=True)
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


def sandbox_run_pending(pid, params):
    """승인 대기 중인 업로드 하나를 plugins/ 로 옮기지 않고, 격리된 상태로 한 번만 실행해 본다.
    설치(plugin_store.install)는 여전히 보안 서버 터미널의 approve_plugin.py 에서만 할 수 있다 — 이 함수는
    '설치 없이 시험 실행'만 하고, 결과는 저장하지 않는다 (plugins/ 나 runs 상태에 남지 않음)."""
    info = plugin_store.read_pending(pid, with_text=True)
    if not info["intact"]:
        raise ValueError("업로드가 저장된 뒤 바뀐 것으로 보입니다 (변조 의심). 삭제하고 다시 올리세요")
    pid2, manifest, raw = plugin_store.parse_upload(info["texts"])
    if pid2 != pid:
        raise ValueError("매니페스트(plugin.json / rule.json)의 id 가 업로드 폴더 이름과 다릅니다")
    if plugin_store.bundle_kind(raw) == "rule":
        # 탐지 규칙 스크립트: 승인 대기 파일은 실행 권한이 없으므로 확장자로 해석기를 골라 한 번만 돌려 본다.
        # 실제 규칙은 Guardian 이 주기마다 돌리며, 출력의 한 줄 JSON({"source","detail"})이 판정이다
        first = manifest["command"][0][2:]
        interp = sys.executable if first.endswith(".py") else "bash"
        pdir = os.path.join(plugin_store.PENDING_DIR, pid)
        cmd = [interp, os.path.join(pdir, first)] + list(manifest["command"][1:])
        plugin = {"timeout_sec": manifest.get("timeout_sec", 10), "_dir": pdir}
        result = plugin_sandbox.run_sandboxed(cmd, plugin["_dir"], plugin["timeout_sec"])
        result["findings"] = info["findings"]
        return result
    plugin = {"command": manifest["command"], "params": manifest.get("params", []),
              "timeout_sec": manifest.get("timeout_sec", 30), "_dir": os.path.join(plugin_store.PENDING_DIR, pid)}
    cmd = build_command(plugin, params)
    result = plugin_sandbox.run_sandboxed(cmd, plugin["_dir"], plugin["timeout_sec"])
    result["findings"] = info["findings"]
    return result


def stop_plugin(pid):
    with state_lock:
        proc = procs.get(pid)
        if not proc:
            return False
        runs[pid]["status"] = "stopped"
    _kill_group(proc, signal.SIGTERM)
    threading.Timer(2, _kill_group, args=(proc, signal.SIGKILL)).start()     # 정상 종료할 시간을 준 뒤 남은 것을 강제로
    return True


def describe(plugin):
    pid = plugin["id"]
    with state_lock:
        run = runs.get(pid)
        info = None
        if run:
            info = {k: run[k] for k in ("status", "started", "ended", "rc", "command")}
            info["output"] = run["output"][-MAX_OUTPUT_LINES:]
    return {
        "id": pid, "name": plugin["name"], "description": plugin["description"],
        "kind": plugin["kind"], "tags": plugin.get("tags", []), "params": plugin["params"],
        "running": pid in procs, "last_run": info,
    }


# ─────────────────────────── HTTP ───────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "GuardianDash"

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._status = code
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        """토큰 확인. 틀리면 기록하고, 짧은 시간에 너무 많이 틀리면 맞는 토큰을 넣어도 잠시 거부한다"""
        ip, now = self.client_address[0], time.time()
        if login_blocked(ip, now):
            return False
        given = self.headers.get("X-Token", "")
        if hmac.compare_digest(given.encode(), CFG["token"].encode()):
            return True
        if given:                                 # 토큰 없이 온 요청(첫 화면)은 실패로 세지 않음
            _login_fails.setdefault(ip, []).append(now)
            audit(ip, "login_failed", {}, 401)
        return False

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

    def _proxy_pcap(self, path_with_query):
        """/api/pcap 은 JSON 이 아니라 파일(바이트)이라 따로 전달한다. 오류는 JSON 으로 온다"""
        req = urllib.request.Request(CFG["guardian_url"].rstrip("/") + path_with_query, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data = r.read(20_000_000)
                count = r.headers.get("X-Packet-Count", "")
        except urllib.error.HTTPError as e:
            try:
                return self._json(e.code, json.loads(e.read()))
            except ValueError:
                return self._json(e.code, {"error": "Guardian 오류"})
        except (urllib.error.URLError, OSError):
            return self._json(502, {"error": "Guardian 에 연결할 수 없습니다"})
        name = time.strftime("guardian_%Y%m%d_%H%M%S.pcap")
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("X-Packet-Count", count if count.isdigit() else "")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

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
        if u.path == "/api/pcap":
            return self._proxy_pcap(u.path + (f"?{u.query}" if u.query else ""))
        if u.path == "/api/whoami":
            return self._json(200, {"ip": self.client_address[0]})
        if u.path == "/api/audit":
            return self._json(200, {"audit": read_audit()})
        if u.path == "/api/plugins":
            plugins = load_plugins()
            return self._json(200, {"plugins": [describe(p) for p in plugins.values()],
                                    "errors": dict(plugin_errors)})
        if u.path == "/api/plugin_uploads":
            return self._json(200, {"uploads": plugin_store.list_pending()})
        m = re.fullmatch(r"/api/plugin_uploads/([a-z0-9_]{1,40})", u.path)
        if m:
            try:
                return self._json(200, plugin_store.read_pending(m.group(1), with_text=True))
            except LookupError:
                return self._json(404, {"error": "없는 승인 대기 항목"})
            except (OSError, ValueError) as e:
                return self._json(500, {"error": str(e)})
        self._json(404, {"error": "not found"})

    # ── 플러그인 업로드: 승인 대기 폴더에 저장만 함 (실행·설치는 터미널의 approve_plugin.py 에서만) ──
    def _upload(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = -1
        if not 0 < n <= UPLOAD_MAX_BODY:
            return self._json(413, {"error": f"업로드 크기는 {UPLOAD_MAX_BODY // 1000}KB 이하여야 합니다"})
        try:
            body = json.loads(self.rfile.read(n))
        except ValueError:
            return self._json(400, {"error": "JSON 형식이 아닙니다"})
        expect = body.get("expect") if isinstance(body, dict) else None      # 도구 칸 / 탐지 규칙 칸에서 올렸는지
        if expect not in (None, "tool", "rule"):
            return self._json(400, {"error": "expect 는 tool 또는 rule 이어야 합니다"})
        try:
            info = plugin_store.save_pending(body.get("files") if isinstance(body, dict) else None, self.client_address[0], expect)
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        except OSError as e:
            return self._json(500, {"error": f"저장 실패: {e}"})
        self._detail = {"id": info["id"], "type": info["type"], "hash": info["short"]}
        self._json(200, {"ok": True, "upload": info})

    def do_POST(self):
        u = urlparse(self.path)
        if not self._authed():
            return self._json(401, {"error": "토큰이 필요합니다"})
        self._detail, self._status = {}, None
        try:
            self._post(u)
        finally:
            audit(self.client_address[0], u.path, self._detail, self._status)

    def _post(self, u):
        if u.path == "/api/plugin_uploads":
            return self._upload()
        m = re.fullmatch(r"/api/plugin_uploads/([a-z0-9_]{1,40})/delete", u.path)
        if m:
            return self._json(200, {"ok": plugin_store.delete_pending(m.group(1))})
        body = self._body()
        self._detail = {k: body[k] for k in AUDIT_KEYS if k in body}
        if isinstance(body.get("rule"), dict) and body["rule"].get("id"):     # 수정(/update)은 id 가 rule 밖에 있음
            self._detail["id"] = str(body["rule"]["id"])[:40]
        if u.path in GUARDIAN_POST:
            return self._proxy(u.path, "POST", body)
        m = re.fullmatch(r"/api/plugin_uploads/([a-z0-9_]{1,40})/run_sandboxed", u.path)
        if m:
            if not plugin_sandbox.available():
                return self._json(503, {"error": "샌드박스 도구(bwrap/prlimit/timeout)가 서버에 없습니다"})
            try:
                return self._json(200, sandbox_run_pending(m.group(1), body.get("params") or {}))
            except LookupError:
                return self._json(404, {"error": "없는 승인 대기 항목"})
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            except RuntimeError as e:
                return self._json(500, {"error": str(e)})
        m = re.fullmatch(r"/api/plugins/([\w-]+)/(run|stop)", u.path)
        if not m:
            return self._json(404, {"error": "not found"})
        pid, action = m.groups()
        plugin = load_plugins().get(pid)
        if not plugin:
            return self._json(404, {"error": "없는 플러그인"})
        if action == "stop":
            return self._json(200, {"ok": stop_plugin(pid)})
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
    CFG.update(load_config())
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
