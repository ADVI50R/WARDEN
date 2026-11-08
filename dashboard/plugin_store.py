#!/usr/bin/env python3
"""
플러그인 업로드 저장소 (승인 대기) — 파이썬 표준 라이브러리만 사용

대시보드(server.py)는 올라온 파일을 plugins_pending/<id>/ 에 '실행되지 않는 상태'로 저장만 한다.
plugins/ 로 옮겨 실제로 쓸 수 있게 만드는 승인은 보안 서버 터미널의 approve_plugin.py 에서만 가능하다
(대시보드 API 에는 승인 기능이 없다). 그래서 대시보드 토큰이 새도 업로드만으로는 코드가 실행되지 않는다.

한계: 이 모듈의 '위험 패턴 표시'는 검토하는 사람이 놓치지 않도록 돕는 표시일 뿐 보안 장치가 아니다.
승인할 때는 반드시 코드를 직접 읽어야 한다.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import time

BASE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.join(BASE, "plugins")
PENDING_DIR = os.path.join(os.path.dirname(BASE), "plugins_pending")      # dashboard/ 밖에 둠
RULES_DIR = os.path.join(os.path.dirname(BASE), "rules")                  # 플러그인 방식 규칙의 설치 위치 (Guardian 이 읽음)

ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
PARAM_RE = re.compile(r"^[a-z][a-z0-9_]{0,19}$")
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,59}$")                 # 첫 글자가 영문·숫자라서 _meta.json 과 겹치지 않음
ALLOWED_EXT = (".json", ".py", ".sh")
MAX_FILES, MAX_FILE_BYTES, MAX_PENDING = 6, 64 * 1024, 20
PARAM_TYPES = ("ip", "int", "choice", "text")
META_NAME = "_meta.json"
# 올리기는 두 종류: 도구(plugin.json + 스크립트 → plugins/) 와 플러그인 방식 탐지 규칙(rule.json + 스크립트 → rules/)
TOOL_MANIFEST, RULE_MANIFEST = "plugin.json", "rule.json"
RULE_KEYS = {"id", "detector", "name", "description", "tags", "notify", "enabled", "severity", "block", "block_duration_sec",
             "block_permanent", "command", "interval_sec", "timeout_sec"}
RESERVED_RULE_IDS = {"port_scan", "syn_flood", "icmp_flood", "ssh_bruteforce", "ssh_login_success", "arp_spoof", "exfiltration",
                     "unblock", "manual_block", "syn_flood_distributed", "rule_toggle"}      # guardian.py 가 쓰는 이름

# 검토할 때 눈에 띄게 표시할 패턴 (정규식, 설명)
RISKY = [
    (r"\bsudo\b", "sudo 사용"),
    (r"\b(?:bash|sh|zsh)\s+-c\b", "셸 명령 문자열 실행(-c)"),
    (r"\beval\b|\bexec\s*\(|__import__", "eval / exec"),
    (r"\b(?:curl|wget|nc|ncat|netcat|ssh|scp|ftp|telnet)\b", "외부 통신 도구"),
    (r"\brm\s+-\w*[rf]", "삭제 명령(rm -r / -f)"),
    (r"os\.system|subprocess|\bpopen\b|os\.exec|os\.spawn", "다른 프로그램 실행"),
    (r"\bsocket\b|\brequests\b|urllib|http\.client|ftplib|smtplib", "네트워크 접속"),
    (r"/etc/|/root\b|\.ssh|shadow|authorized_keys|/proc/", "시스템·인증 파일 접근"),
    (r"\bchmod\b|\bchown\b|\bsetuid\b", "권한 변경"),
    (r"base64|pickle|marshal|zlib\.decompress", "난독화·직렬화 의심"),
    (r"\.\./", "상위 폴더 접근"),
    (r"guardian\.py|dashboard_config|sudoers|iptables", "Guardian·토큰·방화벽·sudo 설정 접근"),
]
_RISKY = [(re.compile(p, re.IGNORECASE), why) for p, why in RISKY]


TAG_RE = re.compile(r"^[\w-]{1,20}$")


def normalize_tags(raw):
    """plugin.json 의 tags 를 화면용 목록으로 정리 (앞의 '#' 제거, 중복 제거, 6개까지). 규칙에 안 맞는 값은 건너뜀"""
    out = []
    if isinstance(raw, list):
        for t in raw:
            t = t.strip().lstrip("#") if isinstance(t, str) else ""
            if TAG_RE.match(t) and t not in out:
                out.append(t)
    return out[:6]


def check_tags(m):
    tags = m.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 6 or not all(isinstance(t, str) and TAG_RE.match(t.lstrip("#")) for t in tags):
        raise ValueError("tags 는 6개 이하의 짧은 단어(공백 없이 20자까지) 목록이어야 합니다 (예: [\"포트공격\", \"스캔\"])")


def validate_rule_manifest(m, rid, filenames=()):
    """rule.json(플러그인 방식 탐지 규칙) 내용 검사. 이상하면 ValueError(이유). guardian.py 의 validate_rule 이 읽을 때 한 번 더 검사하지만,
    올릴 때 미리 걸러서 승인 대기에 이상한 것이 쌓이지 않게 한다. 새 규칙은 항상 꺼진 상태로 설치되므로 enabled 는 무시된다"""
    if not isinstance(m, dict):
        raise ValueError("rule.json 은 JSON 객체여야 합니다")
    unknown = sorted(set(m) - RULE_KEYS)
    if unknown:
        raise ValueError(f"rule.json 에 알 수 없는 항목이 있습니다: {', '.join(map(str, unknown[:5]))}")
    if not isinstance(rid, str) or not ID_RE.match(rid):
        raise ValueError("id 는 영소문자로 시작하고 영소문자·숫자·밑줄만, 40자까지 쓸 수 있습니다")
    if m.get("id") != rid:
        raise ValueError("id 가 올바르지 않습니다")
    if rid in RESERVED_RULE_IDS:
        raise ValueError(f"'{rid}' 는 기본 탐지기가 쓰는 이름입니다")
    if m.get("detector") != "script":
        raise ValueError("detector 는 \"script\" 여야 합니다 (플러그인 방식 규칙)")
    for key, limit in (("name", 60), ("description", 200)):
        v = m.get(key, "")
        if not isinstance(v, str) or len(v) > limit:
            raise ValueError(f"{key} 는 {limit}자 이하의 문자열이어야 합니다")
    check_tags(m)
    nt = m.get("notify", {})
    if not isinstance(nt, dict) or set(nt) - {"popup", "sound"} or not all(isinstance(v, bool) for v in nt.values()):
        raise ValueError("notify 는 {\"popup\": true/false, \"sound\": true/false} 형식이어야 합니다 (생략하면 위험도 기본값)")
    if m.get("severity", "warning") not in ("info", "warning", "critical"):
        raise ValueError("severity 는 info / warning / critical 중 하나여야 합니다")
    for key in ("block", "block_permanent", "enabled"):
        if key in m and not isinstance(m[key], bool):
            raise ValueError(f"{key} 는 true / false 여야 합니다")
    if "block_duration_sec" in m:
        v = m["block_duration_sec"]
        if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 10 * 365 * 86400:
            raise ValueError("block_duration_sec 는 1 이상의 정수(초)여야 합니다")
    cmd = m.get("command")
    if not isinstance(cmd, list) or not 1 <= len(cmd) <= 6 or not all(isinstance(c, str) and 0 < len(c) <= 200 for c in cmd):
        raise ValueError("command 는 문자열 1~6개의 목록이어야 합니다")
    if not cmd[0].startswith("./") or not cmd[0].endswith((".py", ".sh")):
        raise ValueError("command 의 첫 항목은 './파일이름.py' (또는 .sh) 형식이어야 합니다")
    for part in cmd:
        if ".." in part.split("/"):
            raise ValueError("command 에 '..' 는 쓸 수 없습니다")
        if part.startswith("./") and part[2:] not in filenames:
            raise ValueError(f"command 의 {part} 파일이 함께 올라오지 않았습니다")
    for key, lo, hi in (("interval_sec", 5, 3600), ("timeout_sec", 1, 60)):
        if key in m or key == "interval_sec":
            v = m.get(key)
            if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                raise ValueError(f"{key} 는 {lo}~{hi} 사이의 정수여야 합니다")


def validate_manifest(m, pid, filenames=()):
    """plugin.json 내용 검사. 이상하면 ValueError(이유). filenames = 함께 올라온 파일 이름들"""
    if not isinstance(m, dict):
        raise ValueError("plugin.json 은 JSON 객체여야 합니다")
    if not isinstance(pid, str) or not ID_RE.match(pid):
        raise ValueError("id 는 영소문자로 시작하고 영소문자·숫자·밑줄만, 40자까지 쓸 수 있습니다")
    if m.get("id") != pid:
        raise ValueError("id 가 올바르지 않습니다")
    if m.get("kind", "task") not in ("task", "service"):
        raise ValueError("kind 는 task 또는 service 여야 합니다")
    for key, limit in (("name", 60), ("description", 300)):
        v = m.get(key, "")
        if not isinstance(v, str) or len(v) > limit:
            raise ValueError(f"{key} 는 {limit}자 이하의 문자열이어야 합니다")
    check_tags(m)
    cmd = m.get("command")
    if not isinstance(cmd, list) or not 1 <= len(cmd) <= 20 or not all(isinstance(c, str) and 0 < len(c) <= 200 for c in cmd):
        raise ValueError("command 는 문자열 1~20개의 목록이어야 합니다")
    first = cmd[0]
    if "/" in first and not first.startswith("./"):
        raise ValueError("command 의 첫 항목에는 경로를 쓸 수 없습니다 (프로그램 이름이나 ./파일 만)")
    for part in cmd:
        if ".." in part.split("/"):
            raise ValueError("command 에 '..' 는 쓸 수 없습니다")
        if part.startswith("./") and part[2:] not in filenames:
            raise ValueError(f"command 의 {part} 파일이 함께 올라오지 않았습니다")
    params = m.get("params", [])
    if not isinstance(params, list) or len(params) > 8:
        raise ValueError("params 는 8개 이하의 목록이어야 합니다")
    seen = set()
    for p in params:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not PARAM_RE.match(p["name"]) or p["name"] in seen:
            raise ValueError("입력값(params)의 name 은 영소문자로 시작하는 서로 다른 이름이어야 합니다")
        seen.add(p["name"])
        if p.get("type", "text") not in PARAM_TYPES:
            raise ValueError("입력값의 type 은 ip / int / choice / text 중 하나여야 합니다")
        if not isinstance(p.get("label", ""), str) or len(p.get("label", "")) > 60:
            raise ValueError("입력값의 label 은 60자 이하여야 합니다")
        if p.get("type") == "choice":
            ch = p.get("choices")
            if not isinstance(ch, list) or not 2 <= len(ch) <= 20 or not all(isinstance(c, str) and 0 < len(c) <= 60 for c in ch):
                raise ValueError("choice 입력값은 choices 에 문자열 2~20개가 필요합니다")
        for k in ("min", "max"):
            if k in p and (isinstance(p[k], bool) or not isinstance(p[k], int)):
                raise ValueError(f"입력값의 {k} 는 정수여야 합니다")
    t = m.get("timeout_sec", 30)
    if isinstance(t, bool) or not isinstance(t, int) or not 1 <= t <= 600:
        raise ValueError("timeout_sec 는 1~600 사이의 정수여야 합니다")


def scan_risky(texts):
    """{파일이름: 텍스트} 에서 검토가 필요한 패턴을 찾아 [{file, line, what, text}] 로 돌려준다 (최대 60개)"""
    found = []
    for name in sorted(texts):
        for no, line in enumerate(texts[name].splitlines(), 1):
            for rx, why in _RISKY:
                if rx.search(line):
                    found.append({"file": name, "line": no, "what": why, "text": line.strip()[:160]})
                    if len(found) >= 60:
                        return found
    return found


def combined_hash(files):
    """{파일이름: bytes} 전체를 하나로 요약하는 SHA-256 (파일 이름·내용이 하나라도 바뀌면 달라짐)"""
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode("utf-8") + b"\0" + hashlib.sha256(files[name]).digest())
    return h.hexdigest()


def parse_upload(files, expect=None):
    """브라우저가 보낸 {파일이름: 텍스트} 를 검사해 (id, 매니페스트, {이름: bytes}) 로 돌려준다. 이상하면 ValueError.
    plugin.json 이 있으면 도구, rule.json 이 있으면 플러그인 방식 탐지 규칙. expect("tool"/"rule")를 주면 그 종류만 받는다"""
    if not isinstance(files, dict) or not files:
        raise ValueError("올릴 파일이 없습니다")
    if len(files) > MAX_FILES:
        raise ValueError(f"파일은 한 번에 {MAX_FILES}개까지 올릴 수 있습니다")
    raw = {}
    for name, text in files.items():
        if not isinstance(name, str) or not FILE_RE.match(name) or not name.endswith(ALLOWED_EXT):
            raise ValueError(f"파일 이름 '{str(name)[:40]}' 은 허용되지 않습니다 (영문·숫자·._- 만, 확장자는 .json .py .sh)")
        if not isinstance(text, str) or "\0" in text:
            raise ValueError(f"'{name}' 은 텍스트 파일이어야 합니다")
        data = text.replace("\r\n", "\n").encode("utf-8")
        if len(data) > MAX_FILE_BYTES:
            raise ValueError(f"'{name}' 이 너무 큽니다 (파일당 {MAX_FILE_BYTES // 1024}KB 까지)")
        raw[name] = data
    has_tool, has_rule = TOOL_MANIFEST in raw, RULE_MANIFEST in raw
    if has_tool and has_rule:
        raise ValueError("plugin.json(도구)과 rule.json(탐지 규칙)은 함께 올릴 수 없습니다. 따로 올리세요")
    if not has_tool and not has_rule:
        raise ValueError("plugin.json (도구) 또는 rule.json (탐지 규칙) 이 필요합니다")
    kind = "rule" if has_rule else "tool"
    if expect and expect != kind:
        raise ValueError("이 칸에는 " + ("plugin.json (도구)" if expect == "tool" else "rule.json (탐지 규칙)") + " 을 올려야 합니다")
    name = RULE_MANIFEST if has_rule else TOOL_MANIFEST
    try:
        manifest = json.loads(raw[name].decode("utf-8"))
    except ValueError as e:
        raise ValueError(f"{name} 형식 오류: {e}")
    pid = manifest.get("id") if isinstance(manifest, dict) else None
    if has_rule:
        extra = [n for n in raw if n.endswith(".json") and n != RULE_MANIFEST]
        if extra:
            raise ValueError(f"탐지 규칙에는 rule.json 외의 .json 파일을 올릴 수 없습니다: {extra[0]}")
        validate_rule_manifest(manifest, pid, set(raw))
    else:
        validate_manifest(manifest, pid, set(raw))
    return pid, manifest, raw


def bundle_kind(raw):
    """{파일이름: ...} 가 도구인지 탐지 규칙인지"""
    return "rule" if RULE_MANIFEST in raw else "tool"


def _rule_conflicts(pid, raw):
    """탐지 규칙을 rules/ 에 설치할 때 이미 있는 파일(규칙 파일·같은 이름의 스크립트)"""
    paths = [os.path.join(RULES_DIR, pid + ".json")] + [os.path.join(RULES_DIR, n) for n in raw if n != RULE_MANIFEST]
    return [p for p in paths if os.path.exists(p)]


def save_pending(files, uploader="", expect=None):
    """검사를 통과한 업로드를 plugins_pending/<id>/ 에 저장 (실행 권한 없음). 같은 id 를 다시 올리면 덮어씀"""
    pid, manifest, raw = parse_upload(files, expect)
    kind = bundle_kind(raw)
    if kind == "tool" and os.path.exists(os.path.join(PLUGIN_DIR, pid)):
        raise ValueError(f"이미 설치된 플러그인 id 입니다: {pid} (다른 id 를 쓰세요)")
    if kind == "rule" and _rule_conflicts(pid, raw):
        raise ValueError(f"rules/ 에 같은 이름의 파일이 이미 있습니다: {os.path.basename(_rule_conflicts(pid, raw)[0])} (id 나 스크립트 이름을 바꾸세요)")
    prev = os.path.join(PENDING_DIR, pid)
    if os.path.isdir(prev) and os.path.exists(os.path.join(prev, RULE_MANIFEST)) != (kind == "rule"):
        raise ValueError("같은 id 의 다른 종류(도구/탐지 규칙)가 승인 대기 중입니다. 먼저 삭제하거나 다른 id 를 쓰세요")
    os.makedirs(PENDING_DIR, mode=0o750, exist_ok=True)
    existing = [d for d in os.listdir(PENDING_DIR) if ID_RE.match(d)]
    if pid not in existing and len(existing) >= MAX_PENDING:
        raise ValueError(f"승인 대기 목록이 가득 찼습니다 ({MAX_PENDING}개). 안 쓰는 것을 삭제하세요")
    tmp = os.path.join(PENDING_DIR, ".tmp_" + secrets.token_hex(4))
    os.makedirs(tmp, mode=0o750)
    try:
        for name, data in raw.items():
            with open(os.path.join(tmp, name), "wb") as f:
                f.write(data)
            os.chmod(os.path.join(tmp, name), 0o640)
        meta = {"id": pid, "uploaded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "uploader": str(uploader)[:64],
                "hash": combined_hash(raw), "files": {n: {"size": len(b), "sha256": hashlib.sha256(b).hexdigest()} for n, b in raw.items()}}
        with open(os.path.join(tmp, META_NAME), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        dest = os.path.join(PENDING_DIR, pid)
        shutil.rmtree(dest, ignore_errors=True)
        os.replace(tmp, dest)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return read_pending(pid)


def read_pending(pid, with_text=False):
    """승인 대기 중인 업로드 하나의 정보. 없으면 LookupError, 파일이 업로드 뒤에 바뀌었으면 intact=False"""
    if not isinstance(pid, str) or not ID_RE.match(pid):
        raise LookupError(pid)
    d = os.path.join(PENDING_DIR, pid)
    if not os.path.isdir(d):
        raise LookupError(pid)
    with open(os.path.join(d, META_NAME), encoding="utf-8") as f:
        meta = json.load(f)
    raw = {}
    for name in sorted(os.listdir(d)):
        if name != META_NAME and FILE_RE.match(name) and name.endswith(ALLOWED_EXT):
            with open(os.path.join(d, name), "rb") as f:
                raw[name] = f.read()
    digest = combined_hash(raw)
    kind = bundle_kind(raw)
    manifest = json.loads(raw[RULE_MANIFEST if kind == "rule" else TOOL_MANIFEST].decode("utf-8"))
    texts = {n: b.decode("utf-8", "replace") for n, b in raw.items()}
    info = {"id": pid, "type": kind, "name": manifest.get("name", pid), "description": manifest.get("description", ""),
            "kind": "rule" if kind == "rule" else manifest.get("kind", "task"), "tags": normalize_tags(manifest.get("tags")), "hash": digest, "short": digest[:12], "intact": digest == meta.get("hash"),
            "uploaded_at": meta.get("uploaded_at", ""), "uploader": meta.get("uploader", ""),
            "files": [{"name": n, "size": len(b), "sha256": hashlib.sha256(b).hexdigest()[:12]} for n, b in raw.items()],
            "findings": scan_risky(texts)}
    if kind == "rule":
        info["rule"] = {"severity": manifest.get("severity", "warning"), "block": manifest.get("block", False) is True,
                        "interval_sec": manifest.get("interval_sec"), "command": manifest.get("command")}
    if with_text:
        info["texts"] = texts
    return info


def list_pending():
    """승인 대기 목록 (읽을 수 없는 항목은 error 로 표시)"""
    out = []
    if not os.path.isdir(PENDING_DIR):
        return out
    for pid in sorted(os.listdir(PENDING_DIR)):
        if not ID_RE.match(pid):
            continue
        try:
            out.append(read_pending(pid))
        except (OSError, ValueError, KeyError, LookupError) as e:
            out.append({"id": pid, "error": str(e)})
    return out


def delete_pending(pid):
    if not isinstance(pid, str) or not ID_RE.match(pid) or not os.path.isdir(os.path.join(PENDING_DIR, pid)):
        return False
    shutil.rmtree(os.path.join(PENDING_DIR, pid))
    return True


def _install_rule(pid, manifest, raw):
    """탐지 규칙 승인: 스크립트를 먼저 rules/ 에 쓰고(실행 권한 755) 마지막에 규칙 파일을 쓴다 — Guardian 이 5초마다 rules/ 를 읽으므로
    규칙 파일이 먼저 보이면 스크립트가 없는 채로 켜질 수 있다. 규칙은 항상 꺼진 상태로 설치되고, 켜는 건 사람이 대시보드에서 한다"""
    taken = _rule_conflicts(pid, raw)
    if taken:
        raise ValueError(f"이미 있는 파일입니다: {taken[0]} (겹치는 이름을 바꿔서 다시 올리게 하세요)")
    os.makedirs(RULES_DIR, exist_ok=True)
    written = []
    try:
        for name, data in raw.items():
            if name == RULE_MANIFEST:
                continue
            path = os.path.join(RULES_DIR, name)
            with open(path, "wb") as f:
                f.write(data)
            written.append(path)
            os.chmod(path, 0o755)
        rule = dict(manifest)
        rule["enabled"] = False
        tmp = os.path.join(RULES_DIR, pid + ".json.tmp")                       # .json 으로 끝나지 않아 Guardian 이 무시함
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rule, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o644)
        dest = os.path.join(RULES_DIR, pid + ".json")
        os.replace(tmp, dest)
        written.append(dest)
    except BaseException:
        for p in written + [os.path.join(RULES_DIR, pid + ".json.tmp")]:
            try:
                os.remove(p)
            except OSError:
                pass
        raise
    shutil.rmtree(os.path.join(PENDING_DIR, pid), ignore_errors=True)
    return dest


def install(pid, expected_hash):
    """관리자가 승인: 해시가 맞고 파일이 그대로면 옮긴다 (approve_plugin.py 만 호출).
    도구는 plugins/<id>/ 로, 탐지 규칙은 rules/ 로 (꺼진 상태). 성공하면 설치된 경로"""
    info = read_pending(pid, with_text=True)
    if not info["intact"]:
        raise ValueError("승인 대기 파일이 업로드 뒤에 바뀌었습니다 (변조 의심). 삭제하고 다시 올리세요")
    eh = (expected_hash or "").strip().lower()
    if len(eh) < 8 or not info["hash"].startswith(eh):
        raise ValueError("해시가 맞지 않습니다. 방금 본 내용의 해시(앞 12자리)를 정확히 입력하세요")
    pid2, manifest, raw = parse_upload(info["texts"])
    if pid2 != pid:
        raise ValueError("매니페스트(plugin.json / rule.json)의 id 가 폴더 이름과 다릅니다")
    if bundle_kind(raw) == "rule":
        return _install_rule(pid, manifest, raw)
    dest = os.path.join(PLUGIN_DIR, pid)
    if os.path.exists(dest):
        raise ValueError(f"이미 설치된 플러그인입니다: {dest}")
    os.makedirs(PLUGIN_DIR, exist_ok=True)
    tmp = os.path.join(PLUGIN_DIR, ".tmp_" + secrets.token_hex(4))            # '.' 로 시작하면 대시보드 로더가 무시함
    os.makedirs(tmp)
    try:
        for name, data in raw.items():
            with open(os.path.join(tmp, name), "wb") as f:
                f.write(data)
            os.chmod(os.path.join(tmp, name), 0o644 if name.endswith(".json") else 0o755)
        os.replace(tmp, dest)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    shutil.rmtree(os.path.join(PENDING_DIR, pid), ignore_errors=True)
    return dest
