#!/usr/bin/env python3
"""
새 플러그인 만들기 도우미 (파이썬 표준 라이브러리만 사용)

질문에 답하면 dashboard/plugins/<id>/ 에 plugin.json 과 스크립트(run.py 또는 run.sh)를 만들어 줍니다.
만들어진 플러그인은 서버를 다시 켜지 않아도 3초 안에 대시보드 "도구" 목록에 나타납니다.

  python3 dashboard/new_plugin.py                       (질문에 답하는 방식)
  python3 dashboard/new_plugin.py --id my_scan --name "내 스캔" --kind task --lang python \
      --param "host:ip:대상 IP:192.168.56.20"           (한 줄로 만들기. --param 은 여러 번 가능)

--param 형식: 이름:종류:라벨:기본값   (종류 = ip / int / choice / text, choice 의 기본값 칸에는 '허용값1|허용값2' 를 씀)
"""
import argparse
import ipaddress
import json
import os
import re
import shlex
import sys

PLUGIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
PARAM_RE = re.compile(r"^[a-z][a-z0-9_]{0,19}$")
TEXT_RE = re.compile(r"^[\w .:/@,=-]{0,100}$")          # dashboard/server.py 의 text 파라미터 규칙과 같음
INT_MIN, INT_MAX = 0, 100000


def make_param(name, ptype, label, default):
    """--param / 질문 답을 plugin.json 의 params 항목으로 바꾸고, 기본값이 규칙에 맞는지 검사한다"""
    if not PARAM_RE.match(name):
        raise ValueError(f"입력값 이름 '{name}' 은 영소문자로 시작하고 영소문자·숫자·밑줄만 쓸 수 있습니다")
    if ptype not in ("ip", "int", "choice", "text"):
        raise ValueError("종류는 ip / int / choice / text 중 하나입니다")
    p = {"name": name, "label": label or name, "type": ptype}
    if ptype == "ip":
        p["default"] = str(ipaddress.ip_address(default or "127.0.0.1"))
    elif ptype == "int":
        p["default"] = int(default or 1)
        p["min"], p["max"] = INT_MIN, INT_MAX
        if not INT_MIN <= p["default"] <= INT_MAX:
            raise ValueError(f"기본값은 {INT_MIN}~{INT_MAX} 사이여야 합니다 (범위는 plugin.json 에서 바꿀 수 있어요)")
    elif ptype == "choice":
        choices = [c.strip() for c in (default or "").split("|") if c.strip()]
        if len(choices) < 2:
            raise ValueError("choice 는 기본값 칸에 허용값을 '|' 로 구분해 두 개 이상 쓰세요 (예: tcp|udp)")
        if any(c.startswith("-") or not TEXT_RE.match(c) for c in choices):
            raise ValueError("허용값에는 영문·숫자·공백과 . : / @ , = - _ 만 쓸 수 있고 '-' 로 시작할 수 없습니다")
        p["choices"], p["default"] = choices, choices[0]
    else:
        default = default or ""
        if default.startswith("-") or not TEXT_RE.match(default):
            raise ValueError("text 기본값에는 영문·숫자·공백과 . : / @ , = - _ 만 쓸 수 있고 '-' 로 시작할 수 없습니다")
        p["default"] = default
    return p


def parse_param_arg(text):
    parts = text.split(":", 3)
    if len(parts) < 2:
        raise ValueError(f"--param '{text}' 형식은 이름:종류:라벨:기본값 입니다")
    parts += [""] * (4 - len(parts))
    return make_param(parts[0], parts[1], parts[2], parts[3])


def py_script(manifest):
    lines = [f"# {manifest['name']}", f"# {manifest['description']}", "import sys"]
    if manifest["kind"] == "service":
        lines.append("import time")
    lines.append("")
    for i, p in enumerate(manifest["params"], 1):
        conv = "int" if p["type"] == "int" else ""
        lines.append(f"{p['name']} = {conv}(sys.argv[{i}] if len(sys.argv) > {i} else {p['default']!r})   # {p['label']}")
    lines += ["", "# ── 여기에 하고 싶은 일을 쓰세요. print() 로 찍은 내용이 대시보드 화면에 나옵니다 ──",
              "# 표·그래프로 보이려면: print('@gui ' + json.dumps({'type': 'metric', 'label': '이름', 'value': 1}))",
              "# (종류: metric / table / bars / chart / alert, 자세한 형식은 dashboard/README.md)",
              f"print({manifest['name'] + ' 시작'!r})"]
    for p in manifest["params"]:
        lines.append(f"print({p['label'] + ':'!r}, {p['name']})")
    if manifest["kind"] == "service":
        lines += ["", "n = 0", "while True:                  # 서비스형: '중지' 를 누를 때까지 계속 실행", "    n += 1",
                  '    print("동작 중", n)', "    time.sleep(2)"]
    else:
        lines += ["", 'print("끝")']
    return "\n".join(lines) + "\n"


def sh_script(manifest):
    lines = ["#!/usr/bin/env bash", f"# {manifest['name']}", f"# {manifest['description']}", ""]
    for i, p in enumerate(manifest["params"], 1):
        lines.append(f"{p['name'].upper()}=\"${{{i}:-{p['default']}}}\"   # {p['label']}")     # 기본값은 make_param 이 안전한 글자만 허용
    lines += ["", "# ── 여기에 하고 싶은 일을 쓰세요. echo 로 찍은 내용이 대시보드 화면에 나옵니다 ──",
              f"echo {shlex.quote(manifest['name'] + ' 시작')}"]
    for p in manifest["params"]:
        lines.append(f"echo {shlex.quote(p['label'] + ':')} \"${p['name'].upper()}\"")
    if manifest["kind"] == "service":
        lines += ["", "n=0", "while true; do              # 서비스형: '중지' 를 누를 때까지 계속 실행", "  n=$((n + 1))",
                  '  echo "동작 중 $n"', "  sleep 2", "done"]
    else:
        lines += ["", 'echo "끝"']
    return "\n".join(lines) + "\n"


TAG_RE = re.compile(r"^[\w-]{1,20}$")


def parse_tags(text):
    """'포트공격, 스캔' 또는 '#포트공격 #스캔' 을 태그 목록으로 (대시보드 카드의 #태그)"""
    tags = []
    for t in re.split(r"[,\s]+", text or ""):
        t = t.lstrip("#")
        if not t:
            continue
        if not TAG_RE.match(t):
            raise ValueError(f"태그 '{t}' 는 공백 없이 20자까지의 글자·숫자·'-'·'_' 만 쓸 수 있습니다")
        if t not in tags:
            tags.append(t)
    if len(tags) > 6:
        raise ValueError("태그는 6개까지 달 수 있습니다")
    return tags


def create(pid, name, desc, kind, lang, params, tags=None):
    if not ID_RE.match(pid):
        raise ValueError("id 는 영소문자로 시작하고 영소문자·숫자·밑줄만, 40자까지 쓸 수 있습니다 (예: my_scan)")
    if kind not in ("task", "service"):
        raise ValueError("종류는 task(1회 실행) 또는 service(계속 실행) 입니다")
    if lang not in ("python", "bash"):
        raise ValueError("언어는 python 또는 bash 입니다")
    folder = os.path.join(PLUGIN_DIR, pid)
    if os.path.exists(folder):
        raise ValueError(f"이미 있는 플러그인입니다: {folder} (다른 id 를 쓰거나 그 폴더를 직접 고치세요)")
    script = "run.py" if lang == "python" else "run.sh"
    command = (["{python}", "-u", "./run.py"] if lang == "python" else ["bash", "./run.sh"]) + ["{" + p["name"] + "}" for p in params]
    manifest = {"id": pid, "name": name or pid, "description": desc or "", "kind": kind, "command": command, "params": params}
    if tags:
        manifest["tags"] = tags
    if kind == "task":
        manifest["timeout_sec"] = 30
    os.makedirs(folder)
    with open(os.path.join(folder, "plugin.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")
    with open(os.path.join(folder, script), "w", encoding="utf-8", newline="\n") as f:
        f.write(py_script(manifest) if lang == "python" else sh_script(manifest))
    try:
        os.chmod(os.path.join(folder, script), 0o755)
    except OSError:
        pass
    return folder, script


def ask(prompt, default=None, check=None):
    """질문하고 답을 받는다 (엔터 = 기본값). check 가 ValueError 를 내면 다시 묻는다"""
    while True:
        raw = input(f"{prompt}" + (f" [{default}]" if default not in (None, "") else "") + ": ").strip()
        val = raw or (default if default is not None else "")
        try:
            return check(val) if check else val
        except ValueError as e:
            print(f"  ! {e}")


def one_of(*options):
    def check(v):
        if v not in options:
            raise ValueError(" 또는 ".join(options) + " 중에서 고르세요")
        return v
    return check


def new_id(v):
    if not ID_RE.match(v):
        raise ValueError("영소문자로 시작하고 영소문자·숫자·밑줄만 쓸 수 있습니다 (예: my_scan)")
    if os.path.exists(os.path.join(PLUGIN_DIR, v)):
        raise ValueError("이미 있는 id 입니다")
    return v


def interactive():
    print("새 플러그인을 만듭니다. 엔터를 누르면 [ ] 안의 기본값을 씁니다.\n")
    pid = ask("1) 플러그인 id (영소문자·숫자·밑줄, 예: my_scan)", check=new_id)
    name = ask("2) 화면에 보일 이름", pid)
    desc = ask("3) 설명 (한 줄)", "")
    kind = ask("4) 종류: task = 한 번 실행하고 끝 / service = 중지할 때까지 계속", "task", one_of("task", "service"))
    lang = ask("5) 스크립트 언어: python / bash", "python", one_of("python", "bash"))
    tags = ask("   태그 (카드에 #태그로 보임, 쉼표로 구분, 예: 포트공격,스캔. 없으면 엔터)", "", parse_tags)
    params = []
    print("\n6) 실행할 때 입력받을 값이 있나요? 없으면 이름 칸에서 그냥 엔터.")
    while True:
        pname = input("   입력값 이름 (영소문자, 예: host): ").strip()
        if not pname:
            break
        ptype = ask("   종류: ip / int / choice / text", "text", one_of("ip", "int", "choice", "text"))
        label = ask("   화면에 보일 라벨", pname)
        default = ask("   기본값" + (" (허용값을 | 로 구분, 예: tcp|udp)" if ptype == "choice" else ""), "")
        try:
            params.append(make_param(pname, ptype, label, default))
        except ValueError as e:
            print(f"  ! {e} -> 이 입력값은 건너뜁니다")
    return pid, name, desc, kind, lang, params, tags


def main():
    ap = argparse.ArgumentParser(description="새 플러그인 만들기 도우미")
    ap.add_argument("--id")
    ap.add_argument("--name")
    ap.add_argument("--desc", default="")
    ap.add_argument("--kind", default="task", choices=["task", "service"])
    ap.add_argument("--lang", default="python", choices=["python", "bash"])
    ap.add_argument("--param", action="append", default=[], help="이름:종류:라벨:기본값 (여러 번 가능)")
    ap.add_argument("--tags", default="", help="카드에 보일 #태그 (쉼표로 구분, 예: 포트공격,스캔)")
    a = ap.parse_args()
    try:
        if a.id:
            pid, name, desc, kind, lang = a.id, a.name or a.id, a.desc, a.kind, a.lang
            params = [parse_param_arg(x) for x in a.param]
            tags = parse_tags(a.tags)
        else:
            if not sys.stdin.isatty():
                sys.exit("질문에 답하려면 터미널에서 실행하세요. 한 줄로 만들려면 --id 를 주세요 (--help 참고).")
            pid, name, desc, kind, lang, params, tags = interactive()
        folder, script = create(pid, name, desc, kind, lang, params, tags)
    except (ValueError, OSError) as e:
        sys.exit(f"[!] {e}")
    except (KeyboardInterrupt, EOFError):
        sys.exit("\n취소했습니다.")
    print(f"\n만들었습니다: {folder}")
    print(f"  - {os.path.join(folder, script)}   <- 여기에 하고 싶은 일을 쓰세요")
    print("  - plugin.json                       <- 이름·설명·입력값을 바꾸고 싶을 때")
    print("\n대시보드 '도구' 목록에 3초 안에 나타납니다 (안 보이면 '지금 다시 찾기').")


if __name__ == "__main__":
    main()
