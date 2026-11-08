#!/usr/bin/env python3
"""
업로드된 플러그인 승인 도구 (보안 서버 터미널에서만 사용)

대시보드에 올라온 도구·탐지 규칙(플러그인 방식)은 plugins_pending/ 에 '실행되지 않는 상태'로 쌓입니다.
여기서 내용을 읽어 본 뒤 승인해야 도구는 plugins/ 로, 탐지 규칙은 rules/ 로(꺼진 상태) 옮겨져 대시보드에 나타납니다.

  python3 dashboard/approve_plugin.py                           화면으로 하나씩 확인 (화살표로 고르기)
  python3 dashboard/approve_plugin.py list                      승인 대기 목록
  python3 dashboard/approve_plugin.py show <id>                 파일 내용과 주의할 패턴 보기
  python3 dashboard/approve_plugin.py approve <id> [--hash 해시]   내용을 다시 보여 주고 승인
  python3 dashboard/approve_plugin.py reject <id>               삭제(거절)

화면 모드에서는 파일 내용을 끝까지 내려 봐야 승인을 고를 수 있고, yes 를 입력해야 설치됩니다.
해시는 화면을 연 순간의 값을 자동으로 확인하므로, 읽는 사이에 파일이 바뀌면 설치되지 않습니다.
"""
import argparse
import sys
import unicodedata

import plugin_store as store


def info_lines(info, with_text):
    """승인 대기 항목을 사람이 읽을 줄 목록으로 만든다. 각 항목은 (글, 종류) — 종류: head / warn / bad / code / ''"""
    out = [("=" * 66, "")]
    out.append((f" id: {info['id']}   이름: {info['name']}   종류: "
                f"{'탐지 규칙(플러그인 방식)' if info['type'] == 'rule' else '도구 ' + info['kind']}", "head"))
    if info["description"]:
        out.append((f" 설명: {info['description']}", ""))
    if info["type"] == "rule":
        r = info["rule"]
        out.append((f" 판정 스크립트: {' '.join(r['command'])}   {r['interval_sec']}초마다   위험도: {r['severity']}   "
                    f"{'방화벽 차단 켜짐' if r['block'] else '알림만'}", ""))
        out.append((" (승인하면 rules/ 에 '꺼진 상태'로 설치됩니다. 스크립트는 Guardian 이 일반 계정 권한으로 주기마다 실행합니다)", ""))
    out.append((f" 올린 시각: {info['uploaded_at']}   올린 곳: {info['uploader'] or '-'}", ""))
    out.append((f" 해시(앞 12자리): {info['short']}", ""))
    if not info["intact"]:
        out.append((" !! 업로드 뒤에 파일이 바뀌었습니다 (승인 불가) !!", "bad"))
    out.append((" 파일: " + ", ".join(f"{f['name']}({f['size']}B)" for f in info["files"]), ""))
    out.append(("", ""))
    if info["findings"]:
        out.append((f" [주의] 검토가 필요한 패턴 {len(info['findings'])}개 (보안 장치가 아니라 표시일 뿐, 코드를 직접 읽으세요)", "warn"))
        for f in info["findings"]:
            out.append((f"   - {f['file']}:{f['line']}  {f['what']}  |  {f['text']}", "warn"))
    else:
        out.append((" 표시할 위험 패턴은 없습니다 (그래도 코드를 직접 읽어 보세요).", ""))
    if with_text:
        for name, text in info["texts"].items():
            out += [("", ""), ("-" * 66, ""), (f" {name}", "head"), ("-" * 66, "")]
            out += [(f"{no:4d}  {line}", "code") for no, line in enumerate(text.splitlines(), 1)]
    out.append(("=" * 66, ""))
    return out


def print_info(info, with_text):
    for text, _ in info_lines(info, with_text):
        print(text)


def done_message(info, dest):
    if info["type"] == "rule":
        return (f"승인했습니다: {dest}",
                "대시보드 '탐지 규칙'(플러그인 방식)에 5초 안에 나타납니다. 꺼진 상태라서 내용을 확인한 뒤 직접 '켜기'를 눌러 주세요.")
    return (f"승인했습니다: {dest}", "대시보드 '도구' 목록에 3초 안에 나타납니다.")


# ───────────────────────── 화면 모드 (curses) ─────────────────────────

def _cw(ch):
    return 2 if unicodedata.east_asian_width(ch) in "WF" else 1


def _clip(text, width):
    """한글처럼 두 칸 차지하는 글자를 고려해 화면 너비에 맞게 자른다."""
    out, used = [], 0
    for ch in text.replace("\t", "    "):
        w = _cw(ch)
        if used + w > width:
            break
        out.append(ch)
        used += w
    return "".join(out)


class Tui:
    KEYS_LIST = " 위/아래 이동   Enter 열기   r 새로고침   q 끝내기"
    KEYS_VIEW = " 위/아래/PgUp/PgDn 읽기   좌/우 고르기   Enter 실행   Esc 목록"

    def __init__(self, scr):
        import curses
        self.c = curses
        self.scr = scr
        curses.curs_set(0)
        scr.keypad(True)
        self.attr = {"": curses.A_NORMAL, "code": curses.A_NORMAL, "head": curses.A_BOLD,
                     "warn": curses.A_BOLD, "bad": curses.A_BOLD | curses.A_REVERSE, "dim": curses.A_DIM}
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            for n, fg in ((1, curses.COLOR_YELLOW), (2, curses.COLOR_RED), (3, curses.COLOR_CYAN), (4, curses.COLOR_GREEN)):
                curses.init_pair(n, fg, -1)
            self.attr.update(warn=curses.color_pair(1) | curses.A_BOLD, bad=curses.color_pair(2) | curses.A_BOLD,
                             head=curses.color_pair(3) | curses.A_BOLD, ok=curses.color_pair(4) | curses.A_BOLD)
        self.attr.setdefault("ok", curses.A_BOLD)
        self.message = None      # (글, 종류) 목록 화면 위에 한 번 보여 줄 결과

    def put(self, y, x, text, kind=""):
        h, w = self.scr.getmaxyx()
        if 0 <= y < h and x < w - 1:
            try:
                self.scr.addstr(y, x, _clip(text, w - 1 - x), self.attr.get(kind, kind if isinstance(kind, int) else 0))
            except self.c.error:
                pass

    def footer(self, text):
        h, _ = self.scr.getmaxyx()
        self.put(h - 1, 0, text, self.c.A_REVERSE)

    # ── 목록 ──
    def run(self):
        sel = 0
        items = store.list_pending()
        while True:
            self.scr.erase()
            h, w = self.scr.getmaxyx()
            self.put(0, 0, " 플러그인 승인 대기 목록", "head")
            self.put(1, 0, " 올라온 도구·탐지 규칙을 하나씩 열어 내용을 읽고 승인하거나 거절합니다.", "dim")
            row = 3
            if self.message:
                for text, kind in self.message:
                    self.put(row, 1, text, kind)
                    row += 1
                row += 1
            if not items:
                self.put(row, 2, "승인 대기 중인 항목이 없습니다.  (r: 새로고침, q: 끝내기)")
            sel = max(0, min(sel, len(items) - 1))
            top = max(0, sel - (h - row - 3))
            for i, it in enumerate(items[top:], top):
                if row >= h - 2:
                    break
                mark = "❯ " if i == sel else "  "
                if "error" in it:
                    line, kind = f"{mark}{it['id']:<22} 읽을 수 없음: {it['error']}", "bad"
                else:
                    warn = f"주의 {len(it['findings'])}" if it["findings"] else "주의 없음"
                    line = (f"{mark}[{'규칙' if it['type'] == 'rule' else '도구'}] {it['id']:<22} {it['name']}"
                            f"   · 파일 {len(it['files'])}개 · {warn} · {it['uploaded_at']}")
                    kind = "warn" if it["findings"] else ""
                self.put(row, 1, line, (self.c.A_REVERSE | self.attr.get(kind, 0)) if i == sel else kind)
                row += 1
            self.footer(self.KEYS_LIST)
            self.scr.refresh()
            k = self.scr.getch()
            if k in (ord("q"), ord("Q")):          # Esc 는 끝내지 않음 (모르는 키 조합의 앞머리가 Esc 라서)
                return
            if k in (self.c.KEY_UP, ord("k")):
                sel -= 1
            elif k in (self.c.KEY_DOWN, ord("j")):
                sel += 1
            elif k in (ord("r"), ord("R")):
                items, self.message = store.list_pending(), None
            elif k in (10, 13, self.c.KEY_ENTER) and items and "error" not in items[sel]:
                self.message = self.view(items[sel]["id"])
                items = store.list_pending()

    # ── 한 항목 읽기 + 고르기 ──
    def view(self, pid):
        try:
            info = store.read_pending(pid, with_text=True)
        except (LookupError, ValueError, OSError) as e:
            return [(f"열 수 없습니다: {pid} ({e})", "bad")]
        lines = info_lines(info, with_text=True)
        pos, choice, read_all, note = 0, 2, False, ""
        options = ["승인", "거절 (삭제)", "목록으로"]
        while True:
            self.scr.erase()
            h, w = self.scr.getmaxyx()
            body = max(3, h - 5)
            pos = max(0, min(pos, max(0, len(lines) - body)))
            if pos + body >= len(lines):
                read_all = True
            for i, (text, kind) in enumerate(lines[pos:pos + body]):
                self.put(i, 0, text, kind)
            pct = 100 if len(lines) <= body else int((pos + body) * 100 / len(lines))
            self.put(h - 4, 0, "─" * (w - 1), "dim")
            can_approve = read_all and info["intact"]
            x = 1
            for i, opt in enumerate(options):
                label = ("❯ " if i == choice else "  ") + f"{i + 1}. {opt}"
                kind = "dim" if (i == 0 and not can_approve) else ("ok" if i == choice else "")
                self.put(h - 3, x, label, (self.c.A_REVERSE | self.attr.get(kind, 0)) if i == choice else kind)
                x += sum(_cw(ch) for ch in label) + 3
            hint = note or (f"읽은 위치 {pct}%" + ("" if read_all else "  — 끝까지 내려 읽어야 승인할 수 있습니다")
                            + ("" if info["intact"] else "  — 파일이 바뀌어 승인할 수 없습니다 (거절 후 다시 올리세요)"))
            self.put(h - 2, 1, hint, "warn" if note or not can_approve else "dim")
            self.footer(self.KEYS_VIEW)
            self.scr.refresh()
            k = self.scr.getch()
            note = ""
            if k in (self.c.KEY_UP, ord("k")):
                pos -= 1
            elif k in (self.c.KEY_DOWN, ord("j")):
                pos += 1
            elif k in (self.c.KEY_PPAGE, ord("b")):
                pos -= body - 1
            elif k in (self.c.KEY_NPAGE, ord(" ")):
                pos += body - 1
            elif k == self.c.KEY_HOME:
                pos = 0
            elif k == self.c.KEY_END:
                pos = len(lines)
            elif k in (self.c.KEY_LEFT, ord("h")):
                choice = (choice - 1) % 3
            elif k in (self.c.KEY_RIGHT, ord("l"), 9):
                choice = (choice + 1) % 3
            elif k in (ord("1"), ord("2"), ord("3")):
                choice = k - ord("1")
            elif k in (27, ord("q")):
                return None
            elif k in (10, 13, self.c.KEY_ENTER):
                if choice == 2:
                    return None
                if choice == 1:
                    if self.confirm(f"'{pid}' 를 삭제(거절)할까요? 되돌릴 수 없습니다."):
                        return ([(f"거절(삭제)했습니다: {pid}", "ok")] if store.delete_pending(pid)
                                else [(f"이미 없는 항목입니다: {pid}", "warn")])
                    continue
                if not info["intact"]:
                    note = "파일이 업로드 뒤에 바뀌어서 승인할 수 없습니다."
                    continue
                if not read_all:
                    note = "아직 끝까지 읽지 않았습니다. 아래로 내려 모든 파일 내용을 확인하세요."
                    continue
                if not self.ask_yes():
                    note = "승인을 취소했습니다. (yes 를 정확히 입력해야 설치됩니다)"
                    continue
                try:
                    # 화면을 연 순간의 해시를 그대로 넘긴다: 읽는 사이에 파일이 바뀌었으면 설치되지 않음
                    dest = store.install(pid, info["short"])
                except (ValueError, OSError, LookupError) as e:
                    note = f"설치하지 않았습니다: {e}"
                    continue
                a, b = done_message(info, dest)
                return [(a, "ok"), (b, "")]

    def confirm(self, question):
        h, _ = self.scr.getmaxyx()
        self.put(h - 2, 1, " " * 200)
        self.put(h - 2, 1, question + "  (y = 예 / 그 밖의 키 = 아니오)", "warn")
        self.scr.refresh()
        return self.scr.getch() in (ord("y"), ord("Y"))

    def ask_yes(self):
        """'yes' 를 직접 입력받는다 (실수로 Enter 를 두 번 눌러 설치되는 것을 막음). Esc = 취소"""
        typed = ""
        while True:
            h, _ = self.scr.getmaxyx()
            self.put(h - 2, 1, " " * 200)
            self.put(h - 2, 1, f"내용을 모두 읽었고 설치해도 좋다면 yes 를 입력하고 Enter (취소: Esc): {typed}_", "warn")
            self.scr.refresh()
            k = self.scr.getch()
            if k == 27:
                return False
            if k in (10, 13, self.c.KEY_ENTER):
                return typed.strip().lower() == "yes"
            if k in (self.c.KEY_BACKSPACE, 127, 8):
                typed = typed[:-1]
            elif 32 < k < 127 and len(typed) < 10:
                typed += chr(k)


def run_tui():
    import curses
    import locale
    import os
    locale.setlocale(locale.LC_ALL, "")
    os.environ.setdefault("ESCDELAY", "25")      # Esc 를 눌렀을 때 바로 반응하게
    curses.wrapper(lambda scr: Tui(scr).run())


def main():
    if len(sys.argv) == 1:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            sys.exit("[!] 화면 모드는 터미널에서만 됩니다. list / show / approve / reject 명령을 쓰세요.")
        try:
            run_tui()
        except KeyboardInterrupt:
            pass
        return

    ap = argparse.ArgumentParser(description="업로드된 플러그인 승인 도구 (인자 없이 실행하면 화면 모드)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    for name in ("show", "approve", "reject"):
        p = sub.add_parser(name)
        p.add_argument("id")
        if name == "approve":
            p.add_argument("--hash", help="확인한 내용의 해시(앞 8자리 이상). 없으면 직접 입력하게 물어봄")
    a = ap.parse_args()

    if a.cmd == "list":
        items = store.list_pending()
        if not items:
            print("승인 대기 중인 플러그인이 없습니다.")
        for i in items:
            if "error" in i:
                print(f"  {i['id']:<24} 읽을 수 없음: {i['error']}")
            else:
                print(f"  {i['id']:<24} {i['short']}  [{'규칙' if i['type'] == 'rule' else '도구'}] {i['name']}  (파일 {len(i['files'])}개, 주의 패턴 {len(i['findings'])}개, {i['uploaded_at']})")
        return
    try:
        if a.cmd == "reject":
            if not store.delete_pending(a.id):
                sys.exit(f"[!] 그런 대기 항목이 없습니다: {a.id}")
            print(f"삭제했습니다: {a.id}")
            return
        info = store.read_pending(a.id, with_text=True)
        print_info(info, with_text=True)
        if a.cmd == "show":
            return
        if not info["intact"]:
            sys.exit("[!] 파일이 업로드 뒤에 바뀌어서 승인할 수 없습니다. reject 후 다시 올리게 하세요.")
        h = a.hash
        if not h:
            if not sys.stdin.isatty():
                sys.exit("[!] 터미널이 아니면 --hash 를 주세요.")
            print(f"\n위 내용을 모두 읽었고 설치해도 좋다면, 해시 앞 12자리 ({info['short']}) 를 그대로 입력하세요.")
            h = input("해시 입력 (그냥 엔터 = 취소): ").strip()
            if not h:
                sys.exit("취소했습니다.")
        dest = store.install(a.id, h)
        print("\n" + "\n".join(done_message(info, dest)))
    except LookupError:
        sys.exit(f"[!] 그런 대기 항목이 없습니다: {a.id}")
    except (ValueError, OSError) as e:
        sys.exit(f"[!] {e}")
    except (KeyboardInterrupt, EOFError):
        sys.exit("\n취소했습니다.")


if __name__ == "__main__":
    main()
