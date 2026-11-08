#!/usr/bin/env python3
"""대시보드 미리보기 파일(index.html) 만들기.

실제 dashboard/static 의 HTML·CSS·JS 를 그대로 한 파일에 합치고, 가짜 서버(mock.js)를 붙입니다.
브라우저로 index.html 을 더블클릭해서 열면 서버 없이 화면을 볼 수 있습니다 (데이터는 예시).
화면 코드를 고친 뒤에는 다시 실행하세요:   python make_preview.py
"""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# 기본은 실제 화면 코드(dashboard/static). 적용 전 시안은 `python make_preview.py staged` 처럼 폴더 이름을 주면 그 폴더(preview/staged)를 씁니다.
STATIC = os.path.join(HERE, sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "src", "dashboard", "static")


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


html = read(STATIC, "index.html")
css, app, mock = read(STATIC, "style.css"), read(STATIC, "app.js"), read(HERE, "mock.js")

html = html.replace('<link rel="stylesheet" href="style.css">', f"<style>\n{css}\n</style>")
html = html.replace('<script src="app.js"></script>', f"<script>\n{mock}\n</script>\n<script>\n{app}\n</script>")
html = html.replace("<body>", '<body>\n<div style="background:#ff4b4b;color:#fff;text-align:center;padding:4px;font-size:13px">'
                    "미리보기 (예시 데이터 · 서버에 연결되지 않음 · 새로고침하면 처음 상태)</div>", 1)

out = os.path.join(HERE, "index.html")
with open(out, "w", encoding="utf-8") as f:
    f.write(html)
print("만들었습니다:", out)

# "구성 안내 PDF 받기" 링크(guide_*.pdf)가 미리보기에서도 열리도록 같은 폴더로 복사
for name in sorted(os.listdir(STATIC)):
    if name.startswith("guide_") and name.endswith(".pdf"):
        shutil.copyfile(os.path.join(STATIC, name), os.path.join(HERE, name))
        print("복사했습니다:", os.path.join(HERE, name))
