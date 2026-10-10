# Guardian 대시보드

파이썬 표준 라이브러리만 사용 → **인터넷 없이** 실행됩니다 (Streamlit/pip 설치 불필요).

```
브라우저(윈도우 10) ──► server.py :8080 ──► Guardian API 127.0.0.1:8000
                          └─► plugins/*  (보안 스크립트들)
```

## 실행 (보안 서버)
```bash
cd ~/guardian
sudo python3 guardian.py            # 터미널 1
python3 dashboard/server.py         # 터미널 2 (일반 권한으로 충분)
```
출력된 **로그인 토큰**을 브라우저 로그인 창에 입력합니다 (`dashboard/dashboard_config.json` 에도 저장됨).

접속 주소: 윈도우 10 브라우저에서 `http://192.168.57.10:8080/` (가이드 7.5단계 — 호스트 전용 어댑터 설정). 서버 안에서는 `http://127.0.0.1:8080/`
(같은 서버 안에서 확인만 할 땐 `http://127.0.0.1:8080/`)

## 플러그인 추가하는 법
`dashboard/plugins/<id>/plugin.json` 폴더를 만들면 **서버 재시작 없이** 플러그인 탭에 나타납니다.

```json
{
  "id": "ping_check",                       // 폴더 이름과 같아야 함
  "name": "핑 확인",
  "description": "설명",
  "kind": "task",                           // task = 1회 실행 후 종료 / service = 중지할 때까지 계속 실행
  "command": ["ping", "-c", "3", "{host}"], // 쉘을 거치지 않는 목록 형태. {python} = 파이썬 경로, "./run.py" = 플러그인 폴더 안 파일
  "params": [{"name": "host", "label": "대상 IP", "type": "ip", "default": "192.168.56.20"}],
  "timeout_sec": 15                         // task 만 해당
}
```
- 파라미터 `type`: `ip`, `int`(min/max), `choice`(choices), `text`(영문/숫자/일부 기호만). 값은 서버가 검사한 뒤 명령 인자로만 들어가므로 명령 주입이 되지 않습니다.
- 스크립트는 화면에 보일 내용을 그냥 `print()` 하면 됩니다 (최근 500줄 표시).
- 예제: `system_info`(파이썬 1회 실행), `heartbeat`(서비스형), `ping_check`, `net_connections`.
- 대시보드 화면에서 **실행/중지/활성·비활성**은 되지만, **새 스크립트 파일 업로드는 일부러 막아 두었습니다** (토큰이 새면 서버에서 임의 코드가 실행되기 때문). 새 플러그인은 공유 폴더나 git 으로 `plugins/` 에 넣으세요.

## 서버 API (토큰 필요: 헤더 `X-Token`)
Guardian API 6개(`/api/status|events|blocked|rules|block|unblock`)를 그대로 전달 +
`GET /api/plugins`, `POST /api/plugins/<id>/run|stop|enable`.
