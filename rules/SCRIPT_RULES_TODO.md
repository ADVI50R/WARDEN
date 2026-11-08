# 스크립트 기반 탐지 규칙 ("플러그인 방식" — 구현됨, 2026-11-02)

**이 설계대로 구현되었습니다.** 사용법·형식은 `dashboard/README.md` 의 "플러그인 방식 규칙" 항목을 보세요.
이 문서는 설계 당시의 기록으로 남겨 둡니다.

**2026-11-07 변경:** 아래의 "대시보드에서 업로드하지 않음"은 바뀌었습니다. 이제 `rule.json` + 스크립트를 대시보드로 올리고 서버 터미널에서 승인하면 `rules/` 에 꺼진 상태로 설치됩니다. API 로 스크립트 규칙을 직접 만들거나 명령을 바꿀 수는 없습니다.

## 합의한 구조

스크립트는 공격 여부를 **판정만** 해서 결과를 출력하고, 화이트리스트 검사·차단·로그 기록은 전부 Guardian이 합니다. 스크립트가 직접
iptables를 건드리거나 차단하지 않습니다. 대시보드에서 스크립트 파일을 업로드하거나 편집하는 기능도 넣지 않습니다 (지금 플러그인과
같은 원칙 — `dashboard/README.md` 참고). 새 스크립트는 공유 폴더나 git으로 `rules/` 에 파일로만 넣습니다.

예상되는 규칙 파일 형식 (현재 `rules/<id>.json` 의 `detector` 필드를 확장):
```json
{
  "id": "my_script_rule",
  "detector": "script",
  "command": ["./check.py"],
  "interval_sec": 10,
  "severity": "warning",
  "block": true
}
```
스크립트는 공격이 있으면 `{"source": "1.2.3.4", "detail": "..."}` 같은 한 줄 JSON을 표준출력으로 내보내고, Guardian이 그걸 읽어서
`normalize_target()` 검사 → 화이트리스트 확인 → `emit()`/`block()` 을 호출합니다.

## 정한 것 (2026-11-02)

1. **스크립트가 보는 데이터**: 주기적으로 실행(`interval_sec`)해서 결과를 보는 방식으로 정함 (추천대로).
2. **실행 권한**: `nobody` 같은 별도 계정이 아니라 **지금 플러그인과 같은 계정**(`rules/`=`~/guardian` 을 소유한 계정, 보통 `kali`)으로
   정함 — Guardian(root) 이 `preexec_fn` 으로 그 계정 권한까지 낮춰서 실행합니다 (`guardian.py` 의 `_drop_priv_to_owner()`).

## 만들 때 참고할 곳

- `guardian.py` 의 `validate_rule()` — `detector` 필드가 확장점. `BUILTIN_PARAMS` 처럼 `"script"` 전용 검사를 추가
- `check_custom()` — 직접 만든 규칙(사용자 규칙)을 어떻게 패킷과 매칭하는지의 참고 예시 (스크립트는 패킷 대신 프로세스 출력을 봄)
- 시간 제한과 출력 크기 제한을 꼭 걸 것 (플러그인 실행기의 `timeout_sec`, `MAX_OUTPUT_LINES` 참고 — `dashboard/server.py`)
