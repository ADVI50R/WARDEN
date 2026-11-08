# WARDEN — Watch, Alert, Respond, Defend, Explain, Notify

실습용 리눅스 네트워크 관제·방어 도구입니다. 본체는 `warden.py`, 웹 대시보드는 `dashboard/server.py` 입니다. (2026-11-08 이전 이름: Guardian)

| | 하는 일 |
|---|---|
| **W**atch | scapy 로 지나가는 패킷을 감시 (패킷 보기, PCAP 내보내기) |
| **A**lert | 포트 스캔·플러드·SSH 무차별 대입·ARP 변조·유출 등 규칙으로 탐지 |
| **R**espond | iptables 로 자동 차단, 반복 공격자는 더 길게 (dry-run 으로 시험 가능) |
| **D**efend | 화이트리스트, 업로드 코드는 터미널 승인 후에만 실행, 감사 기록 |
| **E**xplain | 탐지마다 "정보" 분석: 어디서 · 무엇을 · 영향 · 대응 결과 · 권고 |
| **N**otify | 웹 대시보드의 실시간 알림·보고서·CSV |

## 0. 빠른 설치 (GitHub 에서 받아 새 서버에 설치)
학교 실습 컴퓨터에 접속할 수 없어도, 칼리(데비안 계열)나 록키(레드햇 계열) 리눅스 VM 만 있으면 이 저장소로 다시 설치해 시연할 수 있습니다.

1. **인터넷 되는 PC 에서 받기** (비공개 저장소라 GitHub 로그인 필요)
   - 가장 쉬움: 저장소 오른쪽 **Releases** → 최신 버전의 `WARDEN-<버전>.zip` (설치에 필요한 것만 들어 있음)
   - 또는 `Code` → `Download ZIP`, 또는 `git clone https://github.com/ADVI50R/WARDEN.git`
2. **보안 서버 VM 으로 옮기기**: 공유 폴더·USB 등으로 압축을 푼 폴더를 서버 VM 에 복사 (실습망은 인터넷이 없어도 됨. 처음 설치 때 `python3-scapy` 가 없으면 인터넷이 잠깐 필요)
3. **설치**: 서버 VM 에서 (`setup.py` 옆에 `src/` 폴더가 있어야 합니다)
   ```bash
   cd WARDEN
   sudo python3 setup.py
   ```
   화면에서 감시 인터페이스·대시보드 주소·관리 PC IP 를 고르고, 부팅 때 자동으로 켜려면 "자동 시작 서비스"를 켭니다. 끝나면 대시보드 주소와 로그인 토큰이 화면에 나옵니다. 설치 위치(기본 `~/warden`)에는 `src/` 의 내용과 `setup.py`·`uninstall.py` 가 한 폴더로 들어갑니다.
4. **확인**: `wstatus` (켜짐·모드·주소), 브라우저로 대시보드 접속
5. **시연 공격**: 공격자 VM 에서 `docs/attack_test_guide.md` 의 명령 (같은 내부 네트워크에 둘 것, 아래 2번 참고)

제거는 `sudo python3 uninstall.py` (백업 후 삭제). 대시보드 사용법은 `src/dashboard/README.md`.

## 1. 구성

```
WARDEN/
├── README.md          # 이 문서
├── setup.py           # 설치 도구 (sudo python3 setup.py)
├── uninstall.py       # 제거 도구 (sudo python3 uninstall.py)
├── src/               # 서버에 설치되는 프로그램
│   ├── warden.py    # 메인 프로그램 (탐지 + 차단 + API)
│   ├── wardenctl.py # 켜기·끄기 (wstart / wstop / wstatus / wlog / wunblock)
│   ├── config.json    # 기본 설정
│   ├── selftest.py    # 가짜 패킷으로 하는 자가 시험
│   ├── rules/         # 탐지 규칙 (파일 하나가 규칙 하나)
│   └── dashboard/     # 웹 대시보드 (사용법: src/dashboard/README.md)
└── docs/              # 설치에는 필요 없는 문서·예제
    ├── attack_test_guide.md   # 공격자 VM 에서 규칙별로 시험하는 명령
    ├── attack_auto.sh         # 위 시험 중 root 가 필요한 것 자동 실행
    ├── lab_setup_guide.txt    # 실습 환경 준비 순서
    ├── migration_guide.txt    # VM 을 다른 컴퓨터로 옮기는 순서
    ├── ROADMAP.md · 진행상황_및_계획.txt
    ├── examples/              # 플러그인 방식 규칙 예제 (슬로로리스)
    └── preview/               # 서버 없이 대시보드 화면 보기 (index.html)
```
설치된 서버에서는 `~/warden/warden.py`, `~/warden/logs/events.jsonl`(실행하면 자동 생성되는 이벤트 로그)처럼 한 폴더에 모입니다.

동작 흐름: **패킷 수집(scapy) → 규칙으로 판단 → 이벤트 기록 → (설정 시) iptables로 차단 → 5분 뒤 자동 해제**

| 탐지 항목 | 판단 기준 (기본값) | 대응 |
|---|---|---|
| 포트 스캔 | 10초 안에 서로 다른 포트 20개 이상 접속 시도 | IP 차단 |
| SYN 플러드 | 5초 안에 한 IP에서 SYN 200개 이상 | IP 차단 |
| 출발지 위조 SYN 플러드 | 5초 안에 전체 SYN 1000개 이상 + 출발지 10곳 이상 | 알림 + syncookies |
| ICMP(핑) 플러드 | 5초 안에 ping 50개 이상 | IP 차단 |
| SSH 무차별 대입 | 60초 안에 22번 포트 접속 10회 이상 | IP 차단 |
| ARP 스푸핑 | 이미 알던 IP의 MAC 주소가 바뀜 | MAC 차단 |
| 데이터 유출 | 60초 안에 한 목적지로 50MB 이상 전송 | 알림만 |

## 2. 실습 환경 준비 (가장 중요)

**VM 네트워크는 반드시 "내부 네트워크(Internal Network)" 또는 "호스트 전용(Host-only)"으로 설정하세요.**
플러드 공격은 실제로 네트워크를 마비시킵니다. "브리지(Bridged)"로 두고 학교·회사 망에서 테스트하면 다른 사람에게 피해가 가고 문제가 될 수 있습니다.

- VirtualBox: 설정 → 네트워크 → 어댑터 1 → "내부 네트워크", 두 VM 모두 같은 이름(예: `lab`)
- 내부 네트워크는 DHCP가 없으니 IP를 직접 지정:
  ```bash
  # 관제 서버
  sudo ip addr add 192.168.56.10/24 dev eth0 && sudo ip link set eth0 up
  # 공격자
  sudo ip addr add 192.168.56.20/24 dev eth0 && sudo ip link set eth0 up
  ```
- 서로 `ping` 이 되는지 먼저 확인하세요.

## 3. 실행 (관제 서버에서)

```bash
ip a                                  # 인터페이스 이름 확인 (eth0 인지 등)
sudo apt install python3-scapy        # 칼리엔 보통 이미 있음
sudo systemctl start ssh              # SSH 공격 테스트용으로 서비스 켜기
cd warden
sudo python3 warden.py
```

처음에는 `"dry_run": true` 상태로 **탐지만** 되는지 확인하고, 잘 되면 실제 차단을 테스트하세요. `config.json` 을 고치고 재시작하는 대신, 대시보드 "관제 서버 상태" 카드의 슬라이드로 바로 켤 수 있습니다 (재시작 없이 적용, `logs/dry_run_override.json` 에 저장되어 다음 시작에도 유지).

## 4. 공격자 VM에서 테스트해 보기

아래는 **본인 실습 VM끼리만** 사용하세요. `192.168.56.10` 은 관제 서버 IP입니다.

| 테스트 | 공격자에서 실행 | 관제 서버에 떠야 할 것 |
|---|---|---|
| 포트 스캔 | `nmap -sS 192.168.56.10` | `port_scan` |
| 핑 플러드 | `sudo ping -f -c 500 192.168.56.10` | `icmp_flood` |
| SYN 플러드 | `sudo hping3 -S -p 80 -i u1000 -c 2000 192.168.56.10` | `syn_flood` |
| SSH 대입 흉내 | `for i in $(seq 15); do nc -z -w1 192.168.56.10 22; done` | `ssh_bruteforce` |
| ARP 변조 흉내 | `docs/attack_test_guide.md` 6번 (scapy 한 줄 명령) | `arp_spoof` |

- `hping3 --flood` 는 VM이 멈출 정도로 강하니 처음엔 위처럼 `-i u1000 -c 2000`(속도·개수 제한)으로 하세요.
- ARP 테스트: 관제 서버가 먼저 해당 IP의 진짜 MAC을 알아야 탐지됩니다. 먼저 두 VM끼리 ping을 주고받은 뒤 테스트하세요. 실습망에 VM이 2대뿐이면 게이트웨이를 사칭하는 `arpspoof` 방식은 쓸 수 없어서, 같은 IP의 MAC이 바뀌는 상황을 scapy로 직접 만들어 테스트합니다.
- 차단된 뒤 공격자에서 `ping 192.168.56.10` 이 안 되면 방어 성공입니다.

## 5. 대시보드 연동

### 방법 A – REST API (추천)
기본 주소: `http://127.0.0.1:8000`

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/api/status` | 가동 시간, 모드, 패킷/이벤트 통계 |
| GET | `/api/events?limit=50&type=port_scan` | 최근 이벤트 (최신순, type 은 생략 가능) |
| GET | `/api/blocked` | 현재 차단 목록 + 남은 시간 (영구 차단은 `permanent: true`, 남은 시간 null) + 메모 |
| GET | `/api/history?limit=50` | IP별 누적 공격 기록 (탐지 횟수, 차단 횟수, 유형별 횟수, 처음/마지막 시각, 메모) |
| GET | `/api/rules` | 모든 탐지 규칙 목록 + 불러오기 오류 (`rules/*.json`, 형식은 `src/dashboard/README.md`) |
| POST | `/api/block` | 수동 차단 `{"target":"1.2.3.4","duration_sec":600}` 또는 영구 `{"target":"1.2.3.4","permanent":true,"note":"메모"}` |
| POST | `/api/rules` · `/update` · `/enable` · `/delete` | 규칙 저장 `{"rule":{...}}` / 수정 `{"id":..,"rule":{...}}` (바뀌면 꺼짐 상태로 저장) / 켜기끄기 `{"id":..,"enabled":true}` / 삭제 `{"id":..}` (켜져 있으면 먼저 꺼서 삭제) |
| POST | `/api/dry_run` | 실제 차단 켜기/끄기 `{"dry_run": false}` (켜져 있던 차단 대상에 iptables 규칙을 다시 걸거나 비움) |
| GET | `/api/rule_changes?limit=50` | 규칙 변경 기록 (켜기/끄기/추가/삭제, `logs/rule_changes.jsonl`). 탐지 이벤트·통계에는 포함되지 않음 |
| POST | `/api/note` | 메모 저장 `{"target":"1.2.3.4","note":"..."}` (빈 문자열이면 삭제) |
| POST | `/api/unblock` | 차단 해제 `{"target":"1.2.3.4"}` |

```bash
curl http://127.0.0.1:8000/api/status
curl -X POST http://127.0.0.1:8000/api/unblock -H "Content-Type: application/json" -d '{"target":"192.168.56.20"}'
```
- `target` 은 IP **하나** 또는 `mac:aa:bb:cc:dd:ee:ff` 만 허용합니다. `0.0.0.0/0` 같은 범위는 실수로 서버 전체를 막을 수 있어 400 오류로 거부합니다.
- 차단/해제가 안 된 경우 `{"ok": false, "reason": "이미 차단 중"}` 처럼 이유가 함께 옵니다 (`화이트리스트 대상`, `차단 목록에 없음`).

이 API(8000번)는 토큰이 없어서 서버 안(127.0.0.1)에서만 열리고, 브라우저는 대시보드(8080번, 토큰 필요)를 통해서만 부릅니다 (CORS 허용 안 함).

### 방법 B – 로그 파일
`logs/events.jsonl` 에 한 줄에 이벤트 하나씩 JSON으로 쌓입니다. Grafana/ELK 같은 도구를 쓸 거면 이 파일을 읽게 하면 됩니다.

### 이벤트 형식 (공통)
```json
{
  "id": "a1b2c3d4e5f6",
  "timestamp": "2026-09-28T14:03:11+09:00",
  "type": "port_scan",
  "severity": "warning",
  "source": "192.168.56.20",
  "target": "192.168.56.10",
  "detail": "10초 동안 서로 다른 포트 23개에 접속 시도",
  "action": "block"
}
```
`severity`: `info` / `warning` / `critical` → 대시보드 색상(파랑/노랑/빨강)에 바로 매핑하면 됩니다.

## 6. 설정 항목 설명 (config.json)

| 항목 | 의미 |
|---|---|
| `interface` | 감시할 네트워크 카드 이름 (`ip a` 로 확인) |
| `dry_run` | `true` = 탐지·기록만 / `false` = 실제 iptables 차단 (시작할 때의 기본값. 이후 대시보드 슬라이드로 켜면 `logs/dry_run_override.json` 이 이 값보다 우선함) |
| `whitelist` | 절대 차단하지 않을 IP·MAC (게이트웨이, 본인 PC 등 추가 권장) |
| `block_duration_sec` | 자동 차단 유지 시간(초) |
| `alert_cooldown_sec` | 같은 공격이 반복될 때 같은 알림을 다시 띄우기까지 대기 시간 |
| `api.host` | `127.0.0.1` = 관제 서버 안에서만 접근. 다른 PC에서 대시보드를 볼 거면 `0.0.0.0` |
| (탐지 규칙) | 탐지 규칙과 임계값은 `src/rules/` 폴더의 파일로 관리합니다 (`src/dashboard/README.md` 의 "탐지 규칙" 참고) |

JSON 파일에는 주석(`//`)을 쓸 수 없으니 설명은 이 문서를 보세요. 쉼표 하나만 틀려도 실행이 안 됩니다.

## 7. 처음 하는 분들이 헷갈리기 쉬운 것

1. **왜 sudo 가 필요한가?** 모든 패킷을 엿보는 것(스니핑)과 방화벽 수정은 관리자 권한이 필요합니다.
2. **차단했는데 로그에 계속 패킷이 보여요.** 정상입니다. scapy는 방화벽(iptables)보다 **앞단**에서 패킷을 보기 때문에, 차단된 패킷도 "보이긴" 합니다. 실제로는 버려지고 있습니다. (코드에선 차단된 IP는 무시하도록 처리함)
3. **iptables 규칙이 남아서 네트워크가 이상해요.** 프로그램이 강제 종료(kill -9 등)되면 정리가 안 될 수 있습니다. 아래로 수동 정리:
   ```bash
   sudo iptables -D INPUT -j WARDEN; sudo iptables -F WARDEN; sudo iptables -X WARDEN
   sudo iptables -L -n     # 현재 규칙 확인
   ```
4. **오탐(정상인데 공격으로 판단).** 기준값은 실습용 대략치입니다. 너무 자주 뜨면 숫자를 올리고, 안 뜨면 내리세요. 예를 들어 웹페이지 하나 여는 것도 연결을 여러 개 만듭니다.
5. **SSH로 관제 서버에 접속해 작업 중이라면** 본인 PC IP를 `whitelist` 에 꼭 넣으세요. 안 그러면 스스로를 차단할 수 있습니다.
6. **출발지를 위조하는 공격(`--rand-source`)은 IP 차단이 소용없습니다.** 매 패킷 IP가 다르기 때문입니다. 그래서 전체량만 감시하고 커널의 SYN 쿠키(syncookies)로 버팁니다.
7. **ARP 스푸핑 탐지는 "처음 본 MAC이 정상"이라고 가정합니다.** 공격자가 먼저 가짜 정보를 뿌리면 반대로 판단할 수 있습니다. 실무에선 게이트웨이 MAC을 고정(`ip neigh replace <IP> lladdr <MAC> nud permanent dev eth0`)해 두기도 합니다.
8. **이 도구는 학습용 초안입니다.** 실제 서비스 보호에는 Suricata, Snort(침입 탐지), fail2ban(무차별 대입 차단) 같은 검증된 도구를 쓰고, 이 코드는 원리 이해와 대시보드 연결 연습용으로 보시면 좋습니다.

## 8. 다음 단계 아이디어
- 대시보드: 이벤트 표 + 유형별 개수 차트 + 차단 목록 + "해제" 버튼
- `/api/auth.log` 파싱으로 SSH **로그인 실패** 기반 탐지 (지금은 접속 횟수 기반)
- 이벤트를 SQLite에 저장해 재시작 후에도 기록 유지
- API에 간단한 토큰 인증 추가 (`api.host` 를 `0.0.0.0` 으로 열 경우 권장)
