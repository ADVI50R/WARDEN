#!/bin/bash
# Guardian 공격 시험 자동 실행 (공격자 VM 192.168.56.20 에서만, 실습망 lab 안에서만 사용)
# attack_test_guide.md 의 root 가 필요한 시험(잘 안 보이는 스캔, 핑·SYN 플러드, ARP 스푸핑, 다른 IP 로 들어오기)을
# 순서대로 실행한다. 같은 알림은 30초에 한 번만 기록되므로 시험 사이에 기다린다.
#   사용법:  sudo bash ~/attack_auto.sh
set -u
SERVER=192.168.56.10
MGMT_NET=192.168.57.0/24
MGMT_IP=192.168.57.10
WAIT=35

if [ "$(id -u)" -ne 0 ]; then
    echo "root 권한이 필요합니다:  sudo bash $0"
    exit 1
fi

cleanup() { ip route del "$MGMT_NET" 2>/dev/null; }      # 중간에 멈춰도 6번 시험의 임시 경로를 지움
trap cleanup EXIT INT TERM

step() { echo; echo "[$(date +%T)] $1"; }
pause() { echo "    ... ${WAIT}초 기다림 (같은 알림은 30초에 한 번만 기록됨)"; sleep "$WAIT"; }

echo "Guardian 공격 시험 시작: $(date '+%F %T')  (대상 $SERVER, 약 5분)"

step "1/8 NULL 스캔 (플래그 없는 패킷)"
nmap -sN -p 1-100 "$SERVER" | tail -n 1
pause

step "2/8 FIN 스캔"
nmap -sF -p 1-100 "$SERVER" | tail -n 1
pause

step "3/8 Xmas 스캔"
nmap -sX -p 1-100 "$SERVER" | tail -n 1
pause

step "4/8 UDP 스캔"
nmap -sU -p 1-100 --max-retries 0 "$SERVER" | tail -n 1
pause

step "5/8 핑 플러드 (200개)"
ping -f -c 200 "$SERVER" | tail -n 2

step "6/8 SYN 플러드 (5초)"
timeout -s INT 5 hping3 -S -p 80 --flood "$SERVER" 2>&1 | tail -n 3

step "7/8 ARP 스푸핑 (같은 IP 를 서로 다른 MAC 으로 두 번 알림)"
python3 -c "from scapy.all import *; [sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=2, psrc='192.168.56.99', hwsrc=m, pdst='$SERVER'), iface='eth0', verbose=0) for m in ('02:00:00:00:00:01', '02:00:00:00:00:02')]" && echo "    보냄"
pause

step "8/8 서버의 다른 IP($MGMT_IP)로 포트 스캔"
ip route add "$MGMT_NET" via "$SERVER"
nmap -p 1-100 "$MGMT_IP" | grep -E "open|Nmap done"
ip route del "$MGMT_NET"

echo
echo "[$(date +%T)] 끝. 대시보드 '개요' 에서 결과를 확인하세요."
