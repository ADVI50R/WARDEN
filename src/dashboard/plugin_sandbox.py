#!/usr/bin/env python3
"""
승인 대기 중인 플러그인 업로드를 '격리된 상태로 한 번 실행'해 보는 모듈 (표준 라이브러리만 사용).

bwrap(bubblewrap)으로 새 네임스페이스를 만들어 그 안에서 명령을 돌린다:
- 네트워크 없음 (--unshare-net)
- 쓰기 가능한 곳은 이번 실행을 위해 새로 만든 빈 임시 폴더 하나뿐, 나머지(/usr /bin /lib 등)는 읽기 전용
- /etc, /home, /root 등은 아예 보이지 않음 (바인드하지 않은 경로는 샌드박스 안에서 존재하지 않는 것처럼 동작)
- prlimit 으로 메모리·열 수 있는 파일 수·프로세스 수·CPU 시간을 제한
- timeout 으로 실행 시간을 강제로 끝냄 (두 번째 안전장치로 subprocess 쪽에도 타임아웃을 또 걺)

이 네 가지 도구(bwrap, prlimit, timeout, python3)는 모두 Kali 기본 설치에 들어 있어
인터넷이 없는 lab 망에서도 추가 설치 없이 그대로 쓸 수 있다.

주의: 이 격리는 커널 네임스페이스에 기대는 것이라 '절대 안전'을 보장하는 것은 아니다
(커널 자체의 취약점이 있다면 뚫릴 수 있음). 그래도 '검토 없이 업로드만으로 실제 피해
(네트워크로 빠져나가기, 다른 사용자 파일 접근, 시스템 설정 변경)를 바로 주지 않는다'는
목표에는 충분하다. 승인 대기(plugins_pending/) 구조와 터미널 전용 approve_plugin.py 설치
절차는 그대로 두고, 이 모듈은 '설치하지 않고 한 번 시험 실행'만 담당한다.
"""
import os
import shutil
import subprocess
import tempfile

BWRAP = shutil.which("bwrap")
PRLIMIT = shutil.which("prlimit")
TIMEOUT = shutil.which("timeout")

READ_ONLY_SYSTEM_BINDS = ("/usr", "/bin", "/lib", "/lib64", "/lib32")
MIN_TIMEOUT_SEC, MAX_TIMEOUT_SEC = 1, 45
MAX_OUTPUT_BYTES = 32 * 1024
MAX_MEM_BYTES = 256 * 1024 * 1024
MAX_NOFILE = 128
MAX_NPROC = 32


def available():
    """샌드박스 도구가 서버에 다 있는지"""
    return bool(BWRAP and PRLIMIT and TIMEOUT)


def _system_bind_args():
    args = []
    for p in READ_ONLY_SYSTEM_BINDS:
        if os.path.isdir(p):
            args += ["--ro-bind", p, p]
    return args


def run_sandboxed(cmd, code_dir, timeout_sec):
    """cmd: 실행할 argv (프로그램 경로는 이미 절대/상대로 해석되어 있어야 함)
    code_dir: 읽기 전용으로 마운트할, 업로드된 코드가 있는 폴더
    돌려주는 값: {"rc": int|None, "output": str, "timed_out": bool}
    """
    if not available():
        raise RuntimeError("샌드박스 도구(bwrap/prlimit/timeout)가 서버에 설치되어 있지 않습니다")
    timeout_sec = max(MIN_TIMEOUT_SEC, min(int(timeout_sec), MAX_TIMEOUT_SEC))
    with tempfile.TemporaryDirectory(prefix="plugin_sandbox_") as scratch:
        os.chmod(scratch, 0o700)
        wrapped = [
            TIMEOUT, "-k", "2", str(timeout_sec),
            BWRAP,
            *_system_bind_args(),
            "--ro-bind", code_dir, code_dir,
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--bind", scratch, scratch,     # /tmp 보다 뒤에 와야 한다 (안 그러면 --tmpfs /tmp 가 이 바인드를 덮어씀)
            "--chdir", code_dir,            # command 의 './run.py' 같은 상대경로가 코드 폴더 기준으로 풀리게 함
            "--unshare-net", "--unshare-uts", "--unshare-ipc", "--unshare-pid",
            "--die-with-parent", "--new-session",
            "--clearenv",
            "--setenv", "PATH", "/usr/bin:/bin",
            "--setenv", "HOME", scratch,
            "--setenv", "LANG", "C.UTF-8",
            "--",
            # 제한은 샌드박스 안쪽에서 건다. 프로세스 수 제한(nproc)은 계정 전체를 세므로, 바깥에서 걸면
            # kali 의 다른 프로세스가 많을 때(데스크톱 로그인 등) 샌드박스를 만드는 것부터 실패한다
            PRLIMIT, f"--as={MAX_MEM_BYTES}", f"--nofile={MAX_NOFILE}", f"--nproc={MAX_NPROC}",
            f"--cpu={timeout_sec + 2}", "--",
            *cmd,
        ]
        try:
            proc = subprocess.run(wrapped, cwd=code_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, timeout=timeout_sec + 10)
        except subprocess.TimeoutExpired as e:
            out = (e.output or b"").decode("utf-8", "replace")
            return {"rc": None, "output": out[-MAX_OUTPUT_BYTES:], "timed_out": True}
        out = proc.stdout.decode("utf-8", "replace")
        timed_out = proc.returncode == 124          # timeout 명령이 시간 초과로 끝낸 경우의 종료 코드
        return {"rc": proc.returncode, "output": out[-MAX_OUTPUT_BYTES:], "timed_out": timed_out}
