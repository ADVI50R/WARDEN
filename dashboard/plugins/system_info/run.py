import os
import shutil
import subprocess

print("== 가동 시간 ==")
print(subprocess.run(["uptime", "-p"], capture_output=True, text=True).stdout.strip())
total, used, free = shutil.disk_usage("/")
print("\n== 디스크(/) ==")
print(f"전체 {total // 2**30} GB / 사용 {used // 2**30} GB / 남음 {free // 2**30} GB")
print("\n== 메모리 ==")
print(subprocess.run(["free", "-h"], capture_output=True, text=True).stdout.strip())
print("\n== 부하 평균 (1/5/15분) ==")
print(*os.getloadavg())
