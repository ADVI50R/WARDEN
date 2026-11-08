import json
import os
import shutil
import subprocess


def gui(**block):
    """대시보드가 표·그래프로 그리는 줄 (형식은 dashboard/README.md 의 '도구 결과 화면 표시')"""
    print("@gui " + json.dumps(block, ensure_ascii=False))


def meminfo():
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            info[k] = int(v.split()[0])          # kB
    return info


uptime = subprocess.run(["uptime", "-p"], capture_output=True, text=True).stdout.strip()
total, used, free = shutil.disk_usage("/")
mem = meminfo()
mem_total, mem_avail = mem.get("MemTotal", 0), mem.get("MemAvailable", 0)
load = os.getloadavg()
cpus = os.cpu_count() or 1

gui(type="metric", label="가동 시간", value=uptime.replace("up ", ""))
gui(type="metric", label="디스크(/) 사용", value=round(used / total * 100, 1), unit="%", max=100)
if mem_total:
    gui(type="metric", label="메모리 사용", value=round((mem_total - mem_avail) / mem_total * 100, 1), unit="%", max=100)
gui(type="metric", label=f"부하(1분) / CPU {cpus}개", value=round(load[0], 2), max=cpus)
gui(type="bars", title="부하 평균", items=[["1분", round(load[0], 2)], ["5분", round(load[1], 2)], ["15분", round(load[2], 2)]])
gui(type="table", title="용량", columns=["항목", "전체", "사용", "남음"],
    rows=[["디스크(/)", f"{total // 2**30} GB", f"{used // 2**30} GB", f"{free // 2**30} GB"],
          ["메모리", f"{mem_total // 1024} MB", f"{(mem_total - mem_avail) // 1024} MB", f"{mem_avail // 1024} MB"]])

print("== 가동 시간 ==")
print(uptime)
print("\n== 디스크(/) ==")
print(f"전체 {total // 2**30} GB / 사용 {used // 2**30} GB / 남음 {free // 2**30} GB")
print("\n== 메모리 ==")
print(subprocess.run(["free", "-h"], capture_output=True, text=True).stdout.strip())
print("\n== 부하 평균 (1/5/15분) ==")
print(*load)
