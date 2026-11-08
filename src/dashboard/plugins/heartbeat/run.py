import json
import os
import sys
import time

interval = int(sys.argv[1]) if len(sys.argv) > 1 else 2
cpus = os.cpu_count() or 1
n = 0
while True:
    n += 1
    print(f"[{time.strftime('%H:%M:%S')}] 살아있음 #{n}", flush=True)
    # 대시보드가 그래프로 그리는 줄: 같은 label 로 계속 출력하면 값이 쌓임 (최근 60개)
    print("@gui " + json.dumps({"type": "chart", "label": "부하(1분)", "value": round(os.getloadavg()[0], 2), "max": cpus},
                               ensure_ascii=False), flush=True)
    print("@gui " + json.dumps({"type": "metric", "label": "보낸 신호", "value": n, "unit": "회"}, ensure_ascii=False), flush=True)
    time.sleep(interval)
