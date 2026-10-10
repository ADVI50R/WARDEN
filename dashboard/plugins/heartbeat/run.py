import sys
import time

interval = int(sys.argv[1]) if len(sys.argv) > 1 else 2
n = 0
while True:
    n += 1
    print(f"[{time.strftime('%H:%M:%S')}] 살아있음 #{n}", flush=True)
    time.sleep(interval)
