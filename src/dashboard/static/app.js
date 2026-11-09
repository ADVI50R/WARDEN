"use strict";
const $ = (s) => document.querySelector(s);
let token = "";
try { token = localStorage.getItem("gd_token") || ""; } catch (e) {}
let lastPackets = null, lastPacketsAt = 0;
let currentView = "overview";

// ── 안전한 DOM 생성 (공격자가 만든 문자열이 들어와도 HTML 로 해석되지 않음) ──
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(c));
  return e;
}
const selecting = (n) => { const sel = window.getSelection(); return !!(sel && sel.toString() && n.contains(sel.anchorNode)); };   // 복사하려고 드래그 중
const typing = (n) => n.contains(document.activeElement) && /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };
// 설명 글 상자: 내용 줄 수만큼 높이를 맞춤 (입력할 때마다, 그리고 창을 열 때)
const autoGrow = (t) => { if (!t) return; t.style.height = "auto"; t.style.height = t.scrollHeight + 2 + "px"; };
document.addEventListener("input", (e) => { if (e.target.matches && e.target.matches("textarea.desc")) autoGrow(e.target); });function alertBox(box, kind, text) { clear(box); box.append(el("div", {class: "alert " + kind}, text)); }

async function api(path, method = "GET", body) {
  const r = await fetch(path, {
    method, headers: {"X-Token": token, "Content-Type": "application/json"},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) { showLogin(); throw new Error("로그인 필요"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ("오류 " + r.status));
  return data;
}

function showLogin(msg) {
  $("#login").hidden = false;
  $("#loginErr").hidden = !msg; $("#loginErr").textContent = msg || "";
}
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  token = $("#tokenInput").value.trim();
  try {
    await api("/api/plugins");
    try { localStorage.setItem("gd_token", token); } catch (err) {}
    $("#login").hidden = true; myIp = ""; refresh(true).then(() => { if (currentView === "report") loadReport().catch(() => {}); });
  } catch (err) { showLogin("토큰이 맞지 않습니다"); }
});

// ── 값 변환 ──
// 시각은 서버 시간대가 아니라 보는 사람의 시간대로 표시 (패킷 보기와 같은 기준)
function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(String(iso).replace(/([+-]\d\d)(\d\d)$/, "$1:$2"));
  if (isNaN(d)) return String(iso).replace("T", " ").slice(0, 19);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
const fmtDur = (s) => s >= 60 ? Math.floor(s / 60) + "분 " + (s % 60) + "초" : s + "초";
const fmtUp = (s) => `${Math.floor(s / 3600)}시간 ${Math.floor(s % 3600 / 60)}분`;
const RISK = {info: "Low", warning: "Medium", critical: "Critical"};
const ACTION = {alert: "탐지됨", block: "차단됨", "block(dry-run)": "차단(모의)", unblock: "해제됨"};
const ADMIN_TYPES = new Set(["unblock", "manual_block", "rule_toggle"]);       // 공격 탐지가 아닌 관리 작업 기록
const ruleNames = {syn_flood_distributed: "분산 SYN 플러드", unblock: "차단 해제", manual_block: "수동 차단"};   // 규칙 이름은 loadRules 가 채움
const typeName = (t) => ruleNames[t] || t;
// 알림: 위험도 기본값(Critical = 팝업+소리, Medium = 팝업, Low = 없음). 규칙에 따로 정한 값(notify)이 있으면 그것이 먼저
const DEFAULT_ALERT = {critical: {popup: true, sound: true}, warning: {popup: true, sound: false}, info: {popup: false, sound: false}};
const ruleNotify = {};                                 // 규칙 id -> {popup?, sound?} (loadRules 가 채움)
function alertPolicy(type, severity) {
  const d = DEFAULT_ALERT[severity] || DEFAULT_ALERT.info, n = ruleNotify[type] || {};
  return {popup: n.popup ?? d.popup, sound: n.sound ?? d.sound, custom: "popup" in n || "sound" in n};
}
const alertText = (p) => p.popup && p.sound ? "팝업+소리" : p.popup ? "팝업만" : p.sound ? "소리만" : "알림 없음";
let lastStatus = null, myIp = "", currentDry = true;

function metric(label, value, delta, cls) {
  return el("div", {class: "metric"}, el("div", {class: "label"}, label), el("div", {class: "value"}, value),
    el("div", {class: "delta " + (cls || "flat")}, delta));
}
const signed = (n, unit) => (n > 0 ? "▲ +" : n < 0 ? "▼ " : "") + n + unit;

function realBlockWarning() {
  let msg = "실제로 방화벽 차단을 켤까요?\n화이트리스트에 없는 탐지 대상은 이제부터 진짜로 막힙니다.";
  const n = lastStatus ? lastStatus.blocked_count : 0;
  if (n) msg += `\n\n지금 모의 차단 목록에 있는 ${n}건도 바로 실제로 차단됩니다.`;
  if (myIp && lastStatus && !lastStatus.whitelist.includes(myIp))
    msg += `\n\n⚠ 지금 접속한 이 PC(${myIp})가 화이트리스트에 없습니다. 차단되면 대시보드에 못 들어올 수 있습니다.`;
  return msg;
}

// 관제 서버 상태 카드: '탐지만(dry-run)' ↔ '실제 차단' 슬라이드. 3초마다 다시 그려도 조작 중에는 건드리지 않음
let dryRunBusy = false;
function dryRunMetric(dryRun) {
  const sw = el("input", {type: "checkbox", role: "switch"});
  sw.checked = !dryRun;                              // 켜짐 = 실제 차단
  const txt = el("span", {class: "swtxt"});
  const sync = () => { txt.textContent = sw.checked ? "실제 차단" : "탐지만 (dry-run)"; };
  sync();
  sw.addEventListener("change", async () => {
    const goingReal = sw.checked;
    if (goingReal && !confirm(realBlockWarning())) {
      sw.checked = false; sync(); return;
    }
    dryRunBusy = true; sw.disabled = true;
    try {
      await api("/api/dry_run", "POST", {dry_run: !goingReal});
      sync();
    } catch (e) {
      sw.checked = !goingReal; sync(); alert(e.message);
    } finally {
      sw.disabled = false; dryRunBusy = false; refresh(true);
    }
  });
  return el("div", {class: "metric"}, el("div", {class: "label"}, "관제 서버 상태"), el("div", {class: "value", id: "statusValue"}, "정상 (Normal)"),
    el("div", {class: "delta flat"}, el("label", {class: "switch"}, sw, el("span", {class: "slider"}), txt)));
}

// ── 연결 상태: 응답이 끊기면 화면 전체에 알리고, 옛 숫자는 흐리게 ──
let lastOkAt = 0;
function setWarden(up, why) {
  const conn = $("#conn"), banner = $("#downBanner");
  conn.textContent = up ? "WARDEN 연결됨" : "⚠ 응답 없음";
  conn.className = "conn " + (up ? "ok" : "bad");
  banner.hidden = up;
  $("#metrics").classList.toggle("stale", !up);
  $("#eventRows").classList.toggle("stale", !up);
  if (up) { lastOkAt = Date.now(); $("#lastOk").textContent = ""; return; }
  const when = lastOkAt ? new Date(lastOkAt).toTimeString().slice(0, 8) : "없음";
  $("#lastOk").textContent = "마지막 응답 " + when;
  banner.textContent = `⚠ WARDEN 응답 없음: 탐지·차단이 멈췄을 수 있습니다. 화면의 숫자는 마지막으로 받은 값입니다 (마지막 정상 응답 ${when}). ${why || ""}`;
  const v = $("#statusValue");
  if (v) v.textContent = "⚠ 응답 없음";
}
function setMode(dry) {
  currentDry = dry;
  const m = $("#modeBadge");
  m.textContent = dry ? "🧪 탐지만 (dry-run)" : "🔥 실제 차단 중";
  m.className = "conn" + (dry ? "" : " real");
}

// ── 새 위협 알림: 다른 메뉴를 보고 있어도 알 수 있게 (브라우저 알림은 HTTPS 가 필요해 화면 안 알림과 소리로) ──
let seenEvents = null, unread = 0, soundOn = false;
soundOn = true;                                         // 전체 소리 스위치 (규칙별 설정보다 위). 기본은 켬
try { soundOn = localStorage.getItem("gd_sound") !== "0"; } catch (e) {}
const baseTitle = document.title;
function drawUnread() {
  const b = $("#newBadge");
  b.hidden = !unread; b.textContent = unread;
  document.title = (unread ? `(${unread}) ` : "") + baseTitle;
}
function drawSound() { $("#soundBtn").textContent = soundOn ? "🔔 소리 켬" : "🔕 소리 끔"; }
function beep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.frequency.value = 880; g.gain.value = 0.08;
    o.connect(g); g.connect(ctx.destination);
    o.start(); o.stop(ctx.currentTime + 0.18);
    o.onended = () => ctx.close();
  } catch (e) {}
}
function toast(e) {
  const t = el("button", {class: "toast " + e.severity, type: "button", onclick: () => { t.remove(); showView("overview", true); showAnalysis(e.id); }},
    el("b", {}, typeName(e.type)), ` · ${e.source}`, el("br"), e.detail);
  $("#toasts").append(t);
  while ($("#toasts").children.length > 3) $("#toasts").firstChild.remove();
  setTimeout(() => t.remove(), 9000);
}
function notifyNew(list) {
  const real = list.filter((e) => !ADMIN_TYPES.has(e.type));
  if (seenEvents === null) { seenEvents = new Set(real.map((e) => e.id)); return; }    // 처음 받은 것은 새 위협이 아님
  const fresh = real.filter((e) => !seenEvents.has(e.id));
  if (!fresh.length) return;
  fresh.forEach((e) => seenEvents.add(e.id));
  const loud = fresh.map((e) => [e, alertPolicy(e.type, e.severity)]).filter(([, p]) => p.popup || p.sound);   // '알림 없음'은 기록만
  if (!loud.length) return;
  if (currentView !== "overview" || document.hidden) { unread += loud.length; drawUnread(); }
  loud.filter(([, p]) => p.popup).slice(0, 3).reverse().forEach(([e]) => toast(e));
  if (soundOn && loud.some(([, p]) => p.sound)) beep();
}
document.addEventListener("visibilitychange", () => { if (!document.hidden && currentView === "overview") { unread = 0; drawUnread(); } });
$("#soundBtn").addEventListener("click", () => {
  soundOn = !soundOn;
  try { localStorage.setItem("gd_sound", soundOn ? "1" : "0"); } catch (e) {}
  drawSound();
  if (soundOn) beep();
});
drawSound();
$("#logoutBtn").addEventListener("click", () => {
  token = "";
  try { localStorage.removeItem("gd_token"); } catch (e) {}
  $("#tokenInput").value = "";
  showLogin();
});

// ── 지표 + 로그 ──
const eventMatches = (e) => {
  const sev = $("#evSev").value, q = $("#evIp").value.trim().toLowerCase(), type = $("#typeFilter").value;
  return (!type || e.type === type) && (!sev || e.severity === sev)
    && (!q || `${e.source} ${e.detail} ${typeName(e.type)}`.toLowerCase().includes(q));
};
// IP·MAC 옆에 붙는 메모 태그 (메모는 '보안 정책'의 차단 목록·IP별 기록에서 적음, /api/status 의 notes 로 받음)
let ipNotes = {};
const noteOf = (ip) => (ip && (ipNotes[ip] || ipNotes["mac:" + ip] || ipNotes[String(ip).replace(/^mac:/, "")])) || "";
const noteTag = (ip) => { const n = noteOf(ip); return n ? el("span", {class: "tag memo", title: "메모: " + n}, n) : null; };
const sourceLink = (src) => src === "*" ? src : [el("button", {class: "linkbtn", type: "button", title: "이 출발지의 공격 흐름 보기", onclick: () => showTimeline(src)}, src), noteTag(src)];
let lastEvents = [];
async function loadTop() {
  const [st, evs] = await Promise.all([api("/api/status"), api("/api/events?limit=200")]);
  lastStatus = st;
  ipNotes = st.notes || {};
  setWarden(true);
  setMode(st.dry_run);
  const s = st.stats || {};
  const attacks = evs.events.filter((e) => !ADMIN_TYPES.has(e.type));
  const recent5 = attacks.filter((e) => Date.now() - Date.parse(e.timestamp) < 300000).length;
  const now = Date.now();
  let rate = 0;
  if (lastPackets !== null && now > lastPacketsAt) rate = Math.round(((s.packets_total || 0) - lastPackets) / ((now - lastPacketsAt) / 1000));
  lastPackets = s.packets_total || 0; lastPacketsAt = now;

  const m = $("#metrics");
  if (!dryRunBusy) {
    clear(m);
    const srv = st.server;
    m.append(
      metric("탐지된 위협 (누적)", (s.events_total || 0) + " 건", signed(recent5, " 건 (최근 5분)"), recent5 ? "down" : "flat"),
      metric("방화벽 자동 차단 (누적)", (s.blocks_auto || 0) + " 건",
        (s.blocks_auto_sim ? `모의 ${s.blocks_auto_sim} 건 · ` : "") + `지금 ${st.dry_run ? "모의 " : ""}차단 중 ${st.blocked_count} 건`, st.blocked_count ? "up" : "flat"),
      metric("처리한 패킷", (s.packets_total || 0).toLocaleString() + " 개",
        `초당 ${rate} 개` + (st.missed_packets ? ` · 못 따라간 패킷 약 ${st.missed_packets.toLocaleString()} 개` : ""), st.missed_packets > 1000 ? "down" : "flat"),
      metric("서버 부담", srv ? `메모리 ${srv.mem_percent}%` : "-", srv ? `부하 ${srv.load1} (CPU ${srv.cpus}개)` : "", "flat"),
      dryRunMetric(st.dry_run),
    );
  }

  const sel = $("#typeFilter");
  const known = new Set([...sel.options].map((o) => o.value));
  evs.events.forEach((e) => { if (!known.has(e.type)) { known.add(e.type); sel.append(el("option", {value: e.type}, typeName(e.type))); } });
  notifyNew(evs.events);
  lastEvents = evs.events;
  drawEvents();
  const t = $("#blockTarget");                          // 차단 칸의 기본값: 가장 최근 공격자 (유출 목적지·출발지 없는 탐지·관리 작업은 제외)
  const att = attacks.find((e) => e.type !== "exfiltration" && e.source !== "*");
  if (!t.value && !t.dataset.touched && att) t.value = (att.type === "arp_spoof" ? "mac:" : "") + att.source;
}
function drawEvents() {
  const tb = $("#eventRows");
  if (selecting(tb)) return;
  const rows = lastEvents.filter(eventMatches);
  clear(tb);
  if (!rows.length) tb.append(el("tr", {}, el("td", {colspan: 8}, lastEvents.length ? "조건에 맞는 이벤트가 없습니다." : "아직 탐지된 이벤트가 없습니다.")));
  rows.forEach((e) => tb.append(el("tr", {},
    el("td", {}, fmtTime(e.timestamp)), el("td", {}, sourceLink(e.source)), el("td", {}, e.target || "", noteTag(e.target)), el("td", {title: e.type}, typeName(e.type)),
    el("td", {class: "sev-" + RISK[e.severity]}, RISK[e.severity] || e.severity),
    el("td", {}, ACTION[e.action] || e.action), el("td", {class: "wrap"}, e.detail),
    el("td", {}, el("button", {class: "btn sm", type: "button", onclick: () => showAnalysis(e.id)}, "ℹ️ 정보")))));
}
["#typeFilter", "#evSev", "#evIp"].forEach((id) => $(id).addEventListener("input", drawEvents));

// ── CSV 내보내기 (엑셀에서 한글이 깨지지 않게 BOM 포함, 수식으로 해석될 값은 앞에 ' 를 붙임) ──
function downloadCsv(events) {
  const cell = (v) => {
    let t = String(v == null ? "" : v);
    if (/^[=+\-@]/.test(t)) t = "'" + t;
    return `"${t.replace(/"/g, '""')}"`;
  };
  const head = ["시간", "출발지", "출발지 메모", "대상", "유형", "이벤트", "위험도", "상태", "상세"];
  const lines = events.map((e) => [fmtTime(e.timestamp), e.source, noteOf(e.source), e.target, e.type, typeName(e.type), RISK[e.severity] || e.severity, ACTION[e.action] || e.action, e.detail].map(cell).join(","));
  const a = el("a", {href: URL.createObjectURL(new Blob(["\ufeff" + [head.map(cell).join(","), ...lines].join("\r\n")], {type: "text/csv;charset=utf-8"})), download: "warden_events.csv"});
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
$("#evCsv").addEventListener("click", async () => {
  try { downloadCsv((await api("/api/events?limit=1000")).events.filter(eventMatches)); } catch (e) { alert(e.message); }
});

// ── 공격자 타임라인: 한 출발지의 탐지·차단·해제를 시간순으로 ──
let tlSource = "";
async function showTimeline(src) {
  tlSource = src;
  $("#tlTitle").textContent = `🕒 ${src}${noteOf(src) ? ` (${noteOf(src)})` : ""} 의 공격 흐름`;
  const body = $("#tlBody");
  clear(body); body.append(el("p", {class: "caption"}, "불러오는 중…"));
  if (!$("#tlDialog").open) $("#tlDialog").showModal();
  try {
    const list = (await api("/api/events?limit=1000&source=" + encodeURIComponent(src))).events.slice().reverse();
    clear(body);
    if (!list.length) return body.append(el("p", {}, "기록이 없습니다."));
    const attacks = list.filter((e) => !ADMIN_TYPES.has(e.type));
    const kinds = [...new Set(attacks.map((e) => typeName(e.type)))];
    body.append(el("p", {class: "caption"}, `탐지 ${attacks.length}건 · ${kinds.join(" → ") || "관리 작업만 있음"}`));
    body.append(el("ul", {class: "timeline"}, list.map((e) => el("li", {class: ADMIN_TYPES.has(e.type) ? "admin" : e.severity},
      el("time", {}, fmtTime(e.timestamp)), el("b", {}, typeName(e.type)), ` · ${ACTION[e.action] || e.action}`, el("br"), e.detail))));
  } catch (err) { clear(body); alertBox(body, "error", err.message); }
}
$("#tlClose").addEventListener("click", () => $("#tlDialog").close());
$("#tlBlock").addEventListener("click", () => {
  $("#tlDialog").close();
  goBlock(/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(tlSource) ? "mac:" + tlSource : tlSource);
});
function goBlock(target) {
  $("#blockTarget").value = target; $("#blockTarget").dataset.touched = "1";     // 차단은 직접 눌러야 실행됨 (여기서는 칸만 채움)
  showView("policy", true);
  $("#blockForm").scrollIntoView({behavior: "smooth", block: "center"});
  $("#blockTarget").focus();
}
// ── 침입 상세 분석 ('정보' 버튼): 어디서 · 어떤 공격 · 영향 · 대응 결과 · 권고 ──
const EV_LEVEL = {good: "success", warn: "warning", bad: "error", info: "info"};
let evOpenId = null;
async function showAnalysis(id) {
  evOpenId = id;
  const body = $("#evBody");
  clear(body); body.append(el("p", {class: "caption"}, "분석 중…"));
  if (!$("#evDialog").open) $("#evDialog").showModal();
  try {
    const a = await api("/api/event_analysis?id=" + encodeURIComponent(id));
    if (evOpenId !== id) return;                      // 그 사이 다른 이벤트를 열었으면 무시
    clear(body);
    $("#evTitle").textContent = "ℹ️ 침입 상세 분석 — " + a.name;
    body.append(el("div", {class: "alert " + (EV_LEVEL[a.headline.level] || "info")}, el("b", {}, a.headline.text)));
    a.sections.forEach((s) => body.append(el("div", {class: "evsec"}, el("h4", {}, s.title), el("ul", {}, s.lines.map((l) => el("li", {}, l))))));
    if (a.server_now) body.append(el("p", {class: "caption"},
      `지금 서버: 메모리 사용 ${a.server_now.mem_percent}% · 부하(1분) ${a.server_now.load1} (CPU ${a.server_now.cpus}개) — 공격 당시가 아니라 조회한 지금의 값입니다.`));
    body.append(el("details", {class: "expander"}, el("summary", {}, "🔎 근거 데이터"),
      el("div", {}, el("dl", {class: "evdl"}, a.evidence.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])))));
    $("#evBlockGo").hidden = !a.actions.can_block;
    $("#evBlockGo").dataset.target = a.actions.target;
    const ev = a.event || {};                          // 관리 작업(차단 해제 등)·IP 가 아닌 출발지는 관련 패킷을 고를 수 없음
    $("#evPcap").hidden = !(a.headline.level !== "info" && (ev.type === "arp_spoof" || /^\d+\.\d+\.\d+\.\d+$/.test(ev.source || "")));
  } catch (err) { if (evOpenId === id) { clear(body); alertBox(body, "error", err.message); } }
}
$("#evPcap").addEventListener("click", () => evOpenId && downloadPcap("event=" + encodeURIComponent(evOpenId), $("#evPcap")));

// ── PCAP 내보내기: 토큰을 헤더로 보내야 해서 링크 대신 받아서 파일로 저장 ──
async function downloadPcap(qs, btn) {
  const label = btn.textContent;
  btn.disabled = true; btn.textContent = "만드는 중…";
  try {
    const r = await fetch("/api/pcap?" + qs, {headers: {"X-Token": token}});
    if (r.status === 401) { showLogin(); return; }
    if (!r.ok) { const d = await r.json().catch(() => ({})); alert(d.error || ("오류 " + r.status)); return; }
    const blob = await r.blob();
    const name = (/filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "") || [])[1] || "warden.pcap";
    const a = el("a", {href: URL.createObjectURL(blob), download: name});
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    const n = r.headers.get("X-Packet-Count");
    if (n) btn.title = `마지막으로 받은 파일: ${name} (패킷 ${n}개)`;
  } catch (e) { alert(e.message); }
  finally { btn.disabled = false; btn.textContent = label; }
}
$("#evRefresh").addEventListener("click", () => evOpenId && showAnalysis(evOpenId));
$("#evClose").addEventListener("click", () => $("#evDialog").close());
$("#evBlockGo").addEventListener("click", () => {
  const t = $("#evBlockGo").dataset.target;
  if (!t) return;
  $("#evDialog").close();
  goBlock(t);
});
$("#blockTarget").addEventListener("input", (e) => e.target.dataset.touched = "1");

// ── 차단 제어 ──
// 메모 칸: 입력 중에는 3초 새로고침이 다시 그리지 않도록 포커스가 있으면 건너뜀 (loadBlocked/loadHistory 참고)
function noteEditor(target, current) {
  const inp = el("input", {class: "txt", maxlength: "200", placeholder: "메모"});
  inp.value = current || "";
  const save = async () => {
    try { await api("/api/note", "POST", {target, note: inp.value}); inp.blur(); refresh(true); }
    catch (e) { alert(e.message); }
  };
  inp.addEventListener("keydown", (e) => { if (e.key === "Enter") save(); });
  return el("div", {class: "note-edit"}, inp, el("button", {class: "btn sm", onclick: save}, "저장"));
}
async function loadBlocked() {
  const d = await api("/api/blocked");
  const tb = $("#blockedRows"), note = $("#blockedNote");
  clear(note);
  if (d.simulated && d.blocked.length) note.append(el("div", {class: "alert warning"},
    "지금은 탐지만(dry-run) 모드라 아래 목록은 '모의'입니다. 실제로 막고 있지 않습니다. 실제 차단으로 바꾸면 이 목록이 바로 적용됩니다."));
  if (typing(tb) || selecting(tb)) return;
  clear(tb);
  if (!d.blocked.length) tb.append(el("tr", {}, el("td", {colspan: 6}, "차단 중인 대상이 없습니다.")));
  d.blocked.forEach((b) => tb.append(el("tr", {}, el("td", {}, sourceLink(b.target.replace(/^mac:/, "")), d.simulated && el("span", {class: "tag sim"}, "모의")),
    el("td", {}, typeName(b.reason), b.repeat > 1 ? el("span", {class: "tag", title: "24시간 안에 다시 자동 차단되어 더 길게 막음 (누적 차단)"}, `반복 ${b.repeat}회째`) : null),
    el("td", {}, fmtTime(b.since)), el("td", {}, b.permanent ? "영구" : fmtSpan(Math.max(0, b.remaining_sec))),
    el("td", {}, noteEditor(b.target, b.note)),
    el("td", {}, el("button", {class: "btn sm", onclick: () => unblock(b.target)}, "해제")))));
}
async function loadHistory() {
  const d = await api("/api/history?limit=200");
  const tb = $("#historyRows");
  if (typing(tb) || selecting(tb)) return;
  clear(tb);
  if (!d.history.length) tb.append(el("tr", {}, el("td", {colspan: 7}, "아직 기록된 공격자가 없습니다.")));
  d.history.forEach((h) => tb.append(el("tr", {},
    el("td", {}, sourceLink(h.source), h.blocked_now && el("span", {class: "tag"}, currentDry ? "모의 차단 중" : "차단 중")),
    el("td", {}, h.total + " 회"), el("td", {}, h.blocks + " 회"),
    el("td", {class: "tagline"}, Object.entries(h.by_type).sort((a, b) => b[1] - a[1]).map(([t, n]) => `${typeName(t)} ×${n}`).join(", ")),
    el("td", {}, fmtTime(h.first)), el("td", {}, fmtTime(h.last)),
    el("td", {}, noteEditor(h.source, h.note)))));
}
function drawWhitelist() {
  const box = $("#whitelistBox");
  if (!lastStatus) return;
  if (typing(box)) return;
  clear(box);
  const fixed = new Set(lastStatus.whitelist_fixed || []);
  const asTarget = (w) => (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(w) ? "mac:" + w : w);
  box.append(el("div", {class: "ptags"}, lastStatus.whitelist.map((w) => el("span", {class: "ptag"}, w, noteOf(w) ? ` · ${noteOf(w)}` : "", " ",
    fixed.has(w) ? el("span", {title: "서버 자신의 주소라 뺄 수 없습니다"}, "🔒")
      : el("button", {class: "linkbtn", type: "button", title: "화이트리스트에서 빼기", onclick: () => removeWhitelist(w, asTarget(w))}, "✕")))));
  if (myIp && !lastStatus.whitelist.includes(myIp)) box.append(el("div", {class: "alert warning"},
    `지금 접속한 이 PC(${myIp})는 화이트리스트에 없습니다. 차단되면 대시보드에 못 들어올 수 있습니다.`));
}
async function whitelistAct(action, target, done) {
  try {
    const r = await api("/api/whitelist", "POST", {action, target});
    alertBox($("#whitelistMsg"), r.ok ? "success" : "warning", r.ok ? done + (r.unblocked ? " 지금 차단 중이던 것은 차단을 풀었습니다." : "") : r.reason);
    await loadTop(); drawWhitelist(); loadBlocked();
  } catch (e) { alertBox($("#whitelistMsg"), "error", e.message); }
}
function removeWhitelist(w, target) {
  let msg = `${w} 을(를) 화이트리스트에서 뺄까요?\n앞으로 이 주소가 공격으로 탐지되면 자동 차단됩니다.`;
  if (w === myIp) msg += `\n\n⚠ ${w} 은(는) 지금 접속한 이 PC 입니다. 빼면 차단되어 대시보드에 못 들어올 수 있습니다.`;
  if (confirm(msg)) whitelistAct("remove", target, `${w} 을(를) 뺐습니다.`);
}
$("#whitelistForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const t = $("#wlTarget").value.trim();
  if (!t) return;
  if (!confirm(`${t} 은(는) 앞으로 어떤 공격을 해도 자동 차단되지 않습니다 (탐지·알림은 됩니다).\n신뢰하는 주소가 맞나요?`)) return;
  whitelistAct("add", t, `${t} 을(를) 추가했습니다.`).then(() => { $("#wlTarget").value = ""; });
});
async function loadAudit() {
  if (!$("#auditBox").open) return;
  const d = await api("/api/audit");
  const tb = $("#auditRows");
  if (selecting(tb)) return;
  clear(tb);
  if (!d.audit.length) tb.append(el("tr", {}, el("td", {colspan: 5}, "아직 기록이 없습니다.")));
  d.audit.forEach((x) => tb.append(el("tr", {}, el("td", {}, fmtTime(x.time)), el("td", {}, x.ip), el("td", {}, x.action),
    el("td", {class: "wrap"}, Object.entries(x.detail || {}).map(([k, v]) => `${k}=${v}`).join(", ")), el("td", {}, x.code))));
}
$("#auditBox").addEventListener("toggle", () => loadAudit().catch(() => {}));
async function unblock(target) {
  try {
    const r = await api("/api/unblock", "POST", {target});
    alertBox($("#blockMsg"), r.ok ? "success" : "warning", r.ok ? `해제 완료: ${target}` : r.reason);
    loadBlocked();
  } catch (e) { alertBox($("#blockMsg"), "error", e.message); }
}
$("#blockForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = $("#blockTarget").value.trim();
  if (target === myIp && !confirm(`${target} 은(는) 지금 접속한 이 PC 입니다. 차단하면 대시보드에 못 들어올 수 있습니다. 계속할까요?`)) return;
  const body = {target, reason: "dashboard"};
  const note = $("#blockNote").value.trim(); if (note) body.note = note;
  if ($("#blockPerm").checked) body.permanent = true;
  else {
    const n = (id) => Math.max(0, parseInt($(id).value, 10) || 0);
    const sec = n("#durDay") * 86400 + n("#durHour") * 3600 + n("#durMin") * 60;
    if (sec <= 0) return alertBox($("#blockMsg"), "warning", "차단 기간을 1분 이상으로 지정하거나 '영구 차단'을 체크하세요.");
    body.duration_sec = sec;
  }
  try {
    let r = await api("/api/block", "POST", body);
    if (r.exists) {                               // 이미 차단 중 -> 현재 상태를 보여주고 덮어쓸지 확인
      const c = r.current;
      const left = c.permanent ? "영구 차단" : "남은 시간 " + fmtDur(Math.max(0, c.remaining_sec));
      const next = body.permanent ? "영구 차단" : "차단 기간 " + fmtDur(body.duration_sec);
      const ok = confirm(`${target} 은(는) 이미 차단 중입니다.\n\n` +
        `현재 차단 이유: ${c.reason}\n시작: ${fmtTime(c.since)}\n${left}\n` + (c.note ? `메모: ${c.note}\n` : "") +
        `\n새 설정(${next})으로 덮어쓰시겠습니까?`);
      if (!ok) return alertBox($("#blockMsg"), "info", "덮어쓰기를 취소했습니다. 기존 차단은 그대로입니다.");
      r = await api("/api/block", "POST", {...body, overwrite: true});
    }
    if (r.ok) {
      const box = $("#blockMsg"); clear(box);
      box.append(el("div", {class: "alert success"}, `대응 완료: ${target} 이(가) ${body.permanent ? "영구 " : ""}차단 목록에 등록되었습니다.`),
        currentDry && el("div", {class: "alert info"}, "지금은 모의 모드(dry-run)라 실제 iptables 차단 없이 기록만 됩니다. 실제 차단은 '개요' 메뉴의 '관제 서버 상태' 슬라이드로 켭니다."));
    } else alertBox($("#blockMsg"), "warning", r.reason);
    loadBlocked(); loadHistory();
  } catch (err) { alertBox($("#blockMsg"), "error", err.message); }
});
const syncPerm = () => $("#durBox").classList.toggle("off", $("#blockPerm").checked);
$("#blockPerm").addEventListener("change", () => {
  const off = $("#blockPerm").checked;
  ["#durDay", "#durHour", "#durMin"].forEach((id) => { $(id).disabled = off; });
  syncPerm();
});

// ── 탐지 규칙 (모든 규칙이 rules/ 폴더의 파일 하나씩. 기본/사용자 구분 없음) ──
// 작동 방식: 방화벽(패킷을 직접 봄 — 기본 탐지기 + 직접 만든 규칙) / 플러그인(주기적으로 스크립트 실행)
const BUILTIN_DETECTORS = ["port_scan", "syn_flood", "icmp_flood", "ssh_bruteforce", "ssh_login_success", "arp_spoof", "exfiltration"];
const ruleGroup = (r) => (r.detector === "script" ? "script" : "firewall");
const ruleKind = (r) => (r.detector === "script" ? "🧩 플러그인 스크립트" : BUILTIN_DETECTORS.includes(r.detector) ? `🔥 내장 탐지기(${r.detector})` : "🔥 직접 만든 규칙");
const PROTO_TXT = {tcp: "TCP", udp: "UDP", icmp: "ICMP(핑 등)", any: "TCP/UDP/ICMP"};
// 조건을 사람이 읽는 문장으로 (기본 탐지기는 파일에 든 임계값으로 만든다)
const COND = {
  port_scan: (r) => `${r.window_sec}초 동안 서로 다른 포트 ${r.distinct_ports}개에 접속 시도`,
  syn_flood: (r) => `${r.window_sec}초 동안 한 IP 에서 SYN ${r.max_syn}개 (출발지 ${r.global_min_sources}곳 이상이면 합계 ${r.global_max_syn}개)`,
  icmp_flood: (r) => `${r.window_sec}초 동안 ping ${r.max_packets}개`,
  ssh_bruteforce: (r) => `${r.ports.join(", ")}번 포트에 ${r.window_sec}초 동안 접속 시도 ${r.max_attempts}회`,
  ssh_login_success: (r) => `${fmtSpan(r.window_sec)} 안에 로그인 실패 ${r.min_failures}회 이상인 IP 의 로그인 성공 (sshd 로그)`,
  arp_spoof: () => "알려진 IP 의 MAC 주소가 바뀜",
  exfiltration: (r) => `${r.window_sec}초 동안 외부로 ${(r.max_bytes / 1e6).toFixed(0)}MB 이상 전송`,
  custom: (r) => {
    const ports = r.dst_ports.length ? ` ${r.dst_ports.join(", ")}번 포트` : "";
    const syn = r.protocol === "tcp" && r.tcp_flags === "syn" ? " 새 연결" : "";
    const what = r.distinct === "dst_port" ? `서로 다른 포트 ${r.count}개` : `${r.count}회`;
    return `${PROTO_TXT[r.protocol]}${ports}${syn} — ${r.window_sec}초 동안 ${what}`;
  },
  script: (r) => `${r.command.join(" ")} · ${r.interval_sec}초마다 (시간제한 ${r.timeout_sec}초)`,
};
const condText = (r) => (COND[r.detector] || COND.custom)(r);

// ── 규칙의 차단 설정: 켜짐/꺼짐 슬라이드 + 차단 기간(일·시간·분) 또는 영구 차단 ──
let defaultBlockSec = 300;                           // config.json 의 기본 차단 시간 (loadRules 가 서버 값으로 갱신)
function fmtSpan(sec) {
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  return [d && `${d}일`, h && `${h}시간`, m && `${m}분`, s && `${s}초`].filter(Boolean).join(" ") || "0초";
}
const blockText = (r) => !r.block ? "알림만" : r.block_permanent ? "차단 · 영구" : `차단 · ${fmtSpan(r.block_duration_sec || defaultBlockSec)}`;

// r: 기존 규칙(없으면 {}). 돌려주는 read() 는 규칙에 합칠 값({block, block_duration_sec | block_permanent})을 만든다.
// 기간을 건드리지 않았으면 기존 값(없으면 기본값 사용)을 그대로 둬서, 열었다가 저장만 해도 '수정'으로 잡히지 않는다.
function blockControls(r) {
  const orig = r.block_duration_sec, sec = orig || defaultBlockSec;
  let touched = false;
  const sw = el("input", {type: "checkbox", role: "switch"}); sw.checked = !!r.block;
  const swTxt = el("span", {class: "swtxt"});
  const num = (v, max) => { const i = el("input", {class: "txt num", type: "number", min: "0", max: String(max)}); i.value = v; return i; };
  const dd = num(Math.floor(sec / 86400), 3650), hh = num(Math.floor(sec % 86400 / 3600), 23), mm = num(Math.floor(sec % 3600 / 60), 59);
  const perm = el("input", {type: "checkbox"}); perm.checked = !!r.block_permanent;
  const unit = (i, t) => el("label", {}, i, " " + t);
  const dur = el("div", {class: "blockdur"}, el("span", {class: "lbl"}, "차단 기간"),
    el("div", {class: "dur"}, unit(dd, "일"), unit(hh, "시간"), unit(mm, "분"), el("label", {class: "chk"}, perm, " 영구 차단 (직접 해제할 때까지)")));
  const sync = () => {
    swTxt.textContent = "방화벽 차단 " + (sw.checked ? "켜짐" : "꺼짐");
    dur.hidden = !sw.checked;
    [dd, hh, mm].forEach((i) => { i.disabled = perm.checked; });
  };
  [dd, hh, mm, perm].forEach((i) => i.addEventListener("input", () => { touched = true; }));
  sw.addEventListener("change", sync);
  perm.addEventListener("change", sync);
  sync();
  const read = () => {
    if (!sw.checked) return {block: false};
    if (perm.checked) return {block: true, block_permanent: true};
    if (!touched) return orig ? {block: true, block_duration_sec: orig} : {block: true};
    const n = (i) => Math.max(0, parseInt(i.value, 10) || 0);
    const total = n(dd) * 86400 + n(hh) * 3600 + n(mm) * 60;
    if (total <= 0) throw new Error("차단 기간을 1분 이상으로 지정하거나 '영구 차단'을 체크하세요.");
    return total === defaultBlockSec && !orig ? {block: true} : {block: true, block_duration_sec: total};
  };
  return {node: el("div", {class: "blockctl"}, el("label", {class: "switch"}, sw, el("span", {class: "slider"}), swTxt), dur), read};
}

const splitTags = (s) => s.split(/[\s,]+/).map((t) => t.replace(/^#+/, "")).filter(Boolean);   // "#a #b, c" -> ["a","b","c"]

// 검색·정렬·필터: 3초마다 카드를 다시 그려도 입력값은 유지되고, 다시 그릴 때마다 같은 조건이 적용된다
let ruleItems = [];
const squash = (t) => String(t).toLowerCase().replace(/[\s_]+/g, "");
const SEV_RANK = {critical: 3, warning: 2, info: 1};
// 정렬 기준별 비교 (기본 방향: 글자순=가나다, 위험도순=높은 것 먼저, 차단 여부=차단 먼저, 상태=켜짐 먼저). 같으면 이름순
const SORTS = {
  name: (a, b) => 0,
  sev: (a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity],
  block: (a, b) => Number(b.block) - Number(a.block),
  state: (a, b) => Number(b.enabled) - Number(a.enabled),
};
let ruleRev = false;
let ruleTag = "";                                    // 태그 필터 (빈 값 = 전체)
let ruleHits = {};                                   // 규칙 id -> {count, last}
let ruleSig = "";                                    // 규칙 목록이 바뀌었는지 비교용 (그대로면 카드를 다시 만들지 않음)
function ruleTagButton(t) {
  return el("button", {class: "ptag" + (ruleTag === t ? " on" : ""), type: "button", title: "이 태그로 걸러 보기",
    onclick: () => { ruleTag = ruleTag === t ? "" : t; drawRules(); }}, "#" + t);
}
function drawRules() {
  const q = squash($("#ruleSearch").value), sev = $("#ruleSev").value, blk = $("#ruleBlock").value, st = $("#ruleState").value;
  const allTags = [...new Set(ruleItems.flatMap((i) => i.rule.tags || []))].sort();
  if (ruleTag && !allTags.includes(ruleTag)) ruleTag = "";
  const tagBar = $("#ruleTags"); clear(tagBar);
  allTags.forEach((t) => tagBar.append(ruleTagButton(t)));
  if (ruleTag) tagBar.append(el("button", {class: "btn sm", type: "button", onclick: () => { ruleTag = ""; drawRules(); }}, "태그 해제"));
  const shown = ruleItems.filter((i) =>
    (!q || squash(i.rule.name).includes(q) || squash(i.rule.id).includes(q) || (i.rule.tags || []).some((t) => squash(t).includes(q))) &&   // 이름·ID·태그 중 하나라도 맞으면 표시
    (!ruleTag || (i.rule.tags || []).includes(ruleTag)) &&
    (!sev || i.rule.severity === sev) &&
    (!blk || (blk === "block") === i.rule.block) &&
    (!st || (st === "on") === i.rule.enabled));
  const key = $("#ruleSort").value;
  shown.sort((x, y) => (SORTS[key](x.rule, y.rule)) || x.rule.name.localeCompare(y.rule.name, "ko"));
  if (ruleRev) shown.reverse();                      // 역순은 어떤 정렬 기준에도 적용
  const fwTb = $("#ruleRows"), scTb = $("#scriptRuleRows");
  clear(fwTb); clear(scTb);
  const fwShown = shown.filter((i) => ruleGroup(i.rule) === "firewall");
  const scShown = shown.filter((i) => ruleGroup(i.rule) === "script");
  const fwTotal = ruleItems.filter((i) => ruleGroup(i.rule) === "firewall").length;
  const scTotal = ruleItems.filter((i) => ruleGroup(i.rule) === "script").length;
  if (!fwShown.length) fwTb.append(el("div", {class: "alert info"}, fwTotal ? "조건에 맞는 규칙이 없습니다." : "방화벽 방식 규칙이 없습니다."));
  fwShown.forEach((i) => fwTb.append(i.card));
  if (!scShown.length) scTb.append(el("div", {class: "alert info"}, scTotal ? "조건에 맞는 규칙이 없습니다." : "플러그인 방식 규칙이 없습니다."));
  scShown.forEach((i) => scTb.append(i.card));
  const active = [sev, blk, st].filter(Boolean).length;
  $("#ruleFilterSummary").textContent = "🔽 필터" + (active ? ` (${active}개 적용 중)` : "");
  $("#ruleRev").classList.toggle("on", ruleRev);
  $("#ruleRev").setAttribute("aria-pressed", String(ruleRev));
  $("#ruleCount").textContent = `${ruleItems.length}개 중 ${shown.length}개 표시`;
}
["#ruleSearch", "#ruleSort", "#ruleSev", "#ruleBlock", "#ruleState"].forEach((id) => $(id).addEventListener("input", drawRules));
$("#ruleRev").addEventListener("click", () => { ruleRev = !ruleRev; drawRules(); });
$("#ruleFilterReset").addEventListener("click", () => {
  ["#ruleSearch", "#ruleSev", "#ruleBlock", "#ruleState"].forEach((id) => { $(id).value = ""; });
  $("#ruleSort").value = "sev";                      // 정렬 기본값은 위험도순
  ruleRev = false; ruleTag = "";
  drawRules();
});

// 삭제 확인 창: 규칙의 모든 정보를 보여 주고, 켜져 있으면 비활성화 후 삭제된다고 알려 준다
function confirmDelete(r) {
  return new Promise((resolve) => {
    const dlg = $("#delDialog"), body = $("#delBody");
    clear(body);
    const row = (k, v) => body.append(el("dt", {}, k), el("dd", {}, v));
    row("규칙", `${r.name} (${r.id})`);
    row("설명", r.description || "(없음)");
    row("조건", condText(r));
    row("위험도", RISK[r.severity] || r.severity);
    row("차단 여부", r.block ? "방화벽 차단 · " + (r.block_permanent ? "영구" : fmtSpan(r.block_duration_sec || defaultBlockSec)) : "알림만 (차단 안 함)");
    row("현재 상태", r.enabled ? "켜짐" : "꺼짐");
    clear($("#delNotes"));
    if (r.enabled) $("#delNotes").append(el("div", {class: "alert warning"}, "이 규칙은 지금 켜져 있습니다. 삭제하면 먼저 비활성화한 뒤 삭제합니다."));
    if (BUILTIN_DETECTORS.includes(r.detector)) $("#delNotes").append(el("div", {class: "alert info"},
      "기본 탐지기의 규칙입니다. 삭제하면 이 탐지가 꺼진 상태가 됩니다. (rules/ 에 같은 이름의 파일을 다시 넣으면 복구됩니다)"));
    if (r.detector === "script") $("#delNotes").append(el("div", {class: "alert info"},
      "플러그인 방식 규칙입니다. 규칙 삭제는 이 파일만 지우고, rules/ 에 둔 스크립트 파일 자체는 지우지 않습니다."));
    const done = (ok) => { dlg.close(); resolve(ok); };
    $("#delCancel").onclick = () => done(false);
    $("#delOk").onclick = () => done(true);
    dlg.oncancel = () => resolve(false);              // Esc 로 닫은 경우
    dlg.showModal();
  });
}

// 수정 창: id·탐지기 종류는 바꿀 수 없다. 저장하면 (바뀐 게 있을 때) 서버가 그 규칙을 꺼짐 상태로 만든다
const PARAM_LABEL = {
  window_sec: "기간(초)", distinct_ports: "서로 다른 포트 수", max_syn: "한 IP 의 SYN 수", global_max_syn: "전체 SYN 합계",
  global_min_sources: "합계로 볼 최소 출발지 수", max_packets: "ping 수", max_attempts: "접속 시도 횟수", max_bytes: "전송량(바이트)", min_failures: "로그인 실패 횟수",
};
function editRule(r) {
  const dlg = $("#editDialog"), box = $("#editFields"), msg = $("#editMsg");
  clear(box); clear(msg); clear($("#editNotes"));
  const get = {};                                     // 항목 이름 -> 값을 읽는 함수
  const field = (name, label, input, read, wide) => {
    get[name] = read;
    box.append(el("label", {class: wide ? "wide" : ""}, label, input));
  };
  const text = (v, attrs) => { const i = el("input", {class: "txt", ...attrs}); i.value = v ?? ""; return i; };
  const select = (opts, v) => { const s = el("select", {}, opts.map(([val, t]) => el("option", {value: val}, t))); s.value = v; return s; };
  const num = (v, min) => text(v, {type: "number", min: String(min || 1)});
  const checkbox = (v) => { const c = el("input", {type: "checkbox"}); c.checked = v; return c; };

  box.append(el("div", {class: "wide idline"}, `ID: ${r.id}`, " · ", ruleKind(r)));
  const iName = text(r.name, {maxlength: "60"});
  const iDesc = el("textarea", {class: "txt desc", maxlength: "200", rows: "1"}); iDesc.value = r.description ?? "";   // 쓰는 만큼 늘어남 (저장은 한 줄)
  field("name", "이름", iName, () => iName.value.trim() || r.id);
  field("description", "설명", iDesc, () => iDesc.value.replace(/\s*\n\s*/g, " ").trim(), true);
  const iTags = text((r.tags || []).map((t) => "#" + t).join(" "), {placeholder: "#포트스캔 #정찰 (공백·쉼표로 구분, 6개까지)"});
  field("tags", "태그", iTags, () => splitTags(iTags.value), true);
  const iSev = select([["info", "Low"], ["warning", "Medium"], ["critical", "Critical"]], r.severity);
  field("severity", "위험도", iSev, () => iSev.value);
  const NOTIFY_OPTS = [["", "기본 (위험도에 따름)"], ["on", "켜기"], ["off", "끄기"]];
  const asOpt = (v) => (v === true ? "on" : v === false ? "off" : "");
  const iPop = select(NOTIFY_OPTS, asOpt((r.notify || {}).popup)), iSnd = select(NOTIFY_OPTS, asOpt((r.notify || {}).sound));
  const defText = () => `알림 기본값: ${RISK[iSev.value]} 는 ${alertText(DEFAULT_ALERT[iSev.value])}. 아래에서 따로 정하면 그 값이 먼저 적용됩니다.`;
  const defLine = el("div", {class: "wide idline"}, defText());
  iSev.addEventListener("change", () => { defLine.textContent = defText(); });
  box.append(defLine, el("label", {}, "화면 팝업", iPop), el("label", {}, "소리", iSnd));
  get.notify = () => {
    const o = {};
    if (iPop.value) o.popup = iPop.value === "on";
    if (iSnd.value) o.sound = iSnd.value === "on";
    return o;
  };
  if (r.detector !== "exfiltration") {               // 유출 규칙은 알림만 (차단 슬라이드 없음)
    const bc = blockControls(r);
    box.append(el("div", {class: "wide"}, bc.node));
    get.__block = bc.read;                           // block / block_duration_sec / block_permanent 를 한꺼번에 돌려줌
  }
  if (r.detector === "custom") {
    const iProto = select([["tcp", "tcp"], ["udp", "udp"], ["icmp", "icmp"], ["any", "any"]], r.protocol);
    const iPorts = text(r.dst_ports.join(", "), {placeholder: "비우면 전체 (예: 23, 2323)"});
    const iFlags = select([["syn", "새 연결 시도(SYN)만"], ["any", "모든 TCP 패킷"]], r.tcp_flags);
    const iCount = num(r.count), iWin = num(r.window_sec);
    const iDist = select([["none", "패킷 수"], ["dst_port", "서로 다른 포트 수"]], r.distinct);
    field("protocol", "프로토콜", iProto, () => iProto.value);
    field("dst_ports", "대상 포트 (쉼표로 구분)", iPorts, () => iPorts.value.split(/[\s,]+/).filter(Boolean).map(Number));
    field("tcp_flags", "TCP 조건", iFlags, () => iFlags.value);
    field("count", "횟수 (이 이상이면 탐지)", iCount, () => parseInt(iCount.value, 10));
    field("window_sec", "기간(초)", iWin, () => parseInt(iWin.value, 10));
    field("distinct", "세는 방법", iDist, () => iDist.value);
  } else if (r.detector === "script") {
    box.append(el("div", {class: "wide idline"}, `실행 명령: ${r.command.join(" ")} (바꿀 수 없습니다. 바꾸려면 새로 올려서 서버에서 승인하세요)`));
    const iInterval = num(r.interval_sec, 5), iTimeout = num(r.timeout_sec, 1);
    field("interval_sec", "실행 주기(초)", iInterval, () => parseInt(iInterval.value, 10));
    field("timeout_sec", "시간 제한(초)", iTimeout, () => parseInt(iTimeout.value, 10));
  } else {
    Object.keys(PARAM_LABEL).filter((k) => k in r).forEach((k) => {
      const i = num(r[k]);
      field(k, PARAM_LABEL[k], i, () => parseInt(i.value, 10));
    });
    if ("ports" in r) {
      const i = text(r.ports.join(", "));
      field("ports", "감시할 포트 (쉼표로 구분)", i, () => i.value.split(/[\s,]+/).filter(Boolean).map(Number));
    }
  }
  $("#editNotes").append(el("div", {class: "alert warning"}, r.enabled
    ? "이 규칙은 지금 켜져 있습니다. 내용을 바꿔서 저장하면 충돌을 막기 위해 먼저 꺼짐 상태가 됩니다. 확인한 뒤 '켜기'를 눌러 주세요. (알림 설정만 바꾸면 켜진 상태 그대로입니다)"
    : "이 규칙은 꺼져 있습니다. 저장해도 꺼진 상태로 유지되니, 확인한 뒤 '켜기'를 눌러 주세요."));

  return new Promise((resolve) => {
    $("#editCancel").onclick = () => { dlg.close(); resolve(null); };
    dlg.oncancel = () => resolve(null);
    $("#editForm").onsubmit = async (e) => {
      e.preventDefault();
      const rule = {};
      try {
        Object.entries(get).forEach(([k, f]) => { const v = f(); if (k === "__block") Object.assign(rule, v); else if (v !== undefined) rule[k] = v; });
        const res = await api("/api/rules/update", "POST", {id: r.id, rule});
        if (!res.ok) throw new Error(res.reason);
        dlg.close(); resolve(res);
      } catch (err) { alertBox(msg, "error", err.message); }
    };
    dlg.showModal();
    autoGrow(iDesc);
  });
}

async function loadRules() {
  const [d, ch] = await Promise.all([api("/api/rules"), api("/api/rule_changes?limit=50")]);
  showErrors($("#ruleErrors"), d.errors, "규칙 파일");
  defaultBlockSec = d.default_block_sec || 300;
  ruleHits = d.hits || {};
  d.rules.forEach((r) => { ruleNames[r.id] = r.name; ruleNotify[r.id] = r.notify || {}; });
  const logBox = $("#ruleLogBox");
  const logBusy = selecting(logBox);
  if (!logBusy) clear(logBox);

  const call = async (path, body) => { try { return await api(path, "POST", body); } catch (e) { alert(e.message); } finally { ruleSig = ""; loadRules(); } };
  const del = async (r) => {
    if (!(await confirmDelete(r))) return;
    const res = await call("/api/rules/delete", {id: r.id});
    if (res && !res.ok) alert(res.reason);
  };
  const edit = async (r) => {
    const res = await editRule(r);
    if (!res) return;
    alertBox($("#ruleNotice"), res.changed ? "success" : "info", !res.changed ? `'${r.name}' 은(는) 바뀐 내용이 없어 그대로 두었습니다.`
      : res.kept_enabled ? `'${r.name}' 의 알림 설정을 바꿨습니다. 탐지 조건은 그대로라 상태도 그대로입니다.`
      : res.was_enabled ? `'${r.name}' 이(가) 수정되었습니다. 충돌을 막기 위해 꺼짐 상태가 되었으니, 내용을 확인한 뒤 '켜기'를 눌러 주세요.`
      : `'${r.name}' 이(가) 수정되었습니다. 꺼짐 상태 그대로입니다. 확인한 뒤 '켜기'를 눌러 주세요.`);
    loadRules();
  };
  // 규칙 카드: 이름 밑에 #태그, 오른쪽에 ⚙(수정)·🗑️(삭제)·켜기/끄기 스위치
  const ruleCard = (r) => {
    const sw = el("input", {type: "checkbox", role: "switch"}); sw.checked = r.enabled;
    sw.addEventListener("change", () => { sw.disabled = true; call("/api/rules/enable", {id: r.id, enabled: !r.enabled}); });
    return el("div", {class: "pcard sev-" + r.severity + (r.enabled ? "" : " off")},
      el("div", {class: "pc-head"}, el("div", {class: "pc-title", title: `${r.name} (${r.id})`}, r.name),
        el("div", {class: "pc-acts"},
          el("button", {class: "iconbtn", type: "button", title: "수정", onclick: () => edit(r)}, "⚙"),
          el("button", {class: "iconbtn", type: "button", title: "삭제", onclick: () => del(r)}, "🗑️"),
          el("label", {class: "switch", title: r.enabled ? "끄기" : "켜기"}, sw, el("span", {class: "slider"})))),
      (r.tags || []).length ? el("div", {class: "ptags"}, r.tags.map(ruleTagButton)) : null,
      el("p", {class: "pc-desc"}, r.description || "(설명 없음)"),
      el("p", {class: "caption pc-cond"}, condText(r)),
      el("div", {class: "pc-foot"}, el("span", {class: "tag sev-" + RISK[r.severity]}, RISK[r.severity]), el("span", {class: "tag"}, blockText(r)),
        el("span", {class: "tag"}, ruleKind(r)),
        // 알림은 따로 정한 항목만 보여 줌 (안 정했으면 위험도 기본값이라 표시하지 않음). 켜짐/꺼짐은 오른쪽 위 스위치가 보여 줌
        ["popup", "sound"].filter((k) => k in (r.notify || {})).map((k) =>
          el("span", {class: "tag", title: "이 규칙에만 따로 정한 알림 (⚙ 수정에서 바꿈)"}, `${k === "popup" ? "팝업" : "소리"} ${r.notify[k] ? "켬" : "끔"}`)),
        el("span", {class: "tag"}, ruleHits[r.id] ? `탐지 ${ruleHits[r.id].count}회 · 마지막 ${fmtTime(ruleHits[r.id].last)}` : "아직 탐지 없음")));
  };
  const sig = JSON.stringify([d.rules, defaultBlockSec, ruleHits]);
  if (sig !== ruleSig) {                               // 규칙이 그대로면 카드를 다시 만들지 않음 (클릭 중에 바뀌지 않게)
    ruleSig = sig;
    ruleItems = d.rules.map((r) => ({rule: r, card: ruleCard(r)}));
    drawRules();
  }

  if (logBusy) return;
  // 규칙 변경 기록 (탐지 로그·누적 통계와 별개)
  const log = el("tbody", {});
  if (!ch.changes.length) log.append(el("tr", {}, el("td", {colspan: 3}, "아직 규칙을 바꾼 기록이 없습니다.")));
  ch.changes.forEach((c) => log.append(el("tr", {}, el("td", {}, fmtTime(c.timestamp)), el("td", {}, typeName(c.rule)), el("td", {}, c.detail))));
  logBox.append(el("div", {class: "df"}, el("table", {}, el("thead", {}, el("tr", {},
    el("th", {}, "시간"), el("th", {}, "규칙"), el("th", {}, "내용"))), log)));
}

// ── 도구(플러그인): 카드 격자 + #태그. 입력값·출력은 ⚙ 를 누르면 나오는 상세 창에서 ──
let pluginData = [];                // 마지막으로 받은 목록
let pluginSig = "";                 // 목록이 바뀌었는지 비교용 (그대로면 다시 그리지 않아 클릭 중에 카드가 바뀌지 않음)
let toolTag = "";                   // 태그 필터 (빈 값 = 전체)
let pdId = null, pdSig = "";        // 상세 창에 열려 있는 도구 id, 그 도구의 마지막으로 그린 상태
let pdInputs = {};                  // 상세 창의 입력 칸 (이름 -> input)
const RUN_STATUS = {done: "완료", failed: "실패", stopped: "중지됨", timeout: "시간 초과"};
const statusText = (p) => p.running ? "실행 중" : p.last_run ? (RUN_STATUS[p.last_run.status] || p.last_run.status) : "";

async function pluginAct(p, path, body) {
  try { await api(`/api/plugins/${p.id}/${path}`, "POST", body); } catch (e) { alert(e.message); }
  await loadPlugins(true).catch(() => {});
}
function tagButton(t) {
  return el("button", {class: "ptag" + (toolTag === t ? " on" : ""), type: "button", title: "이 태그로 걸러 보기",
    onclick: () => { toolTag = toolTag === t ? "" : t; drawTools(); }}, "#" + t);
}
function pluginCard(p) {
  let ctl;
  if (p.kind === "service") {         // 서비스형: 켜기/끄기 스위치 (입력값은 기본값으로 시작, 바꾸려면 ⚙)
    const sw = el("input", {type: "checkbox", role: "switch"});
    sw.checked = p.running;
    sw.addEventListener("change", () => { sw.disabled = true; pluginAct(p, p.running ? "stop" : "run", p.running ? undefined : {params: {}}); });
    ctl = el("label", {class: "switch", title: p.running ? "중지" : "시작"}, sw, el("span", {class: "slider"}));
  } else if (p.running) {
    ctl = el("button", {class: "btn sm", type: "button", onclick: () => pluginAct(p, "stop")}, "⏹ 중지");
  } else {                            // 1회 실행형: 입력값이 있으면 상세 창에서 값을 넣고 실행
    ctl = el("button", {class: "btn sm primary", type: "button",
      onclick: async () => {                          // 결과가 보이도록 실행하면서 상세 창을 연다
        if (!p.params.length) await pluginAct(p, "run", {params: {}});
        openPlugin(p.id);
      }}, p.params.length ? "▶ 실행…" : "▶ 실행");
  }
  const st = statusText(p);
  return el("div", {class: "pcard"},
    el("div", {class: "pc-head"}, el("div", {class: "pc-title", title: p.name}, p.name),
      el("div", {class: "pc-acts"}, el("button", {class: "iconbtn", type: "button", title: "자세히 · 입력값 · 출력", onclick: () => openPlugin(p.id)}, "⚙"), ctl)),
    (p.tags || []).length ? el("div", {class: "ptags"}, p.tags.map(tagButton)) : null,
    el("p", {class: "pc-desc"}, p.description || "(설명 없음)"),
    el("div", {class: "pc-foot"}, el("span", {class: "tag"}, p.kind === "service" ? "서비스" : "1회 실행"),
      st ? el("span", {class: "tag" + (p.running ? " live" : "")}, st) : null));
}
function toolMatches(p) {
  if (toolTag && !(p.tags || []).includes(toolTag)) return false;
  const q = $("#toolSearch").value.trim().toLowerCase();
  return !q || [p.name, p.id, p.description, ...(p.tags || [])].join(" ").toLowerCase().includes(q);
}
function drawTools() {
  const all = [...new Set(pluginData.flatMap((p) => p.tags || []))].sort();
  if (toolTag && !all.includes(toolTag)) toolTag = "";
  const bar = $("#toolTags"); clear(bar);
  all.forEach((t) => bar.append(tagButton(t)));
  if (toolTag) bar.append(el("button", {class: "btn sm", type: "button", onclick: () => { toolTag = ""; drawTools(); }}, "태그 해제"));
  const shown = pluginData.filter(toolMatches);
  const list = $("#pluginList"); clear(list);
  if (!pluginData.length) list.append(el("div", {class: "alert info"}, "plugins/ 폴더에 플러그인이 없습니다."));
  else if (!shown.length) list.append(el("div", {class: "alert info"}, "조건에 맞는 도구가 없습니다."));
  shown.forEach((p) => list.append(pluginCard(p)));
  $("#toolCount").textContent = pluginData.length ? `${pluginData.length}개 중 ${shown.length}개 표시` : "";
}
$("#toolSearch").addEventListener("input", drawTools);

function openPlugin(id) {
  const p = pluginData.find((x) => x.id === id);
  if (!p) return;
  pdId = id; pdSig = ""; pdInputs = {};
  $("#pdTitle").textContent = "⚙️ " + p.name;
  const tags = $("#pdTags"); clear(tags);
  (p.tags || []).forEach((t) => tags.append(el("span", {class: "ptag"}, "#" + t)));
  $("#pdDesc").textContent = p.description || "";
  const row = $("#pdParams"); clear(row);
  p.params.forEach((s) => {
    const inp = s.type === "choice"
      ? el("select", {}, (s.choices || []).map((c) => el("option", {value: c}, c)))
      : el("input", {class: "txt", type: s.type === "int" ? "number" : "text"});
    if (s.default !== undefined) inp.value = s.default;
    pdInputs[s.name] = inp;
    row.append(el("label", {}, s.label, inp));
  });
  drawPluginDialog(p);
  if (!$("#pluginDialog").open) $("#pluginDialog").showModal();
}
function drawPluginDialog(p) {
  const sig = JSON.stringify([p.running, p.last_run]);
  if (sig === pdSig) return;          // 바뀐 게 없으면 그대로 둠 (출력을 읽는 중에 스크롤이 튀지 않게)
  pdSig = sig;
  const acts = $("#pdActions"); clear(acts);
  acts.append(p.running
    ? el("button", {class: "btn", type: "button", onclick: () => pluginAct(p, "stop")}, "⏹ 중지")
    : el("button", {class: "btn primary", type: "button",
        onclick: () => pluginAct(p, "run", {params: Object.fromEntries(Object.entries(pdInputs).map(([k, v]) => [k, v.value]))})},
        p.kind === "service" ? "▶ 시작" : "▶ 실행"));
  $("#pdStatus").textContent = statusText(p);
  const out = $("#pdOut"); clear(out);
  if (p.last_run) out.append(guiOutput(p.last_run.output, "tool:" + p.id));
}

// ── 도구 결과 화면 표시: 스크립트가 "@gui {JSON}" 한 줄을 출력하면 표·그래프로 그린다 ──
// 종류: metric(숫자 카드, max 가 있으면 막대), table(표), bars(가로 막대), chart(값을 계속 출력하면 쌓이는 그래프), alert(안내 상자)
// 내용은 글자로만 넣고(HTML 해석 안 함) 크기를 제한한다. 형식이 틀린 줄은 원본 출력에 그대로 남는다.
const GUI_LIMIT = {line: 20000, text: 200, rows: 200, cols: 12, items: 50, points: 60, alerts: 5};
const gText = (v) => String(v == null ? "" : v).slice(0, GUI_LIMIT.text);
const gNum = (v) => (typeof v === "number" && isFinite(v) ? v : null);
function parseGui(lines) {
  const blocks = new Map(), text = [];
  let alerts = [];
  lines.forEach((line) => {
    if (!line.startsWith("@gui ") || line.length > GUI_LIMIT.line) return text.push(line);
    let g;
    try { g = JSON.parse(line.slice(5)); } catch (e) { return text.push(line); }
    if (!g || typeof g !== "object") return text.push(line);
    const key = g.type + ":" + gText(g.label || g.title);
    if (g.type === "metric" && (gNum(g.value) !== null || typeof g.value === "string")) {
      blocks.set(key, {type: "metric", label: gText(g.label), value: g.value, unit: gText(g.unit), max: gNum(g.max)});
    } else if (g.type === "table" && Array.isArray(g.columns) && Array.isArray(g.rows)) {
      const cols = g.columns.slice(0, GUI_LIMIT.cols).map(gText);
      blocks.set(key, {type: "table", title: gText(g.title), columns: cols,
        rows: g.rows.slice(0, GUI_LIMIT.rows).map((r) => (Array.isArray(r) ? r : []).slice(0, cols.length).map(gText)), more: Math.max(0, g.rows.length - GUI_LIMIT.rows)});
    } else if (g.type === "bars" && Array.isArray(g.items)) {
      blocks.set(key, {type: "bars", title: gText(g.title),
        items: g.items.slice(0, GUI_LIMIT.items).filter((i) => Array.isArray(i) && gNum(i[1]) !== null).map((i) => [gText(i[0]), i[1]])});
    } else if (g.type === "chart" && gNum(g.value) !== null) {
      const old = blocks.get(key);
      const pts = (old ? old.points : []).concat([g.value]).slice(-GUI_LIMIT.points);
      blocks.set(key, {type: "chart", label: gText(g.label), unit: gText(g.unit), max: gNum(g.max), points: pts});   // 같은 키는 처음 나온 자리 유지
    } else if (g.type === "alert" && g.text) {
      alerts = alerts.concat([{level: ["info", "success", "warning", "error"].includes(g.level) ? g.level : "info", text: gText(g.text)}]).slice(-GUI_LIMIT.alerts);
    } else text.push(line);
  });
  return {blocks, alerts, text};
}
const gFmt = (v, unit) => (typeof v === "number" ? (Number.isInteger(v) ? v.toLocaleString() : v.toLocaleString(undefined, {maximumFractionDigits: 2})) : gText(v)) + (unit ? " " + unit : "");
function guiBlock(b) {
  if (b.type === "metric") {
    const pct = b.max && typeof b.value === "number" ? Math.max(0, Math.min(100, b.value / b.max * 100)) : null;
    return el("div", {class: "metric gcard"}, el("div", {class: "label"}, b.label), el("div", {class: "value"}, gFmt(b.value, b.unit)),
      pct === null ? null : el("div", {class: "gmeter", role: "img", "aria-label": `${b.label} ${Math.round(pct)}%`},
        el("div", {class: "fill" + (pct >= 90 ? " hot" : ""), style: `width:${Math.max(1, pct)}%`})));
  }
  if (b.type === "table") return el("div", {class: "gwide"}, b.title ? el("h4", {}, b.title) : null,
    el("div", {class: "df"}, el("table", {}, el("thead", {}, el("tr", {}, b.columns.map((c) => el("th", {}, c)))),
      el("tbody", {}, b.rows.length ? b.rows.map((r) => el("tr", {}, r.map((c) => el("td", {}, c)))) : el("tr", {}, el("td", {colspan: b.columns.length || 1}, "(비어 있음)"))))),
    b.more ? el("p", {class: "caption"}, `… ${b.more}줄 더 있음 (최대 ${GUI_LIMIT.rows}줄 표시)`) : null);
  if (b.type === "bars") { const box = el("div", {}); hbars(box, b.items); return el("div", {class: "gwide"}, b.title ? el("h4", {}, b.title) : null, box); }
  if (b.type === "chart") {
    const top = b.max || Math.max(...b.points, 0) || 1, last = b.points[b.points.length - 1];
    return el("div", {class: "gwide"}, el("h4", {}, `${b.label} — 지금 ${gFmt(last, b.unit)}`),
      el("div", {class: "tchart gchart", role: "img", "aria-label": `${b.label} 최근 ${b.points.length}개 값, 마지막 ${gFmt(last, b.unit)}`},
        b.points.map((v) => el("div", {class: "tcol", title: gFmt(v, b.unit)}, el("div", {class: "tbar", style: `height:${Math.max(1, Math.min(100, v / top * 100))}%`})))),
      el("div", {class: "taxis"}, el("span", {}, `최근 ${b.points.length}개`), el("span", {}, `최대 ${gFmt(top, b.unit)}`)));
  }
  return null;
}
const guiRawOpen = new Set();          // "원본 출력" 을 펼쳐 둔 도구 (새 출력이 와서 다시 그려도 펼친 채로)
function guiOutput(lines, key) {
  const g = parseGui(lines || []);
  const box = el("div", {});
  const hasGui = g.blocks.size || g.alerts.length;
  if (hasGui) {
    g.alerts.forEach((a) => box.append(el("div", {class: "alert " + a.level}, a.text)));
    const blocks = [...g.blocks.values()];
    const metrics = blocks.filter((b) => b.type === "metric");
    if (metrics.length) box.append(el("div", {class: "metrics gmetrics"}, metrics.map(guiBlock)));
    blocks.filter((b) => b.type !== "metric").forEach((b) => box.append(guiBlock(b)));
  }
  const pre = el("pre", {}, g.text.join("\n") || "(출력 없음)");
  if (hasGui) {
    const det = el("details", {class: "expander"}, el("summary", {}, `📜 원본 출력 (${g.text.length}줄)`), pre);
    if (key && guiRawOpen.has(key)) det.open = true;
    det.addEventListener("toggle", () => { if (key) det.open ? guiRawOpen.add(key) : guiRawOpen.delete(key); });
    box.append(det);
  } else box.append(pre);
  setTimeout(() => pre.scrollTop = pre.scrollHeight, 0);
  return box;
}
$("#pdClose").addEventListener("click", () => $("#pluginDialog").close());
$("#pluginDialog").addEventListener("close", () => { pdId = null; });

function showErrors(box, errors, label) {
  clear(box);
  Object.entries(errors || {}).forEach(([n, why]) => box.append(el("div", {class: "perr"}, `${label} '${n}' 을(를) 불러오지 못했습니다: ${why}`)));
}
$("#pluginRescan").addEventListener("click", () => loadPlugins(true).catch((e) => alert(e.message)));
async function loadPlugins(force) {
  const d = await api("/api/plugins");
  showErrors($("#pluginErrors"), d.errors, "플러그인");
  pluginData = d.plugins;
  const sig = JSON.stringify(d.plugins);
  if (force || sig !== pluginSig) { pluginSig = sig; drawTools(); }
  if (pdId) { const p = pluginData.find((x) => x.id === pdId); if (p) drawPluginDialog(p); }
}

// ── 플러그인 올리기 (승인 대기): 올리기·내용 보기·삭제만 가능. 승인은 서버 터미널의 approve_plugin.py 에서만 ──
const openUploads = new Set();          // 펼쳐 둔 항목 (3초마다 다시 그려도 유지)
const uploadText = {};                  // id + 해시 -> 파일 내용 (한 번만 불러옴)
const sbState = {};                     // id -> 샌드박스 실행 상태·결과 (목록을 다시 그려도 사라지지 않게 카드 밖에 보관)
let uploadSig = "";                     // 목록이 그대로면 다시 그리지 않음 (읽는 중에 스크롤이 튀지 않게)
function uploadCard(u) {
  if (u.error) return el("div", {class: "perr"}, `${u.id}: 읽을 수 없습니다 (${u.error})`);
  const key = u.id + u.short;
  const box = el("div", {});
  if (u.findings.length) {
    box.append(el("div", {class: "alert warning"}, el("b", {}, `검토가 필요한 패턴 ${u.findings.length}개`),
      " (보안 장치가 아니라 표시일 뿐입니다. 코드를 직접 읽으세요)",
      el("ul", {}, u.findings.map((f) => el("li", {}, `${f.file}:${f.line} ${f.what} — ${f.text}`)))));
  }
  const texts = uploadText[key];
  if (texts) Object.entries(texts).forEach(([n, t]) => box.append(el("div", {}, el("div", {class: "caption"}, n), el("pre", {}, t))));
  else box.append(el("div", {class: "caption"}, "내용을 불러오는 중…"));
  const sb = sbState[u.id] || {};
  const sbOut = el("div", {});
  if (sb.busy) sbOut.append(el("div", {class: "caption"}, "격리 상태에서 실행 중…"));
  else if (sb.error) sbOut.append(el("div", {class: "alert error"}, sb.error));
  else if (sb.result) sbOut.append(el("div", {class: sb.result.timed_out ? "alert warning" : "alert info"},
    `종료 코드: ${sb.result.rc === null ? "(시간 초과로 강제 종료)" : sb.result.rc}${sb.result.timed_out ? " · 시간 제한에 걸림" : ""}`),
    guiOutput((sb.result.output || "").split("\n"), "sandbox:" + u.id));
  const card = el("details", {class: "plugin"},
    el("summary", {}, el("b", {}, u.name), el("span", {class: "tag"}, u.id), (u.tags || []).map((t) => el("span", {class: "tag"}, "#" + t)),
      el("span", {class: "tag"}, "해시 " + u.short),
      u.findings.length ? el("span", {class: "tag"}, `주의 ${u.findings.length}`) : null,
      u.intact ? null : el("span", {class: "tag live"}, "변조됨")),
    el("p", {class: "caption"}, `${u.description || "(설명 없음)"} · 파일 ${u.files.map((f) => f.name).join(", ")} · 올린 시각 ${fmtTime(u.uploaded_at)} · 올린 곳 ${u.uploader || "-"}`),
    el("p", {class: "caption"}, "🧪 샌드박스로 실행해보기: 설치하지 않고 네트워크·파일시스템이 막힌 격리 상태에서 한 번만 돌려본다. 결과는 저장되지 않는다."),
    el("p", {}, u.type === "rule" ? "승인(rules/ 에 '꺼진 상태'로 설치)은 보안 서버 터미널에서만 가능:" : "그래도 영구 설치(plugins/ 로 옮기기)는 보안 서버 터미널에서만 가능:"),
    el("pre", {}, "approve"),
    el("p", {class: "caption"}, `승인 화면 목록에서 '${u.id}' 를 골라 Enter → 끝까지 읽고 '승인' 선택 → yes 입력. ` +
      `(approve 단축 명령이 없는 서버라면 python3 ~/warden/dashboard/approve_plugin.py)`),
    box,
    el("div", {class: "row"},
      el("button", {class: "btn sm", type: "button", ...(sb.busy ? {disabled: ""} : {}), onclick: async () => {
        sbState[u.id] = {busy: true};
        loadUploads(true).catch(() => {});
        try {
          sbState[u.id] = {result: await api(`/api/plugin_uploads/${u.id}/run_sandboxed`, "POST", {params: {}})};
        } catch (e) { sbState[u.id] = {error: e.message}; }
        loadUploads(true).catch(() => {});
      }}, "🧪 샌드박스로 실행"),
      el("button", {class: "btn sm", type: "button", onclick: async () => {
        if (!confirm(`'${u.id}' 업로드를 삭제할까요?`)) return;
        try { await api(`/api/plugin_uploads/${u.id}/delete`, "POST", {}); loadUploads(true); } catch (e) { alert(e.message); }
      }}, "🗑️ 삭제")),
    sbOut);
  card.open = openUploads.has(u.id);
  card.addEventListener("toggle", () => { if (card.open) openUploads.add(u.id); else openUploads.delete(u.id); });
  if (!texts) api("/api/plugin_uploads/" + u.id).then((d) => { uploadText[key] = d.texts; loadUploads(true); }).catch(() => {});
  return card;
}
// 올리기 칸은 두 곳: 도구(plugin.json → 승인하면 plugins/)와 플러그인 방식 탐지 규칙(rule.json → 승인하면 rules/ 에 꺼진 상태로)
const UPLOAD_LISTS = [["tool", "#upList", "승인 대기 중인 도구가 없습니다."], ["rule", "#ruleUpList", "승인 대기 중인 규칙이 없습니다."]];
async function loadUploads(force) {
  if (!force && !(currentView === "tools" && $("#upBox").open) && !(currentView === "rules" && $("#ruleUpBox").open)) return;
  const d = await api("/api/plugin_uploads");
  const sig = JSON.stringify(d.uploads);
  if (!force && sig === uploadSig) return;
  uploadSig = sig;
  UPLOAD_LISTS.forEach(([type, sel, none]) => {
    const list = $(sel);
    if (!force && typing(list)) return;
    clear(list);
    const items = d.uploads.filter((u) => (u.type || "tool") === type);   // 읽을 수 없는 항목(error)은 종류를 몰라 도구 칸에 표시
    if (!items.length) list.append(el("div", {class: "caption"}, none));
    items.forEach((u) => list.append(uploadCard(u)));
  });
}
function bindUpload(boxSel, filesSel, sendSel, msgSel, expect) {
  const need = expect === "rule" ? "rule.json 과 판정 스크립트" : "plugin.json 과 스크립트";
  $(boxSel).addEventListener("toggle", () => { if ($(boxSel).open) loadUploads(true).catch(() => {}); });
  $(sendSel).addEventListener("click", async () => {
    const picked = [...$(filesSel).files];
    if (!picked.length) return alertBox($(msgSel), "warning", `올릴 파일을 먼저 선택하세요 (${need}).`);
    try {
      const files = {};
      for (const f of picked) files[f.name] = await f.text();
      const r = await api("/api/plugin_uploads", "POST", {files, expect});
      alertBox($(msgSel), "success", `'${r.upload.id}' 을(를) 올렸습니다. 아직 ${expect === "rule" ? "적용되지" : "실행되지"} 않습니다. 서버 터미널에서 내용을 확인하고 승인하세요 (해시 ${r.upload.short}).`
        + (expect === "rule" ? " 승인하면 꺼진 상태로 설치되니, 위 카드에서 직접 켜세요." : ""));
      $(filesSel).value = "";
      loadUploads(true);
    } catch (e) { alertBox($(msgSel), "error", e.message); }
  });
}
bindUpload("#upBox", "#upFiles", "#upSend", "#upMsg", "tool");
bindUpload("#ruleUpBox", "#ruleUpFiles", "#ruleUpSend", "#ruleUpMsg", "rule");

const addBlock = blockControls({});
$("#rBlockBox").append(addBlock.node);
$("#ruleForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const ports = $("#rPorts").value.split(/[\s,]+/).filter(Boolean).map(Number);
  const rule = {
    id: $("#rId").value.trim(), name: $("#rName").value.trim() || $("#rId").value.trim(), description: $("#rDesc").value.replace(/\s*\n\s*/g, " ").trim(),
    protocol: $("#rProto").value, dst_ports: ports, tcp_flags: $("#rFlags").value,
    count: parseInt($("#rCount").value, 10), window_sec: parseInt($("#rWindow").value, 10),
    distinct: $("#rDistinct").value, severity: $("#rSev").value, enabled: true, tags: splitTags($("#rTags").value),
  };
  try {
    Object.assign(rule, addBlock.read());
    await api("/api/rules", "POST", {rule});
    alertBox($("#ruleMsg"), "success", `규칙 '${rule.id}' 이(가) 저장되었습니다. 5초 안에 적용됩니다.`);
    loadRules();
  } catch (err) { alertBox($("#ruleMsg"), "error", err.message); }
});

// ── 새 규칙 추가: 먼저 방식(방화벽/플러그인)을 묻는 창 ──
$("#ruleAddBtn").addEventListener("click", () => $("#ruleTypeDialog").showModal());
$("#chooseCancelBtn").addEventListener("click", () => $("#ruleTypeDialog").close());
$("#chooseFwBtn").addEventListener("click", () => {
  $("#ruleTypeDialog").close();
  $("#ruleUpBox").open = false;
  $("#fwRuleBox").open = true;
  $("#fwRuleBox").scrollIntoView({behavior: "smooth", block: "center"});
});
$("#chooseScriptBtn").addEventListener("click", () => {     // 플러그인 방식 규칙은 올리기로만 추가 (양식 없음)
  $("#ruleTypeDialog").close();
  $("#fwRuleBox").open = false;
  $("#ruleUpBox").open = true;
  $("#ruleUpBox").scrollIntoView({behavior: "smooth", block: "center"});
});

// ── 패킷 보기 (와이어샤크처럼 지나가는 패킷 요약) ──
// 1초마다 '마지막으로 받은 번호 이후' 패킷만 받아 표 맨 위에 쌓는다. 조건을 바꾸면 처음부터 다시 받는다.
const PK_MAX = 500;
const PK_DIR = {in: "⬇ 들어옴", out: "⬆ 나감", other: "·"};
let pkLast = 0, pkPaused = false, pkBusy = false, pkRows = [];
const pkTime = (t) => { const d = new Date(t * 1000); return d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0"); };

function pkDraw() {
  const tb = $("#pkRows");
  const sel = window.getSelection();
  if (sel && sel.toString() && tb.contains(sel.anchorNode)) return;   // 복사하려고 드래그 중이면 다시 그리지 않음
  clear(tb);
  if (!pkRows.length) tb.append(el("tr", {}, el("td", {colspan: 8}, pkPaused ? "일시정지 중입니다." : "조건에 맞는 패킷을 기다리는 중입니다…")));
  const frag = document.createDocumentFragment();
  pkRows.forEach((p) => frag.append(el("tr", {class: [p.proto === "ICMP" ? "icmp" : p.proto === "ARP" ? "arp" : "", p.dir === "out" ? "out" : ""].join(" ").trim()},
    el("td", {}, p.seq), el("td", {}, pkTime(p.time)), el("td", {}, PK_DIR[p.dir] || ""),
    el("td", {}, p.sport ? `${p.src}:${p.sport}` : p.src, noteTag(p.src)), el("td", {}, p.dport ? `${p.dst}:${p.dport}` : p.dst, noteTag(p.dst)),
    el("td", {}, p.proto), el("td", {}, p.len), el("td", {}, p.info))));
  tb.append(frag);
  $("#pkCount").textContent = pkRows.length ? `${pkRows.length}개 표시 (최신 ${PK_MAX}개까지)` : "";
}

function pkReset() { pkLast = 0; pkRows = []; pkDraw(); loadPackets(); }

async function loadPackets() {
  if (pkPaused || pkBusy || document.hidden || currentView !== "packets" || $("#login").hidden === false) return;
  pkBusy = true;
  try {
    const qs = new URLSearchParams({since: pkLast, limit: 200});
    if ($("#pkProto").value) qs.set("proto", $("#pkProto").value);
    if ($("#pkIp").value.trim()) qs.set("ip", $("#pkIp").value.trim());
    if ($("#pkHide").checked) qs.set("hide_ports", ["22", "8000", location.port].filter(Boolean).join(","));
    const d = await api("/api/packets?" + qs);
    const box = $("#pkNotice"); clear(box);
    if (!d.enabled) box.append(el("div", {class: "alert info"}, "패킷 기록이 꺼져 있습니다 (보안 서버 config.json 의 packet_view.enabled)."));
    else if (d.unrecorded) box.append(el("div", {class: "caption"}, `초당 기록 한도를 넘어 ${d.unrecorded.toLocaleString()}개는 보관하지 않았습니다 (플러드 중이면 정상입니다).`));
    if (d.last_seq < pkLast) { pkLast = 0; pkRows = []; pkDraw(); return; }   // WARDEN 이 다시 시작됨
    pkLast = d.last_seq;
    if (d.packets.length) { pkRows = d.packets.reverse().concat(pkRows).slice(0, PK_MAX); pkDraw(); }
  } catch (e) { /* 연결 상태는 3초 새로고침이 표시함 */ }
  finally { pkBusy = false; }
}
["pkProto", "pkHide"].forEach((id) => $("#" + id).addEventListener("change", pkReset));
$("#pkIp").addEventListener("input", pkReset);
$("#pkPause").addEventListener("click", () => {
  pkPaused = !pkPaused;
  $("#pkPause").textContent = pkPaused ? "▶ 계속" : "⏸ 일시정지";
  if (!pkPaused) loadPackets(); else pkDraw();
});
$("#pkClear").addEventListener("click", () => { pkRows = []; pkDraw(); });
$("#pkPcap").addEventListener("click", () => {
  const qs = new URLSearchParams();
  if ($("#pkProto").value) qs.set("proto", $("#pkProto").value);
  if ($("#pkIp").value.trim()) qs.set("ip", $("#pkIp").value.trim());
  if ($("#pkHide").checked) qs.set("hide_ports", ["22", "8000", location.port].filter(Boolean).join(","));
  downloadPcap(qs.toString(), $("#pkPcap"));
});
setInterval(loadPackets, 1000);
pkDraw();

// ── 점검·보고서 ──
// rows: [이름, 값, (선택) 마우스를 올렸을 때 보일 글]
// rows: [이름, 수, 설명(선택), 위험도라벨(선택: Low/Medium/Critical)]. 위험도가 있으면 막대 색을 위험도에 맞춘다
function hbars(box, rows) {
  clear(box);
  if (!rows.length) return box.append(el("p", {class: "caption"}, "아직 기록이 없습니다."));
  const max = Math.max(...rows.map((r) => r[1]));
  rows.forEach(([name, n, tip, sev]) => box.append(el("div", {class: "hbar", title: `${tip || name}: ${n}건`}, el("span", {class: "nm"}, name),
    el("div", {class: "track"}, el("div", {class: "fill" + (sev ? " sev-" + sev : ""), style: `width:${Math.max(1, n / max * 100)}%`})), el("span", {class: "val"}, n))));
}
const startOfDay = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
// 기간별 탐지 수 그래프. mode: "24h"(시간별) / "7d" / "30d"(일별) / "12mo"(월별)
function timeChart(box, events, mode) {
  clear(box);
  const now = new Date();
  let bins, labelOf, binOf, desc;
  if (mode === "7d" || mode === "30d") {
    const days = mode === "7d" ? 7 : 30;
    const start = new Date(now.getFullYear(), now.getMonth(), now.getDate() - (days - 1)).getTime();
    bins = Array(days).fill(0);
    binOf = (d) => Math.floor((startOfDay(d) - start) / 86400000);
    labelOf = (i) => { const d = new Date(start + i * 86400000); return (d.getMonth() + 1) + "/" + d.getDate(); };
    desc = `최근 ${days}일 일별`;
  } else if (mode === "12mo") {
    const baseY = now.getFullYear(), baseM = now.getMonth();     // 이번 달이 마지막 칸
    bins = Array(12).fill(0);
    binOf = (d) => (d.getFullYear() - baseY) * 12 + (d.getMonth() - baseM) + 11;
    labelOf = (i) => (new Date(baseY, baseM - 11 + i, 1).getMonth() + 1) + "월";
    desc = "최근 12개월 월별";
  } else {
    const hour = 3600000, end = Math.ceil(now.getTime() / hour) * hour;
    bins = Array(24).fill(0);
    binOf = (d) => 23 - Math.floor((end - 1 - d.getTime()) / hour);
    labelOf = (i) => new Date(end - (24 - i) * hour).getHours() + "시";
    desc = "최근 24시간 시간별";
  }
  events.forEach((e) => { const i = binOf(new Date(Date.parse(e.timestamp))); if (i >= 0 && i < bins.length) bins[i]++; });
  const max = Math.max(1, ...bins), mid = Math.floor((bins.length - 1) / 2);
  box.append(el("div", {class: "tchart", role: "img", "aria-label": `${desc} 탐지 수, 최대 ${max}건`},
    bins.map((n, i) => el("div", {class: "tcol", title: `${labelOf(i)}: ${n}건`}, n ? el("div", {class: "tbar", style: `height:${n / max * 100}%`}) : null))));
  box.append(el("div", {class: "taxis"}, el("span", {}, labelOf(0)), el("span", {}, labelOf(mid)), el("span", {}, `${labelOf(bins.length - 1)} · 최대 ${max}건`)));
}
const browserOffset = () => { const m = -new Date().getTimezoneOffset(), p = (n) => String(Math.floor(n)).padStart(2, "0"); return `${m < 0 ? "-" : "+"}${p(Math.abs(m) / 60)}:${p(Math.abs(m) % 60)}`; };
function drawPreflight(st, rules) {
  const item = (ok, text) => el("li", {}, (ok === null ? "ℹ️ " : ok ? "✅ " : "⚠️ ") + text);
  const box = $("#preflight"); clear(box);
  const on = rules.filter((r) => r.enabled), off = rules.filter((r) => !r.enabled), never = on.filter((r) => !ruleHits[r.id]);
  box.append(item(true, `WARDEN 응답 정상 (감시 인터페이스 ${st.interface}, 켜진 지 ${fmtUp(st.uptime_sec)})`),
    item(null, st.dry_run ? "지금 모드: 탐지만 (dry-run). 실제 차단 시연이면 개요에서 바꾸세요" : "지금 모드: 실제 차단"),
    item(!myIp || st.whitelist.includes(myIp), myIp ? `이 PC(${myIp}) ${st.whitelist.includes(myIp) ? "는 화이트리스트에 있음" : "가 화이트리스트에 없음: 차단되면 대시보드에 못 들어옴"}` : "이 PC 주소를 확인하지 못함"),
    item(st.utc_offset === browserOffset(), st.utc_offset === browserOffset() ? `서버와 이 PC 의 시간대가 같음 (${st.utc_offset})` : `서버 시간대(${st.utc_offset})가 이 PC(${browserOffset()})와 다름: 화면은 이 PC 기준이지만 서버 로그와 맞춰 보기 어려움`),
    item(!off.length, off.length ? `꺼진 규칙 ${off.length}개: ${off.map((r) => r.name).join(", ")}` : "모든 규칙이 켜져 있음"),
    item(!never.length, never.length ? `아직 한 번도 탐지 안 된 규칙 ${never.length}개 (시험해 보세요): ${never.map((r) => r.name).join(", ")}` : "켜진 규칙이 모두 한 번 이상 탐지됨"));
}
let reportEvents = [], reportAttacks = [], timeMode = "24h";
function renderTimeChart() { timeChart($("#chartTime"), reportAttacks, timeMode); }
document.querySelectorAll("#timeRange button").forEach((b) => b.addEventListener("click", () => {
  timeMode = b.dataset.range;
  document.querySelectorAll("#timeRange button").forEach((x) => x.classList.toggle("active", x === b));
  renderTimeChart();
}));
async function loadReport() {
  const [st, evs, rl, hist] = await Promise.all([api("/api/status"), api("/api/events?limit=1000"), api("/api/rules"), api("/api/history?limit=10")]);
  ruleHits = rl.hits || {};
  ipNotes = st.notes || {};
  rl.rules.forEach((r) => { ruleNames[r.id] = r.name; ruleNotify[r.id] = r.notify || {}; });
  reportEvents = evs.events;
  const attacks = evs.events.filter((e) => !ADMIN_TYPES.has(e.type));
  $("#repAt").textContent = "작성 시각 " + fmtTime(new Date().toISOString());
  drawPreflight(st, rl.rules);
  const s = st.stats || {}, sum = $("#repSummary"); clear(sum);
  sum.append(metric("탐지된 위협", (s.events_total || 0) + " 건", `Critical ${attacks.filter((e) => e.severity === "critical").length} 건 (최근 기록 기준)`),
    metric("자동 차단", (s.blocks_auto || 0) + " 건", `모의 ${s.blocks_auto_sim || 0} 건`),
    metric("공격 출발지", hist.history.length + " 곳", "탐지 기록이 있는 IP·MAC (최대 10곳 표시)"),
    metric("켜진 규칙", rl.rules.filter((r) => r.enabled).length + " 개", `전체 ${rl.rules.length} 개`));
  reportAttacks = attacks;
  renderTimeChart();
  // 메모가 있으면 메모를 이름으로 (주소는 길어서 메모가 잘림), 마우스를 올리면 주소와 메모
  hbars($("#chartIps"), hist.history.map((h) => { const n = noteOf(h.source); return [n || h.source, h.total, n ? `${h.source} (메모: ${n})` : h.source]; }));
  const byType = {};   // 유형별: 탐지 수 + 그 유형의 위험도(가장 센 값) -> 막대 색을 위험도에 맞춤
  attacks.forEach((e) => { const k = typeName(e.type), b = byType[k] || (byType[k] = {n: 0, sev: e.severity}); b.n++; if (SEV_RANK[e.severity] > SEV_RANK[b.sev]) b.sev = e.severity; });
  hbars($("#chartTypes"), Object.entries(byType).sort((x, y) => y[1].n - x[1].n).map(([name, b]) => [name, b.n, null, RISK[b.sev]]));
  const rr = $("#repRules"); clear(rr);
  rl.rules.forEach((r) => rr.append(el("tr", {}, el("td", {}, r.name), el("td", {}, r.enabled ? "켜짐" : "꺼짐"), el("td", {class: "sev-" + RISK[r.severity]}, RISK[r.severity]),
    el("td", {}, blockText(r)), el("td", {}, (ruleHits[r.id] || {}).count || 0), el("td", {}, fmtTime((ruleHits[r.id] || {}).last)))));
  const re = $("#repEvents"); clear(re);
  if (!evs.events.length) re.append(el("tr", {}, el("td", {colspan: 6}, "아직 기록이 없습니다.")));
  evs.events.forEach((e) => re.append(el("tr", {}, el("td", {}, fmtTime(e.timestamp)), el("td", {}, e.source, noteTag(e.source)), el("td", {}, typeName(e.type)),
    el("td", {class: "sev-" + RISK[e.severity]}, RISK[e.severity] || e.severity), el("td", {}, ACTION[e.action] || e.action), el("td", {class: "wrap"}, e.detail))));
}
$("#repReload").addEventListener("click", () => loadReport().catch((e) => alert(e.message)));
$("#repPrint").addEventListener("click", () => window.print());
$("#repCsv").addEventListener("click", () => downloadCsv(reportEvents));

// ── 주기적 새로고침: 상태·탐지 로그는 항상(알림용), 나머지는 보고 있는 메뉴 것만 받는다. 앞 요청이 안 끝났으면 건너뜀 (느린 VM 에서 쌓이지 않게) ──
let refreshing = false, refreshTick = 0;
async function refresh(force) {
  if (refreshing && !force) return;
  refreshing = true;
  refreshTick++;
  const jobs = [];
  if (currentView === "policy") jobs.push(loadBlocked(), loadHistory(), loadAudit());
  if (currentView === "tools") jobs.push(loadPlugins(force), loadUploads(force));
  if (currentView === "rules") jobs.push(loadRules(), loadUploads(force));
  else if (force || refreshTick % 10 === 1) jobs.push(loadRules());             // 이벤트에 규칙 이름을 쓰기 위해 가끔 받음
  if (force && !myIp) jobs.push(api("/api/whoami").then((d) => { myIp = d.ip; }));
  try {
    await loadTop();
    if (currentView === "policy") drawWhitelist();
  } catch (e) {
    if (e.message !== "로그인 필요") setWarden(false, e.message.slice(0, 120));
  }
  await Promise.allSettled(jobs);
  refreshing = false;
}
setInterval(() => { if ($("#login").hidden) refresh(false); }, 3000);

// ── 왼쪽 메뉴: 한 번에 한 화면만 보여줌. 주소 뒤 #tools 처럼 기억해서 새로고침·뒤로가기도 그 화면으로 돌아옴 ──
const VIEWS = ["overview", "packets", "policy", "tools", "rules", "report"];
function showView(name, push) {
  if (!VIEWS.includes(name)) name = "overview";
  const prev = currentView;
  currentView = name;
  document.querySelectorAll(".view").forEach((v) => { v.hidden = v.dataset.view !== name; });
  document.querySelectorAll(".navitem").forEach((n) => n.classList.toggle("active", n.dataset.view === name));
  try {
    if (location.hash !== "#" + name) history[push ? "pushState" : "replaceState"](null, "", "#" + name);
  } catch (e) {}
  if (name === "overview") { unread = 0; drawUnread(); }
  if (name === prev) return;
  window.scrollTo(0, 0);
  if (name === "packets" && !pkPaused) pkReset();   // 안 보는 동안 쌓이지 않았으니 지금부터 새로 받음
  if (token && $("#login").hidden) {
    refresh(true);
    if (name === "report") loadReport().catch(() => {});
  }
}
// 클릭은 주소(#) 이동에 기대지 않고 직접 처리 (주소 이동이 막힌 곳에서 열어도 메뉴가 바뀜). 뒤로가기·직접 입력은 아래 두 이벤트로
document.querySelectorAll(".navitem").forEach((n) => n.addEventListener("click", (e) => { e.preventDefault(); showView(n.dataset.view, true); }));
window.addEventListener("popstate", () => showView(location.hash.slice(1)));
window.addEventListener("hashchange", () => showView(location.hash.slice(1)));
const startView = location.hash.slice(1);
if (token) {
  showView(startView);
  refresh(true).then(() => { if (currentView === "report") loadReport().catch(() => {}); });
} else {
  $("#login").hidden = false;                         // 로그인 전에는 데이터를 받지 않음
  showView(startView);
}
