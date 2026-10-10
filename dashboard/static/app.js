"use strict";
const $ = (s) => document.querySelector(s);
let token = "";
try { token = localStorage.getItem("gd_token") || ""; } catch (e) {}
let lastPackets = null, lastPacketsAt = 0;

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
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };
function alertBox(box, kind, text) { clear(box); box.append(el("div", {class: "alert " + kind}, text)); }

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
    $("#login").hidden = true; refresh(true);
  } catch (err) { showLogin("토큰이 맞지 않습니다"); }
});

// ── 값 변환 ──
const fmtTime = (iso) => iso ? iso.replace("T", " ").slice(0, 19) : "";
const fmtDur = (s) => s >= 60 ? Math.floor(s / 60) + "분 " + (s % 60) + "초" : s + "초";
const fmtUp = (s) => `${Math.floor(s / 3600)}시간 ${Math.floor(s % 3600 / 60)}분`;
const RISK = {info: "Low", warning: "Medium", critical: "Critical"};
const ACTION = {alert: "탐지됨", block: "차단됨", "block(dry-run)": "차단(모의)", unblock: "해제됨"};

function metric(label, value, delta, cls) {
  return el("div", {class: "metric"}, el("div", {class: "label"}, label), el("div", {class: "value"}, value),
    el("div", {class: "delta " + (cls || "flat")}, delta));
}
const signed = (n, unit) => (n > 0 ? "▲ +" : n < 0 ? "▼ " : "") + n + unit;

// ── 지표 + 로그 ──
async function loadTop() {
  const [st, evs] = await Promise.all([api("/api/status"), api("/api/events?limit=200")]);
  const s = st.stats || {};
  const recent5 = evs.events.filter((e) => Date.now() - Date.parse(e.timestamp) < 300000).length;
  const now = Date.now();
  let rate = 0;
  if (lastPackets !== null && now > lastPacketsAt) rate = Math.round((s.packets_total - lastPackets) / ((now - lastPacketsAt) / 1000));
  lastPackets = s.packets_total || 0; lastPacketsAt = now;

  const m = $("#metrics"); clear(m);
  m.append(
    metric("탐지된 위협 (누적)", (s.events_total || 0) + " 건", signed(recent5, " 건 (최근 5분)"), recent5 ? "down" : "flat"),
    metric("방화벽 자동 차단 (누적)", (s.blocks_total || 0) + " 건", "현재 차단 중 " + st.blocked_count + " 건", st.blocked_count ? "up" : "flat"),
    metric("처리한 패킷", (s.packets_total || 0).toLocaleString() + " 개", "초당 " + rate + " 개", "flat"),
    metric("관제 서버 상태", "정상 (Normal)", st.dry_run ? "Active · 탐지만(dry-run)" : "Active · 실제 차단", "up"),
  );

  const sel = $("#typeFilter");
  const known = new Set([...sel.options].map((o) => o.value));
  evs.events.forEach((e) => { if (!known.has(e.type)) { known.add(e.type); sel.append(el("option", {value: e.type}, e.type)); } });
  const rows = evs.events.filter((e) => !sel.value || e.type === sel.value);
  const tb = $("#eventRows"); clear(tb);
  if (!rows.length) tb.append(el("tr", {}, el("td", {colspan: 7}, "아직 탐지된 이벤트가 없습니다.")));
  rows.forEach((e) => tb.append(el("tr", {},
    el("td", {}, fmtTime(e.timestamp)), el("td", {}, e.source), el("td", {}, e.target || ""), el("td", {}, e.type),
    el("td", {class: "sev-" + RISK[e.severity]}, RISK[e.severity] || e.severity),
    el("td", {}, ACTION[e.action] || e.action), el("td", {class: "wrap"}, e.detail))));
  const t = $("#blockTarget");
  if (!t.value && !t.dataset.touched && rows.length) t.value = rows[0].source;   // 가장 최근 공격자 IP 를 기본값으로
}
$("#typeFilter").addEventListener("change", () => loadTop().catch(() => {}));
$("#blockTarget").addEventListener("input", (e) => e.target.dataset.touched = "1");

// ── 차단 제어 ──
async function loadBlocked() {
  const d = await api("/api/blocked");
  const tb = $("#blockedRows"); clear(tb);
  if (!d.blocked.length) tb.append(el("tr", {}, el("td", {colspan: 5}, "차단 중인 대상이 없습니다.")));
  d.blocked.forEach((b) => tb.append(el("tr", {}, el("td", {}, b.target), el("td", {}, b.reason),
    el("td", {}, fmtTime(b.since)), el("td", {}, fmtDur(Math.max(0, b.remaining_sec))),
    el("td", {}, el("button", {class: "btn sm", onclick: () => unblock(b.target)}, "해제")))));
}
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
  const body = {target, reason: "dashboard"};
  const dur = parseInt($("#blockDur").value, 10); if (dur > 0) body.duration_sec = dur;
  try {
    const r = await api("/api/block", "POST", body);
    if (r.ok) {
      const box = $("#blockMsg"); clear(box);
      box.append(el("div", {class: "alert success"}, `대응 완료: ${target} 이(가) 차단 목록에 등록되었습니다.`),
        el("div", {class: "alert info"}, "모의 모드(dry-run)에서는 실제 iptables 차단 없이 기록만 됩니다. 실제 차단은 config.json 의 dry_run 을 false 로 바꾼 뒤 적용됩니다."));
    } else alertBox($("#blockMsg"), "warning", r.reason);
    loadBlocked();
  } catch (err) { alertBox($("#blockMsg"), "error", err.message); }
});

// ── 규칙 ──
async function loadRules() {
  const d = await api("/api/rules");
  const box = $("#rulesBox"); clear(box);
  const tb = el("tbody", {});
  Object.entries(d.rules).forEach(([name, r]) => tb.append(el("tr", {}, el("td", {}, name),
    el("td", {}, r.enabled ? "켜짐" : "꺼짐"), el("td", {}, JSON.stringify(r)))));
  box.append(el("div", {class: "df"}, el("table", {}, el("thead", {}, el("tr", {},
    el("th", {}, "규칙"), el("th", {}, "상태"), el("th", {}, "설정"))), tb)));
}

// ── 플러그인 ──
function pluginCard(p) {
  const inputs = {};
  const row = el("div", {class: "row"});
  p.params.forEach((s) => {
    const inp = s.type === "choice"
      ? el("select", {}, (s.choices || []).map((c) => el("option", {value: c}, c)))
      : el("input", {class: "txt", type: s.type === "int" ? "number" : "text"});
    if (s.default !== undefined) inp.value = s.default;
    inputs[s.name] = inp;
    row.append(el("label", {}, s.label, inp));
  });
  const act = async (path, body) => { try { await api(`/api/plugins/${p.id}/${path}`, "POST", body); loadPlugins(true); } catch (e) { alert(e.message); } };
  if (p.enabled) {
    row.append(p.running
      ? el("button", {class: "btn", onclick: () => act("stop")}, "⏹ 중지")
      : el("button", {class: "btn primary", onclick: () => act("run", {params: Object.fromEntries(Object.entries(inputs).map(([k, v]) => [k, v.value]))})},
          p.kind === "service" ? "▶ 시작" : "▶ 실행"));
  }
  row.append(el("button", {class: "btn", onclick: () => act("enable", {enabled: !p.enabled})}, p.enabled ? "비활성화" : "활성화"));
  const run = p.last_run;
  const status = p.running ? "실행 중" : run ? ({done: "완료", failed: "실패", stopped: "중지됨", timeout: "시간 초과"}[run.status] || run.status) : "";
  const out = run ? el("pre", {}, run.output.join("\n") || "(출력 없음)") : null;
  if (out) setTimeout(() => out.scrollTop = out.scrollHeight, 0);
  return el("div", {class: "plugin"},
    el("h4", {}, p.name, el("span", {class: "tag"}, p.kind === "service" ? "서비스" : "1회 실행"),
      status && el("span", {class: "tag"}, status), !p.enabled && el("span", {class: "tag"}, "비활성")),
    el("p", {class: "caption"}, p.description), row, out);
}
async function loadPlugins(force) {
  const d = await api("/api/plugins");
  const list = $("#pluginList");
  if (!force && list.contains(document.activeElement)) return;   // 입력 중이면 다시 그리지 않음
  clear(list);
  if (!d.plugins.length) list.append(el("div", {class: "alert info"}, "plugins/ 폴더에 플러그인이 없습니다."));
  d.plugins.forEach((p) => list.append(pluginCard(p)));
}

// ── 주기적 새로고침 ──
async function refresh(force) {
  try {
    await Promise.all([loadTop(), loadBlocked(), loadPlugins(force)]);
    if (!refresh.rulesLoaded) { await loadRules(); refresh.rulesLoaded = true; }
    $("#conn").textContent = "Guardian 연결됨"; $("#conn").className = "conn ok";
  } catch (e) {
    if (e.message !== "로그인 필요") { $("#conn").textContent = e.message.slice(0, 60); $("#conn").className = "conn bad"; }
  }
}
setInterval(() => { if ($("#login").hidden) refresh(false); }, 3000);
if (token) refresh(true); else showLogin();
