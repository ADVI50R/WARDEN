"use strict";
const $ = (s) => document.querySelector(s);
const SEV_KO = {info: "정보", warning: "경고", critical: "위험"};
let token = "";
try { token = localStorage.getItem("gd_token") || ""; } catch (e) {}
let tab = "overview";
let pluginOutputOpen = {};

// ── 안전한 DOM 생성 (공격자가 만든 문자열이 들어와도 HTML 로 해석되지 않음) ──
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(c));
  return e;
}
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.style.display = "block";
  clearTimeout(toast.t); toast.t = setTimeout(() => t.style.display = "none", 3500);
}

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

function showLogin(msg) { $("#login").hidden = false; $("#loginErr").textContent = msg || ""; }
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  token = $("#tokenInput").value.trim();
  try {
    await api("/api/plugins");
    try { localStorage.setItem("gd_token", token); } catch (e) {}
    $("#login").hidden = true; refresh();
  } catch (err) { showLogin("토큰이 맞지 않습니다"); }
});

// ── 탭 ──
$("#tabs").addEventListener("click", (e) => {
  const t = e.target.dataset.tab; if (!t) return;
  tab = t;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === t));
  document.querySelectorAll("main > section").forEach((s) => s.hidden = s.id !== "tab-" + t);
  refresh();
});

const fmtTime = (iso) => iso ? iso.replace("T", " ").slice(0, 19) : "";
const fmtDur = (s) => s >= 60 ? Math.floor(s / 60) + "분 " + (s % 60) + "초" : s + "초";
const fmtUp = (s) => `${Math.floor(s / 3600)}시간 ${Math.floor(s % 3600 / 60)}분`;

function sevCell(s) { return el("td", {class: "sev " + s}, SEV_KO[s] || s); }
function eventRow(ev) {
  return el("tr", {}, el("td", {}, fmtTime(ev.timestamp)), el("td", {}, ev.type), sevCell(ev.severity),
    el("td", {}, ev.source), el("td", {}, ev.detail), el("td", {}, ev.action));
}

// ── 개요 ──
async function loadOverview() {
  const [st, evs] = await Promise.all([api("/api/status"), api("/api/events?limit=200")]);
  const ev = evs.events;
  const crit = ev.filter((e) => e.severity === "critical").length;
  const cards = [
    ["모드", st.dry_run ? "탐지만 (dry-run)" : "실제 차단"],
    ["가동 시간", fmtUp(st.uptime_sec)],
    ["현재 차단", st.blocked_count + " 건"],
    ["최근 200건 중 위험", crit + " 건"],
    ["감시 인터페이스", st.interface + " / " + st.my_ip],
  ];
  const box = $("#cards"); clear(box);
  cards.forEach(([k, v]) => box.append(el("div", {class: "card"}, el("div", {class: "k"}, k), el("div", {class: "v"}, v))));

  const counts = {};
  ev.forEach((e) => counts[e.type] = (counts[e.type] || 0) + 1);
  const max = Math.max(1, ...Object.values(counts));
  const chart = $("#typeChart"); clear(chart);
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (!entries.length) chart.append(el("p", {}, "아직 탐지된 이벤트가 없습니다."));
  entries.forEach(([t, n]) => chart.append(el("div", {class: "hbar"}, el("span", {class: "n"}, t),
    el("span", {class: "b", style: `width:${Math.round(n / max * 60)}%`}), el("span", {class: "c"}, n))));

  const recent = $("#recent"); clear(recent);
  const tb = el("tbody", {}); ev.slice(0, 8).forEach((e) => tb.append(eventRow(e)));
  recent.append(el("table", {}, tb));
}

// ── 이벤트 ──
async function loadEvents() {
  const t = $("#typeFilter").value;
  const d = await api("/api/events?limit=200" + (t ? "&type=" + encodeURIComponent(t) : ""));
  const known = new Set([...$("#typeFilter").options].map((o) => o.value));
  d.events.forEach((e) => { if (!known.has(e.type)) { known.add(e.type); $("#typeFilter").append(el("option", {value: e.type}, e.type)); } });
  const tb = $("#eventRows"); clear(tb);
  d.events.forEach((e) => tb.append(eventRow(e)));
}
$("#typeFilter").addEventListener("change", loadEvents);

// ── 차단 ──
async function loadBlocked() {
  const d = await api("/api/blocked");
  const tb = $("#blockedRows"); clear(tb);
  if (!d.blocked.length) tb.append(el("tr", {}, el("td", {colspan: 5}, "차단 중인 대상이 없습니다.")));
  d.blocked.forEach((b) => tb.append(el("tr", {}, el("td", {}, b.target), el("td", {}, b.reason),
    el("td", {}, fmtTime(b.since)), el("td", {}, fmtDur(Math.max(0, b.remaining_sec))),
    el("td", {}, el("button", {onclick: () => unblock(b.target)}, "해제")))));
}
async function unblock(target) {
  try { const r = await api("/api/unblock", "POST", {target}); toast(r.ok ? "해제했습니다: " + target : r.reason); loadBlocked(); }
  catch (e) { toast(e.message); }
}
$("#blockForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {target: $("#blockTarget").value.trim(), reason: "dashboard"};
  const dur = parseInt($("#blockDur").value, 10); if (dur > 0) body.duration_sec = dur;
  try { const r = await api("/api/block", "POST", body); toast(r.ok ? "차단했습니다" : r.reason); loadBlocked(); }
  catch (err) { toast(err.message); }
});

// ── 규칙 ──
async function loadRules() {
  const d = await api("/api/rules");
  const box = $("#rulesBox"); clear(box);
  const tb = el("tbody", {});
  Object.entries(d.rules).forEach(([name, r]) => tb.append(el("tr", {}, el("td", {}, name),
    el("td", {}, r.enabled ? "켜짐" : "꺼짐"), el("td", {}, JSON.stringify(r)))));
  box.append(el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "규칙"), el("th", {}, "상태"), el("th", {}, "설정"))), tb));
}

// ── 플러그인 ──
function pluginCard(p) {
  const inputs = {};
  const form = el("div", {class: "bar"});
  p.params.forEach((s) => {
    let inp;
    if (s.type === "choice") inp = el("select", {}, (s.choices || []).map((c) => el("option", {value: c}, c)));
    else inp = el("input", {type: s.type === "int" ? "number" : "text", placeholder: s.label});
    if (s.default !== undefined) inp.value = s.default;
    inputs[s.name] = inp;
    form.append(el("label", {}, s.label + " ", inp));
  });
  const getParams = () => Object.fromEntries(Object.entries(inputs).map(([k, v]) => [k, v.value]));
  const act = async (path, body) => { try { await api(`/api/plugins/${p.id}/${path}`, "POST", body); loadPlugins(); } catch (e) { toast(e.message); } };

  const run = p.last_run;
  const status = p.running ? "실행 중" : run ? ({done: "완료", failed: "실패", stopped: "중지됨", timeout: "시간 초과"}[run.status] || run.status) : "";
  if (p.enabled) {
    form.append(p.running
      ? el("button", {class: "danger", onclick: () => act("stop")}, "중지")
      : el("button", {class: "primary", onclick: () => act("run", {params: getParams()})}, p.kind === "service" ? "시작" : "실행"));
  }
  form.append(el("button", {onclick: () => act("enable", {enabled: !p.enabled})}, p.enabled ? "비활성화" : "활성화"));

  const out = el("pre", {}, run ? run.output.join("\n") || "(출력 없음)" : "");
  const card = el("div", {class: "panel plugin"},
    el("h3", {}, p.name, el("span", {class: "tag"}, p.kind === "service" ? "서비스" : "1회 실행"),
      status && el("span", {class: "tag"}, status), !p.enabled && el("span", {class: "tag"}, "비활성")),
    el("p", {}, p.description), form, run ? out : null);
  if (run) setTimeout(() => out.scrollTop = out.scrollHeight, 0);
  return card;
}
async function loadPlugins() {
  const d = await api("/api/plugins");
  const list = $("#pluginList");
  // 입력 중인 값이 지워지지 않도록, 입력칸에 포커스가 있으면 이번엔 다시 그리지 않음
  if (list.contains(document.activeElement) && document.activeElement.tagName !== "BODY" && !loadPlugins.force) return;
  clear(list);
  if (!d.plugins.length) list.append(el("p", {}, "plugins/ 폴더에 플러그인이 없습니다."));
  d.plugins.forEach((p) => list.append(pluginCard(p)));
}

// ── 주기적 새로고침 ──
async function refresh() {
  try {
    if (tab === "overview") await loadOverview();
    else if (tab === "events") await loadEvents();
    else if (tab === "blocked") await loadBlocked();
    else if (tab === "rules") await loadRules();
    else if (tab === "plugins") { loadPlugins.force = true; await loadPlugins(); loadPlugins.force = false; }
    $("#conn").textContent = "Guardian 연결됨"; $("#conn").className = "pill ok";
  } catch (e) {
    if (e.message !== "로그인 필요") { $("#conn").textContent = e.message.slice(0, 40); $("#conn").className = "pill bad"; }
  }
}
setInterval(() => { if (!$("#login").hidden) return; if (tab === "plugins") loadPlugins().catch(() => {}); else refresh(); }, 3000);
if (token) refresh(); else showLogin();
