/* Log Analyzer UI — vanilla JS. All log-derived text is inserted with textContent (never innerHTML):
   log files contain attacker-controlled strings. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const SEV_ORDER = ["Critical", "High", "Medium", "Low"];
// Kill-chain order used to draw "what this attacker did" left to right.
const STAGE = { scanning: 0, rate_abuse: 1, brute_force: 1, sql_injection: 1, path_traversal: 1, xss: 1, command_injection: 1,
  prompt_injection: 1, other: 1, unauthorized_access: 2, credential_compromise: 3, data_exfiltration: 4 };
const SEV_HELP = {
  Critical: "Likely compromise. Act now.",
  High: "Active attack attempts.",
  Medium: "Suspicious probing.",
  Low: "Weak single indicator.",
};
const state = { file: null, jobId: null, es: null, report: null, filter: new Set(), query: "", maxMb: 20, pollTimer: null };

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c != null) n.append(c.nodeType ? c : document.createTextNode(String(c)));
  return n;
}
const fmtBytes = (b) => (b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`);
const fmtMs = (ms) => (ms == null ? "–" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);
const fmtDur = (s) => (s == null ? "" : s < 60 ? `${Math.max(1, Math.round(s))} s` : `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`);
const fmtNum = (n) => (n == null ? "–" : Number(n).toLocaleString());
function announce(msg, urgent = false) {
  const r = $(urgent ? "#announceUrgent" : "#announce");
  r.textContent = "";
  setTimeout(() => (r.textContent = msg), 50);
}

async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch(path, opts);
  } catch {
    throw { message: "Can't reach the analyzer service.", hint: "Check that the app is running, then try again." };
  }
  const isJson = (res.headers.get("content-type") || "").includes("json");
  const body = isJson ? await res.json().catch(() => ({})) : await res.text();
  if (!res.ok) throw { message: body.message || `Request failed (${res.status}).`, hint: body.hint };
  return body;
}

/* ---------------------------------------------------------------- views */
function show(view) {
  for (const id of ["viewUpload", "viewProgress", "viewReport"]) $("#" + id).hidden = id !== view;
  const step = { viewUpload: 1, viewProgress: 2, viewReport: 3 }[view];
  [1, 2, 3].forEach((i) => {
    const li = $("#step" + i);
    li.toggleAttribute("aria-current", i === step);
    if (i === step) li.setAttribute("aria-current", "step");
    li.classList.toggle("done", i < step);
  });
}
function showError(box, err) {
  box.hidden = false;
  box.replaceChildren(el("b", { text: err.message || String(err) }), err.hint ? el("span", { text: err.hint }) : "");
  announce(err.message || String(err), true);
}

/* ---------------------------------------------------------------- system status */
async function refreshSystem() {
  try {
    const s = await api("/api/system");
    const pill = $("#modelPill");
    pill.classList.toggle("ok", s.model.ready);
    pill.classList.toggle("bad", !s.model.ready);
    $("#modelText").textContent = s.model.ready ? `${s.model.name} ready` : "Model loading…";
    $("#footModel").textContent = `${s.model.name} (${s.model.file || "GGUF"})`;
    const m = s.memory;
    const total = m.total_mb;
    $("#ramText").textContent = `${fmtNum(total)} / ${fmtNum(m.limit_mb)} MB`;
    const pct = Math.min(100, (total / m.limit_mb) * 100);
    const bar = $("#ramBar");
    bar.style.width = pct + "%";
    bar.className = pct > 90 ? "bad" : pct > 75 ? "warn" : "";
    $(".ram").title = `Model ${m.model_mb ?? "?"} MB + app ${m.api_mb} MB, limit ${m.limit_mb} MB`;
    state.maxMb = s.limits.max_upload_mb;
    $("#maxMb").textContent = state.maxMb;
  } catch {
    $("#modelPill").className = "pill bad";
    $("#modelText").textContent = "Service unreachable";
  }
}

/* ---------------------------------------------------------------- upload */
function pickFile(f) {
  $("#uploadError").hidden = true;
  if (!f) return;
  const ext = (f.name.split(".").pop() || "").toLowerCase();
  if (!["log", "txt"].includes(ext)) {
    showError($("#uploadError"), { message: `“${f.name}” is not a .log or .txt file.`, hint: "Choose a plain-text log file." });
    return;
  }
  if (f.size === 0) return showError($("#uploadError"), { message: "The file is empty.", hint: "Choose a log file that contains entries." });
  if (f.size > state.maxMb * 1048576)
    return showError($("#uploadError"), { message: `The file is larger than ${state.maxMb} MB.`, hint: "Upload a shorter time range." });
  state.file = f;
  $("#drop").hidden = true;
  $("#fileChosen").hidden = false;
  $("#fileName").textContent = f.name;
  $("#fileMeta").textContent = `${fmtBytes(f.size)} · ready to analyze`;
  $("#startBtn").disabled = false;
  $("#startHint").textContent = "Takes a few minutes on CPU. You can leave this page open or come back later.";
  announce(`${f.name} selected. Press Start analysis.`);
  $("#startBtn").focus();
}
function resetUpload() {
  state.file = null;
  $("#fileInput").value = "";
  $("#drop").hidden = false;
  $("#fileChosen").hidden = true;
  $("#startBtn").disabled = true;
  $("#startHint").textContent = "Choose a file to continue.";
  $("#uploadError").hidden = true;
}
async function startAnalysis() {
  if (!state.file) return;
  const btn = $("#startBtn");
  btn.disabled = true;
  btn.textContent = "Uploading…";
  try {
    const fd = new FormData();
    fd.append("file", state.file);
    const job = await api("/api/jobs", { method: "POST", body: fd });
    await api(`/api/jobs/${job.id}/start`, { method: "POST" });
    openJob(job.id, true);
  } catch (e) {
    showError($("#uploadError"), e);
    btn.disabled = false;
  } finally {
    btn.textContent = "Start analysis";
  }
}

/* ---------------------------------------------------------------- progress */
function openJob(id, push = false) {
  state.jobId = id;
  if (push) history.pushState(null, "", `#job=${id}`);
  else history.replaceState(null, "", `#job=${id}`);
  api(`/api/jobs/${id}`).then(render).catch((e) => {
    show("viewUpload");
    showError($("#uploadError"), e);
  });
}
function listen(id) {
  if (state.es) state.es.close();
  if (!("EventSource" in window)) return poll(id);
  const es = new EventSource(`/api/jobs/${id}/stream`);
  state.es = es;
  es.onmessage = (ev) => {
    const job = JSON.parse(ev.data);
    if (state.jobId === id) render(job);
    if (["done", "failed", "cancelled"].includes(job.status)) es.close();
  };
  es.onerror = () => {
    es.close();
    setTimeout(() => state.jobId === id && poll(id), 2000);
  };
}
function poll(id) {
  clearTimeout(state.pollTimer);
  api(`/api/jobs/${id}`).then((job) => {
    render(job);
    if (!["done", "failed", "cancelled"].includes(job.status)) state.pollTimer = setTimeout(() => poll(id), 2000);
  }).catch(() => (state.pollTimer = setTimeout(() => poll(id), 4000)));
}

let lastAnnounced = "";
function render(job) {
  if (job.status === "done" && job.report) return renderReport(job);
  if (job.status === "uploaded") {
    show("viewUpload");
    return;
  }
  show("viewProgress");
  $("#progFile").textContent = job.filename;
  const p = job.progress || { done: 0, total: 0 };
  const stage = job.status === "cancelled" ? "Stopped. Completed parts are kept." :
    job.status === "failed" ? "The analysis stopped." : job.stage || "Starting…";
  $("#stageText").textContent = stage;
  const bar = $("#progBar");
  const pct = p.total ? Math.round(((p.done + p.failed) / p.total) * 100) : 0;
  bar.classList.toggle("indeterminate", !p.total);
  bar.firstElementChild.style.width = p.total ? pct + "%" : "";
  bar.setAttribute("aria-valuenow", String(pct));
  bar.setAttribute("aria-valuetext", p.total ? `${p.done} of ${p.total} parts analyzed` : "Preparing");
  $("#progPct").textContent = p.total ? `${pct}%` : "Preparing…";
  $("#progParts").textContent = p.total ? `${p.done} of ${p.total} parts${p.failed ? ` · ${p.failed} failed` : ""}` : "";
  $("#progEta").textContent = p.eta_s ? `about ${fmtDur(p.eta_s)} left` : "";
  $("#kFindings").textContent = fmtNum(p.findings_so_far || 0);
  $("#kTokens").textContent = job.compact_tokens ? `${fmtNum(job.compact_tokens)}` : "–";
  $("#kTokens").title = job.raw_tokens ? `Raw file: ${fmtNum(job.raw_tokens)} tokens` : "";
  $("#kAvg").textContent = fmtMs(p.avg_ms);

  const ol = $("#parts");
  ol.replaceChildren(...(job.chunks || []).map((c) => {
    const label = `Part ${c.idx + 1}, lines ${c.line_start} to ${c.line_end}, ${c.status}` +
      (c.status === "done" ? `, ${c.n_findings} findings, ${fmtMs(c.latency_ms)}, ${c.prompt_tokens + c.completion_tokens} tokens` : "") +
      (c.error ? `. Error: ${c.error}` : "");
    return el("li", { class: c.status, title: label, tabindex: "0", "aria-label": label },
      String(c.idx + 1), c.n_findings ? el("span", { class: "fdot", "aria-hidden": "true", text: c.n_findings }) : null);
  }));

  const msg = `${stage}${p.total ? `. ${p.done} of ${p.total} parts done` : ""}`;
  if (msg !== lastAnnounced && (p.done !== state._lastDone || job.status !== state._lastStatus)) {
    announce(msg);
    lastAnnounced = msg;
  }
  state._lastDone = p.done;
  state._lastStatus = job.status;

  const errBox = $("#progError");
  const cancelBtn = $("#cancelBtn");
  if (job.status === "failed" || job.status === "cancelled") {
    errBox.hidden = false;
    errBox.replaceChildren(
      el("b", { text: job.status === "cancelled" ? "Analysis stopped." : job.error || "The analysis failed." }),
      el("span", { text: "Completed parts are saved. " }),
      el("button", { class: "btn secondary", type: "button", onclick: () => restart(job.id), text: "Resume analysis" }));
    cancelBtn.hidden = true;
  } else {
    errBox.hidden = true;
    cancelBtn.hidden = false;
    if (!state.es || state.es.readyState === 2) listen(job.id);
  }
}
async function restart(id) {
  try {
    await api(`/api/jobs/${id}/start`, { method: "POST" });
    listen(id);
  } catch (e) { showError($("#progError"), e); }
}
async function cancelJob() {
  if (!state.jobId || !confirm("Stop the analysis? Completed parts are kept and you can resume later.")) return;
  await api(`/api/jobs/${state.jobId}/cancel`, { method: "POST" }).then(render).catch((e) => showError($("#progError"), e));
}

/* ---------------------------------------------------------------- report */
function renderReport(job) {
  if (state.es) state.es.close();
  show("viewReport");
  const r = job.report;
  state.report = r;
  const s = r.stats;
  const took = job.finished_at && job.started_at ? fmtDur(job.finished_at - job.started_at) : "";
  $("#repTitle").textContent = `Report · ${job.filename}`;
  $("#repMeta").textContent = `${fmtNum(s.lines)} lines · ${s.parts} parts · ${s.model_calls} model calls` +
    (took ? ` · took ${took}` : "") + ` · ${job.model}`;
  $("#dlMd").href = `/api/jobs/${job.id}/report.md`;
  $("#dlJson").href = `/api/jobs/${job.id}/report.json`;

  const warn = $("#repWarn");
  warn.hidden = !job.error;
  if (job.error) warn.replaceChildren(el("b", { text: "Some parts could not be analyzed." }), el("span", { text: job.error + " " }),
    el("button", { class: "btn secondary", type: "button", text: "Retry failed parts",
      onclick: async () => { await api(`/api/jobs/${job.id}/retry`, { method: "POST" }); openJob(job.id); } }));

  $("#sumText").textContent = r.summary.summary;
  $("#sumSrc").textContent = r.summary.source === "model" ? "written by the local model · checked against findings"
    : "generated from findings";
  $("#sumSrc").title = r.summary.source === "model" ? "" :
    (r.summary.rejected_reasons || []).length ? `The model's summary was not used: ${r.summary.rejected_reasons.join("; ")}` : "";
  $("#prioWrap").hidden = !(r.summary.priorities || []).length;
  $("#prioList").replaceChildren(...(r.summary.priorities || []).map((p) => el("li", { text: p })));

  // Severity tiles act as filters.
  $("#sevTiles").replaceChildren(...SEV_ORDER.map((sev) => {
    const n = r.severity_counts[sev] || 0;
    return el("button", {
      class: `sev-tile sev-${sev}`, type: "button", "aria-pressed": String(state.filter.has(sev)), disabled: !n,
      title: SEV_HELP[sev], onclick: () => toggleSev(sev),
    }, el("span", { class: "n", text: n }), el("span", { class: "lbl", text: sev }), el("span", { class: "muted small", text: SEV_HELP[sev] }));
  }));

  // Attack chains per source.
  const multi = r.incidents.filter((i) => i.finding_ids.length > 0);
  $("#chainsCard").hidden = !multi.length;
  $("#chains").replaceChildren(...multi.map((inc) => {
    const fs = inc.finding_ids.map((id) => r.findings.find((f) => f.id === id))
      .sort((a, b) => (STAGE[a.attack_type] ?? 1) - (STAGE[b.attack_type] ?? 1) || a.first_line - b.first_line);
    const steps = [];
    fs.forEach((f, i) => {
      if (i) steps.push(el("span", { class: "arrow", "aria-hidden": "true", text: "→" }));
      steps.push(el("a", { class: "stepchip", href: `#${f.id}`, onclick: (e) => { e.preventDefault(); focusFinding(f.id); } },
        `${f.label} `, el("span", { class: "muted", text: `L${f.first_line}` })));
    });
    return el("li", { class: "chain" }, el("span", { class: `sev sev-${inc.severity}`, text: inc.severity }),
      el("code", { text: inc.ip }), el("span", { class: "muted small", text: `lines ${inc.first_line}–${inc.last_line}` }),
      el("div", { class: "steps-inline grow" }, steps));
  }));

  renderFindings();

  const unc = r.unconfirmed || [];
  $("#unconfCount").textContent = `(${unc.length})`;
  $("#unconfList").replaceChildren(...(unc.length ? unc.map((u) => el("li", {},
    el("code", { text: u.ip }), " — ", Object.entries(u.signals).map(([k, v]) => `${k.replaceAll("_", " ")} ×${v}`).join(", "),
    el("span", { class: "muted small", text: ` (lines ${u.first_line}–${u.last_line})` }))) : [el("li", { class: "muted", text: "None." })]));
  renderRunDetails(job);
  loadHistory();
  announce(`Analysis complete. ${r.findings.length} findings.`);
  $("#repTitle").setAttribute("tabindex", "-1");
  $("#repTitle").focus({ preventScroll: true });
}

function toggleSev(sev) {
  state.filter.has(sev) ? state.filter.delete(sev) : state.filter.add(sev);
  document.querySelectorAll(".sev-tile").forEach((b) => b.setAttribute("aria-pressed", String(state.filter.has(b.classList[1].slice(4)))));
  renderFindings();
}
function renderFindings() {
  const r = state.report;
  if (!r) return;
  const q = state.query.trim().toLowerCase();
  const list = r.findings.filter((f) => (!state.filter.size || state.filter.has(f.severity)) &&
    (!q || [f.ip, f.label, f.attack_type, f.reason, f.action].join(" ").toLowerCase().includes(q)));
  $("#findTitle").textContent = `Findings (${list.length}${list.length !== r.findings.length ? ` of ${r.findings.length}` : ""})`;
  $("#clearFilters").hidden = !state.filter.size && !q;
  $("#noFindings").hidden = list.length > 0;
  $("#noFindings").textContent = r.findings.length ? "No findings match the filters." : "No attacks were found with supporting evidence.";
  const tpl = $("#tplFinding");
  $("#findings").replaceChildren(...list.map((f) => {
    const node = tpl.content.firstElementChild.cloneNode(true);
    node.id = f.id;
    node.classList.add(`sev-border-${f.severity}`);
    const sev = $(".sev", node);
    sev.classList.add(`sev-${f.severity}`);
    sev.textContent = f.severity;
    $(".f-title", node).textContent = f.label;
    $(".f-ip code", node).textContent = f.ip;
    $(".copy", node).addEventListener("click", () => navigator.clipboard?.writeText(f.ip).then(() => announce(`Copied ${f.ip}`)));
    $(".f-reason", node).textContent = f.reason;
    $(".f-action span", node).textContent = f.action;
    const meta = $(".f-meta", node);
    meta.append(el("span", { text: `Lines ${f.first_line}–${f.last_line}` }),
      el("span", { text: `Seen in part${f.chunks.length > 1 ? "s" : ""} ${f.chunks.join(", ")}` }),
      el("span", { text: `Detected by ${f.sources.map((s) => (s === "model" ? "AI model" : "cross-part linking")).join(" + ")}` }));
    if (f.related.length) meta.append(el("span", {}, "Related: ", ...f.related.flatMap((id, i) =>
      [i ? ", " : "", el("a", { href: `#${id}`, onclick: (e) => { e.preventDefault(); focusFinding(id); }, text: id })])));
    $(".ev-count", node).textContent = `(${f.lines.length} line${f.lines.length > 1 ? "s" : ""})`;
    const det = $(".evidence", node);
    det.addEventListener("toggle", () => det.open && loadEvidence(det, f), { once: false });
    return node;
  }));
}
async function loadEvidence(det, f) {
  if (det.dataset.loaded) return;
  const body = $(".ev-body", det);
  try {
    const lines = await api(`/api/jobs/${state.jobId}/lines?n=${f.lines.slice(0, 200).join(",")}`);
    const list = el("ol", { class: "ev-lines", "aria-label": "Original log lines" });
    const draw = (raw) => list.replaceChildren(...f.lines.map((n) => {
      const text = lines[n] ?? "(line not available)";
      return el("li", {}, el("span", { class: "ln", text: `L${n}` }), el("span", { class: "tx", text: raw ? text : readable(text) }));
    }));
    const toggle = el("label", { class: "small muted raw-toggle" }, el("input", { type: "checkbox", onchange: (e) => draw(e.target.checked) }), " Show raw lines");
    draw(false);
    body.replaceChildren(toggle, list);
    det.dataset.loaded = "1";
  } catch (e) {
    body.replaceChildren(el("p", { class: "muted small", text: e.message }));
  }
}
/* Human-readable form of a JSON log line: the key facts first, everything else after. */
const NOISE = new Set(["host", "request_id", "response_bytes", "duration_ms", "user_agent", "app"]);
function readable(line) {
  let o;
  try { o = JSON.parse(line); } catch { return line; }
  if (!o || typeof o !== "object") return line;
  const t = (o.time || o.timestamp || "").replace("T", " ").replace(/\.\d+Z$|Z$/, "");
  const parts = [t, o.client_ip || o.ip, [o.method, o.path ? safeDecode(o.path) : ""].filter(Boolean).join(" "),
    o.status != null ? `→ ${o.status}` : "", o.level && o.level !== "INFO" ? o.level : "", o.message ? `"${o.message}"` : ""];
  const rest = Object.entries(o).filter(([k]) => !["time", "timestamp", "client_ip", "ip", "method", "path", "status", "level", "message", "service"].includes(k) && !NOISE.has(k))
    .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`);
  if (o.user_agent && !/Mozilla/.test(o.user_agent)) rest.push(`ua=${o.user_agent}`);
  return parts.filter(Boolean).join("  ") + (rest.length ? "   · " + rest.join("  ") : "");
}
function safeDecode(p) { try { return decodeURIComponent(decodeURIComponent(p)); } catch { return p; } }

function focusFinding(id) {
  state.filter.clear();
  state.query = "";
  $("#search").value = "";
  renderFindings();
  const n = document.getElementById(id);
  if (!n) return;
  n.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  n.setAttribute("tabindex", "-1");
  n.focus({ preventScroll: true });
  history.replaceState(null, "", `#job=${state.jobId}`);
}
function renderRunDetails(job) {
  const r = job.report, s = r.stats, b = r.budget || {};
  const box = $("#runDetails");
  const rows = (pairs) => el("table", { class: "t" }, el("tbody", {}, pairs.map(([k, v]) => el("tr", {}, el("th", { scope: "row", text: k }), el("td", { text: v })))));
  box.replaceChildren(
    el("h4", { text: "Token budget per model call" }),
    rows([["Model context", `${fmtNum(b.ctx)} tokens`], ["System + instructions", `${fmtNum(b.prompt_overhead)}`],
      ["Carried facts from earlier parts", `≤ ${fmtNum(b.carry)}`], ["Log text per part", `≤ ${fmtNum(b.chunk)}`],
      ["Reserved for the reply", `${fmtNum(b.output_reserve)}`], ["Safety margin", `${fmtNum(b.safety_margin)}`],
      ["Largest call actually used", `${fmtNum(s.max_total_tokens)} / ${fmtNum(b.ctx)}`]]),
    el("h4", { text: "Volume and timing" }),
    rows([["Original tokens", fmtNum(s.raw_tokens)], ["After compaction", fmtNum(s.compact_tokens)],
      ["Routine entries folded", `${fmtNum(s.folded)} of ${fmtNum(s.entries)}`], ["Model calls", fmtNum(s.model_calls)],
      ["Total model time", fmtMs(s.total_model_ms)], ["Average per call", fmtMs(s.avg_call_ms)]]),
    el("h4", { text: "Per-part calls" }),
    el("div", { class: "tablewrap" }, el("table", { class: "t" },
      el("thead", {}, el("tr", {}, ["Part", "Lines", "Status", "Tries", "Prompt", "Reply", "Time", "Findings", "JSON"].map((h) => el("th", { scope: "col", text: h })))),
      el("tbody", {}, (job.chunks || []).map((c) => el("tr", {},
        [c.idx + 1, `${c.line_start}–${c.line_end}`, c.status, c.attempts, c.prompt_tokens ?? "–", c.completion_tokens ?? "–",
          fmtMs(c.latency_ms), c.n_findings, c.parse_mode || "–"].map((v) => el("td", { text: v }))))))),
    r.rejected?.length ? el("p", { class: "muted small", text: `${r.rejected.length} model finding(s) were rejected because their evidence lines did not exist in that part.` }) : "");
}

/* ---------------------------------------------------------------- history */
async function loadHistory() {
  try {
    const jobs = await api("/api/jobs?limit=8");
    $("#historyCard").hidden = !jobs.length;
    $("#history").replaceChildren(...jobs.map((j) => el("li", {}, el("a", { href: `#job=${j.id}`, onclick: (e) => { e.preventDefault(); openJob(j.id, true); } },
      el("span", { class: "fname", text: j.filename }),
      el("span", { class: "muted small" }, new Date(j.created_at * 1000).toLocaleString(), " ", el("span", { class: "status-chip", text: j.status }))))));
  } catch { /* history is optional */ }
}

/* ---------------------------------------------------------------- wiring */
function route() {
  const m = location.hash.match(/job=([a-f0-9]+)/);
  if (m) openJob(m[1]);
  else { state.jobId = null; if (state.es) state.es.close(); show("viewUpload"); }
}
document.addEventListener("DOMContentLoaded", () => {
  const drop = $("#drop");
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => pickFile(e.dataTransfer.files[0]));
  // Dropping anywhere on the page also works when on the upload step.
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => { e.preventDefault(); if (!$("#viewUpload").hidden && e.dataTransfer.files[0]) pickFile(e.dataTransfer.files[0]); });
  $("#fileInput").addEventListener("change", (e) => pickFile(e.target.files[0]));
  $("#changeFile").addEventListener("click", () => { resetUpload(); $("#fileInput").click(); });
  $("#startBtn").addEventListener("click", startAnalysis);
  $("#cancelBtn").addEventListener("click", cancelJob);
  $("#newBtn").addEventListener("click", () => { resetUpload(); history.pushState(null, "", location.pathname); route(); $("#main").focus(); });
  $("#search").addEventListener("input", (e) => { state.query = e.target.value; renderFindings(); });
  $("#clearFilters").addEventListener("click", () => {
    state.filter.clear(); state.query = ""; $("#search").value = "";
    document.querySelectorAll(".sev-tile").forEach((b) => b.setAttribute("aria-pressed", "false"));
    renderFindings();
  });
  window.addEventListener("popstate", route);
  refreshSystem();
  setInterval(refreshSystem, 5000);
  loadHistory();
  route();
});
