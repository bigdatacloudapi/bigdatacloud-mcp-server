/* urlscan-verify — browser side.
 *
 * Deliberately plain: no build step, no framework, no CDN. This page is served
 * by a local process that holds an API key, and every dependency it does not
 * have is one fewer thing that can reach the network from here.
 */
"use strict";

const $ = (s) => document.querySelector(s);
const el = (t, c, x) => {
  const n = document.createElement(t);
  if (c) n.className = c;
  if (x !== undefined && x !== null) n.textContent = x;
  return n;
};
const msg = (sel, kind, text) => {
  const box = $(sel);
  box.innerHTML = "";
  if (!text) return;
  box.appendChild(el("div", "msg " + (kind || ""), text));
};

const SEVERITIES = ["critical", "warning", "notice", "clean", "unknown"];
const LABEL = {
  critical: "Flagged",
  warning: "Check this",
  notice: "Worth a look",
  clean: "No signal",
  unknown: "No evidence",
};

let CSV_TEXT = "";
let CSV_NAME = "";
let ANALYSIS = null;
let REPORT = null;
let FILTER_SEV = null;
let controller = null;

// ------------------------------------------------------------------- key

async function refreshStatus() {
  const box = $("#keystate");
  try {
    const s = await (await fetch("/api/status")).json();
    box.innerHTML = "";
    box.appendChild(el("span", "dot " + (s.keyConfigured ? "on" : "off")));
    box.appendChild(
      el("span", null, s.keyConfigured ? `key ${s.keyMasked} (${s.keySource})` : "no API key")
    );
    $("#cardKey").classList.toggle("hide", s.keyConfigured);
    return s;
  } catch {
    box.textContent = "server unreachable";
    return null;
  }
}

$("#saveKey").onclick = async () => {
  const key = $("#key").value.trim();
  if (!key) return msg("#keyMsg", "err", "Paste the key first.");
  const btn = $("#saveKey");
  btn.disabled = true;
  btn.textContent = "Verifying…";
  try {
    const r = await fetch("/api/key", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "could not verify the key");
    $("#key").value = "";
    msg("#keyMsg", "ok", `Verified and stored as ${d.keyMasked}.`);
    await refreshStatus();
  } catch (e) {
    msg("#keyMsg", "err", e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Verify & save";
  }
};

$("#clearKey").onclick = async () => {
  await fetch("/api/key", { method: "DELETE" });
  msg("#keyMsg", "", "Stored key removed.");
  await refreshStatus();
};

// ------------------------------------------------------------------- csv

const drop = $("#drop");
const fileInput = $("#file");
drop.onclick = () => fileInput.click();
drop.onkeydown = (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    fileInput.click();
  }
};
["dragenter", "dragover"].forEach((ev) =>
  drop.addEventListener(ev, (e) => {
    e.preventDefault();
    drop.classList.add("hot");
  })
);
["dragleave", "drop"].forEach((ev) =>
  drop.addEventListener(ev, (e) => {
    e.preventDefault();
    drop.classList.remove("hot");
  })
);
drop.addEventListener("drop", (e) => {
  const f = e.dataTransfer.files[0];
  if (f) loadFile(f);
});
fileInput.onchange = () => {
  const f = fileInput.files[0];
  if (f) loadFile(f);
};

function loadFile(file) {
  msg("#analyzeMsg", "", "");
  const fr = new FileReader();
  fr.onerror = () => msg("#analyzeMsg", "err", "Could not read that file.");
  fr.onload = async () => {
    CSV_TEXT = String(fr.result || "");
    CSV_NAME = file.name;
    drop.querySelector("b").textContent = file.name;
    await analyze();
  };
  fr.readAsText(file);
}

async function analyze() {
  msg("#analyzeMsg", "", "Reading…");
  try {
    const r = await fetch("/api/analyze", { method: "POST", body: CSV_TEXT });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "could not parse that file");
    ANALYSIS = d;
    renderPreview(d);
    msg("#analyzeMsg", "", "");
  } catch (e) {
    $("#preview").classList.add("hide");
    msg("#analyzeMsg", "err", e.message);
  }
}

function renderPreview(d) {
  $("#preview").classList.remove("hide");
  const facts = $("#facts");
  facts.innerHTML = "";
  const fact = (label, value, sub) => {
    const box = el("div", "fact");
    box.appendChild(el("span", "lbl", label));
    box.appendChild(el("b", null, value));
    if (sub) box.appendChild(el("s", null, sub));
    facts.appendChild(box);
  };
  fact("Rows", d.rowCount.toLocaleString(), CSV_NAME);
  fact("Hostnames", d.uniqueHosts.toLocaleString(), d.hosts.slice(0, 3).join(", "));
  fact("Addresses", d.uniqueIPs.toLocaleString(), d.ips.slice(0, 3).join(", "));
  fact("Name→address pairs", d.pairs.toLocaleString(), d.pairs ? "cross-checkable" : "none on the same row");

  const fill = (sel, cols, chosen) => {
    const s = $(sel);
    s.innerHTML = "";
    d.columns.headers.forEach((h, i) => {
      const o = el("option", null, `${i + 1}. ${h}`);
      o.value = String(i);
      if (chosen.includes(i)) o.selected = true;
      s.appendChild(o);
    });
    s.size = Math.min(6, Math.max(3, d.columns.headers.length));
  };
  fill("#hostCol", d.columns.hostCols, d.columns.hostCols.map((c) => c.index));
  fill("#ipCol", d.columns.ipCols, d.columns.ipCols.map((c) => c.index));

  if (!d.uniqueHosts && !d.uniqueIPs) {
    msg("#analyzeMsg", "err", "No hostnames or addresses found. Pick the right columns above and try again.");
  }
}

const chosen = (sel) => [...$(sel).selectedOptions].map((o) => Number(o.value));

// ------------------------------------------------------------------- run

$("#run").onclick = () => run(false);
$("#runOffline").onclick = () => run(true);
$("#stop").onclick = () => {
  if (controller) controller.abort();
};

async function run(offline) {
  if (!CSV_TEXT) return msg("#analyzeMsg", "err", "Load a CSV first.");
  const status = await refreshStatus();
  if (!offline && status && !status.keyConfigured) {
    return msg("#analyzeMsg", "err", "No API key configured. Add one above, or use structure checks only.");
  }

  $("#cardRun").classList.remove("hide");
  $("#cardResults").classList.add("hide");
  $("#spin").classList.remove("hide");
  $("#barFill").style.width = "0%";
  $("#progCur").textContent = "";
  $("#run").disabled = true;
  $("#runOffline").disabled = true;

  controller = new AbortController();
  try {
    const res = await fetch("/api/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        csv: CSV_TEXT,
        filename: CSV_NAME,
        offline,
        hostColumns: chosen("#hostCol"),
        ipColumns: chosen("#ipCol"),
        limitHosts: Number($("#limit").value) || 0,
        deep: $("#deep").checked,
        allow: $("#allow").value.split(",").map((s) => s.trim()).filter(Boolean),
      }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      throw new Error(d.error || `server returned ${res.status}`);
    }
    await consumeStream(res.body);
  } catch (e) {
    if (e.name === "AbortError") {
      msg("#analyzeMsg", "warn", "Stopped. Anything already looked up is cached, so re-running picks up cheaply.");
    } else {
      msg("#analyzeMsg", "err", e.message);
    }
  } finally {
    controller = null;
    $("#spin").classList.add("hide");
    $("#run").disabled = false;
    $("#runOffline").disabled = false;
  }
}

/** Read the NDJSON progress stream the server writes while it works. */
async function consumeStream(body) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const lines = buf.split("\n");
    buf = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      let ev;
      try {
        ev = JSON.parse(line);
      } catch {
        continue;
      }
      handleEvent(ev);
    }
  }
}

function handleEvent(ev) {
  if (ev.type === "progress") {
    const pct = ev.total ? (ev.done / ev.total) * 100 : 0;
    $("#barFill").style.width = pct.toFixed(1) + "%";
    $("#progNow").textContent = `${ev.done} / ${ev.total}`;
    $("#progCur").textContent = ev.current;
  } else if (ev.type === "done") {
    REPORT = ev.report;
    $("#cardRun").classList.add("hide");
    renderReport(REPORT);
  } else if (ev.type === "error") {
    msg("#analyzeMsg", "err", ev.error);
  }
}

// --------------------------------------------------------------- results

function renderReport(report) {
  $("#cardResults").classList.remove("hide");
  const s = report.scope;
  $("#resultSub").textContent =
    `${s.rowCount.toLocaleString()} rows · ${s.hostsChecked} hostnames and ${s.ipsChecked} addresses checked · ` +
    (report.api.offline
      ? "structure checks only, urlscan was not contacted"
      : `${report.api.calls} urlscan calls, ${report.api.cacheHits} from cache`) +
    (report.stoppedEarly ? " · stopped early on a rate limit — re-run to continue" : "");

  const board = $("#scoreboard");
  board.innerHTML = "";
  for (const sev of SEVERITIES) {
    const n = (report.summary.hosts[sev] || 0) + (report.summary.ips[sev] || 0);
    const b = el("button", `score s-${sev}`);
    b.setAttribute("aria-pressed", String(FILTER_SEV === sev));
    b.appendChild(el("b", null, String(n)));
    b.appendChild(el("span", "lbl", LABEL[sev]));
    b.onclick = () => {
      FILTER_SEV = FILTER_SEV === sev ? null : sev;
      renderReport(report);
    };
    board.appendChild(b);
  }

  renderRows();
}

$("#filter").oninput = renderRows;

function renderRows() {
  if (!REPORT) return;
  const q = $("#filter").value.trim().toLowerCase();
  const rows = [...REPORT.hosts, ...REPORT.ips]
    .filter((r) => !FILTER_SEV || r.severity === FILTER_SEV)
    .filter((r) => !q || String(r.host || r.ip).toLowerCase().includes(q))
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || b.weight - a.weight);

  const tb = $("#rows");
  tb.innerHTML = "";
  for (const r of rows) {
    const name = r.host || r.ip;
    const tr = el("tr");
    const td = (child, cls) => {
      const c = el("td", cls);
      if (typeof child === "string" || typeof child === "number") c.textContent = child;
      else if (child) c.appendChild(child);
      tr.appendChild(c);
      return c;
    };
    td(el("span", "tag " + r.severity, LABEL[r.severity]));
    td(name, "name");
    td(r.count ?? "", "num");
    td(r.scans ?? "", "num");
    const asns = (r.evidence?.asns || []).map((a) => a.name || a.asn).slice(0, 2).join(", ");
    td(asns || (r.special ? r.special : ""), "");
    const why = r.signals.filter((x) => x.weight > 0).map((x) => x.id).join(", ");
    td(why || (r.signals[0] ? r.signals[0].id : ""), "");

    let open = false;
    tr.onclick = () => {
      if (open) {
        tr.nextSibling?.remove();
        open = false;
        return;
      }
      tr.after(detailRow(r));
      open = true;
    };
    tb.appendChild(tr);
  }
  if (!rows.length) {
    const tr = el("tr");
    const td = el("td", null, "Nothing matches that filter.");
    td.colSpan = 6;
    tr.appendChild(td);
    tb.appendChild(tr);
  }
}

function detailRow(r) {
  const tr = el("tr", "detail");
  const td = el("td");
  td.colSpan = 6;

  const list = el("ul");
  for (const s of r.signals) {
    list.appendChild(el("li", null, s.detail));
  }
  if (!r.signals.length) list.appendChild(el("li", null, "No signals — nothing about this name or address stood out."));
  td.appendChild(list);

  const ev = r.evidence;
  if (ev) {
    const kv = el("dl", "kv");
    const put = (k, v) => {
      if (!v || (Array.isArray(v) && !v.length)) return;
      kv.appendChild(el("dt", null, k));
      kv.appendChild(el("dd", null, Array.isArray(v) ? v.join(", ") : String(v)));
    };
    put("urlscan scans", r.scans);
    put("tags", ev.tags);
    put("addresses seen", ev.ips);
    put("domains hosted", (ev.domains || []).slice(0, 12));
    put("networks", (ev.asns || []).map((a) => `${a.asn}${a.name ? ` ${a.name}` : ""}`));
    put("countries", ev.countries);
    put("last scanned", ev.newest?.time);
    td.appendChild(kv);

    if (ev.newest?.uuid) {
      const a = el("a", null, "Open the newest scan on urlscan.io →");
      a.href = `https://urlscan.io/result/${ev.newest.uuid}/`;
      a.target = "_blank";
      a.rel = "noopener";
      const p = el("div");
      p.style.marginTop = "8px";
      p.appendChild(a);
      td.appendChild(p);
    }
  }
  if (r.error) td.appendChild(el("div", "msg err", `Lookup failed: ${r.error}`));

  tr.appendChild(td);
  return tr;
}

// --------------------------------------------------------------- exports

function download(name, body, type) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const stamp = () => new Date().toISOString().slice(0, 10);

$("#expJson").onclick = () => REPORT && download(`urlscan-verify-${stamp()}.json`, JSON.stringify(REPORT, null, 2), "application/json");
$("#expCsv").onclick = async () => {
  const r = await fetch("/api/export", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ format: "csv" }),
  });
  download(`urlscan-verify-${stamp()}.csv`, await r.text(), "text/csv");
};
$("#expMd").onclick = async () => {
  const r = await fetch("/api/export", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ format: "markdown" }),
  });
  download(`urlscan-verify-${stamp()}.md`, await r.text(), "text/markdown");
};

$("#expBlock").onclick = () => $("#blockPanel").classList.toggle("hide");

$("#doSave").onclick = async () => {
  const severities = [...document.querySelectorAll(".bsev:checked")].map((c) => c.value);
  if (!severities.length) return msg("#blockMsg", "err", "Pick at least one verdict to include.");
  const btn = $("#doSave");
  btn.disabled = true;
  try {
    const r = await fetch("/api/export/save", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        severities,
        setName: $("#setName").value.trim() || "urlscan_verify",
        interface: $("#pbrIface").value.trim() || "wan",
        dir: $("#saveDir").value.trim() || "urlscan-verify-export",
      }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    msg("#blockMsg", "ok", `Wrote ${d.files.length} files to ${d.dir}`);
  } catch (e) {
    msg("#blockMsg", "err", e.message);
  } finally {
    btn.disabled = false;
  }
};

refreshStatus();
