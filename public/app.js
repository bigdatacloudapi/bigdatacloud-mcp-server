/* urlscan-verify — browser side.
 *
 * Deliberately plain: no build step, no framework, no CDN. The same page is
 * served by the local process and by the hosted build, and it adapts to which
 * one it is talking to by asking /api/status what that deployment can do.
 *
 * Verification is driven from here, a batch at a time. That is what lets a run
 * of several hundred names survive a serverless function timeout, resume after
 * a rate limit, and show results as they arrive rather than after a long blank
 * wait. See the note in src/api.mjs for the reasoning.
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

let STATUS = null;
let CSV_TEXT = "";
let CSV_NAME = "";
let EXTRACTION = null;
let REPORT = null;
let FILTER_SEV = null;
let RUNNING = false;
let STOP = false;

// ------------------------------------------------------------------- key

async function refreshStatus() {
  const box = $("#keystate");
  try {
    const s = await (await fetch("/api/status")).json();
    STATUS = s;
    box.innerHTML = "";
    box.appendChild(el("span", "dot " + (s.keyConfigured ? "on" : "off")));
    box.appendChild(el("span", null, s.keyConfigured ? `key ${s.keyMasked}` : "no API key"));

    // A hosted deployment reads its key from the environment and cannot store
    // one, so the whole card would be a dead end. Explain instead of offering it.
    $("#cardKey").classList.toggle("hide", s.keyConfigured);
    $("#keyForm").classList.toggle("hide", !s.canStoreKey);
    $("#keyHosted").classList.toggle("hide", s.canStoreKey);
    $("#saveRow").classList.toggle("hide", !s.canWriteFiles);
    $("#downloadRow").classList.toggle("hide", Boolean(s.canWriteFiles));
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

async function analyze(overrides) {
  msg("#analyzeMsg", "", "Reading…");
  try {
    const r = await fetch("/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ csv: CSV_TEXT, ...overrides }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "could not parse that file");
    EXTRACTION = d;
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
  const est = Math.round(((d.uniqueHosts + d.uniqueIPs) * (STATUS?.pacingMs || 900)) / 1000);
  fact("Rows", d.rowCount.toLocaleString(), CSV_NAME);
  fact("Hostnames", d.uniqueHosts.toLocaleString(), d.hosts.slice(0, 3).map((h) => h.host).join(", "));
  fact("Addresses", d.uniqueIPs.toLocaleString(), d.ips.slice(0, 3).map((i) => i.ip).join(", "));
  fact("Est. time", est > 90 ? `${Math.round(est / 60)} min` : `${est}s`, "one lookup per unique name");

  const fill = (sel, chosen) => {
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
  fill("#hostCol", d.columns.hostCols.map((c) => c.index));
  fill("#ipCol", d.columns.ipCols.map((c) => c.index));

  if (!d.uniqueHosts && !d.uniqueIPs) {
    msg("#analyzeMsg", "err", "No hostnames or addresses found. Pick the right columns above and press Re-read.");
  }
}

const chosen = (sel) => [...$(sel).selectedOptions].map((o) => Number(o.value));

$("#recolumn").onclick = () =>
  analyze({ hostColumns: chosen("#hostCol"), ipColumns: chosen("#ipCol") });

// ------------------------------------------------------------------- run

$("#run").onclick = () => run(false);
$("#runOffline").onclick = () => run(true);
$("#stop").onclick = () => {
  STOP = true;
  $("#stop").textContent = "Stopping…";
};

/**
 * Drive the batch loop.
 *
 * Records accumulate here and are only assembled into a report at the end, so
 * stopping early — by choice or by rate limit — still yields a usable report of
 * everything checked so far.
 */
async function run(offline) {
  if (!EXTRACTION) return msg("#analyzeMsg", "err", "Load a CSV first.");
  if (RUNNING) return;
  const status = await refreshStatus();
  if (!offline && status && !status.keyConfigured) {
    return msg("#analyzeMsg", "err", "No API key configured. " + (status.canStoreKey ? "Add one above" : "Set URLSCAN_API_KEY on the deployment") + ", or use structure checks only.");
  }

  const limit = Number($("#limit").value) || 0;
  const hostQueue = limit > 0 ? EXTRACTION.hosts.slice(0, limit) : EXTRACTION.hosts.slice();
  const ipQueue = EXTRACTION.ips.slice();
  const total = hostQueue.length + ipQueue.length;
  if (!total) return msg("#analyzeMsg", "err", "Nothing to check in that file.");

  // Small batches offline are pointless overhead; online they are what makes
  // progress visible and a timeout survivable.
  const maxBatch = Math.max(1, Math.min(STATUS?.maxBatch || 25, offline ? 25 : 5));

  RUNNING = true;
  STOP = false;
  $("#cardRun").classList.remove("hide");
  $("#stop").textContent = "Stop";
  $("#run").disabled = true;
  $("#runOffline").disabled = true;
  msg("#analyzeMsg", "", "");

  const hosts = [];
  const ips = [];
  let api = null;
  let stoppedEarly = false;
  let done = 0;

  const opts = {
    offline,
    allow: $("#allow").value.split(",").map((s) => s.trim()).filter(Boolean),
    deep: $("#deep").checked,
    answerIPs: EXTRACTION.answerIPs || [],
  };

  try {
    while ((hostQueue.length || ipQueue.length) && !STOP) {
      const batchHosts = hostQueue.splice(0, maxBatch);
      const room = maxBatch - batchHosts.length;
      const batchIPs = room > 0 ? ipQueue.splice(0, room) : [];

      const r = await fetch("/api/verify-batch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...opts, hosts: batchHosts, ips: batchIPs }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || `server returned ${r.status}`);

      hosts.push(...d.hosts);
      ips.push(...d.ips);
      if (d.api) api = d.api;
      done += d.hosts.length + d.ips.length;

      const pct = (done / total) * 100;
      $("#barFill").style.width = pct.toFixed(1) + "%";
      $("#progNow").textContent = `${done} / ${total}`;
      const last = [...d.hosts, ...d.ips].slice(-1)[0];
      $("#progCur").textContent = last ? (last.host || last.ip) : "";

      // Show results as they land rather than after a long blank wait.
      REPORT = await finalize(hosts, ips, api, false);
      renderReport(REPORT);

      if (d.rateLimited) {
        stoppedEarly = true;
        msg("#analyzeMsg", "warn", "urlscan's rate limit was reached, so the run stopped here. Everything checked is cached — press Verify again in a minute and it will pick up where it left off.");
        break;
      }
    }

    if (STOP) {
      msg("#analyzeMsg", "warn", `Stopped at ${done} of ${total}. Everything checked is cached, so continuing is cheap.`);
    }
    REPORT = await finalize(hosts, ips, api, stoppedEarly);
    renderReport(REPORT);
  } catch (e) {
    msg("#analyzeMsg", "err", e.message);
  } finally {
    RUNNING = false;
    $("#cardRun").classList.add("hide");
    $("#run").disabled = false;
    $("#runOffline").disabled = false;
  }
}

async function finalize(hosts, ips, api, stoppedEarly) {
  const r = await fetch("/api/finalize", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      hosts,
      ips,
      pairs: EXTRACTION.pairs,
      api,
      stoppedEarly,
      filename: CSV_NAME,
      scope: {
        rowCount: EXTRACTION.rowCount,
        uniqueHosts: EXTRACTION.uniqueHosts,
        uniqueIPs: EXTRACTION.uniqueIPs,
        hostsChecked: hosts.length,
        ipsChecked: ips.length,
        pairsChecked: EXTRACTION.pairs.length,
        columns: {
          hosts: EXTRACTION.columns.hostCols.map((c) => c.header),
          ips: EXTRACTION.columns.ipCols.map((c) => c.header + (c.role === "source" ? " (source)" : "")),
        },
      },
    }),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || "could not assemble the report");
  return d;
}

// --------------------------------------------------------------- results

function renderReport(report) {
  $("#cardResults").classList.remove("hide");
  const s = report.scope;
  $("#resultSub").textContent =
    `${(s.rowCount || 0).toLocaleString()} rows · ${s.hostsChecked} hostnames and ${s.ipsChecked} addresses checked · ` +
    (report.api?.offline
      ? "structure checks only, urlscan was not contacted"
      : `${report.api?.calls ?? 0} urlscan calls, ${report.api?.cacheHits ?? 0} from cache`) +
    (report.stoppedEarly ? " · stopped early on a rate limit" : "");

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
    tr.tabIndex = 0;
    // data-label drives the stacked card layout on narrow screens, where the
    // header row is hidden and each cell has to name itself.
    const td = (child, cls, label) => {
      const c = el("td", cls);
      if (label) c.dataset.label = label;
      if (typeof child === "string" || typeof child === "number") c.textContent = child;
      else if (child) c.appendChild(child);
      tr.appendChild(c);
      return c;
    };
    td(el("span", "tag " + r.severity, LABEL[r.severity]), "verdict", "");
    td(name, "name", "Name");
    td(r.count ?? "", "num", "Rows");
    td(r.scans ?? "", "num", "Scans");
    const asns = (r.evidence?.asns || []).map((a) => a.name || a.asn).slice(0, 2).join(", ");
    td(asns || r.special || "", "", "Network");
    const why = r.signals.filter((x) => x.weight > 0).map((x) => x.id).join(", ");
    td(why || (r.signals[0] ? r.signals[0].id : ""), "why", "Why");

    const toggle = () => {
      const next = tr.nextElementSibling;
      if (next && next.classList.contains("detail")) {
        next.remove();
        return;
      }
      tr.after(detailRow(r));
    };
    tr.onclick = toggle;
    tr.onkeydown = (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle();
      }
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
  for (const s of r.signals) list.appendChild(el("li", null, s.detail));
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

const postExport = (body) =>
  fetch("/api/export", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ report: REPORT, ...body }),
  });

$("#expJson").onclick = () => REPORT && download(`urlscan-verify-${stamp()}.json`, JSON.stringify(REPORT, null, 2), "application/json");
$("#expCsv").onclick = async () => {
  if (!REPORT) return;
  download(`urlscan-verify-${stamp()}.csv`, await (await postExport({ format: "csv" })).text(), "text/csv");
};
$("#expMd").onclick = async () => {
  if (!REPORT) return;
  download(`urlscan-verify-${stamp()}.md`, await (await postExport({ format: "markdown" })).text(), "text/markdown");
};
$("#expBlock").onclick = () => $("#blockPanel").classList.toggle("hide");

const blockOpts = () => ({
  severities: [...document.querySelectorAll(".bsev:checked")].map((c) => c.value),
  setName: $("#setName").value.trim() || "urlscan_verify",
  interface: $("#pbrIface").value.trim() || "wan",
});

$("#doDownload").onclick = async () => {
  if (!REPORT) return;
  const o = blockOpts();
  if (!o.severities.length) return msg("#blockMsg", "err", "Pick at least one verdict to include.");
  const r = await postExport({ format: "blocklist", ...o });
  const d = await r.json();
  if (!r.ok) return msg("#blockMsg", "err", d.error);
  for (const [name, content] of Object.entries(d.files)) download(name, content, "text/plain");
  msg("#blockMsg", "ok", `Downloaded ${Object.keys(d.files).length} files. Your browser may ask to allow multiple downloads.`);
};

$("#doSave").onclick = async () => {
  if (!REPORT) return;
  const o = blockOpts();
  if (!o.severities.length) return msg("#blockMsg", "err", "Pick at least one verdict to include.");
  const btn = $("#doSave");
  btn.disabled = true;
  try {
    const r = await fetch("/api/export/save", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ report: REPORT, ...o, dir: $("#saveDir").value.trim() || "urlscan-verify-export" }),
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
