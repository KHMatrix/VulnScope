const CSRF = window.CSRF_TOKEN;
let CURRENT_SCAN_ID = null;
let socket = null;

function authHeaders(extra) {
  return Object.assign({ "Content-Type": "application/json", "X-CSRFToken": CSRF }, extra || {});
}

async function api(path, opts = {}) {
  const res = await fetch(path, Object.assign({ headers: authHeaders() }, opts));
  if (res.status === 401) { window.location.href = "/login"; throw new Error("unauthenticated"); }
  return res;
}

// ---------------- Audio toggle ----------------
const audioBtn = document.getElementById("audioToggle");
audioBtn.addEventListener("click", () => {
  const next = !KHAudio.isEnabled();
  KHAudio.setEnabled(next);
  audioBtn.textContent = "AUDIO: " + (next ? "ON" : "OFF");
  if (next) KHAudio.click();
});
document.body.addEventListener("click", (e) => {
  if (e.target.classList.contains("neon-btn") || e.target.classList.contains("ghost-btn")) KHAudio.click();
});

// ---------------- Logout ----------------
document.getElementById("logoutBtn").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  window.location.href = "/login";
});

// ---------------- Assets ----------------
const assetSelect = document.getElementById("assetSelect");
const authBanner = document.getElementById("authBanner");

async function loadAssets(selectId) {
  const res = await api("/api/assets");
  const assets = await res.json();
  assetSelect.innerHTML = "";
  assets.forEach((a) => {
    const opt = document.createElement("option");
    opt.value = a.id;
    opt.dataset.authorized = a.authorized ? "1" : "0";
    opt.textContent = `${a.name} — ${a.target} (${a.target_type})${a.authorized ? "" : " [UNAUTHORIZED]"}`;
    assetSelect.appendChild(opt);
  });
  document.getElementById("statAssets").textContent = assets.length;
  if (selectId) assetSelect.value = selectId;
  updateAuthBanner();
  return assets;
}

function updateAuthBanner() {
  const opt = assetSelect.options[assetSelect.selectedIndex];
  const authorized = opt && opt.dataset.authorized === "1";
  authBanner.textContent = authorized ? "TARGET AUTHORIZATION: VERIFIED" : "TARGET AUTHORIZATION: NOT VERIFIED";
  authBanner.classList.toggle("verified", !!authorized);
  document.getElementById("startScanBtn").disabled = !authorized;
}
assetSelect.addEventListener("change", updateAuthBanner);

// Add asset modal
const modal = document.getElementById("assetModal");
document.getElementById("newAssetBtn").addEventListener("click", () => modal.classList.remove("hidden"));
document.getElementById("closeAssetModal").addEventListener("click", () => modal.classList.add("hidden"));
document.getElementById("assetForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    name: document.getElementById("af_name").value,
    target: document.getElementById("af_target").value,
    device_type: document.getElementById("af_devicetype").value,
    environment: document.getElementById("af_env").value,
    owner: document.getElementById("af_owner").value,
    notes: document.getElementById("af_notes").value,
    authorized: document.getElementById("af_authorized").checked,
  };
  const res = await api("/api/assets", { method: "POST", body: JSON.stringify(body) });
  const data = await res.json();
  if (res.ok) {
    modal.classList.add("hidden");
    document.getElementById("assetForm").reset();
    document.getElementById("assetFormError").textContent = "";
    await loadAssets(data.id);
  } else {
    document.getElementById("assetFormError").textContent = data.error || "Failed to save asset.";
  }
});

// ---------------- Scans ----------------
const startBtn = document.getElementById("startScanBtn");
const abortBtn = document.getElementById("abortScanBtn");

startBtn.addEventListener("click", async () => {
  const assetId = parseInt(assetSelect.value, 10);
  if (!assetId) return;
  clearTelemetry();
  clearTables();
  const res = await api("/api/scan/start", { method: "POST", body: JSON.stringify({ asset_id: assetId, scan_type: "single" }) });
  const data = await res.json();
  if (!res.ok) { pushTelemetry({ event: "ERROR", message: data.error, level: "error" }); return; }
  CURRENT_SCAN_ID = data.scan_id;
  startBtn.disabled = true;
  abortBtn.disabled = false;
  KHAudio.scanStart();
  subscribeScan(CURRENT_SCAN_ID);
  pollScanStatus();
  loadReportLinks(CURRENT_SCAN_ID);
});

abortBtn.addEventListener("click", async () => {
  if (!CURRENT_SCAN_ID) return;
  await api(`/api/scan/${CURRENT_SCAN_ID}/abort`, { method: "POST" });
  pushTelemetry({ event: "ABORT REQUESTED", message: "Cancellation signal sent. Workers will stop shortly.", level: "warn" });
});

function loadReportLinks(scanId) {
  const el = document.getElementById("reportLinks");
  el.innerHTML = ["html", "json", "csv", "txt"].map(
    (fmt) => `<a href="/api/scan/${scanId}/report/${fmt}" target="_blank">${fmt.toUpperCase()}</a>`
  ).join("");
}

// ---------------- Telemetry (Socket.IO) ----------------
function ensureSocket() {
  if (!socket) {
    socket = io();
    socket.on("telemetry", (payload) => {
      pushTelemetry(payload);
      if (payload.event === "SCAN COMPLETED") {
        startBtn.disabled = false;
        abortBtn.disabled = true;
        if (payload.level === "error") KHAudio.warning(); else KHAudio.scanComplete();
        pollScanStatus();
        loadArchive();
      }
    });
  }
  return socket;
}

function subscribeScan(scanId) {
  ensureSocket().emit("subscribe_scan", { scan_id: scanId });
}

const feed = document.getElementById("telemetryFeed");
function clearTelemetry() { feed.innerHTML = ""; }
function pushTelemetry(payload) {
  const div = document.createElement("div");
  div.className = "line" + (payload.level === "error" ? " error" : payload.level === "warn" ? " warn" : "");
  const ts = new Date().toLocaleTimeString();
  div.innerHTML = `<span class="tag">[${ts}] ${payload.event}</span> ${payload.message || ""}`;
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

// ---------------- Scan status polling (tables) ----------------
let pollTimer = null;
function pollScanStatus() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (!CURRENT_SCAN_ID) return;
    const res = await api(`/api/scan/${CURRENT_SCAN_ID}`);
    const data = await res.json();
    renderHosts(data.hosts);
    renderFindings(data.findings);
    if (data.scan.status !== "running") {
      clearInterval(pollTimer);
    }
  }, 2000);
}

function clearTables() {
  document.querySelector("#assetTable tbody").innerHTML = "";
  document.querySelector("#findingsTable tbody").innerHTML = "";
}

function renderHosts(hosts) {
  const tbody = document.querySelector("#assetTable tbody");
  tbody.innerHTML = "";
  let serviceCount = 0;
  hosts.forEach((h) => {
    serviceCount += (h.services || []).length;
    const tr = document.createElement("tr");
    const ports = (h.services || []).map((s) => `${s.port}/${s.service || "?"}`).join(", ");
    tr.innerHTML = `<td>${esc(h.ip)}</td><td>${esc(h.device_type)}</td><td>${esc(h.confidence)}</td>
      <td>${esc(h.hostname || "")}</td><td>${esc(h.os_indicator || "")}</td><td>${esc(ports)}</td>`;
    tbody.appendChild(tr);
  });
  document.getElementById("statServices").textContent = serviceCount;
}

function renderFindings(findings) {
  const tbody = document.querySelector("#findingsTable tbody");
  tbody.innerHTML = "";
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings
    .slice()
    .sort((a, b) => sevRank(b.severity) - sevRank(a.severity))
    .forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      const tr = document.createElement("tr");
      const loc = f.host_ip ? f.host_ip + (f.port ? ":" + f.port : "") : (f.url || "");
      tr.innerHTML = `<td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
        <td>${esc(f.title)}</td><td>${esc(f.confidence)}</td><td>${esc(loc)}</td>
        <td>${esc(f.cve || "")}</td><td>${esc(f.cvss ?? "")}</td>`;
      tbody.appendChild(tr);
    });
  document.getElementById("statFindings").textContent = findings.length;
  document.getElementById("statCritical").textContent = counts.CRITICAL;
  document.getElementById("cCritical").textContent = counts.CRITICAL;
  document.getElementById("cHigh").textContent = counts.HIGH;
  document.getElementById("cMedium").textContent = counts.MEDIUM;
  document.getElementById("cLow").textContent = counts.LOW;
  document.getElementById("cInfo").textContent = counts.INFO;
}

function sevRank(s) { return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }[s] ?? 0; }
function esc(s) { const d = document.createElement("div"); d.textContent = s ?? ""; return d.innerHTML; }

// ---------------- Archived Intel ----------------
async function loadArchive() {
  const res = await api("/api/scans");
  const scans = await res.json();
  const assetsRes = await api("/api/assets");
  const assets = await assetsRes.json();
  const assetMap = Object.fromEntries(assets.map((a) => [a.id, a.name]));

  const tbody = document.querySelector("#archiveTable tbody");
  tbody.innerHTML = "";
  scans.forEach((s) => {
    const summary = s.summary_json ? JSON.parse(s.summary_json) : {};
    const findingsCount = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].reduce((a, k) => a + (summary[k] || 0), 0);
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>#${s.id}</td><td>${esc(assetMap[s.asset_id] || s.asset_id)}</td>
      <td>${esc(new Date(s.started_at).toLocaleString())}</td><td>${esc(s.status)}</td>
      <td>${findingsCount}</td>
      <td><a href="/api/scan/${s.id}/report/html" target="_blank">VIEW</a> &middot;
          <a href="/api/scan/${s.id}/report/json" target="_blank">JSON</a></td>`;
    tbody.appendChild(tr);
  });
}

document.getElementById("archiveSearch").addEventListener("input", (e) => {
  const q = e.target.value.toLowerCase();
  document.querySelectorAll("#archiveTable tbody tr").forEach((tr) => {
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none";
  });
});

// ---------------- Init ----------------
(async function init() {
  await loadAssets();
  await loadArchive();
  ensureSocket();
})();
