# ui.py
# Enhanced Web UI for interacting with main.py (HTTP gateway)
# main.py must be running on http://127.0.0.1:9000
# c_engine must be running and connected to main.py via /tmp/cengine.sock
#
# Improvements:
# - Stream upload proxy (no full file buffering in RAM)
# - Manifest viewer (CID validation + metadata display)
# - Recent manifests list (from local manifests/ directory)
# - Upload progress (XHR in browser)
# - Download progress (fetch streaming in browser)
# - Copy CID button + local history

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import http.client
import json
import os
import time

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 9000  # main.py HTTP gateway
UI_HOST = "127.0.0.1"
UI_PORT = 8000       # UI server port (separate from main.py)

MANIFEST_DIR = "manifests"
STREAM_CHUNK = 256 * 1024


def human_bytes(n: int) -> str:
    try:
        n = int(n)
    except Exception:
        return "?"
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024.0:
            if u == "B":
                return f"{int(f)} {u}"
            return f"{f:.2f} {u}"
        f /= 1024.0
    return f"{f:.2f} PB"


def load_manifest(cid: str):
    path = os.path.join(MANIFEST_DIR, cid + ".json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def list_manifests(limit: int = 20):
    items = []
    if not os.path.isdir(MANIFEST_DIR):
        return items
    try:
        for name in os.listdir(MANIFEST_DIR):
            if not name.endswith(".json"):
                continue
            cid = name[:-5]
            path = os.path.join(MANIFEST_DIR, name)
            try:
                st = os.stat(path)
                m = load_manifest(cid) or {}
                items.append({
                    "cid": cid,
                    "mtime": int(st.st_mtime),
                    "manifest_bytes": int(st.st_size),
                    "filename": m.get("filename"),
                    "total_size": m.get("total_size"),
                    "chunk_size": m.get("chunk_size"),
                    "hash_algo": m.get("hash_algo"),
                    "chunks_count": len(m.get("chunks", [])) if isinstance(m.get("chunks"), list) else None,
                })
            except Exception:
                continue
        items.sort(key=lambda x: x.get("mtime", 0), reverse=True)
        return items[:max(1, min(limit, 200))]
    except Exception:
        return []


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Content Engine Web UI</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin:0; background:#0f172a; color:#e5e7eb; }
    .container { max-width: 1100px; margin: 0 auto; padding: 24px 16px 40px; }
    h1 { font-size: 1.8rem; margin: 0 0 6px; text-align:center; }
    .subtitle { text-align:center; font-size: .95rem; color:#9ca3af; margin-bottom: 18px; }
    .grid { display:grid; gap:16px; }
    @media (min-width: 900px) { .grid { grid-template-columns: 1fr 1fr; } }
    .card { background:#111827; border:1px solid #1f2937; border-radius: 14px; padding: 16px; box-shadow: 0 10px 25px rgba(0,0,0,.35); }
    .card h2 { margin:0 0 8px; font-size: 1.1rem; }
    .muted { color:#9ca3af; font-size:.85rem; margin: 0 0 12px; }
    label { display:block; font-size: .8rem; margin-bottom: 4px; color:#cbd5e1; }
    input[type=file], input[type=text] {
      width: 100%; padding: 8px 10px; border-radius: 10px;
      border: 1px solid #374151; background:#020617; color:#e5e7eb;
      margin-bottom: 10px;
    }
    .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    button {
      border: none; border-radius: 9999px; padding: 9px 14px;
      font-size: .85rem; cursor: pointer; font-weight: 700;
      background: #22c55e; color:white;
      box-shadow: 0 8px 20px rgba(34,197,94,.35);
      transition: transform .08s ease, filter .15s ease;
    }
    button:hover { filter: brightness(1.06); transform: translateY(-1px); }
    button:active { transform: translateY(0); }
    .btn-secondary { background:#3b82f6; box-shadow: 0 8px 20px rgba(59,130,246,.35); }
    .btn-ghost { background:#334155; box-shadow:none; }
    .status { margin-top: 10px; font-size: .85rem; min-height: 1.2em; }
    .ok { color:#4ade80; } .err { color:#f97373; } .warn { color:#fbbf24; }
    .cid-output { margin-top: 10px; font-size:.85rem; word-break: break-all; }
    code { background:#020617; padding: 3px 6px; border-radius: 8px; border: 1px solid #1f2937; font-size:.78rem; }
    .progress { width:100%; height: 10px; background:#0b1222; border:1px solid #1f2937; border-radius:999px; overflow:hidden; }
    .bar { height:100%; width:0%; background:#22c55e; transition: width .1s linear; }
    .bar.blue { background:#3b82f6; }
    .kv { display:grid; grid-template-columns: 140px 1fr; gap: 6px 10px; margin-top: 10px; font-size: .85rem; }
    .k { color:#9ca3af; } .v { color:#e5e7eb; word-break: break-word; }
    .list { margin-top: 10px; border-top: 1px solid #1f2937; padding-top: 10px; }
    .item {
      display:flex; justify-content: space-between; gap: 10px; padding: 8px 10px;
      border:1px solid #1f2937; border-radius: 12px; margin-bottom: 8px;
      background:#0b1222; cursor:pointer;
    }
    .item:hover { border-color:#334155; }
    .item .left { display:flex; flex-direction:column; gap:2px; }
    .item .right { color:#9ca3af; font-size:.8rem; text-align:right; white-space:nowrap; }
    .pill { display:inline-flex; gap:8px; align-items:center; padding: 4px 10px; border-radius:999px; background:#020617; border:1px solid #1f2937; color:#9ca3af; font-size:.75rem; }
    .footer { margin-top: 14px; text-align:center; color:#64748b; font-size:.75rem; }
  </style>
</head>
<body>
<div class="container">
  <h1>Content Engine Web UI</h1>
  <div class="subtitle">Upload files, get a CID, inspect its manifest, and download with progress.</div>

  <div class="row" style="justify-content:center; margin-bottom: 14px;">
    <span class="pill">Backend: <span style="font-family:monospace;">http://127.0.0.1:9000</span></span>
    <span class="pill">Manifests: <span style="font-family:monospace;">./manifests/</span></span>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Upload → Get CID</h2>
      <p class="muted">Upload streams through the UI server to the gateway (no huge memory buffer). Shows progress.</p>

      <label for="fileInput">Choose file</label>
      <input id="fileInput" type="file">

      <div class="row">
        <button id="uploadBtn">Upload</button>
        <button id="copyCidBtn" class="btn-ghost" title="Copy CID">Copy CID</button>
        <button id="refreshBtn" class="btn-ghost" title="Refresh list">Refresh list</button>
      </div>

      <div style="margin-top:10px;">
        <div class="progress"><div id="upBar" class="bar"></div></div>
        <div id="uploadStatus" class="status"></div>
        <div id="cidBox" class="cid-output"></div>
      </div>

      <div class="list">
        <div class="row" style="justify-content:space-between; align-items:baseline;">
          <div style="font-weight:700;">Recent manifests</div>
          <div style="color:#9ca3af; font-size:.8rem;">click to fill CID</div>
        </div>
        <div id="recentBox"></div>
      </div>
    </div>

    <div class="card">
      <h2>Download by CID</h2>
      <p class="muted">We validate CID locally by reading manifests/&lt;cid&gt;.json. Then download with progress.</p>

      <label for="cidInput">CID</label>
      <input id="cidInput" type="text" placeholder="example: boe...">

      <div class="row">
        <button id="inspectBtn" class="btn-ghost">Inspect</button>
        <button id="downloadBtn" class="btn-secondary">Download</button>
      </div>

      <div style="margin-top:10px;">
        <div class="progress"><div id="dlBar" class="bar blue"></div></div>
        <div id="downloadStatus" class="status"></div>

        <div id="manifestBox" class="kv" style="display:none;"></div>
      </div>

      <div class="footer">
        Tip: Download uses streamed fetch + manifest.total_size for percentage.
      </div>
    </div>
  </div>

  <div class="footer" style="margin-top:20px;">
    Run order: c_engine → main.py → ui.py → open http://127.0.0.1:8000/
  </div>
</div>

<script>
const fileInput = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const copyCidBtn = document.getElementById('copyCidBtn');
const refreshBtn = document.getElementById('refreshBtn');
const uploadStatus = document.getElementById('uploadStatus');
const cidBox = document.getElementById('cidBox');
const upBar = document.getElementById('upBar');

const cidInput = document.getElementById('cidInput');
const inspectBtn = document.getElementById('inspectBtn');
const downloadBtn = document.getElementById('downloadBtn');
const downloadStatus = document.getElementById('downloadStatus');
const dlBar = document.getElementById('dlBar');
const manifestBox = document.getElementById('manifestBox');
const recentBox = document.getElementById('recentBox');

let lastCID = "";

function setStatus(el, text, cls) {
  el.textContent = text;
  el.className = "status " + (cls || "");
}

function setBar(barEl, pct) {
  const v = Math.max(0, Math.min(100, pct));
  barEl.style.width = v.toFixed(1) + "%";
}

function humanBytes(n) {
  if (typeof n !== "number") return "?";
  const units = ["B","KB","MB","GB","TB"];
  let f = n;
  let u = 0;
  while (f >= 1024 && u < units.length-1) { f /= 1024; u++; }
  return (u === 0 ? Math.round(f) : f.toFixed(2)) + " " + units[u];
}

async function fetchRecent() {
  recentBox.innerHTML = '<div class="muted">Loading...</div>';
  try {
    const r = await fetch('/api/list?limit=12');
    const data = await r.json();
    if (!Array.isArray(data.items)) throw new Error("bad response");
    if (data.items.length === 0) {
      recentBox.innerHTML = '<div class="muted">No manifests found yet.</div>';
      return;
    }
    recentBox.innerHTML = "";
    data.items.forEach(it => {
      const div = document.createElement('div');
      div.className = 'item';
      const dt = new Date((it.mtime || 0) * 1000);
      const fname = it.filename || "(unknown)";
      const size = (typeof it.total_size === "number") ? humanBytes(it.total_size) : "?";
      const chunks = (typeof it.chunks_count === "number") ? it.chunks_count : "?";
      div.innerHTML = `
        <div class="left">
          <div style="font-weight:700;">${fname}</div>
          <div style="color:#9ca3af; font-size:.8rem; font-family:monospace;">${it.cid}</div>
          <div style="color:#9ca3af; font-size:.8rem;">${size} • ${chunks} chunks</div>
        </div>
        <div class="right">${dt.toLocaleString()}</div>
      `;
      div.addEventListener('click', () => {
        cidInput.value = it.cid;
        inspectCID();
      });
      recentBox.appendChild(div);
    });
  } catch (e) {
    recentBox.innerHTML = '<div class="status err">Failed to load list.</div>';
  }
}

function copyToClipboard(text) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    setStatus(uploadStatus, 'CID copied to clipboard.', 'ok');
    setTimeout(()=> setStatus(uploadStatus, '', ''), 1200);
  }).catch(()=>{});
}

copyCidBtn.addEventListener('click', () => copyToClipboard(lastCID));
refreshBtn.addEventListener('click', fetchRecent);

function uploadFile() {
  setStatus(uploadStatus, '', '');
  cidBox.textContent = '';
  setBar(upBar, 0);

  const file = fileInput.files[0];
  if (!file) {
    setStatus(uploadStatus, 'No file selected.', 'err');
    return;
  }

  setStatus(uploadStatus, 'Uploading...', 'warn');

  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/upload', true);
  xhr.setRequestHeader('X-Filename', encodeURIComponent(file.name));

  xhr.upload.onprogress = (evt) => {
    if (evt.lengthComputable) {
      const pct = (evt.loaded / evt.total) * 100;
      setBar(upBar, pct);
    }
  };

  xhr.onreadystatechange = () => {
    if (xhr.readyState !== 4) return;
    if (xhr.status !== 200) {
      setStatus(uploadStatus, 'Upload failed: ' + xhr.responseText, 'err');
      setBar(upBar, 0);
      return;
    }
    try {
      const data = JSON.parse(xhr.responseText);
      lastCID = data.cid || "";
      cidBox.innerHTML = 'CID: <code>' + lastCID + '</code>';
      cidInput.value = lastCID;
      setStatus(uploadStatus, 'Upload successful.', 'ok');
      setBar(upBar, 100);
      fetchRecent();
      inspectCID(); // auto inspect after upload
    } catch (e) {
      setStatus(uploadStatus, 'Upload ok but response parse failed.', 'err');
      setBar(upBar, 0);
    }
  };

  xhr.send(file);
}

async function inspectCID() {
  setStatus(downloadStatus, '', '');
  manifestBox.style.display = 'none';
  manifestBox.innerHTML = '';
  setBar(dlBar, 0);

  const cid = (cidInput.value || "").trim();
  if (!cid) {
    setStatus(downloadStatus, 'Please enter a CID.', 'err');
    return;
  }

  setStatus(downloadStatus, 'Inspecting manifest...', 'warn');

  try {
    const r = await fetch('/api/manifest?cid=' + encodeURIComponent(cid));
    if (!r.ok) {
      const t = await r.text();
      setStatus(downloadStatus, 'Invalid CID: ' + t, 'err');
      return;
    }
    const m = await r.json();

    const chunksCount = Array.isArray(m.chunks) ? m.chunks.length : null;

    manifestBox.style.display = 'grid';
    manifestBox.innerHTML = `
      <div class="k">filename</div><div class="v">${(m.filename || "(unknown)")}</div>
      <div class="k">total_size</div><div class="v">${(typeof m.total_size === "number") ? humanBytes(m.total_size) : "?"}</div>
      <div class="k">chunk_size</div><div class="v">${(typeof m.chunk_size === "number") ? humanBytes(m.chunk_size) : "?"}</div>
      <div class="k">chunks</div><div class="v">${(chunksCount !== null) ? chunksCount : "?"}</div>
      <div class="k">hash_algo</div><div class="v">${(m.hash_algo || "?")}</div>
      <div class="k">version</div><div class="v">${(m.version || "?")}</div>
    `;
    setStatus(downloadStatus, 'CID is valid.', 'ok');
  } catch (e) {
    setStatus(downloadStatus, 'Inspect failed.', 'err');
  }
}

async function downloadFile() {
  setBar(dlBar, 0);
  const cid = (cidInput.value || "").trim();
  if (!cid) {
    setStatus(downloadStatus, 'Please enter a CID.', 'err');
    return;
  }

  // Step 1: validate + get manifest (for filename + size)
  setStatus(downloadStatus, 'Validating CID...', 'warn');
  let m = null;
  try {
    const r = await fetch('/api/manifest?cid=' + encodeURIComponent(cid));
    if (!r.ok) {
      const t = await r.text();
      setStatus(downloadStatus, 'Invalid CID: ' + t, 'err');
      return;
    }
    m = await r.json();
  } catch (e) {
    setStatus(downloadStatus, 'Failed to read manifest.', 'err');
    return;
  }

  const filename = (m && m.filename) ? m.filename : ('download_' + cid.slice(0,8));
  const total = (m && typeof m.total_size === "number") ? m.total_size : null;

  // Step 2: streamed fetch download from UI proxy endpoint (so same-origin)
  setStatus(downloadStatus, 'Downloading...', 'warn');

  try {
    const resp = await fetch('/download?cid=' + encodeURIComponent(cid));
    if (!resp.ok) {
      const t = await resp.text();
      setStatus(downloadStatus, 'Download failed: ' + t, 'err');
      return;
    }

    const reader = resp.body.getReader();
    const chunks = [];
    let received = 0;

    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.byteLength;
      if (total) setBar(dlBar, (received / total) * 100);
      else setBar(dlBar, 50);
    }

    setBar(dlBar, 100);

    const blob = new Blob(chunks, {type: "application/octet-stream"});
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    setStatus(downloadStatus, `Download completed (${humanBytes(received)}).`, 'ok');
  } catch (e) {
    setStatus(downloadStatus, 'Download error.', 'err');
  }
}

uploadBtn.addEventListener('click', uploadFile);
inspectBtn.addEventListener('click', inspectCID);
downloadBtn.addEventListener('click', downloadFile);

fetchRecent();
</script>
</body>
</html>
"""


class UIHandler(BaseHTTPRequestHandler):
    server_version = "ContentEngineUI/2.0"

    def do_GET(self):
        parsed = urlparse(self.path)

        # Serve UI
        if parsed.path == "/":
            page = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return

        # API: list recent manifests
        if parsed.path == "/api/list":
            qs = parse_qs(parsed.query)
            limit = qs.get("limit", ["12"])[0]
            try:
                limit_i = int(limit)
            except Exception:
                limit_i = 12
            items = list_manifests(limit_i)
            body = json.dumps({"items": items}, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # API: get manifest by CID (strict validation)
        if parsed.path == "/api/manifest":
            qs = parse_qs(parsed.query)
            cid = qs.get("cid", [None])[0]
            if not cid:
                self.send_error(400, "missing cid")
                return
            cid = cid.strip()
            m = load_manifest(cid)
            if m is None:
                self.send_error(404, "manifest not found")
                return
            body = json.dumps(m, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Proxy download (strict CID validation based on local manifests)
        if parsed.path == "/download":
            qs = parse_qs(parsed.query)
            cid = qs.get("cid", [None])[0]
            if not cid:
                self.send_error(400, "Missing cid parameter")
                return

            cid = cid.strip()

            # Validate CID locally
            m = load_manifest(cid)
            if m is None:
                self.send_error(404, "Invalid CID (manifest not found)")
                return

            # Stream from backend to client
            try:
                conn = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=30)
                conn.request("GET", f"/download?cid={cid}")
                resp = conn.getresponse()
            except Exception as e:
                self.send_error(502, f"Backend error: {e}")
                return

            try:
                if resp.status != 200:
                    body = resp.read()
                    self.send_response(resp.status)
                    self.send_header("Content-Type", resp.getheader("Content-Type", "text/plain; charset=utf-8"))
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                self.send_response(200)
                self.send_header("Content-Type", resp.getheader("Content-Type", "application/octet-stream"))

                # (Browser uses JS download name, but keep header too)
                filename = m.get("filename") or f"download_{cid[:8]}"
                safe_name = str(filename).replace('"', "_")
                self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')

                # If total_size exists, set Content-Length
                ts = m.get("total_size")
                if isinstance(ts, int) and ts >= 0:
                    self.send_header("Content-Length", str(ts))

                self.end_headers()

                while True:
                    chunk = resp.read(STREAM_CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            finally:
                conn.close()
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)

        # Stream upload proxy -> backend /upload
        if parsed.path == "/upload":
            length = self.headers.get("Content-Length")
            fname = self.headers.get("X-Filename")
            if not length or not fname:
                self.send_error(400, "Missing Content-Length or X-Filename")
                return

            try:
                total = int(length)
            except ValueError:
                self.send_error(400, "Invalid Content-Length")
                return

            # Stream request body to backend (no full buffering)
            try:
                conn = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=60)
                conn.putrequest("POST", "/upload")
                conn.putheader("Content-Length", str(total))
                conn.putheader("Content-Type", "application/octet-stream")
                conn.putheader("X-Filename", fname)
                conn.endheaders()

                remaining = total
                while remaining > 0:
                    n = STREAM_CHUNK if remaining > STREAM_CHUNK else remaining
                    data = self.rfile.read(n)
                    if not data:
                        break
                    conn.send(data)
                    remaining -= len(data)

                resp = conn.getresponse()
                data = resp.read()

            except Exception as e:
                self.send_error(502, f"Backend error: {e}")
                return
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

            self.send_response(resp.status)
            self.send_header("Content-Type", resp.getheader("Content-Type", "application/json; charset=utf-8"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self.send_error(404, "Not Found")

    def log_message(self, fmt, *args):
        # quiet but useful
        print("%s - - [%s] %s" %
              (self.client_address[0],
               self.log_date_time_string(),
               fmt % args))


def run_ui():
    os.makedirs(MANIFEST_DIR, exist_ok=True)
    srv = ThreadingHTTPServer((UI_HOST, UI_PORT), UIHandler)
    print(f"UI server listening on http://{UI_HOST}:{UI_PORT}")
    print(f"Backend expected at http://{BACKEND_HOST}:{BACKEND_PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    run_ui()
