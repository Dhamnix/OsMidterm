# ui.py
# Simple Web UI (English only) for interacting with main.py (HTTP gateway)
# main.py must be running on http://127.0.0.1:9000
# c_engine must be running and connected to main.py via /tmp/cengine.sock

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import http.client
import json
import os

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 9000  # main.py HTTP gateway
UI_HOST = "127.0.0.1"
UI_PORT = 8000       # UI server port (separate from main.py)


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Content Engine Web UI</title>
  <style>
    * { box-sizing: border-box; font-family: sans-serif; }
    body {
      margin: 0;
      padding: 0;
      background: #0f172a;
      color: #e5e7eb;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      padding: 24px 16px 40px;
    }
    h1 {
      font-size: 1.8rem;
      margin-bottom: 8px;
      text-align: center;
    }
    .subtitle {
      text-align: center;
      font-size: 0.9rem;
      color: #9ca3af;
      margin-bottom: 24px;
    }
    .grid {
      display: grid;
      gap: 16px;
    }
    @media (min-width: 800px) {
      .grid {
        grid-template-columns: 1fr 1fr;
      }
    }
    .card {
      background: #111827;
      border-radius: 12px;
      padding: 16px 16px 20px;
      border: 1px solid #1f2937;
    }
    .card h2 {
      margin: 0 0 8px;
      font-size: 1.1rem;
    }
    .card p {
      margin: 0 0 12px;
      font-size: 0.85rem;
      color: #9ca3af;
    }
    label {
      display: block;
      font-size: 0.8rem;
      margin-bottom: 4px;
    }
    input[type="file"],
    input[type="text"] {
      width: 100%;
      padding: 6px 8px;
      font-size: 0.85rem;
      background: #020617;
      color: #e5e7eb;
      border-radius: 8px;
      border: 1px solid #374151;
      margin-bottom: 10px;
    }
    button {
      border: none;
      border-radius: 9999px;
      padding: 8px 16px;
      font-size: 0.85rem;
      cursor: pointer;
      background: #22c55e;
      color: white;
      font-weight: 600;
    }
    .btn-secondary {
      background: #3b82f6;
    }
    .status {
      margin-top: 10px;
      font-size: 0.8rem;
      min-height: 1.2em;
    }
    .status.ok { color: #4ade80; }
    .status.err { color: #f97373; }
    .cid-output {
      margin-top: 8px;
      font-size: 0.8rem;
      word-break: break-all;
    }
    .cid-output code {
      background: #020617;
      padding: 4px 6px;
      border-radius: 6px;
      border: 1px solid #1f2937;
      font-size: 0.75rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Content Engine Web UI</h1>
    <div class="subtitle">
      Upload files and download them again using a CID.
    </div>

    <div class="grid">
      <div class="card">
        <h2>Upload file → Get CID</h2>
        <label for="fileInput">Choose file</label>
        <input id="fileInput" type="file">
        <button id="uploadBtn">Upload</button>
        <div id="uploadStatus" class="status"></div>
        <div id="cidBox" class="cid-output"></div>
      </div>

      <div class="card">
        <h2>Download by CID</h2>
        <label for="cidInput">CID</label>
        <input id="cidInput" type="text" placeholder="example: b...">
        <button id="downloadBtn" class="btn-secondary">Download</button>
        <div id="downloadStatus" class="status"></div>
      </div>
    </div>
  </div>

<script>
const uploadBtn = document.getElementById('uploadBtn');
const fileInput = document.getElementById('fileInput');
const uploadStatus = document.getElementById('uploadStatus');
const cidBox = document.getElementById('cidBox');

const downloadBtn = document.getElementById('downloadBtn');
const cidInput = document.getElementById('cidInput');
const downloadStatus = document.getElementById('downloadStatus');

async function uploadFile() {
  uploadStatus.textContent = '';
  cidBox.textContent = '';
  uploadStatus.className = 'status';

  const file = fileInput.files[0];
  if (!file) {
    uploadStatus.textContent = 'No file selected.';
    uploadStatus.className = 'status err';
    return;
  }

  uploadStatus.textContent = 'Uploading...';

  try {
    const resp = await fetch('/upload', {
      method: 'POST',
      headers: {
        'X-Filename': encodeURIComponent(file.name)
      },
      body: file
    });

    if (!resp.ok) {
      uploadStatus.textContent = 'Upload failed.';
      uploadStatus.className = 'status err';
      return;
    }

    const data = await resp.json();
    uploadStatus.textContent = 'Upload successful.';
    uploadStatus.className = 'status ok';
    cidBox.innerHTML = 'CID: <code>' + data.cid + '</code>';
    cidInput.value = data.cid;
  } catch (e) {
    uploadStatus.textContent = 'Network error.';
    uploadStatus.className = 'status err';
  }
}

function downloadFile() {
  downloadStatus.textContent = '';
  downloadStatus.className = 'status';

  const cid = cidInput.value.trim();
  if (!cid) {
    downloadStatus.textContent = 'Please enter a CID.';
    downloadStatus.className = 'status err';
    return;
  }

  window.location.href = '/download?cid=' + encodeURIComponent(cid);
  downloadStatus.textContent = 'Download started.';
  downloadStatus.className = 'status ok';
}

uploadBtn.addEventListener('click', uploadFile);
downloadBtn.addEventListener('click', downloadFile);
</script>
</body>
</html>
"""


def load_manifest(cid: str):
    path = os.path.join("manifests", cid + ".json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


class UIHandler(BaseHTTPRequestHandler):
    server_version = "ContentEngineUI/1.0"

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

        # DOWNLOAD (with strict CID validation)
        if parsed.path == "/download":
            qs = parse_qs(parsed.query)
            cid = qs.get("cid", [None])[0]
            if not cid:
                self.send_error(400, "Missing cid parameter")
                return

            cid = cid.strip()
            print(f"[UI] Download requested for CID={cid}")

            # 🔴 THIS IS THE KEY FIX
            manifest = load_manifest(cid)
            if manifest is None:
                self.send_error(404, "Invalid CID (manifest not found)")
                return

            filename = manifest.get("filename") or f"download_{cid[:8]}"
            total_size = manifest.get("total_size")

            try:
                conn = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=20)
                conn.request("GET", f"/download?cid={cid}")
                resp = conn.getresponse()
            except Exception as e:
                self.send_error(502, f"Backend error: {e}")
                return

            try:
                if resp.status != 200:
                    body = resp.read()
                    self.send_response(resp.status)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                safe_name = filename.replace('"', "_")
                self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')

                if isinstance(total_size, int):
                    self.send_header("Content-Length", str(total_size))

                self.end_headers()

                while True:
                    chunk = resp.read(256 * 1024)
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

        if parsed.path == "/upload":
            length = self.headers.get("Content-Length")
            fname = self.headers.get("X-Filename")
            if not length or not fname:
                self.send_error(400, "Missing headers")
                return

            body = self.rfile.read(int(length))

            try:
                conn = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=20)
                conn.request("POST", "/upload", body=body, headers={
                    "Content-Length": str(len(body)),
                    "Content-Type": "application/octet-stream",
                    "X-Filename": fname,
                })
                resp = conn.getresponse()
                data = resp.read()
            except Exception as e:
                self.send_error(502, f"Backend error: {e}")
                return
            finally:
                conn.close()

            self.send_response(resp.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self.send_error(404, "Not Found")

    def log_message(self, fmt, *args):
        print(fmt % args)


def run_ui():
    srv = ThreadingHTTPServer((UI_HOST, UI_PORT), UIHandler)
    print(f"UI server listening on http://{UI_HOST}:{UI_PORT}")
    print(f"Backend expected at http://{BACKEND_HOST}:{BACKEND_PORT}")
    srv.serve_forever()


if __name__ == "__main__":
    run_ui()
