# ui.py
# Simple Web UI (English only) for interacting with main.py (HTTP gateway)
# main.py must be running on http://127.0.0.1:9000
# c_engine must be running and connected to main.py via /tmp/cengine.sock

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import http.client

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
      box-shadow: 0 10px 25px rgba(0,0,0,0.4);
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
    input[type="text"]::placeholder {
      color: #6b7280;
    }
    button {
      appearance: none;
      border: none;
      border-radius: 9999px;
      padding: 8px 16px;
      font-size: 0.85rem;
      cursor: pointer;
      background: #22c55e;
      color: white;
      font-weight: 600;
      box-shadow: 0 8px 20px rgba(34,197,94,0.4);
      transition: transform 0.1s ease, box-shadow 0.1s ease, filter 0.15s ease;
    }
    button:hover {
      filter: brightness(1.05);
      transform: translateY(-1px);
      box-shadow: 0 10px 25px rgba(34,197,94,0.55);
    }
    button:active {
      transform: translateY(0);
      box-shadow: 0 4px 12px rgba(34,197,94,0.35);
    }
    .btn-secondary {
      background: #3b82f6;
      box-shadow: 0 8px 20px rgba(59,130,246,0.4);
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
    .footer {
      margin-top: 24px;
      text-align: center;
      font-size: 0.75rem;
      color: #6b7280;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 999px;
      background: #020617;
      border: 1px solid #1f2937;
      font-size: 0.7rem;
      color: #9ca3af;
      margin-bottom: 10px;
    }
    .pill span {
      direction: ltr;
      font-family: monospace;
      font-size: 0.7rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Content Engine Web UI</h1>
    <div class="subtitle">
      Simple local interface for uploading and downloading files via the HTTP gateway.
    </div>

    <div class="grid">
      <!-- Upload Card -->
      <div class="card">
        <h2>Upload file → Get CID</h2>
        <p>Select a file. It will be sent (as raw bytes) to the HTTP gateway, then stored by the engine. The gateway returns a CID.</p>
        <div class="pill">
          Backend:
          <span>http://127.0.0.1:9000</span>
        </div>
        <label for="fileInput">Choose file</label>
        <input id="fileInput" type="file">

        <button id="uploadBtn">Upload</button>

        <div id="uploadStatus" class="status"></div>
        <div id="cidBox" class="cid-output"></div>
      </div>

      <!-- Download Card -->
      <div class="card">
        <h2>Download by CID</h2>
        <p>Enter a valid CID. The UI will redirect to the backend and trigger a direct download.</p>
        <label for="cidInput">CID</label>
        <input id="cidInput" type="text" placeholder="example: boe...">

        <button id="downloadBtn" class="btn-secondary">Download</button>

        <div id="downloadStatus" class="status"></div>
      </div>
    </div>

    <div class="footer">
      Steps: run c_engine → run main.py (gateway) → run ui.py → open http://127.0.0.1:8000/
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
          const text = await resp.text();
          uploadStatus.textContent = 'Upload error: ' + text;
          uploadStatus.className = 'status err';
          return;
        }

        const data = await resp.json();
        const cid = data.cid;
        uploadStatus.textContent = 'Upload successful.';
        uploadStatus.className = 'status ok';

        cidBox.innerHTML = 'CID: <code>' + cid + '</code>';
        cidInput.value = cid;
      } catch (e) {
        uploadStatus.textContent = 'Network or server error: ' + e;
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

      const url = '/download?cid=' + encodeURIComponent(cid);
      window.location.href = url;

      downloadStatus.textContent = 'Download started via backend.';
      downloadStatus.className = 'status ok';
    }

    uploadBtn.addEventListener('click', uploadFile);
    downloadBtn.addEventListener('click', downloadFile);
  </script>
</body>
</html>
"""


class UIHandler(BaseHTTPRequestHandler):
    server_version = "ContentEngineUI/0.1"

    def do_GET(self):
        parsed = urlparse(self.path)

        # Serve UI
        if parsed.path == "/":
            page_bytes = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page_bytes)))
            self.end_headers()
            self.wfile.write(page_bytes)
            return

        # Redirect download → backend /download
        if parsed.path == "/download":
            qs = parse_qs(parsed.query)
            cid = qs.get("cid", [None])[0]
            if not cid:
                self.send_error(400, "Missing cid parameter")
                return

            backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}/download?cid={cid}"

            self.send_response(302)
            self.send_header("Location", backend_url)
            self.end_headers()
            return

        # Anything else
        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)

        # Proxy upload → backend /upload
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

            body = self.rfile.read(total)
            if len(body) != total:
                self.send_error(400, "Body shorter than Content-Length")
                return

            headers = {
                "Content-Length": str(len(body)),
                "Content-Type": "application/octet-stream",
                "X-Filename": fname,
            }

            try:
                conn = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=20)
                conn.request("POST", "/upload", body=body, headers=headers)
                resp = conn.getresponse()
            except Exception as e:
                self.send_error(502, f"Error contacting backend: {e}")
                return

            try:
                backend_body = resp.read()
                self.send_response(resp.status)
                content_type = resp.getheader("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(backend_body)))
                self.end_headers()
                self.wfile.write(backend_body)
            finally:
                conn.close()
            return

        self.send_error(404, "Not Found")

    def log_message(self, fmt, *args):
        print("%s - - [%s] %s" %
              (self.client_address[0],
               self.log_date_time_string(),
               fmt % args))


def run_ui(host=UI_HOST, port=UI_PORT):
    srv = ThreadingHTTPServer((host, port), UIHandler)
    print(f"UI server listening on http://{host}:{port}")
    print(f"Backend expected at http://{BACKEND_HOST}:{BACKEND_PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    run_ui()
