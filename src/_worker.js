// ============================================================================
// HELPERS
// ============================================================================
const jsonError = (msg, status = 400) => Response.json({ error: msg }, { status });

async function safeParseBody(request) {
  try {
    const clone = request.clone(); 
    return await clone.json();
  } catch (e) {
    return null;
  }
}

// ============================================================================
// MAIN WORKER LOGIC
// ============================================================================
export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      // --- PUBLIC ROUTE: SHARED DOWNLOADS ---
      if (url.pathname.startsWith('/s/')) {
        const code = url.searchParams.get("code") || "";
        let filename = url.pathname.split('/')[2];
        if (!filename) return new Response("Missing file ID", { status: 400 });

        const tokenObj = await env.DRIVE_BUCKET.get(`.tokens/${filename}`);
        if (!tokenObj) return new Response("Invalid or Expired Link", { status: 404 });

        const meta = await tokenObj.json();

        if (meta.expires && Date.now() > meta.expires) {
            await env.DRIVE_BUCKET.delete(`.tokens/${filename}`);
            return new Response("Link Expired", { status: 410 });
        }
        
        if(code !== meta.code){
            return new Response("Invalid Share Code", { status: 403 });
        }

        const object = await env.DRIVE_BUCKET.get(meta.filename);
        if (!object) return new Response("File not found", { status: 404 });

        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set('Content-Disposition', `attachment; filename="${meta.filename}"`);
        return new Response(object.body, { headers });
      }

      // --- AUTHENTICATION ---
      const authKey = env.AUTH_KEY || env.APIKEYSECRET;
      const isAuthorized = () => {
        if (!authKey) return true;
        const queryKey = url.searchParams.get('key');
        const headerKey = request.headers.get('x-api-key');
        return (queryKey === authKey || headerKey === authKey);
      };

      if (url.pathname === '/' && request.method === 'GET') {
        return new Response(renderAdminPanel(url.searchParams.get('key') || ''), {
          status: 200, headers: { 'Content-Type': 'text/html' }
        });
      }

      if (!isAuthorized()) return jsonError('Unauthorized', 401);
      const authParam = authKey ? `?key=${authKey}` : '';

      // --- API ROUTES ---

      // SHARE GENERATE
      if (url.pathname === '/share/generate' && request.method === 'POST') {
        const body = await safeParseBody(request);
        if(!body) return jsonError("Invalid JSON");
        
        const { filename, hours, customCode } = body;
        if (!filename || (!hours && hours !== 0)) return jsonError("Missing params");

        let code = (customCode && customCode.trim() !== "") 
            ? customCode.trim().replace(/[^a-zA-Z0-9-_]/g, '') 
            : crypto.randomUUID().replace(/-/g, '').substring(0, 6);

        let expires = (parseInt(hours) !== 999) ? Date.now() + (hours * 60 * 60 * 1000) : null;
        let encode_filename = btoa(filename).replace(/=/g, '');
        
        await env.DRIVE_BUCKET.put(`.tokens/${encode_filename}`, JSON.stringify({ filename, expires, code }));

        return Response.json({ 
            code, 
            url: `/s/${encode_filename}?code=${code}`,
            expiresAt: expires ? new Date(expires).toLocaleString() : "Never"
        });
      }

      // INIT JOB
      if (url.pathname === '/init-job' && request.method === 'POST') {
        const body = await safeParseBody(request);
        if (!body) return jsonError("Invalid JSON");
        const { sourceUrl, filename, force } = body;
        
        if (!force) {
          const existing = await env.DRIVE_BUCKET.head(filename);
          if (existing) return Response.json({ status: 'exists', downloadUrl: `/get/${filename}${authParam}` });
        }

        const jobId = crypto.randomUUID();
        const id = env.DOWNLOAD_MANAGER.idFromName(jobId);
        return env.DOWNLOAD_MANAGER.get(id).fetch(new Request('https://fake-host/init', {
          method: 'POST', body: JSON.stringify({ sourceUrl, filename, jobId }) 
        }));
      }

      // PROCESS CHUNK
      if (url.pathname === '/process-chunk' && request.method === 'POST') {
        const body = await safeParseBody(request);
        if(!body) return jsonError("Invalid JSON");
        const { jobId, partNumber, start, end } = body;
        if(!jobId) return jsonError("Missing jobId");
        const id = env.DOWNLOAD_MANAGER.idFromName(jobId);
        return env.DOWNLOAD_MANAGER.get(id).fetch(new Request('https://fake-host/chunk', {
          method: 'POST', body: JSON.stringify({ partNumber, start, end })
        }));
      }

      // CHECK STATUS
      if (url.pathname === '/check-status' && request.method === 'POST') {
        const body = await safeParseBody(request);
        if(!body) return jsonError("Invalid JSON");
        const { jobId } = body;
        if(!jobId) return jsonError("Missing jobId");
        const id = env.DOWNLOAD_MANAGER.idFromName(jobId);
        return env.DOWNLOAD_MANAGER.get(id).fetch(new Request('https://fake-host/status'));
      }

      // FINISH JOB
      if (url.pathname === '/finish-job' && request.method === 'POST') {
        const body = await safeParseBody(request);
        if(!body) return jsonError("Invalid JSON");
        const { jobId } = body;
        if(!jobId) return jsonError("Missing jobId");
        const id = env.DOWNLOAD_MANAGER.idFromName(jobId);
        return env.DOWNLOAD_MANAGER.get(id).fetch(new Request('https://fake-host/finish', { 
            method: 'POST', body: JSON.stringify({}) 
        }));
      }

      // LIST FILES
      if (url.pathname === '/list') {
        const listed = await env.DRIVE_BUCKET.list({ limit: 500, include: ["customMetadata"] });
        const files = listed.objects
            .filter(obj => !obj.key.startsWith('.tokens/'))
            .map(obj => ({
                key: obj.key,
                size: obj.size,
                uploaded: obj.uploaded,
                source: obj.customMetadata?.source || 'upload'
            }));
        return Response.json({ files });
      }

      // DELETE FILE
      if (url.pathname === '/delete' && request.method === 'DELETE') {
        const filename = url.searchParams.get('filename');
        await env.DRIVE_BUCKET.delete(filename);
        return Response.json({ status: 'deleted' });
      }

      // RENAME FILE
      if (url.pathname === '/rename' && request.method === 'POST') {
        const body = await safeParseBody(request);
        if(!body) return jsonError("Invalid JSON");
        const { oldName, newName } = body;
        
        if(!oldName || !newName) return jsonError("Missing params");
        const source = await env.DRIVE_BUCKET.get(oldName);
        if (!source) return jsonError("File not found", 404);
        const exists = await env.DRIVE_BUCKET.head(newName);
        if (exists) return jsonError("Name taken", 409);

        await env.DRIVE_BUCKET.put(newName, source.body, {
            httpMetadata: source.httpMetadata,
            customMetadata: source.customMetadata
        });
        await env.DRIVE_BUCKET.delete(oldName);
        return Response.json({ status: 'renamed', oldName, newName });
      }

      // DIRECT DOWNLOAD
      if (url.pathname.startsWith('/get/')) {
        const filename = decodeURIComponent(url.pathname.replace('/get/', ''));
        const object = await env.DRIVE_BUCKET.get(filename);
        if (!object) return new Response('Not found', { status: 404 });
        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set('Content-Disposition', `attachment; filename="${filename}"`);
        return new Response(object.body, { headers });
      }

      // DIRECT UPLOAD
      if (url.pathname === '/upload' && request.method === 'PUT') {
        const filename = url.searchParams.get('filename');
        if(!filename) return jsonError("Missing filename", 400);
        try {
          await env.DRIVE_BUCKET.put(filename, request.body, {
            httpMetadata: { contentType: request.headers.get('Content-Type') || 'application/octet-stream' },
            customMetadata: { source: 'UPLOAD', timestamp: Date.now().toString() }
          });
          return Response.json({ status: 'success', filename });
        } catch (e) {
          return Response.json({ status: 'error', error: e.message }, { status: 500 });
        }
      }

      return jsonError("API Endpoint Not Found: " + url.pathname, 404);
    } catch (e) {
      return jsonError("Internal Worker Error: " + e.message, 500);
    }
  }
};

// ============================================================================
// DURABLE OBJECT: Download Manager
// ============================================================================
export class DownloadManager {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.fallbackStatus = { status: 'idle' };
  }

  async fetch(request) {
    const startTime = performance.now(); // Track CPU time
    const url = new URL(request.url);
    
    let body = {};
    if (request.method === 'POST') {
        try { body = await request.json(); } catch(e) {}
    }

    // --- INIT ---
    if (url.pathname === '/init') {
      const { sourceUrl, filename, jobId } = body;
      
      let headRes;
      try {
        headRes = await fetch(sourceUrl, { method: 'HEAD' });
      } catch(e) {
        return Response.json({ error: "Connection failed: " + e.message }, { status: 400 });
      }
      
      const totalSize = parseInt(headRes.headers.get('content-length')) || 0;
      const contentType = headRes.headers.get('content-type');
      const CHUNK_SIZE = 20 * 1024 * 1024; 

      let supportsParallel = false;
      if (headRes.headers.get('Accept-Ranges') === 'bytes') {
        supportsParallel = true;
      } else {
        try {
            const testRes = await fetch(sourceUrl, { headers: { 'Range': 'bytes=0-0' } });
            if (testRes.status === 206) supportsParallel = true;
        } catch(e) {}
      }

      if (!supportsParallel || totalSize === 0 || totalSize < CHUNK_SIZE) {
        this.state.waitUntil(this.singleStreamDownload(sourceUrl, filename, contentType));
        return Response.json({ mode: 'single', totalSize, jobId, message: "Background Stream (Single)" });
      }

      const mp = await this.env.DRIVE_BUCKET.createMultipartUpload(filename, {
        httpMetadata: { contentType },
        customMetadata: { source: sourceUrl, timestamp: Date.now().toString() }
      });

      const ranges = [];
      let start = 0;
      let partNumber = 1;

      while (start < totalSize) {
        let end = start + CHUNK_SIZE - 1;
        if (end >= totalSize) end = totalSize - 1;
        ranges.push({ partNumber, start, end });
        start += CHUNK_SIZE;
        partNumber++;
      }

      await this.state.storage.put('job_meta', { uploadId: mp.uploadId, filename, sourceUrl });
      await this.state.storage.delete(ranges.map(r => `part_${r.partNumber}`));

      return Response.json({ mode: 'parallel', totalSize, ranges, jobId });
    }

    // --- PROCESS CHUNK ---
    if (url.pathname === '/chunk') {
      const { partNumber, start, end } = body;
      const meta = await this.state.storage.get('job_meta');
      if (!meta) return Response.json({ error: 'Job not found' }, { status: 404 });

      const mp = this.env.DRIVE_BUCKET.resumeMultipartUpload(meta.filename, meta.uploadId);

      try {
        const res = await fetch(meta.sourceUrl, { headers: { 'Range': `bytes=${start}-${end}` } });
        if (res.status !== 206 && res.status !== 200) throw new Error("Range failed");

        const part = await mp.uploadPart(partNumber, res.body);
        await this.state.storage.put(`part_${partNumber}`, { partNumber, etag: part.etag });

        // Calculate Server CPU Time used for this chunk
        const cpuTime = performance.now() - startTime;
        return Response.json({ status: 'done', partNumber, cpuTime });
      } catch(err) {
        return Response.json({ error: err.message }, { status: 500 });
      }
    }

    // --- FINISH ---
    if (url.pathname === '/finish') {
      const meta = await this.state.storage.get('job_meta');
      if (!meta) return Response.json({ error: 'Job not found' }, { status: 404 });

      const list = await this.state.storage.list({ prefix: 'part_' });
      const parts = Array.from(list.values());

      if (parts.length === 0) return Response.json({ error: "No parts found." }, { status: 400 });

      const mp = this.env.DRIVE_BUCKET.resumeMultipartUpload(meta.filename, meta.uploadId);
      parts.sort((a, b) => a.partNumber - b.partNumber);

      try {
        await mp.complete(parts);
        await this.state.storage.deleteAll();
        return Response.json({ status: 'completed', downloadUrl: `/get/${meta.filename}` });
      } catch(e) {
        return Response.json({ error: "R2 Complete Failed: " + e.message }, { status: 500 });
      }
    }

    if (url.pathname === '/status') return Response.json(this.fallbackStatus);

    return Response.json({ error: 'DO Method Not Found' }, { status: 404 });
  }

  async singleStreamDownload(sourceUrl, filename, contentType) {
      this.fallbackStatus = { status: 'running' };
      try {
          const res = await fetch(sourceUrl);
          await this.env.DRIVE_BUCKET.put(filename, res.body, {
              httpMetadata: { contentType },
              customMetadata: { source: sourceUrl, timestamp: Date.now().toString() }
          });
          this.fallbackStatus = { status: 'completed' };
      } catch(e) {
          this.fallbackStatus = { status: 'failed', error: e.message };
      }
  }
}

// ============================================================
// FRONTEND UI
// ============================================================
function renderAdminPanel(currentKey) {
  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>R2 Manager</title>
    <style>
      :root { font-family: system-ui, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f4f4f9; }
      body { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
      h1 { color: #f6821f; margin-bottom: 20px; }
      .tabs { display: flex; border-bottom: 2px solid #ddd; margin-bottom: 20px; }
      .tab { padding: 10px 20px; cursor: pointer; font-weight: bold; color: #666; border-bottom: 2px solid transparent; margin-bottom: -2px;}
      .tab.active { color: #f6821f; border-bottom-color: #f6821f; }
      .tab-content { display: none; }
      .tab-content.active { display: block; }
      .card { background: #fafafa; border: 1px solid #eee; padding: 15px; margin-top: 15px; border-radius: 4px; }
      input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box;}
      input[type="file"] { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #ddd; background: white; border-radius: 4px; }
      button { background: #9ae6bc; color: white; border: none; padding: 10px; margin-top: 20px; border-radius: 4px; cursor: pointer; width:100% }
      button:hover { opacity: 0.9; }
      button:disabled { background: #ccc; cursor: not-allowed; }
      table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; table-layout: fixed; }
      th, td { padding: 10px; border-bottom: 1px solid #eee; text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      th:nth-child(1) { width: 40%; } th:nth-child(2) { width: 20%; } th:nth-child(3) { width: 10%; } th:nth-child(4) { width: 30%; }
      .action-btn { cursor: pointer; margin-right: 12px; text-decoration: none; font-size: 16px; border:none; background:none; padding:0; }
      dialog { border: none; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); padding: 25px; width: 400px; max-width: 90vw; }
      dialog::backdrop { background: rgba(0,0,0,0.5); }
      select { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #ddd; border-radius: 4px; background: white; }
      
      /* NEW STATS STYLES */
      .stats-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-top: 15px; display:none; }
      .stat-box { background: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 4px; text-align: center; }
      .stat-val { font-weight: bold; font-size: 16px; color: #333; }
      .stat-lbl { font-size: 11px; color: #666; text-transform: uppercase; }
      .info-row { font-size: 12px; color: #666; margin-top: 5px; text-align: right; }
    </style>
  </head>
  <body>
    <div style="display:flex; justify-content:space-between; align-items:center">
      <h1>☁️ R2 Manager</h1>
      <div style="margin-bottom: 10px; width: 40%">
        <input type="password" id="apiKey" value="${currentKey}" placeholder="Auth Key">
      </div>
    </div>

    <div class="tabs">
      <div class="tab active" onclick="switchTab('downloader')">Remote Downloader</div>
      <div class="tab" onclick="switchTab('upload')">Direct Upload</div>
      <div class="tab" onclick="switchTab('library')">Library</div>
    </div>

    <!-- REMOTE DOWNLOADER -->
    <div id="downloader" class="tab-content active">
      <div class="card">
        <h3>New Download Job</h3>
        <input type="text" id="sourceUrl" placeholder="Source URL (https://...)" required>
        <input type="text" id="filename" placeholder="Save Filename (video.mp4)" required>
        <button id="startBtn" onclick="startDownload()">Start Download</button>

        <div id="progCont" style="margin-top:20px; background:#eee; height:20px; border-radius:10px; overflow:hidden; display:none">
          <div id="progBar" style="height:100%; background:#4caf50; width:0%; transition:width 0.3s"></div>
        </div>
        <div id="jobInfo" class="info-row"></div>

        <!-- NEW STATS GRID -->
        <div id="statsGrid" class="stats-grid">
           <div class="stat-box">
              <div class="stat-val" id="st-speed">0 MB/s</div>
              <div class="stat-lbl">Speed</div>
           </div>
           <div class="stat-box">
              <div class="stat-val" id="st-cpu">0ms</div>
              <div class="stat-lbl">Server CPU</div>
           </div>
           <div class="stat-box">
              <div class="stat-val" id="st-chunks">0 / 0</div>
              <div class="stat-lbl">Chunks</div>
           </div>
        </div>
        
        <div id="logs" style="margin-top:20px; font-size:11px; color:#666; max-height:150px; overflow-y:auto; background:#fafafa; padding:10px; border:1px solid #eee; font-family:monospace;"></div>
      </div>
    </div>

    <!-- DIRECT UPLOAD -->
    <div id="upload" class="tab-content">
      <div class="card">
        <h3>Upload File</h3>
        <input type="file" id="fileInput">
        <input type="text" id="uploadName" placeholder="Rename (Optional, defaults to file name)">
        <button id="uploadBtn" onclick="uploadFile()">Upload File</button>
        <div id="uploadStatus" style="margin-top:15px; font-weight:bold; color:#555"></div>
      </div>
    </div>

    <!-- LIBRARY -->
    <div id="library" class="tab-content">
      <div style="display:flex; justify-content:space-between; align-items:center">
        <h3>Files in Bucket</h3>
        <button onclick="loadLibrary()" style="width: auto; padding: 5px 15px;">Refresh</button>
      </div>
      <table id="fileTable">
        <thead><tr><th>Filename</th><th>Size</th><th>Source</th><th>Actions</th></tr></thead>
        <tbody><tr><td colspan="4">Loading...</td></tr></tbody>
      </table>
    </div>

    <!-- DIALOGS (Rename & Share) -->
    <dialog id="renameDialog">
      <h3>Rename File</h3>
      <input type="hidden" id="renameOld">
      <label>New Name:</label>
      <input type="text" id="renameNew">
      <div style="margin-top:20px; display:flex; gap:10px">
        <button onclick="document.getElementById('renameDialog').close()" style="background:#ddd; color:#333">Cancel</button>
        <button onclick="doRename()">Save</button>
      </div>
    </dialog>

    <dialog id="shareDialog">
      <h3>Create Share Link</h3>
      <p style="font-size:13px; color:#666; margin-top:0">Generate a public link that hides your API key.</p>
      <input type="hidden" id="shareFile">
      <label>Custom Code (Optional):</label>
      <input type="text" id="shareCode" placeholder="leave empty for random">
      <label>Expires In:</label>
      <select id="shareDuration">
        <option value="1">1 Hour</option>
        <option value="24" selected>24 Hours</option>
        <option value="168">7 Days</option>
        <option value="720">30 Days</option>
        <option value="999">Never Expires</option>
      </select>
      <div id="shareResult" style="display:none; margin-top:15px; background:#f0f8ff; padding:10px; border-radius:4px;">
        <label style="font-size:11px">Public Link:</label>
        <input type="text" id="shareUrl" readonly style="margin-top:2px; font-size:12px">
        <button onclick="copyShare()" style="margin-top:5px; padding:5px; font-size:12px">Copy Link</button>
      </div>
      <div style="margin-top:20px; display:flex; gap:10px">
        <button onclick="closeShare()" style="background:#ddd; color:#333">Close</button>
        <button onclick="doShare()" id="btnShare">Generate Link</button>
      </div>
    </dialog>

    <script>
      const logDiv = document.getElementById('logs');
      const log = (msg) => { logDiv.innerHTML += '<div>' + msg + '</div>'; logDiv.scrollTop = logDiv.scrollHeight; };
      const safeJson = async (res) => {
          const text = await res.text();
          try { return JSON.parse(text); } 
          catch(e) { throw new Error(res.ok ? "Invalid JSON" : "Error: " + text.substring(0,100)); }
      };
      const authFetch = (url, opts = {}) => {
        const key = document.getElementById('apiKey').value;
        const headers = opts.headers || {};
        if(key) headers['x-api-key'] = key;
        if (!headers['Content-Type'] && opts.method !== 'GET') headers['Content-Type'] = 'application/json';
        return fetch(url, { ...opts, headers });
      };
      function switchTab(id) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        if(id === 'library') loadLibrary();
      }

      // --- DOWNLOADER ---
      async function startDownload() {
        const sourceUrl = document.getElementById('sourceUrl').value;
        const filename = document.getElementById('filename').value;
        const btn = document.getElementById('startBtn');
        const progCont = document.getElementById('progCont');
        const progBar = document.getElementById('progBar');
        const jobInfo = document.getElementById('jobInfo');
        const statsGrid = document.getElementById('statsGrid');

        if(!sourceUrl || !filename) return alert("Fill in fields");

        btn.disabled = true;
        progCont.style.display = 'block';
        statsGrid.style.display = 'none';
        logDiv.innerHTML = 'Starting...';
        jobInfo.innerText = '';
        
        try {
          const initRes = await authFetch('/init-job', {
            method: 'POST', body: JSON.stringify({ sourceUrl, filename })
          });
          const initData = await safeJson(initRes);
          if(initData.error) throw new Error(initData.error);
          
          if(initData.status === 'exists') {
             log("✅ File already exists!");
             btn.disabled = false;
             return;
          }

          const jobId = initData.jobId;

          if (initData.mode === 'single') {
             log("⚠️ " + initData.message);
             const poll = setInterval(async () => {
                 try {
                     const sRes = await authFetch('/check-status', { method: 'POST', body: JSON.stringify({ jobId }) });
                     const sData = await safeJson(sRes);
                     if (sData.status === 'completed') {
                         clearInterval(poll);
                         progBar.style.width = '100%';
                         log("✅ Done!");
                         btn.disabled = false;
                         loadLibrary();
                     }
                 } catch(e) {}
             }, 3000);
             return;
          }

          // Parallel Mode
          const ranges = initData.ranges;
          const totalSizeMB = (initData.totalSize / 1024 / 1024).toFixed(2);
          jobInfo.innerText = \`Total Size: \${totalSizeMB} MB\`;
          statsGrid.style.display = 'grid';

          let completed = 0;
          let idx = 0;
          let totalCpu = 0;
          const startTime = Date.now();
          
          const process = async () => {
             if (idx >= ranges.length) return;
             const range = ranges[idx++];
             let attempts = 0;
             while(attempts++ < 3) {
                try {
                    const r = await authFetch('/process-chunk', {
                        method: 'POST', body: JSON.stringify({ jobId, partNumber: range.partNumber, start: range.start, end: range.end })
                    });
                    const rData = await safeJson(r);
                    if(rData.status === 'done') {
                        completed++;
                        
                        // METRICS UPDATE
                        if(rData.cpuTime) totalCpu += rData.cpuTime;
                        const pct = Math.round((completed/ranges.length)*100);
                        progBar.style.width = pct + '%';
                        
                        const elapsedSec = (Date.now() - startTime) / 1000;
                        const downloadedMB = (completed * 20); // Approx 20MB chunks
                        const speed = (downloadedMB / elapsedSec).toFixed(2);
                        
                        document.getElementById('st-chunks').innerText = \`\${completed} / \${ranges.length}\`;
                        document.getElementById('st-speed').innerText = \`\${speed} MB/s\`;
                        document.getElementById('st-cpu').innerText = \`\${Math.round(totalCpu)}ms\`;
                        
                        break;
                    }
                } catch(e) { await new Promise(r => setTimeout(r, 1000)); }
             }
             await process();
          };

          const workers = [process(), process(), process(), process()];
          await Promise.all(workers);

          log("Finalizing...");
          let finAttempts = 0;
          while(finAttempts++ < 3) {
              try {
                  const fRes = await authFetch('/finish-job', { method: 'POST', body: JSON.stringify({ jobId }) });
                  const fData = await safeJson(fRes);
                  if(!fData.error) {
                      log("✅ Done!");
                      btn.disabled = false;
                      loadLibrary();
                      return;
                  }
              } catch(e) { await new Promise(r => setTimeout(r, 2000)); }
          }
          throw new Error("Finalize failed");

        } catch(e) {
          log("❌ Error: " + e.message);
          btn.disabled = false;
        }
      }

      // --- OTHER FUNCTIONS (Upload, Library, etc) ---
      async function uploadFile() {
          const file = document.getElementById('fileInput').files[0];
          const nameOverride = document.getElementById('uploadName').value;
          const status = document.getElementById('uploadStatus');
          const btn = document.getElementById('uploadBtn');
          if(!file) return alert("Select file");
          btn.disabled = true; status.innerText = "Uploading...";
          try {
              const key = document.getElementById('apiKey').value;
              const headers = { 'Content-Type': file.type };
              if(key) headers['x-api-key'] = key;
              const res = await fetch('/upload?filename=' + encodeURIComponent(nameOverride || file.name), { method: 'PUT', headers, body: file });
              const data = await safeJson(res);
              if(data.error) throw new Error(data.error);
              status.innerText = "✅ Success!";
              setTimeout(() => switchTab('library'), 1500);
          } catch(e) { status.innerText = "❌ Error: " + e.message; }
          btn.disabled = false;
      }

      async function loadLibrary() {
        const tbody = document.querySelector('#fileTable tbody');
        tbody.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';
        try {
          const res = await authFetch('/list');
          const data = await safeJson(res);
          if(!data.files?.length) { tbody.innerHTML = '<tr><td colspan="4">No files</td></tr>'; return; }
          const key = document.getElementById('apiKey').value;
          const authParam = key ? '?key='+encodeURIComponent(key) : '';
          tbody.innerHTML = data.files.map(f => {
            const dlLink = \`/get/\${encodeURIComponent(f.key)}\${authParam}\`;
            const src = f.source && f.source.startsWith('http') ? \`<a href="\${f.source}" target="_blank" class="action-btn" title="Src">🖥️</a>\` : '';
            return \`<tr><td title="\${f.key}">\${f.key}</td><td>\${(f.size/1e6).toFixed(2)} MB</td><td>\${src}</td>
            <td><a href="\${dlLink}" target="_blank" class="action-btn">⬇️</a>
            <span class="action-btn" onclick="openRename('\${f.key}')">✏️</span>
            <span class="action-btn" onclick="openShare('\${f.key}')">🔗</span>
            <span class="action-btn" onclick="deleteFile('\${f.key}')" style="color:red">❌</span></td></tr>\`;
          }).join('');
        } catch(e) { tbody.innerHTML = '<tr><td colspan="4">Error</td></tr>'; }
      }

      // Dialog Helpers
      function openRename(n) { document.getElementById('renameOld').value=n; document.getElementById('renameNew').value=n; document.getElementById('renameDialog').showModal(); }
      async function doRename() {
          const oldName = document.getElementById('renameOld').value;
          const newName = document.getElementById('renameNew').value;
          if(!newName || newName===oldName) return document.getElementById('renameDialog').close();
          try {
              const res = await authFetch('/rename', { method:'POST', body:JSON.stringify({oldName, newName}) });
              if((await safeJson(res)).error) throw new Error('Fail');
              document.getElementById('renameDialog').close(); loadLibrary();
          } catch(e) { alert(e.message); }
      }
      function openShare(n) { document.getElementById('shareFile').value=n; document.getElementById('shareCode').value=''; document.getElementById('shareResult').style.display='none'; document.getElementById('btnShare').style.display='inline-block'; document.getElementById('shareDialog').showModal(); }
      function closeShare() { document.getElementById('shareDialog').close(); }
      async function doShare() {
          const filename = document.getElementById('shareFile').value;
          const hours = document.getElementById('shareDuration').value;
          const customCode = document.getElementById('shareCode').value;
          const btn = document.getElementById('btnShare');
          btn.innerText="Generating..."; btn.disabled=true;
          try {
              const res = await authFetch('/share/generate', { method:'POST', body:JSON.stringify({filename, hours:parseInt(hours), customCode}) });
              const data = await safeJson(res);
              if(data.error) throw new Error(data.error);
              document.getElementById('shareUrl').value = \`\${new URL(document.URL).origin}\${data.url}\`;
              document.getElementById('shareResult').style.display='block'; btn.style.display='none';
          } catch(e) { alert(e.message); }
          btn.innerText="Generate"; btn.disabled=false;
      }
      function copyShare() { const u=document.getElementById('shareUrl'); u.select(); document.execCommand('copy'); navigator.clipboard.writeText(u.value); alert("Copied!"); }
      async function deleteFile(n) { if(confirm('Delete '+n+'?')) { await authFetch('/delete?filename='+encodeURIComponent(n), {method:'DELETE'}); loadLibrary(); } }
    </script>
  </body>
  </html>`;
}