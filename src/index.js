import {
  encryptData,
  decryptData,
  arrayBufferToBase64,
  base64ToUint8Array,
  encryptBinary,
  decryptBinary,
  utf8ToBase64,
  base64ToUtf8,
  sanitizeFilename,
  generateToken,
  jsonOK,
  jsonError,
  handleCORS,
  isOriginAllowed,
  processRequest,
  getCORSHeaders,
  forwardRequest,
  addCORSHeaders,
  bufferToText,
  decryptAndDecode
} from './helpers.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ============================================================
    // 1. AUTHENTICATION
    // ============================================================
    const authKey = env.AUTH_KEY || env.APIKEYSECRET; // Support both names

    const isAuthorized = () => {
      if (!authKey) return true;
      const queryKey = url.searchParams.get('key');
      const headerKey = request.headers.get('x-api-key');
      return (queryKey === authKey || headerKey === authKey);
    };




    // ============================================================
    // 1.1. ADMIN PANEL
    // ============================================================
    if (url.pathname === '/' && request.method === 'GET') {
      return new Response(renderAdminPanel(url.searchParams.get('key') || ''), {
        status: 200,
        headers: { 'Content-Type': 'text/html' }
      });
    }

    if (!isAuthorized()) {
      return jsonError('Unauthorized', 401);
    }


    const authParam = authKey ? `?key=${authKey}` : '';

    // ============================================================
    // 2. API ROUTES
    // ============================================================

    // --- START DOWNLOAD (Remote) ---
    if (url.pathname === '/download' && request.method === 'POST') {
      const { sourceUrl, filename, force } = await request.json();
      if (!sourceUrl || !filename) return new Response('Missing info', { status: 400 });

      // CACHE CHECK: Check if file exists in R2
      if (!force) {
        const existing = await env.DRIVE_BUCKET.head(filename);
        if (existing) {
          return Response.json({
            status: 'exists',
            message: 'File already exists. Use force=true to overwrite.',
            file: {
              key: filename,
              size: existing.size,
              uploaded: existing.uploaded
            },
            downloadUrl: `/get/${filename}${authParam}` // Direct R2 link logic
          });
        }
      }

      // Start DO Job
      const jobId = crypto.randomUUID();
      const id = env.DOWNLOAD_MANAGER.idFromName(jobId);
      const stub = env.DOWNLOAD_MANAGER.get(id);

      await stub.fetch(new Request('https://fake-host/start', {
        method: 'POST',
        body: JSON.stringify({ sourceUrl, filename, jobId })
      }));

      return Response.json({
        jobId,
        status: 'started',
        statusUrl: `/status/${jobId}${authParam}`,
        downloadUrl: `/get-job/${jobId}${authParam}`
      });
    }

    // --- DIRECT UPLOAD ---
    // Usage: PUT /upload?filename=myvideo.mp4 (Body = binary file)
    if (url.pathname === '/upload' && request.method === 'PUT') {
      const filename = url.searchParams.get('filename');
      if (!filename) return new Response('Missing filename param', { status: 400 });

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

    // --- LIST FILES ---
    if (url.pathname === '/list') {
      const limit = 100; // Simple pagination limit
      let cursor = url.searchParams.get('cursor') || undefined;

      const options = {
        limit: 500,
        include: ["customMetadata"],
      };




      const listed = await env.DRIVE_BUCKET.list({
        ...options,
        cursor: cursor,
      });
      let truncated = listed.truncated;
      cursor = truncated ? listed.cursor : undefined;

      while (truncated) {
        const next = await env.DRIVE_BUCKET.list({
          ...options,
          cursor: cursor,
        });
        listed.objects.push(...next.objects);

        truncated = next.truncated;
        cursor = next.cursor;
      }



      const files = listed.objects.map(obj => ({
        key: obj.key,
        size: obj.size,
        uploaded: obj.uploaded,
        source: obj.customMetadata?.source || 'upload',
        timestamp: obj.customMetadata?.timestamp || null // Our custom timestamp
      }));

      return Response.json({
        files,
        truncated: listed.truncated,
        cursor: listed.cursor
      });
    }

    // --- DELETE FILE ---
    if (url.pathname === '/delete' && request.method === 'DELETE') {
      const filename = url.searchParams.get('filename');
      if (!filename) return new Response('Missing filename', { status: 400 });

      await env.DRIVE_BUCKET.delete(filename);
      return Response.json({ status: 'deleted', filename });
    }

    // --- CHECK JOB STATUS ---
    if (url.pathname.startsWith('/status/')) {
      const jobId = url.pathname.split('/')[2];
      const id = env.DOWNLOAD_MANAGER.idFromName(jobId);
      return env.DOWNLOAD_MANAGER.get(id).fetch(new Request('https://fake-host/status'));
    }

    // --- DOWNLOAD FROM JOB ID (Redirect wrapper) ---
    if (url.pathname.startsWith('/get-job/')) {
      const jobId = url.pathname.split('/')[2];
      const id = env.DOWNLOAD_MANAGER.idFromName(jobId);
      return env.DOWNLOAD_MANAGER.get(id).fetch(new Request('https://fake-host/get'));
    }

    // --- DIRECT DOWNLOAD (By Filename) ---
    if (url.pathname.startsWith('/get/')) {
      const filename = decodeURIComponent(url.pathname.replace('/get/', ''));
      const object = await env.DRIVE_BUCKET.get(filename);

      if (object === null) return new Response('Not found', { status: 404 });

      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set('etag', object.httpEtag);
      headers.set('Content-Disposition', `attachment; filename="${filename}"`);

      return new Response(object.body, { headers });
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
    this.progress = { status: 'idle', filename: null, downloaded: 0, total: 0, percent: 0, error: null, timestamp: null };
  }

  async fetch(request) {
    const savedState = await this.state.storage.get('jobState');
    if (savedState) this.progress = savedState;

    const url = new URL(request.url);

    if (url.pathname === '/start' && request.method === 'POST') {
      const { sourceUrl, filename, jobId } = await request.json();

      if (this.progress.status === 'downloading') return Response.json({ status: 'already_running' });

      this.progress = {
        status: 'downloading', filename, jobId,
        downloaded: 0, total: 0, percent: 0, error: null,
        timestamp: Date.now()
      };

      await this.saveState();
      this.state.waitUntil(this.streamDownload(sourceUrl, filename));
      return Response.json({ status: 'started' });
    }

    if (url.pathname === '/status') return Response.json(this.progress);

    if (url.pathname === '/get') {
      if (this.progress.status !== 'completed' || !this.progress.filename) return new Response('Not ready', { status: 404 });

      const object = await this.env.DRIVE_BUCKET.get(this.progress.filename);
      if (!object) return new Response('File lost from R2', { status: 404 });

      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set('Content-Disposition', `attachment; filename="${this.progress.filename}"`);
      return new Response(object.body, { headers });
    }

    return new Response('Not found', { status: 404 });
  }

  async streamDownload(sourceUrl, filename) {
    try {
      const sourceResponse = await fetch(sourceUrl);
      if (!sourceResponse.ok) throw new Error(`Source returned ${sourceResponse.status}`);

      const totalSize = parseInt(sourceResponse.headers.get('content-length')) || 0;
      this.progress.total = totalSize;

      const counterTransform = new TransformStream({
        transform: (chunk, controller) => {
          this.progress.downloaded += chunk.length;
          if (totalSize > 0) this.progress.percent = Math.round((this.progress.downloaded / totalSize) * 100);
          this.throttleSave();
          controller.enqueue(chunk);
        }
      });

      let readableForR2;
      const countedStream = sourceResponse.body.pipeThrough(counterTransform);

      if (totalSize > 0) {
        const { readable, writable } = new FixedLengthStream(totalSize);
        countedStream.pipeTo(writable).catch(e => { this.progress.error = "Stream break"; });
        readableForR2 = readable;
      } else {
        readableForR2 = countedStream;
      }

      await this.env.DRIVE_BUCKET.put(filename, readableForR2, {
        httpMetadata: { contentType: sourceResponse.headers.get('content-type') },
        customMetadata: {
          source: sourceUrl,
          timestamp: this.progress.timestamp.toString()
        }
      });

      this.progress.status = 'completed';
      this.progress.percent = 100;
      await this.saveState();

    } catch (error) {
      this.progress.status = 'failed';
      this.progress.error = error.message;
      await this.saveState();
    }
  }

  async saveState() { await this.state.storage.put('jobState', this.progress); }

  throttleSave() {
    const now = Date.now();
    if (!this.lastSave || now - this.lastSave > 1000) {
      this.lastSave = now;
      this.state.storage.put('jobState', this.progress);
    }
  }
}

// ============================================================
// HELPER: RENDER UI
// ============================================================
function renderAdminPanel(currentKey) {
  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="https://img.icons8.com/color/48/w-cute.png"/>
    <title>R2 Manager</title>
    <style>
      :root { font-family: system-ui, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f4f4f9; }
      body { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
      h1 { color: #f6821f; margin-bottom: 20px; }
      
      /* Tabs */
      .tabs { display: flex; border-bottom: 2px solid #ddd; margin-bottom: 20px; }
      .tab { padding: 10px 20px; cursor: pointer; font-weight: bold; color: #666; border-bottom: 2px solid transparent; margin-bottom: -2px;}
      .tab.active { color: #f6821f; border-bottom-color: #f6821f; }
      .tab-content { display: none; }
      .tab-content.active { display: block; }

      /* Forms & Tables */
      label { display: block; margin-top: 1px; font-weight: bold; font-size: 14px; }
      input[type="text"], input[type="password"], textarea { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box;}
      
      input[type="file"] {
      display: none;
      }

      .custom-file-upload {
        border: 1px solid #1b8343;
        display: inline-block;
        padding: 1px 1px;
        cursor: pointer;
      }


      button { background: #9ae6bc; color: white; border: none; padding: 10px 10px; margin-top: 20px; border-radius: 4px; cursor: pointer; }
      button:hover { opacity: 0.9; }
      button:disabled { background: #ccc; }
      button.danger { background: #dc3545; padding: 5px 10px; margin: 0; font-size: 12px; }
      button.primary { background: #2196f3; }
      
      table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
      th, td { padding: 10px; border-bottom: 1px solid #eee; text-align: left; }
      th { background: #fafafa; }
      
      /* Cards & Progress */
      .card { background: #fafafa; border: 1px solid #eee; padding: 15px; margin-top: 15px; border-radius: 4px; }
      .progress-bar { width: 100%; background: #ddd; height: 10px; border-radius: 5px; overflow: hidden; margin-top: 10px;}
      .progress-fill { height: 100%; background: #4caf50; width: 0%; transition: width 0.3s; }
      .tag { font-size: 11px; padding: 2px 6px; border-radius: 4px; font-weight: bold; text-transform: uppercase; }
      .tag.exists { background: #fff3e0; color: #e65100; }
    </style>
  </head>
  <body>
    <div style="display:flex; justify-content:space-between; align-items:center">
      <h1>☁️ R2 Manager</h1>
      <div style="margin-bottom: 10px;">
        <label>Authentication Key</label>
        <input type="password" id="apiKey" style="width:80%" class="apiKey" value="${currentKey}" placeholder="Enter AUTH_KEY if configured">
        <button id="togglePassword">👀</button>
      </div>
    </div>

    <div class="tabs">
      <div class="tab active" onclick="switchTab('downloader')">Remote Downloader</div>
      <div class="tab" onclick="switchTab('upload')">Direct Upload</div>
      <div class="tab" onclick="switchTab('library')">Library (History)</div>
    </div>

    <!-- DOWNLOADER TAB -->
    <div id="downloader" class="tab-content active">
      <div class="card">
        <h3>New Download Job</h3>
        <form id="dlForm">
          <label>Source URL</label>
          <input type="text" id="sourceUrl" placeholder="https://..." required>
          <label>Filename</label>
          <input type="text" id="filename" placeholder="video.mp4" required>
          <label style="display:flex; align-items:center; margin-top:10px;">
            <input type="checkbox" id="force" style="width:auto; margin-right:8px;"> Force Re-download
          </label>
          <button type="submit">Start Download</button>
        </form>
      </div>
      <div id="jobsArea"></div>
    </div>

    <!-- DIRECT UPLOAD TAB -->
    <div id="upload" class="tab-content">
      <div class="card">
        <h3>Direct Upload to R2</h3>
        <p style="font-size:13px; color:#666">Files are streamed directly to R2. Worker memory is not impacted.</p>
        

        <label class="custom-file-upload">
            <input type="file" id="fileInput" onChange='getFileNameWithExt(this, event)'/>
            <span id="fileInputLabel">Choose File</span>
        </label>


        <label>Save as Filename
        <input type="text" id="upFilename" placeholder="Optional (defaults to file name)">
        
        </label>
        <button onclick="uploadFile(this)" class="primary">Upload File</button>
        <div id="uploadStatus" style="margin-top:10px;"></div>
      </div>
    </div>

    <!-- LIBRARY TAB -->
    <div id="library" class="tab-content">
      <div style="display:flex; justify-content:space-between; align-items:center">
        <h3>Files in Bucket</h3>
        <button onclick="loadLibrary()" style="margin:0; padding: 5px 15px; font-size:14px;">Refresh</button>
      </div>
      <table id="fileTable">
        <thead><tr><th>Filename</th><th>Size</th><th>Source</th><th>Date</th><th>Actions</th></tr></thead>
        <tbody><tr><td colspan="5">Loading...</td></tr></tbody>
      </table>
    </div>

    <script>
      const apiKeyInput = document.getElementById('apiKey');
      const togglePasswordBtn = document.getElementById('togglePassword');
      apiKeyInput.oninput = async () => {
          apiKeyInput.type = 'text';
          togglePasswordBtn.innerText = '🙈';
          await new Promise(r => setTimeout(r, 1500));
          apiKeyInput.type = 'password';
          togglePasswordBtn.innerText = '👀';
      };
      togglePasswordBtn.onclick = async () => {
          apiKeyInput.type = 'text';
          togglePasswordBtn.innerText = '🙈';
          await new Promise(r => setTimeout(r, 1500));
          apiKeyInput.type = 'password';
          togglePasswordBtn.innerText = '👀';
      };

      const authFetch = (url, opts = {}) => {
        const key = apiKeyInput.value;
        const headers = opts.headers || {};
        if(key) headers['x-api-key'] = key;
        let fetchUrl = url;
        // Append key to URL for GETs if needed (for simple hrefs)
        if(key && (url.includes('/get') || url.includes('/list'))) {
           fetchUrl += (url.includes('?') ? '&' : '?') + 'key=' + encodeURIComponent(key);
        }
        return fetch(fetchUrl, { ...opts, headers });
      };

      function switchTab(id) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        event.target.classList.add('active');
        document.getElementById(id).classList.add('active');
        if(id === 'library') loadLibrary();
      }

      // Source - https://stackoverflow.com/a
      // Posted by Junius L, modified by community. See post 'Timeline' for change history
      // Retrieved 2026-01-19, License - CC BY-SA 4.0

      function getFileNameWithExt(element, event) {

        if (!event || !event.target || !event.target.files || event.target.files.length === 0) {
          return;
        }

        const file = event.target.files[0];
        if (!file) {
          return;
        }
        const name = file.name;
        const lastDot = name.lastIndexOf('.');

        const fileName = name.substring(0, lastDot);
        const ext = name.substring(lastDot + 1);

        console.log('File Name:', fileName);
        console.log('Extension:', ext);
        console.log('file:', file);

        element.parentElement.querySelector("#fileInputLabel").innerHTML = '<div style="font-size:13px;color: #263b26">' + fileName + '.' + ext + '</div><div style="font-size:9px;color: #40c740">' + (file.size / 1024 / 1024).toFixed(2) + ' MB</div>';


      }
      function isValidHttpUrl(string) {
        let url;
        try {
          url = new URL(string);
        } catch (_) {
          return false;  
        }
        return url.protocol === "http:" || url.protocol === "https:";
      }
      // --- DOWNLOADER LOGIC ---
      document.getElementById('dlForm').onsubmit = async (e) => {
        e.preventDefault();
        const btn = e.target.querySelector('button');
        btn.disabled = true;
        
        try {
          const res = await authFetch('/download', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              sourceUrl: document.getElementById('sourceUrl').value,
              filename: document.getElementById('filename').value,
              force: document.getElementById('force').checked
            })
          });
          const data = await res.json();
          
          if(data.status === 'exists') {
            alert('File already exists in cache!');
            // Show a card indicating it's done
            createJobCard(data.file.key, data.file.key, null, data.downloadUrl, true);
          } else {
            createJobCard(data.jobId, document.getElementById('filename').value, data.statusUrl, data.downloadUrl, false);
          }
          e.target.reset();
        } catch(err) { alert(err.message); }
        btn.disabled = false;
      };

      function createJobCard(id, name, statusUrl, downloadUrl, isCached) {
        const div = document.createElement('div');
        div.className = 'card';
        div.innerHTML = \`
          <div style="display:flex; justify-content:space-between">
            <strong>\${name}</strong>
            \${isCached ? '<span class="tag exists">Cached</span>' : '<span id="badge-'+id+'" class="tag" style="background:#e3f2fd">Starting</span>'}
          </div>
          \${isCached ? '' : '<div class="progress-bar"><div id="prog-'+id+'" class="progress-fill"></div></div>'}
          <div style="margin-top:10px">
            \${isCached 
              ? \`<a href="\${downloadUrl}" target="_blank"><button class="primary" style="margin:0; padding:5px 15px; font-size:12px">Download</button></a>\`
              : \`<span id="stats-\${id}" style="font-size:12px">Waiting...</span> <div id="actions-\${id}"></div>\`
            }
          </div>
        \`;
        document.getElementById('jobsArea').prepend(div);
        if(!isCached) pollStatus(id, statusUrl, downloadUrl);
      }

      function pollStatus(id, statusUrl, downloadUrl) {
        const interval = setInterval(async () => {
          try {
            const res = await authFetch(statusUrl);
            const d = await res.json();
            
            const badge = document.getElementById('badge-'+id);
            const prog = document.getElementById('prog-'+id);
            const stats = document.getElementById('stats-'+id);
            
            if(!badge) { clearInterval(interval); return; }

            badge.innerText = d.status;
            if(d.total > 0) {
              prog.style.width = d.percent + '%';
              stats.innerText = \`\${d.percent}% of \${(d.total/1024/1024).toFixed(2)} MB\`;
            } else {
              stats.innerText = \`\${(d.downloaded/1024/1024).toFixed(2)} MB\`;
            }

            if(d.status === 'completed') {
              clearInterval(interval);
              prog.style.width = '100%';
              badge.style.background = '#e8f5e9';
              document.getElementById('actions-'+id).innerHTML = \`<a href="\${downloadUrl}" target="_blank"><button class="primary" style="margin-top:5px; padding:5px 15px; font-size:12px">Download</button></a>\`;
            } else if (d.status === 'failed') {
              clearInterval(interval);
              badge.style.background = '#ffebee';
              stats.innerText = 'Error: ' + d.error;
            }
          } catch(e) {}
        }, 1000);
      }

      // --- LIBRARY LOGIC ---
      async function loadLibrary() {
        const tbody = document.querySelector('#fileTable tbody');
        tbody.innerHTML = '<tr><td colspan="5">Loading...</td></tr>';
        
        try {
          const res = await authFetch('/list');
          console.log("LIBRARY: res",res);

          const data = await res.json();
          console.log("LIBRARY:",data);
          if(data.error) {
            togglePasswordBtn.innerText = '⚠️';
            tbody.innerHTML = \`<tr><td colspan="5" style="background:#ffebee">Error loading files: \${data.error}</td></tr>\`;
            alert('Error: ' + data.error);
            return;
          }
          
          if(data.files.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5">No files found</td></tr>';
            return;
          }

          tbody.innerHTML = data.files.map(f => {
            const size = (f.size / 1024 / 1024).toFixed(2) + ' MB';
            const date = new Date(f.uploaded).toLocaleString();
            const source = isValidHttpUrl(f.source) ? \`<a href="\${f.source}" target="_blank" title="\${f.source}">remote</a>\` : f.source;
            const keyParam = apiKeyInput.value ? '?key='+encodeURIComponent(apiKeyInput.value) : '';
            const link = '/get/' + encodeURIComponent(f.key) + keyParam;
            
            return \`<tr>
              <td>\${f.key}</td>
              <td>\${size}</td>
              <td>\${source}</td>
              <td>\${date}</td>
              <td>
                <a href="\${link}" target="_blank">⬇️</a>
                <span style="cursor:pointer; margin-left:10px" onclick="deleteFile('\${f.key}')">❌</span>
              </td>
            </tr>\`;
          }).join('');
        } catch(e) {

          togglePasswordBtn.innerText = '⚠️';
            
          tbody.innerHTML = '<tr><td colspan="4">Error loading files 222</td></tr>';
        }
      }

      async function deleteFile(filename) {
        if(!confirm('Delete ' + filename + '?')) return;
        try {
          await authFetch('/delete?filename=' + encodeURIComponent(filename), { method: 'DELETE' });
          loadLibrary();
        } catch(e) { alert(e.message); }
      }

      // --- DIRECT UPLOAD LOGIC ---
      async function uploadFile(element) {
        const input = document.getElementById('fileInput');
        const file = input.files[0];
        if(!file) return alert('Please select a file');

        const nameInput = document.getElementById('upFilename');
        const filename = nameInput.value.trim() || file.name;
        
        const status = document.getElementById('uploadStatus');
        status.innerText = 'Uploading ' + filename + '...';
        
        try {
          const res = await authFetch('/upload?filename=' + encodeURIComponent(filename), {
            method: 'PUT',
            headers: { 'Content-Type': file.type },
            body: file // Stream raw binary
          });
          
          if(!res.ok) throw new Error(await res.text());
          
          status.innerText = '✅ Upload Complete!';
          input.value = '';
          nameInput.value = '';

        } catch(e) {
          status.innerText = '❌ Error: ' + e.message;
        }

         element.parentElement.querySelector("#fileInputLabel").innerHTML = 'Choose File';

      }
    </script>
  </body>
  </html>`;
}