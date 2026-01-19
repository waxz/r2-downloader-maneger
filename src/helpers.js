// Helper functions extracted from jsonbin.js

// --- encryption helpers ---
export async function encryptData(data, key) {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: encoder.encode("salt"), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encoder.encode(data));
  // Convert iv and encrypted bytes to binary strings safely (avoid spread on large arrays)
  let ivStr;
  let encStr;
  try {
    const td = new TextDecoder('latin1');
    ivStr = td.decode(iv);
    encStr = td.decode(new Uint8Array(encrypted));
  } catch (e) {
    // Fallback: build strings byte-by-byte
    ivStr = String.fromCharCode(...iv);
    const encBytes = new Uint8Array(encrypted);
    let s = "";
    for (let i = 0; i < encBytes.length; i++) s += String.fromCharCode(encBytes[i]);
    encStr = s;
  }
  return btoa(ivStr) + ":" + btoa(encStr);
}

export async function decryptData(ciphertext, key) {
  const [ivStr, encStr] = ciphertext.split(":");
  const iv = Uint8Array.from(atob(ivStr), c => c.charCodeAt(0));
  const data = Uint8Array.from(atob(encStr), c => c.charCodeAt(0));
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: encoder.encode("salt"), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, data);
  return new TextDecoder().decode(decrypted);
}

// --- binary helpers ---
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  try {
    // Use latin1 text decoder to produce a binary string from bytes (avoids large apply/spread)
    const td = new TextDecoder('latin1');
    const binary = td.decode(bytes);
    return btoa(binary);
  } catch (e) {
    // Fallback: build string one char at a time
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
}

export function base64ToUint8Array(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

// --- UTF8 <-> base64 helpers (safe for Unicode) ---
export function utf8ToBase64(str) {
  // Encode UTF-8 string to ArrayBuffer then to base64
  const buf = new TextEncoder().encode(str).buffer;
  return arrayBufferToBase64(buf);
}

export function base64ToUtf8(b64) {
  const arr = base64ToUint8Array(b64);
  return new TextDecoder().decode(arr);
}

// --- encryption wrappers for binary ---
export async function encryptBinary(buffer, key) {
  const b64 = arrayBufferToBase64(buffer);
  return await encryptData(b64, key);
}

export async function decryptBinary(ciphertext, key) {
  const b64 = await decryptData(ciphertext, key);
  return base64ToUint8Array(b64).buffer;
}

export function sanitizeFilename(name) {
  name = name.split("/").pop() || name;
  name = name.replace(/[^a-zA-Z0-9._()\[\] \-]+/g, "");
  return name || "file";
}

export function generateToken(len = 18) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function jsonOK(obj) {
  return new Response(JSON.stringify(obj, null, 2), {
    headers: { "Content-Type": "application/json" },
  });
}

export function jsonError(msg, status) {
  return new Response(JSON.stringify({ ok: false, error: msg }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export async function processRequest(request, config) {
  const url = new URL(request.url);

  // Build target URL with forward pathname and query string
  const targetUrl = new URL(config.forwardPathname + url.search, config.targetUrl);
  console.log(`processRequest: method:${request.method}, targetUrl:${targetUrl}`);

  const headers = new Headers(request.headers);

  // Remove Cloudflare-specific headers
  const headersToRemove = [
    'host', 'cf-connecting-ip', 'cf-ray', 'cf-visitor',
    'cf-ipcountry', 'cdn-loop', 'x-forwarded-proto'
  ];
  headersToRemove.forEach(header => headers.delete(header));

  // 🔥 FIX: Rewrite Destination header for WebDAV MOVE/COPY
  if (['MOVE', 'COPY'].includes(request.method)) {
    const destination = headers.get('Destination');
    if (destination) {
      try {
        const destUrl = new URL(destination);
        // Extract the path after the forward prefix
        const destPath = destUrl.pathname;

        // Parse the destination path to extract forwardPathname
        // Format: /_forward/KEY/JSONBIN_PATH/urlsplit/FORWARD_PATH
        const urlsplitIndex = destPath.indexOf('/urlsplit/');
        if (urlsplitIndex > -1) {
          const destForwardPath = destPath.slice(urlsplitIndex + '/urlsplit/'.length);
          const newDestination = new URL(destForwardPath, config.targetUrl).toString();
          headers.set('Destination', newDestination);
          console.log(`Rewritten Destination: ${destination} -> ${newDestination}`);
        } else {
          // Fallback: just replace the origin
          const newDestination = new URL(destUrl.pathname, config.targetUrl).toString();
          headers.set('Destination', newDestination);
          console.log(`Rewritten Destination (fallback): ${destination} -> ${newDestination}`);
        }
      } catch (e) {
        console.error('Failed to rewrite Destination header:', e);
      }
    }
  }

  const requestInit = {
    method: request.method,
    headers: headers,
  };

  // 🔥 FIX: Handle body for more methods (including WebDAV)
  const methodsWithBody = [
    'POST', 'PUT', 'PATCH', 'DELETE',
    'PROPFIND', 'PROPPATCH', 'MKCOL', 'LOCK'
  ];

  if (methodsWithBody.includes(request.method)) {
    const contentLength = request.headers.get('content-length');

    if (contentLength && parseInt(contentLength) > 0) {
      // For small bodies, read as ArrayBuffer
      if (parseInt(contentLength) < 10 * 1024 * 1024) { // < 10MB
        requestInit.body = await request.arrayBuffer();
      } else {
        // For large bodies, use stream directly
        requestInit.body = request.body;
        requestInit.duplex = 'half';
      }
    } else {
      // Try to read the body if no content-length
      try {
        const cloned = request.clone();
        const bodyBuffer = await cloned.arrayBuffer();
        if (bodyBuffer.byteLength > 0) {
          requestInit.body = bodyBuffer;
        }
      } catch (e) {
        // No body or already consumed
        console.log('No body to forward');
      }
    }
  }

  return new Request(targetUrl.toString(), requestInit);
}

export async function forwardRequest(request, config) {
  const isWebSocket = request.headers.get("Upgrade") === "websocket";

  // 1. If it's a WebSocket, we cannot use a timeout (the connection must stay open).
  if (isWebSocket) {
    try {
      const response = await fetch(request);
      // If the backend accepts the upgrade (Status 101), return the raw response object.
      // Do not try to wrap it in 'new Response()', as that throws the RangeError.
      if (response.status === 101) {
        return response;
      }
      // If the handshake failed (e.g. 403 Forbidden), wrap it normally so we can add headers later.
      return new Response(response.body, response);
    } catch (error) {
      throw error;
    }
  }

  // 2. Standard HTTP Request Logic (with Timeout)
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.timeout);

  try {
    const response = await fetch(request, {
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    return new Response(response.body, response);

  } catch (error) {
    clearTimeout(timeoutId);

    if (error.name === 'AbortError') {
      throw new Error(`Request timeout after ${config.timeout}ms`);
    }
    throw error;
  }
}
export function addCORSHeaders(response, request, config) {
  // FIX: WebSockets return status 101.
  // The 'new Response()' constructor throws a RangeError for status codes outside 200-599.
  // If status is 101, return the original response immediately to maintain the open socket.
  if (response.status === 101 || response.status < 200 || response.status > 599) {
    return response;
  }

  const newHeaders = new Headers(response.headers);
  const corsHeaders = getCORSHeaders(request, config.allowedOrigins);

  Object.entries(corsHeaders).forEach(([key, value]) => {
    newHeaders.set(key, value);
  });

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}

export function handleCORS(request, env) {
  const allowedOrigins = env.ALLOWED_ORIGINS?.split(',') || ['*'];

  return new Response(null, {
    status: 204,
    headers: {
      ...getCORSHeaders(request, allowedOrigins),
      'Access-Control-Max-Age': '86400',
    }
  });
}

export function getCORSHeaders(request, allowedOrigins) {
  const origin = request.headers.get('Origin');
  let allowOrigin = '*';

  // If specific origins are allowed, check if request origin is in the list
  if (!allowedOrigins.includes('*') && origin) {
    allowOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];
  } else if (origin) {
    allowOrigin = origin;
  }

  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, Accept, Origin',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}

export function isOriginAllowed(request, allowedOrigins) {
  if (allowedOrigins.includes('*')) return true;

  const origin = request.headers.get('Origin');
  if (!origin) return true;

  return allowedOrigins.includes(origin);
}


/**
 * Convert ArrayBuffer/Uint8Array to UTF-8 text
 */
export function bufferToText(value) {
  if (value instanceof ArrayBuffer) {
    return new TextDecoder().decode(new Uint8Array(value));
  } else if (value instanceof Uint8Array) {
    return new TextDecoder().decode(value);
  }
  return String(value);
}

/**
 * Decrypt data and try to decode (handles base64 or plain JSON)
 */
export async function decryptAndDecode(ciphertext, key) {

  var decrypted = decrypted = await decryptData(ciphertext, key);;

  // Try parsing as JSON first
  try {
    JSON.parse(decrypted);
    return decrypted;
  } catch {
    // Try base64 decode
    try {
      const bytes = base64ToUint8Array(decrypted);
      return new TextDecoder().decode(bytes);
    } catch {
      return decrypted;
    }
  }
}
