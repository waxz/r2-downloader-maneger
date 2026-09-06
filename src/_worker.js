// ============================================================================
// HELPERS
// ============================================================================
const jsonOk = (data) => Response.json(data);
const jsonError = (msg, status = 400) =>
  Response.json({ error: msg }, { status });
async function readBody(req) {
  try {
    return await req.json();
  } catch {
    return null;
  }
}
function baseName(key) {
  return key.split("/").filter(Boolean).pop() || key;
}
function decodeRequestValue(value) {
  if (!value) return value;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
function ensureLeadingSlash(value) {
  return normalizeStoragePath(value);
}
// Distinguishes a browser navigating to "/" (which should see the admin
// frontend) from a WebDAV client mounting "/" as its root (which needs the
// real WebDAV response — a directory listing, or a 401 Basic-Auth challenge
// carrying the DAV capability headers — to be able to connect at all).
// Mirrors the same heuristic fetch_webdav's own auth layer already uses
// (see the User-Agent check next to verifyWebDAVCredentials in webdav.js)
// so both layers agree on who counts as a browser.
function looksLikeBrowserRequest(request) {
  // A request already carrying WebDAV Basic Auth credentials (e.g. a
  // client reconnecting with cached credentials) is unambiguously a
  // WebDAV client, regardless of what its User-Agent claims.
  const authHeader = request.headers.get("Authorization") || "";
  if (authHeader.startsWith("Basic ")) return false;
  const userAgent = request.headers.get("User-Agent") || "";
  return /Mozilla|Chrome|Safari/i.test(userAgent);
}
import {
  fetch_webdav,
  normalizeStoragePath,
  normalizeStorageKey,
  joinStoragePath,
  ensureR2CompatibleStorage,
  getParentPath,
  getSettings,
  saveSettings,
  DEFAULT_SETTINGS,
  timingSafeEqual,
  normalizeWebdavRoot,
} from "./webdav.js";
import { fetch_mcp } from "./mcp.js";

import { checkRateAndBan, recordAuthResult } from './security.js';
// Define your parameters globally or pull them from an external configuration file
const securityOptions = {
  rateLimit: 100,          // Stricter rate limit
  maxAuthFails: 10,        // Lower tolerance for bad login attempts
  banDuration: 60000     // Shorter ban duration (1 minutes in ms)
};

// ============================================================================
// VERSION / SYSTEM INFO
// ============================================================================
// Bumped alongside package.json's "version" field. Kept as a plain constant
// (rather than importing package.json) so the Workers bundler never has to
// deal with JSON-module interop.
const APP_VERSION = "1.1.0";
const APP_NAME = "R2 Drive";
const REPO_OWNER = "waxz";
const REPO_NAME = "r2-downloader-manager";

// ============================================================================
// MAIN WORKER
// ============================================================================

async function ensureWorkerStorage(env) {
  if (env && env.WEBDAV_STORAGE) {
    ensureR2CompatibleStorage(env);
  }
}

// WebDAV (src/webdav.js) recognizes a directory exclusively via a "<path>_dir"
// marker key — it has no concept of the REST API's own ".emptydir" convention
// or of inferring directories from real nested keys. Writes coming from this
// file (uploads, mkdir) must create these markers themselves, for every
// ancestor up to and including `dirPath`, or the directory becomes invisible
// to WebDAV clients (PROPFIND, GET-as-directory-listing) even though the
// file manager can see it fine via R2's native prefix/delimiter grouping.
async function ensureWebDAVDirMarkers(env, dirPath) {
  const now = new Date().toISOString();
  let dir = dirPath;
  while (dir && dir !== "/") {
    await env.WEBDAV_STORAGE.put(
      `${dir}_dir`,
      JSON.stringify({
        type: "directory",
        createdAt: now,
        modifiedAt: now,
      }),
    );
    dir = getParentPath(dir);
  }
  await env.WEBDAV_STORAGE.put(
    `/_dir`,
    JSON.stringify({
      type: "directory",
      createdAt: now,
      modifiedAt: now,
    }),
  );
}

// Thrown by the storage-operation helpers below to carry the HTTP status
// their caller should respond with (404 for "not found", 409 for "already
// exists", etc.) through a single generic try/catch, rather than every
// caller having to know each helper's specific failure modes. Both the
// REST routes in fetch_api and the MCP tool handlers in mcp.js catch these.
export class ApiError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

// Shared by the REST /api/files/delete route and the MCP delete_file/
// delete_directory tools. `keys` are deleted along with their "_meta"
// sidecar; `prefixes` are folders, deleted recursively (however deep) the
// same way WebDAV's own recursive COPY/MOVE walk a subtree, since a
// caller's one-level view of a folder isn't enough to enumerate everything
// under it.
export async function deleteFilesAndFolders(env, { keys = [], prefixes = [] } = {}) {
  const allKeys = new Set();
  for (const k of keys) {
    allKeys.add(k);
    allKeys.add(`${k}_meta`);
  }
  for (const rawPrefix of prefixes) {
    const normalizedPrefix = normalizeStoragePath(rawPrefix).replace(/\/$/, "");
    if (!normalizedPrefix || normalizedPrefix === "/") continue;
    allKeys.add(`${normalizedPrefix}_dir`);
    allKeys.add(`${normalizedPrefix}/.emptydir`);
    const listPrefix = `${normalizedPrefix}/`;
    let cursor;
    do {
      const listed = await env.WEBDAV_STORAGE.list({
        prefix: listPrefix,
        cursor,
        limit: 1000,
      });
      for (const object of listed.objects || []) allKeys.add(object.key);
      cursor = listed.truncated ? listed.cursor : undefined;
    } while (cursor);
  }
  const finalKeys = Array.from(allKeys);
  if (finalKeys.length) await env.WEBDAV_STORAGE.delete(finalKeys);
  return { requested: keys.length + prefixes.length };
}

// Shared by the REST /api/files/mkdir route and the MCP create_directory
// tool: writes both the ".emptydir" marker (used by /api/files' listing)
// and the WebDAV "_dir" markers (see ensureWebDAVDirMarkers), so a folder
// created either way is visible everywhere.
export async function createDirectory(env, path) {
  const folderPath = normalizeStoragePath(path);
  const folderKey =
    folderPath === "/" ? "/" : folderPath.endsWith("/") ? folderPath : folderPath + "/";
  const markerKey =
    folderKey === "/" ? "/.emptydir" : joinStoragePath(folderKey, ".emptydir");
  await env.WEBDAV_STORAGE.put(markerKey, new Uint8Array(0), {
    customMetadata: { type: "folder" },
  });
  await ensureWebDAVDirMarkers(env, folderPath);
  return { created: folderKey };
}

// Shared by the REST /api/upload route and the MCP write_file tool.
export async function writeFile(env, path, bytes, contentType = "application/octet-stream") {
  const filename = normalizeStoragePath(path);
  await env.WEBDAV_STORAGE.put(filename, bytes, {
    httpMetadata: { contentType, contentLength: bytes.length },
    customMetadata: { source: "upload", timestamp: Date.now().toString() },
  });
  const now = new Date().toISOString();
  await env.WEBDAV_STORAGE.put(
    `${filename}_meta`,
    JSON.stringify({ type: "file", size: bytes.length, modifiedAt: now, contentType }),
  );
  await ensureWebDAVDirMarkers(env, getParentPath(filename));
  return { status: "uploaded", filename, size: bytes.length };
}

// Shared by the REST /api/files/move and /api/files/copy routes and the MCP
// move_file/copy_file tools. Operates on a single file (not a folder tree —
// same scope the REST API has always had).
export async function relocateFile(env, source, destination, { remove }) {
  const src = normalizeStoragePath(source);
  const dest = normalizeStoragePath(destination);
  const srcObj = await env.WEBDAV_STORAGE.get(src);
  if (!srcObj) throw new ApiError("Source not found", 404);
  const destKey = dest.endsWith("/") ? dest + src.split("/").pop() : dest;
  if (await env.WEBDAV_STORAGE.head(destKey))
    throw new ApiError("Destination already exists", 409);
  const srcBody = await srcObj.arrayBuffer();
  await env.WEBDAV_STORAGE.put(destKey, srcBody, {
    httpMetadata: srcObj.httpMetadata,
    customMetadata: srcObj.customMetadata,
  });
  const srcMeta = await env.WEBDAV_STORAGE.get(`${src}_meta`);
  if (srcMeta) {
    await env.WEBDAV_STORAGE.put(`${destKey}_meta`, await srcMeta.text());
    if (remove) await env.WEBDAV_STORAGE.delete(`${src}_meta`);
  }
  if (remove) await env.WEBDAV_STORAGE.delete(src);
  return { status: remove ? "moved" : "copied", source: src, destination: destKey };
}

// Shared by the REST /api/files/info route and the MCP get_file_info tool.
export async function getFileInfo(env, key) {
  const normalized = normalizeStoragePath(key);
  if (!normalized || normalized === "/") throw new ApiError("Missing key");
  const head = await env.WEBDAV_STORAGE.head(normalized);
  if (!head) throw new ApiError("Not found", 404);
  return {
    key: head.key,
    size: head.size,
    uploaded: head.uploaded,
    httpMetadata: head.httpMetadata,
    customMetadata: head.customMetadata,
  };
}

async function fetch_api(request, env) {
  try {
    await ensureWorkerStorage(env);
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // --- Serve frontend ---
    if (path === "/api/" || path === "/api/index.html")
      return env.ASSETS.fetch(request);

    // --- Public share (no auth) ---
    if (path.startsWith("/s/")) return handlePublicShare(url, env);

    // --- System info (no auth): version/update badge needs to render even
    // before the user has entered an API key, and none of this is sensitive.
    if (path === "/api/system/info" && method === "GET") {
      const settings = await getSettings(env);
      return jsonOk({
        name: APP_NAME,
        version: APP_VERSION,
        repoOwner: REPO_OWNER,
        repoName: REPO_NAME,
        siteTitle: settings.siteTitle,
        maintenanceMode: settings.maintenanceMode,
        webdavEnabled: settings.webdavEnabled,
        webdavRootPath: normalizeWebdavRoot(settings.webdavRootPath),
      });
    }

    // --- Auth gate for everything else ---
    // Fail closed: if the operator never configured AUTH_KEY/APIKEYSECRET,
    // this used to skip the check entirely and leave every file/job/share
    // operation open to anyone who could reach the worker. Instead, treat
    // "not configured" the same as "wrong key" — deny access — so the
    // management API is never accidentally exposed unauthenticated. This
    // mirrors WebDAV's own fail-closed behavior when its credentials aren't
    // configured (see verifyWebDAVCredentials in webdav.js).
    const authKey = env.AUTH_KEY || env.APIKEYSECRET;
    // Prefer the header: some routes (e.g. /api/files/info) have their own
    // "key" query parameter for an unrelated purpose (the storage key being
    // looked up), which would otherwise collide with the auth key. The
    // query-string form stays supported as a fallback for cases that can't
    // set a custom header, like a plain /get/<file>?key=... link opened
    // directly in a browser tab.
    const providedKey = request.headers.get("x-api-key") || url.searchParams.get("key");
    // Constant-time compare: a plain `!==` short-circuits at the first
    // mismatched character, which is a timing side-channel an attacker
    // could use to guess the key one character at a time.

    
    // 1. Initial Gatekeeping: Rate limits & pre-existing bans



    if (!authKey || !providedKey || !(await timingSafeEqual(providedKey, authKey))) {
        recordAuthResult(request, false);

      return jsonError("Unauthorized", 401);

    }
        recordAuthResult(request, true);

    // --- Admin: system settings ---
    if (path === "/api/admin/settings" && method === "GET") {
      return jsonOk(await getSettings(env));
    }
    if (path === "/api/admin/settings" && method === "POST") {
      const body = await readBody(request);
      if (!body) return jsonError("Invalid body");
      return jsonOk(await saveSettings(env, body));
    }
    if (path === "/api/admin/settings/reset" && method === "POST") {
      await saveSettings(env, DEFAULT_SETTINGS);
      return jsonOk(await getSettings(env));
    }

    // Maintenance mode blocks the rest of the management API (uploads,
    // downloads, file ops, shares) so an admin can safely work on the
    // bucket, but the settings routes above must stay reachable — otherwise
    // there would be no way to turn maintenance mode back off again.
    const settings = await getSettings(env);
    if (settings.maintenanceMode) {
      return jsonError("Service is currently in maintenance mode", 503);
    }

    // --- File routes ---
    if (path === "/api/files" && method === "GET")
      return handleListFiles(url, env);

    // Flat list of every folder path in the bucket, at any depth — powers
    // the destination-folder dropdown in Download/Upload/Move/Copy so users
    // pick an existing folder instead of hand-typing one.
    if (path === "/api/folders" && method === "GET")
      return handleListFolders(env);

    if (path === "/api/files/info" && method === "GET") {
      const info = await getFileInfo(env, url.searchParams.get("key") || "");
      return jsonOk(info);
    }

    if (path === "/api/files/delete" && method === "POST") {
      const body = await readBody(request);
      if (!body) return jsonError("Invalid body");
      const keys = Array.isArray(body.keys)
        ? body.keys
        : body.filename
          ? [body.filename]
          : [];
      const prefixes = Array.isArray(body.prefixes)
        ? body.prefixes
        : body.prefix
          ? [body.prefix]
          : [];
      if (!keys.length && !prefixes.length) return jsonError("No keys");
      const { requested } = await deleteFilesAndFolders(env, { keys, prefixes });
      return jsonOk({ deleted: requested });
    }

    if (path === "/api/files/rename" && method === "POST") {
      const body = await readBody(request);
      if (!body?.oldName || !body?.newName) return jsonError("Missing params");
      const oldName = normalizeStoragePath(body.oldName);
      const newName = normalizeStoragePath(body.newName);
      const src = await env.WEBDAV_STORAGE.get(oldName);
      if (!src) return jsonError("Not found", 404);
      if (await env.WEBDAV_STORAGE.head(newName))
        return jsonError("Name already taken", 409);
      const srcBody = await src.arrayBuffer();
      await env.WEBDAV_STORAGE.put(newName, srcBody, {
        httpMetadata: src.httpMetadata,
        customMetadata: src.customMetadata,
      });
      const srcMeta = await env.WEBDAV_STORAGE.get(`${oldName}_meta`);
      if (srcMeta) {
        await env.WEBDAV_STORAGE.put(`${newName}_meta`, await srcMeta.text());
        await env.WEBDAV_STORAGE.delete(`${oldName}_meta`);
      }
      await env.WEBDAV_STORAGE.delete(oldName);
      return jsonOk({ status: "renamed", oldName, newName });
    }

    if (path === "/api/files/move" && method === "POST") {
      const body = await readBody(request);
      if (!body?.source || !body?.destination)
        return jsonError("Missing source or destination");
      const result = await relocateFile(env, body.source, body.destination, {
        remove: true,
      });
      return jsonOk(result);
    }

    if (path === "/api/files/copy" && method === "POST") {
      const body = await readBody(request);
      if (!body?.source || !body?.destination)
        return jsonError("Missing source or destination");
      const result = await relocateFile(env, body.source, body.destination, {
        remove: false,
      });
      return jsonOk(result);
    }

    if (path === "/api/files/mkdir" && method === "POST") {
      const body = await readBody(request);
      if (!body?.path) return jsonError("Missing path");
      const result = await createDirectory(env, body.path);
      return jsonOk(result);
    }

    if (path === "/api/upload" && (method === "PUT" || method === "POST")) {
      let filename = decodeRequestValue(url.searchParams.get("filename") || "");
      if (!filename) return jsonError("Missing filename");
      filename = ensureLeadingSlash(filename);

      const contentType =
        request.headers.get("Content-Type") || "application/octet-stream";

      const arrayBuffer = await request.arrayBuffer();
      const result = await writeFile(
        env,
        filename,
        new Uint8Array(arrayBuffer),
        contentType,
      );
      return jsonOk(result);
    }

    if (path.startsWith("/get/")) {
      let filename = decodeRequestValue(path.slice(5));
      filename = ensureLeadingSlash(filename);
      const obj = await env.WEBDAV_STORAGE.get(filename);
      if (!obj) return new Response("Not found", { status: 404 });
      return new Response(obj.body, {
        headers: getDownloadHeaders(obj, filename),
      });
    }

    // --- Job routes ---
    if (path === "/api/jobs/init" && method === "POST") {
      const body = await readBody(request);
      if (!body?.sourceUrl || !body?.filename)
        return jsonError("Missing sourceUrl or filename");
      let filename = normalizeStoragePath(body.filename);
      if (!body.force) {
        const existing = await env.WEBDAV_STORAGE.head(filename);
        if (existing)
          return jsonOk({ status: "exists", filename, size: existing.size });
      }
      const jobId = crypto.randomUUID();
      const id = env.DOWNLOAD_MANAGER.idFromName(jobId);
      return env.DOWNLOAD_MANAGER.get(id).fetch(
        new Request("https://do/init", {
          method: "POST",
          body: JSON.stringify({ sourceUrl: body.sourceUrl, filename, jobId }),
        }),
      );
    }

    if (path === "/api/jobs/chunk" && method === "POST") {
      const body = await readBody(request);
      if (!body?.jobId) return jsonError("Missing jobId");
      const id = env.DOWNLOAD_MANAGER.idFromName(body.jobId);
      return env.DOWNLOAD_MANAGER.get(id).fetch(
        new Request("https://do/chunk", {
          method: "POST",
          body: JSON.stringify(body),
        }),
      );
    }

    if (path === "/api/jobs/status" && method === "POST") {
      const body = await readBody(request);
      if (!body?.jobId) return jsonError("Missing jobId");
      const id = env.DOWNLOAD_MANAGER.idFromName(body.jobId);
      return env.DOWNLOAD_MANAGER.get(id).fetch(
        new Request("https://do/status"),
      );
    }

    if (path === "/api/jobs/finish" && method === "POST") {
      const body = await readBody(request);
      if (!body?.jobId) return jsonError("Missing jobId");
      const id = env.DOWNLOAD_MANAGER.idFromName(body.jobId);
      return env.DOWNLOAD_MANAGER.get(id).fetch(
        new Request("https://do/finish", { method: "POST" }),
      );
    }

    if (path === "/api/jobs/abort" && method === "POST") {
      const body = await readBody(request);
      if (!body?.jobId) return jsonError("Missing jobId");
      const id = env.DOWNLOAD_MANAGER.idFromName(body.jobId);
      return env.DOWNLOAD_MANAGER.get(id).fetch(
        new Request("https://do/abort", { method: "POST" }),
      );
    }

    // --- Share routes ---
    if (path === "/api/shares" && method === "GET")
      return handleListShares(env);
    if (path === "/api/shares/create" && method === "POST")
      return handleCreateShare(request, env);
    if (path === "/api/shares/revoke" && method === "POST") {
      const body = await readBody(request);
      if (!body?.token) return jsonError("Missing token");
      await env.WEBDAV_STORAGE.delete(`.tokens/${body.token}`);
      return jsonOk({ revoked: true });
    }

    return jsonError("Not Found: " + path, 404);
  } catch (e) {
    // ApiError (thrown by the shared storage helpers — getFileInfo,
    // relocateFile, etc.) carries the specific status this failure should
    // map to (404 "not found", 409 "already exists"...); anything else is
    // an unexpected failure, reported as a generic 500.
    if (e instanceof ApiError) return jsonError(e.message, e.status);
    return jsonError("Internal Error: " + e.message, 500);
  }
}
// ============================================================================
// CORS
// ============================================================================
// A single set of headers applied to every response from every handler so
// browser-based clients (web UIs, Claude.ai, custom dashboards) can call the
// API, MCP, and WebDAV endpoints cross-origin. The broad method/header lists
// cover REST, MCP (POST + x-api-key), and WebDAV (PROPFIND, COPY, MOVE, …)
// in one place rather than duplicating across handlers.
export const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods":
    "GET, HEAD, POST, PUT, DELETE, OPTIONS, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK",
  "Access-Control-Allow-Headers":
    "Content-Type, Authorization, x-api-key, Depth, Destination, Overwrite, DAV, If",
  "Access-Control-Expose-Headers": "DAV, Allow, Content-Length, Content-Type, ETag",
  "Access-Control-Max-Age": "86400",
};

export function withCors(response) {
  const r = new Response(response.body, response);
  for (const [k, v] of Object.entries(CORS_HEADERS)) r.headers.set(k, v);
  return r;
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;
      // Log only primitive fields, not the raw Request object: logging the
      // whole object (its AbortSignal in particular) has been observed to
      // trip up structured-clone-based log/IPC pipelines — notably Node's
      // test runner reporter when tests exercise this path directly.
      console.log("Incoming request:", { method, path });
      const rateCheck = checkRateAndBan(request, securityOptions);
      if (rateCheck instanceof Response) return rateCheck;

      // CORS preflight: browsers send OPTIONS before any cross-origin request.
      // /api and /mcp have no OPTIONS semantics of their own, so we answer
      // immediately with 204. WebDAV *does* use OPTIONS to advertise DAV
      // capabilities, so we let fetch_webdav handle it and add CORS headers
      // to its response via withCors() below.
      if (
        method === "OPTIONS" &&
        (path.startsWith("/api") || path === "/mcp" || path.startsWith("/get/") || path.startsWith("/s/"))
      ) {
        return new Response(null, { status: 204, headers: CORS_HEADERS });
      }

      // --- Public share (no auth) ---
      if (path.startsWith("/s/")) return withCors(await handlePublicShare(url, env));

      //-- API
      // "/get/<name>" is a plain, API-key-gated download link handled inside
      // fetch_api (see below); it must be routed there explicitly or it
      // falls through to the WebDAV handler further down, which would
      // instead require WebDAV Basic Auth and treat "get" as a literal
      // folder name in the file tree.
      if (path.startsWith("/api") || path.startsWith("/get/"))
        return withCors(await fetch_api(request, env));

      // MCP (Model Context Protocol) server: lets an MCP client (e.g. an
      // AI agent) list/read/write/delete/move files in this bucket as
      // tools, over the same API key auth /api/* uses. Routed explicitly
      // for the same reason "/get/" is above — otherwise it falls through
      // to WebDAV, which would require Basic Auth and treat "mcp" as a
      // literal folder name.
      if (path === "/mcp") return withCors(await fetch_mcp(request, env));

      if (
        (path === "/" || path === "/index.html") &&
        ["GET", "HEAD"].includes(method) &&
        looksLikeBrowserRequest(request)
      ) {
        return env.ASSETS.fetch(request);
      }

      //-- Webdav (OPTIONS passes through here so DAV capability headers are preserved)
      if (path.startsWith("/")) return withCors(await fetch_webdav(request, env));

      return withCors(jsonError("Not Found: " + path, 404));
    } catch (e) {
      return withCors(jsonError("Internal Error: " + e.message, 500));
    }
  },
};

// ============================================================================
// Route Handlers
// ============================================================================
async function handlePublicShare(url, env) {
  await ensureWorkerStorage(env);
  const settings = await getSettings(env);
  if (settings.maintenanceMode) {
    return new Response("Service is currently in maintenance mode", { status: 503 });
  }
  if (!settings.allowPublicShares) {
    return new Response("Public sharing is disabled by the administrator", { status: 403 });
  }
  const code = url.searchParams.get("code") || "";
  const token = url.pathname.split("/")[2];
  if (!token) return new Response("Missing token", { status: 400 });
  const tokenObj = await env.WEBDAV_STORAGE.get(`.tokens/${token}`);
  if (!tokenObj)
    return new Response("Invalid or expired link", { status: 404 });
  const meta = await tokenObj.json();
  if (meta.expires && Date.now() > meta.expires) {
    await env.WEBDAV_STORAGE.delete(`.tokens/${token}`);
    return new Response("Link expired", { status: 410 });
  }
  if (code !== meta.code) return new Response("Invalid code", { status: 403 });
  const filename = normalizeStoragePath(meta.filename);
  const obj = await env.WEBDAV_STORAGE.get(filename);
  if (!obj) return new Response("File not found", { status: 404 });
  return new Response(obj.body, { headers: getDownloadHeaders(obj, filename) });
}

export async function handleListFiles(url, env) {
  const prefix = ensureLeadingSlash(
    decodeRequestValue(url.searchParams.get("prefix") || ""),
  );
  const delimiter = url.searchParams.get("delimiter") || "";
  const cursor = url.searchParams.get("cursor") || undefined;
  const search = (url.searchParams.get("search") || "").toLowerCase();
  const limit = Math.min(
    parseInt(url.searchParams.get("limit") || "500"),
    1000,
  );

  const normalizedPrefix = prefix === "/" ? "/" : normalizeStoragePath(prefix);
  // Every key in this bucket carries a leading "/" (see normalizeStoragePath),
  // so listing the root with an *empty* R2 prefix but a "/" delimiter makes
  // R2 see that leading "/" as the very first delimiter match in every key
  // and group the entire bucket under one bogus "/" pseudo-folder instead of
  // returning root-level files/folders. Passing "/" itself as the prefix
  // keeps the delimiter grouping relative to it, exactly like it already is
  // for any non-root prefix below.
  let storagePrefix =
    normalizedPrefix === "/" ? "/" : normalizeStorageKey(normalizedPrefix);
  if (storagePrefix && delimiter && !storagePrefix.endsWith("/")) {
    storagePrefix += "/";
  }
  const baseOpts = { limit, include: ["customMetadata", "httpMetadata"] };
  if (storagePrefix) baseOpts.prefix = storagePrefix;
  if (delimiter) baseOpts.delimiter = delimiter;
  if (cursor) baseOpts.cursor = cursor;

  const listed = await env.WEBDAV_STORAGE.list(baseOpts);
  let listedFallback = null;
  if (
    normalizedPrefix === "/" &&
    delimiter === "/" &&
    (!listed.objects?.length || listed.objects.length === 0) &&
    (!listed.delimitedPrefixes?.length || listed.delimitedPrefixes.length === 0)
  ) {
    listedFallback = await env.WEBDAV_STORAGE.list({
      limit,
      include: ["customMetadata", "httpMetadata"],
    });
  }

  const collectedObjects = [];
  const collectedPrefixes = [];
  const seenKeys = new Set();

  for (const result of [listed, listedFallback].filter(Boolean)) {
    for (const object of result.objects || []) {
      // Internal bookkeeping keys (.tokens/, .jobs/, .settings/) are stored
      // WITHOUT a leading slash, unlike every user-facing file/folder key.
      // Must check that here, on the raw key, before normalizeStoragePath
      // unconditionally prepends "/" and turns ".tokens/x" into "/.tokens/x"
      // — which no longer starts with ".tokens/" and would otherwise slip
      // past the exclusion check below and appear as a bogus folder in the
      // file manager.
      if (
        object.key.startsWith(".tokens/") ||
        object.key.startsWith(".jobs/") ||
        object.key.startsWith(".settings/") ||
        object.key.startsWith(".fetch_cache/")
      )
        continue;
      const key = normalizeStoragePath(object.key);
      if (seenKeys.has(key)) continue;
      seenKeys.add(key);
      collectedObjects.push({ ...object, key });
    }
    for (const prefixCandidate of result.delimitedPrefixes || []) {
      const normalizedCandidate = normalizeStoragePath(prefixCandidate);
      if (
        normalizedCandidate &&
        normalizedCandidate !== "/" &&
        !normalizedCandidate.startsWith(".")
      ) {
        collectedPrefixes.push(
          normalizedCandidate.endsWith("/")
            ? normalizedCandidate
            : `${normalizedCandidate}/`,
        );
      }
    }
  }

  const fileEntries = [];
  const folderSet = new Set(collectedPrefixes);

  for (const object of collectedObjects) {
    const key = object.key;
    // .tokens/.jobs/.settings keys are already filtered out above, before
    // normalization; collectedObjects only ever contains normalized (leading
    // "/") keys here.
    if (!key || key === "/") continue;
    if (
      key.endsWith(".emptydir") ||
      key.endsWith("_meta") ||
      key.endsWith("_dir")
    )
      continue;

    const displayKey = normalizeStoragePath(key);
    const relative = displayKey.startsWith(normalizedPrefix)
      ? displayKey.slice(normalizedPrefix.length)
      : displayKey;
    const segments = relative.split("/").filter(Boolean);

    if (segments.length > 1) {
      const childFolder =
        normalizedPrefix === "/"
          ? normalizeStoragePath(`/${segments[0]}`)
          : normalizeStoragePath(`${normalizedPrefix}/${segments[0]}`);
      folderSet.add(
        childFolder.endsWith("/") ? childFolder : `${childFolder}/`,
      );
      continue;
    }

    if (segments.length === 1) {
      fileEntries.push({
        key,
        size: object.size,
        uploaded: object.uploaded,
        httpMetadata: object.httpMetadata || {},
        customMetadata: object.customMetadata || {},
      });
    }
  }

  let files = fileEntries;
  if (search) files = files.filter((f) => f.key.toLowerCase().includes(search));

  const folders = Array.from(folderSet)
    .filter((folder) => folder && folder !== "/" && !folder.startsWith("."))
    .sort((a, b) => a.localeCompare(b));

    console.log("list files search:",search);
    console.log("list files:",files);

  return jsonOk({
    files,
    folders,
    truncated: false,
    cursor: null,
  });
}

// Every folder path in the bucket, at any depth, derived from the keys
// themselves (a plain file's ancestor path segments, plus any directory
// marker's own path) rather than from a prefix+delimiter walk — this is the
// one place the app wants the *whole* tree flattened into one list, not one
// level at a time.
export async function handleListFolders(env) {
  const folders = new Set();
  let cursor;
  let pages = 0;
  do {
    const listed = await env.WEBDAV_STORAGE.list({ cursor, limit: 1000 });
    for (const object of listed.objects || []) {
      const key = object.key;
      if (
        key.startsWith(".tokens/") ||
        key.startsWith(".jobs/") ||
        key.startsWith(".settings/") ||
        key.startsWith(".fetch_cache/")
      )
        continue;
      let normalized = normalizeStoragePath(key);
      if (normalized.endsWith("_meta")) continue;
      let isDirMarker = false;
      if (normalized.endsWith("_dir")) {
        normalized = normalized.slice(0, -"_dir".length);
        isDirMarker = true;
      } else if (normalized.endsWith("/.emptydir")) {
        normalized = normalized.slice(0, -"/.emptydir".length);
        isDirMarker = true;
      }
      const segments = normalized.split("/").filter(Boolean);
      const dirSegments = isDirMarker ? segments : segments.slice(0, -1);
      let acc = "";
      for (const segment of dirSegments) {
        acc += `/${segment}`;
        folders.add(acc);
      }
    }
    cursor = listed.truncated ? listed.cursor : undefined;
    pages++;
    // Bound worst-case work for very large buckets; the dropdown this feeds
    // is a convenience, not a guarantee of completeness at that scale.
  } while (cursor && pages < 50);
  return jsonOk({ folders: Array.from(folders).sort() });
}

async function handleListShares(env) {
  const listed = await env.WEBDAV_STORAGE.list({
    prefix: ".tokens/",
    limit: 200,
  });
  const shares = [];
  for (const obj of listed.objects) {
    try {
      const raw = await env.WEBDAV_STORAGE.get(obj.key);
      const data = await raw.json();
      const token = obj.key.replace(".tokens/", "");
      shares.push({
        token,
        filename: data.filename,
        code: data.code,
        expires: data.expires,
        created: data.created,
        expired: data.expires ? Date.now() > data.expires : false,
        url: `/s/${token}?code=${data.code}`,
      });
    } catch {}
  }
  return jsonOk({ shares });
}

async function handleCreateShare(request, env) {
  const body = await readBody(request);
  if (!body?.filename) return jsonError("Missing filename");
  const hours = parseInt(body.hours ?? 24);
  const customCode = (body.customCode || "")
    .trim()
    .replace(/[^a-zA-Z0-9_-]/g, "");
  const code =
    customCode || crypto.randomUUID().replace(/-/g, "").substring(0, 8);
  const expires = hours >= 999 ? null : Date.now() + hours * 3600000;
  const token = btoa(body.filename)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  await env.WEBDAV_STORAGE.put(
    `.tokens/${token}`,
    JSON.stringify({
      filename: body.filename,
      expires,
      code,
      created: Date.now(),
    }),
  );
  return jsonOk({
    token,
    code,
    url: `/s/${token}?code=${code}`,
    expires: expires ? new Date(expires).toISOString() : null,
  });
}

function getDownloadHeaders(obj, filename) {
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set(
    "Content-Disposition",
    `attachment; filename="${baseName(filename)}"`,
  );
  headers.set("Content-Length", String(obj.size));
  headers.set("Cache-Control", "no-store");
  return headers;
}

// ============================================================================
// DURABLE OBJECT: DownloadManager
// ============================================================================
export class DownloadManager {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const cpuStart = performance.now();
    try {
      switch (url.pathname) {
        case "/init":
          return await this.doInit(request);
        case "/chunk":
          return await this.doChunk(request, cpuStart);
        case "/finish":
          return await this.doFinish();
        case "/status":
          return await this.doStatus();
        case "/abort":
          return await this.doAbort();
        default:
          return jsonError("Unknown DO route", 404);
      }
    } catch (e) {
      return jsonError("DO error: " + e.message, 500);
    }
  }

  async doInit(request) {
    const { sourceUrl, filename, jobId } = await request.json();
    const CHUNK = 20 * 1024 * 1024;

    let head = null;
    let totalSize = 0;
    let contentType = "application/octet-stream";
    let rangeOk = false;

    try {
      head = await fetch(sourceUrl, { method: "HEAD" });
      if (head.ok) {
        totalSize = parseInt(head.headers.get("content-length")) || 0;
        contentType = head.headers.get("content-type") || contentType;
        rangeOk = head.headers.get("accept-ranges") === "bytes";
      }
    } catch (e) {
      console.warn("doInit HEAD failed:", e.message);
    }

    console.log("doInit, url: ", sourceUrl);
    console.log("doInit, filename: ", filename);
    console.log("doInit, jobId: ", jobId);
    console.log("doInit, head.ok: ", head?.ok);
    console.log("doInit, rangeOk: ", rangeOk);
    console.log("doInit, totalSize: ", totalSize);

    if (!rangeOk && totalSize > 0) {
      try {
        const probe = await fetch(sourceUrl, {
          headers: { Range: "bytes=0-0" },
        });
        if (probe.status === 206) {
          rangeOk = true;
          const rangeHeader = probe.headers.get("content-range") || "";
          const sizeMatch = rangeHeader.match(/\/(\d+)$/);
          if (sizeMatch) totalSize = Number(sizeMatch[1]);
        }
      } catch (e) {
        console.warn("doInit range probe failed:", e.message);
      }
    }

    if (!rangeOk && totalSize === 0) {
      try {
        const probe = await fetch(sourceUrl, {
          headers: { Range: "bytes=0-0" },
        });
        if (probe.ok) {
          const rangeHeader = probe.headers.get("content-range") || "";
          const sizeMatch = rangeHeader.match(/\/(\d+)$/);
          if (sizeMatch) {
            totalSize = Number(sizeMatch[1]);
            rangeOk = probe.status === 206;
          } else {
            const contentLength =
              parseInt(probe.headers.get("content-length")) || 0;
            if (contentLength > 0) {
              totalSize = contentLength;
              rangeOk = probe.status === 206;
            }
          }
        }
      } catch (e) {
        console.warn("doInit fallback probe failed:", e.message);
      }
    }

    if (!rangeOk || totalSize === 0 || totalSize < CHUNK) {
      await this.state.storage.put("status", {
        mode: "single",
        status: "downloading",
        filename,
        totalSize,
        started: Date.now(),
      });
      this.state.waitUntil(this.singleStream(sourceUrl, filename, contentType));
      return jsonOk({ mode: "single", totalSize, jobId });
    }

    const mp = await this.env.WEBDAV_STORAGE.createMultipartUpload(filename, {
      httpMetadata: { contentType },
      customMetadata: { source: sourceUrl, timestamp: Date.now().toString() },
    });

    const ranges = [];
    let s = 0,
      p = 1;
    while (s < totalSize) {
      const e = Math.min(s + CHUNK - 1, totalSize - 1);
      ranges.push({ partNumber: p++, start: s, end: e });
      s += CHUNK;
    }

    await this.state.storage.put("job", {
      uploadId: mp.uploadId,
      filename,
      sourceUrl,
      totalSize,
      totalParts: ranges.length,
    });
    await this.state.storage.put("status", {
      mode: "parallel",
      status: "downloading",
      filename,
      totalSize,
      totalParts: ranges.length,
      completedParts: 0,
      bytesDownloaded: 0,
      started: Date.now(),
    });

    return jsonOk({ mode: "parallel", totalSize, ranges, jobId });
  }

  async doChunk(request, cpuStart) {
    try {
      const { partNumber, start, end } = await request.json();
      const job = await this.state.storage.get("job");
      if (!job) return jsonOk({ status: "failed", error: "No active job" });
      if (await this.state.storage.get("aborted"))
        return jsonOk({ status: "failed", error: "Job aborted" });

      const mp = this.env.WEBDAV_STORAGE.resumeMultipartUpload(
        job.filename,
        job.uploadId,
      );
      const res = await fetch(job.sourceUrl, {
        headers: { Range: `bytes=${start}-${end}` },
      });
      if (res.status !== 206 && res.status !== 200) {
        return jsonOk({
          status: "failed",
          error: "Range request failed: " + res.status,
        });
      }

      const part = await mp.uploadPart(partNumber, res.body);
      await this.state.storage.put(`part_${partNumber}`, {
        partNumber,
        etag: part.etag,
      });

      const chunkSize = end - start + 1;
      const status = await this.state.storage.get("status");
      if (status) {
        status.completedParts = (status.completedParts || 0) + 1;
        status.bytesDownloaded = (status.bytesDownloaded || 0) + chunkSize;
        await this.state.storage.put("status", status);
      }

      return jsonOk({
        status: "done",
        partNumber,
        chunkSize,
        cpuTime: performance.now() - cpuStart,
      });
    } catch (e) {
      return jsonOk({ status: "failed", error: e.message });
    }
  }

  async doFinish() {
    const job = await this.state.storage.get("job");
    if (!job) return jsonError("No active job", 404);

    const partEntries = await this.state.storage.list({ prefix: "part_" });
    const parts = Array.from(partEntries.values()).sort(
      (a, b) => a.partNumber - b.partNumber,
    );
    if (!parts.length) return jsonError("No parts uploaded");

    const mp = this.env.WEBDAV_STORAGE.resumeMultipartUpload(
      job.filename,
      job.uploadId,
    );
    await mp.complete(parts);

    await this.state.storage.put("status", {
      mode: "parallel",
      status: "completed",
      filename: job.filename,
      totalSize: job.totalSize,
      totalParts: job.totalParts,
      completedParts: job.totalParts,
      finished: Date.now(),
    });
    const delKeys = ["job", ...Array.from(partEntries.keys())];
    await this.state.storage.delete(delKeys);

    return jsonOk({ status: "completed", filename: job.filename });
  }

  async doStatus() {
    const status = await this.state.storage.get("status");
    return jsonOk(status || { status: "idle" });
  }

  async doAbort() {
    await this.state.storage.put("aborted", true);
    const job = await this.state.storage.get("job");
    if (job) {
      try {
        this.env.WEBDAV_STORAGE.resumeMultipartUpload(
          job.filename,
          job.uploadId,
        ).abort();
      } catch {}
    }
    await this.state.storage.put("status", { status: "aborted" });
    await this.state.storage.delete("job");
    return jsonOk({ status: "aborted" });
  }

  async singleStream(sourceUrl, filename, contentType) {
    try {
      const res = await fetch(sourceUrl);
      const body = await res.arrayBuffer();
      await this.env.WEBDAV_STORAGE.put(filename, body, {
        httpMetadata: { contentType },
        customMetadata: { source: sourceUrl, timestamp: Date.now().toString() },
      });
      await this.state.storage.put("status", {
        mode: "single",
        status: "completed",
        filename,
        finished: Date.now(),
      });
    } catch (e) {
      await this.state.storage.put("status", {
        mode: "single",
        status: "failed",
        filename,
        error: e.message,
      });
    }
  }
}
