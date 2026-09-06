// Web Crypto API 辅助函数
async function generateRandomString(length = 32) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// SHA-256 哈希函数
async function sha256(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// 常量时间字符串比较：先对两个值做定长的 SHA-256 摘要，再逐字节异或累加比较，
// 不做提前返回。用于比较凭据（WebDAV 用户名/密码、API Key），避免像
// `a === b` 这种一旦发现不同字符就立刻短路返回的比较方式，被用来通过响应
// 时间差逐字符猜测出正确的密钥。
export async function timingSafeEqual(a, b) {
  const [hashA, hashB] = await Promise.all([sha256(String(a ?? '')), sha256(String(b ?? ''))]);
  let diff = hashA.length ^ hashB.length;
  const len = Math.max(hashA.length, hashB.length);
  for (let i = 0; i < len; i++) {
    diff |= (hashA.charCodeAt(i) || 0) ^ (hashB.charCodeAt(i) || 0);
  }
  return diff === 0;
}

// 安全相关配置（管理员未在系统设置中覆盖时使用的默认值）
const RATE_LIMIT_WINDOW = 60 * 1000; // 1分钟窗口
const MAX_REQUESTS_PER_WINDOW = 60; // 每分钟最多60个请求
const MAX_UPLOAD_SIZE = 10 * 1024 * 1024; // 最大上传大小10MB

// ============================================================================
// SYSTEM SETTINGS
// ============================================================================
// Admin-configurable runtime settings, persisted as a single JSON object in
// the same WEBDAV_STORAGE bucket. This is separate from Wrangler secrets
// (AUTH_KEY, WEBDAV_USERNAME/PASSWORD): those still gate access at the
// platform level, while these knobs are meant to be changed from the app's
// own Admin panel without a redeploy.
// Deliberately no leading "/": every user-facing key in this app is stored
// with a leading slash (see normalizePath), and both the WebDAV directory
// listing and the /api/files listing treat a leading "/" as "just another
// path segment" — a dot-prefixed leading segment only gets filtered out of
// listings by name (".tokens/", ".jobs/", …), which requires no leading
// slash. Keeping this key in the same no-slash "hidden namespace" as those
// existing internal keys keeps it out of the file manager UI.
const SETTINGS_KEY = ".settings/system.json";

export const DEFAULT_SETTINGS = {
  siteTitle: "R2 Drive",
  maxUploadSizeMB: MAX_UPLOAD_SIZE / (1024 * 1024),
  rateLimitPerMinute: MAX_REQUESTS_PER_WINDOW,
  defaultShareHours: 24,
  allowPublicShares: true,
  maintenanceMode: false,
  webdavEnabled: true,
  // The R2 key prefix WebDAV clients see as "/". Lets an admin scope the
  // WebDAV-exposed namespace to a subfolder of the bucket instead of the
  // whole thing. Always resolved through normalizeWebdavRoot() before use —
  // an empty, missing, or otherwise invalid value always falls back to '/'
  // rather than ever leaving WebDAV unable to resolve a root at all.
  webdavRootPath: "/",
};

// Validates/normalizes a candidate WebDAV root path, always returning a safe
// value: a normalized absolute path with no ".." traversal segments, or '/'
// for anything empty, non-string, or otherwise unusable. Every caller that
// reads settings.webdavRootPath must go through this rather than trust the
// stored value directly, since it's meant to be admin-editable free text.
export function normalizeWebdavRoot(root) {
  if (typeof root !== "string") return "/";
  const trimmed = root.trim();
  if (!trimmed) return "/";
  const normalized = normalizePath(trimmed);
  if (normalized.split("/").some((segment) => segment === "..")) return "/";
  return normalized;
}

// Maps a path as seen by a WebDAV client (relative to its mounted root) to
// the real R2 key it corresponds to in the bucket.
export function webdavPathToStorage(davPath, root) {
  const normalizedRoot = normalizeWebdavRoot(root);
  if (normalizedRoot === "/") return normalizePath(davPath);
  const rel = normalizePath(davPath);
  if (rel === "/") return normalizedRoot;
  return normalizePath(normalizedRoot + rel);
}

// The inverse of webdavPathToStorage(): maps a real R2 key back to the path
// a WebDAV client should see for it (relative to its mounted root). Used
// anywhere a path is written into a response — PROPFIND hrefs, the
// directory-listing HTML, Content-Location — so clients never see storage
// keys outside their configured root.
export function storagePathToWebdav(storagePath, root) {
  const normalizedRoot = normalizeWebdavRoot(root);
  if (normalizedRoot === "/") return storagePath;
  if (storagePath === normalizedRoot) return "/";
  if (storagePath.startsWith(`${normalizedRoot}/`)) {
    return storagePath.slice(normalizedRoot.length) || "/";
  }
  // Outside the configured root — shouldn't normally happen since every
  // storage path handled here originated from webdavPathToStorage() in the
  // first place. Returned as-is rather than throwing.
  return storagePath;
}

export async function getSettings(env) {
  ensureR2CompatibleStorage(env);
  try {
    const obj = await env.WEBDAV_STORAGE.get(SETTINGS_KEY);
    if (!obj) return { ...DEFAULT_SETTINGS };
    const stored = await obj.json();
    return { ...DEFAULT_SETTINGS, ...stored };
  } catch (error) {
    console.error("读取系统设置失败，使用默认值:", error);
    return { ...DEFAULT_SETTINGS };
  }
}

// 仅接受已知字段，并做基本的类型/范围校验，防止管理面板提交的畸形数据破坏运行时配置
export function sanitizeSettingsPatch(body) {
  const out = {};
  if (!body || typeof body !== "object") return out;
  if (typeof body.siteTitle === "string" && body.siteTitle.trim()) {
    out.siteTitle = body.siteTitle.trim().slice(0, 60);
  }
  if (Number.isFinite(body.maxUploadSizeMB)) {
    out.maxUploadSizeMB = Math.min(Math.max(1, body.maxUploadSizeMB), 5000);
  }
  if (Number.isFinite(body.rateLimitPerMinute)) {
    out.rateLimitPerMinute = Math.min(Math.max(1, body.rateLimitPerMinute), 10000);
  }
  if (Number.isFinite(body.defaultShareHours)) {
    out.defaultShareHours = Math.min(Math.max(1, body.defaultShareHours), 999);
  }
  if (typeof body.webdavRootPath === "string") {
    // Always normalized rather than rejected outright: a bad/empty value
    // resolves to '/' here too, so WebDAV can never end up unable to
    // resolve a root because of a malformed admin-panel submission.
    out.webdavRootPath = normalizeWebdavRoot(body.webdavRootPath);
  }
  for (const key of ["allowPublicShares", "maintenanceMode", "webdavEnabled"]) {
    if (typeof body[key] === "boolean") out[key] = body[key];
  }
  return out;
}

export async function saveSettings(env, patch) {
  ensureR2CompatibleStorage(env);
  const current = await getSettings(env);
  const next = { ...current, ...sanitizeSettingsPatch(patch) };
  await env.WEBDAV_STORAGE.put(SETTINGS_KEY, JSON.stringify(next));
  return next;
}

function createR2CompatibleStorage(storage) {
  if (!storage || storage.__webdavCompat) return storage;

  const adapter = {
    __webdavCompat: true,
    async get(key, type) {
      const object = await storage.get(key);
      if (!object) return null;

      if (type === 'json') {
        try {
          return await object.json();
        } catch {
          return null;
        }
      }

      if (type === 'arrayBuffer') return object.arrayBuffer();
      if (type === 'text') return object.text();
      return object;
    },
    async put(key, value, options = {}) {
      const normalizedOptions = { ...options };
      if (normalizedOptions.expirationTtl !== undefined) {
        delete normalizedOptions.expirationTtl;
      }

      if (value && typeof value === 'object' && !(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value) && !(value instanceof Blob)) {
        return storage.put(key, JSON.stringify(value), normalizedOptions);
      }

      return storage.put(key, value, normalizedOptions);
    },
    async delete(key) {
      return storage.delete(key);
    },
    async head(key) {
      return storage.head(key);
    },
    async list(options = {}) {
      const result = await storage.list(options);
      const objects = (result.objects || []).map(obj => ({ ...obj, name: obj.key, keyName: obj.key }));
      return { ...result, keys: objects, objects };
    },
    createMultipartUpload(key, options) {
      return storage.createMultipartUpload(key, options);
    },
    resumeMultipartUpload(key, uploadId) {
      return storage.resumeMultipartUpload(key, uploadId);
    }
  };

  return new Proxy(adapter, {
    get(target, prop, receiver) {
      if (prop in target) return Reflect.get(target, prop, receiver);
      if (typeof storage[prop] === 'function') return storage[prop].bind(storage);
      return storage[prop];
    },
    set(target, prop, value) {
      if (prop in target) {
        target[prop] = value;
        return true;
      }
      storage[prop] = value;
      return true;
    },
    has(target, prop) {
      return prop in target || prop in storage;
    }
  });
}

function ensureR2CompatibleStorage(env) {
  if (!env || !env.WEBDAV_STORAGE) return env;
  if (!env.WEBDAV_STORAGE.__webdavCompat) {
    env.WEBDAV_STORAGE = createR2CompatibleStorage(env.WEBDAV_STORAGE);
  }
  return env;
}

// _worker.js drives the /api/* routes on the same WEBDAV_STORAGE bucket and
// needs these same path/key helpers to stay consistent with the WebDAV
// routes below (e.g. a file uploaded via /api/upload must be reachable via
// GET /<name> and vice versa). Export them instead of duplicating the logic.
export { ensureR2CompatibleStorage, getParentPath };
export function normalizeStoragePath(path) {
  return normalizePath(path);
}
export function normalizeStorageKey(path) {
  return normalizePath(path);
}
export function joinStoragePath(base, path) {
  return joinPath(base, path);
}

// 请求速率限制实现（每分钟最大请求数可通过管理面板的系统设置覆盖）
async function applyRateLimit(request, env, maxRequestsPerWindow = MAX_REQUESTS_PER_WINDOW) {
  try {
    // 使用内存缓存而不是KV存储来减少KV读取
    const cache = applyRateLimit.cache || (applyRateLimit.cache = new Map());
    const now = Date.now();

    // 获取客户端IP
    const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';

    // 清理过期的记录
    const cutoff = now - RATE_LIMIT_WINDOW;
    for (const [ip, data] of cache.entries()) {
      if (data.timestamp < cutoff) {
        cache.delete(ip);
      }
    }

    // 检查并更新请求计数
    if (cache.has(clientIP)) {
      const data = cache.get(clientIP);

      // 检查是否超出限制
      if (data.count >= maxRequestsPerWindow) {
        return new Response('请求过于频繁，请稍后再试', {
          status: 429,
          headers: {
            'Retry-After': Math.ceil((data.timestamp + RATE_LIMIT_WINDOW - now) / 1000).toString(),
            'Content-Type': 'text/plain; charset=utf-8'
          }
        });
      }

      // 更新计数
      data.count++;
    } else {
      // 新的客户端记录
      cache.set(clientIP, {
        timestamp: now,
        count: 1
      });
    }

    return null;
  } catch (error) {
    console.error('速率限制检查失败:', error);
    // 速率限制检查失败不应阻止请求，但应记录错误
    return null;
  }
}

// 处理请求的主函数
// export default {

// };

export async function fetch_webdav(request, env, ctx) {
  try {
    ensureR2CompatibleStorage(env);

    const settings = await getSettings(env);

    // 维护模式会暂时阻断所有对外访问（WebDAV、公开分享链接），
    // 但保留受 API Key 保护的管理接口，以便管理员随时关闭维护模式
    if (settings.maintenanceMode) {
      return new Response('服务当前处于维护模式', {
        status: 503,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '300' }
      });
    }

    // 管理员可在系统设置中整体关闭 WebDAV 服务
    if (!settings.webdavEnabled) {
      return new Response('WebDAV 服务已被管理员禁用', {
        status: 503,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '3600' }
      });
    }

    // 应用请求速率限制（限额可在系统设置中调整）
    const rateLimited = await applyRateLimit(request, env, settings.rateLimitPerMinute);
    if (rateLimited) {
      return rateLimited;
    }

    // 安全地解析URL
    let url;
    try {
      // 直接使用 request.url 创建 URL 对象
      url = new URL(request.url);
    } catch (e) {
      // 如果 URL 解析失败，可能是因为 request.url 只是路径部分（如 "/"）
      // 从请求头获取必要信息构建完整 URL
      const host = request.headers.get('Host') || 'localhost';
      const protocol = request.headers.get('X-Forwarded-Proto') ||
        (request.url.startsWith('https://') ? 'https' : 'http');

      // 确保 request.url 是有效的路径
      let requestPath = request.url;
      if (!requestPath.startsWith('/')) {
        requestPath = `/${requestPath}`;
      }

      // 构建完整 URL
      const fullUrl = `${protocol}://${host}${requestPath}`;
      try {
        url = new URL(fullUrl);
      } catch (innerError) {
        // 如果构建的 URL 仍然无效，使用默认值
        console.warn('无法构建完整 URL，使用默认值:', fullUrl);
        url = new URL(`${protocol}://${host}/`);
      }
    }
    const path = url.pathname;

    // 处理根路径
    // 不再拦截根路径请求，让WebDAV服务正常处理根路径
    // WebDAV客户端需要能够访问根目录以列出文件和目录

    // 处理 WebDAV 请求，直接运行在根路径
    try {
      // 处理登出请求
      if (path === '/logout') {
        // 清除 session 和 cookie
        const cookieHeader = request.headers.get('Cookie');
        if (cookieHeader) {
          const tokenMatch = cookieHeader.match(/webdav_auth=([^;]+)/);
          if (tokenMatch && tokenMatch[1]) {
            const token = tokenMatch[1];
            const tokenKey = `session_${token}`;
            // 删除KV中的session数据
            try {
              await env.WEBDAV_STORAGE.delete(tokenKey);
            } catch (error) {
              console.error('删除session失败:', error);
            }
          }
        }

        // 清除cookie
        const protocol = request.url.startsWith('https://') ? 'https://' : 'http://';
        const host = request.headers.get('Host') || 'localhost';
        const redirectUrl = `${protocol}${host}/`;

        const isHttps = request.url.startsWith('https://');
        const secureFlag = isHttps ? 'Secure;' : '';

        return new Response(null, {
          status: 302,
          headers: {
            'Location': redirectUrl,
            'Set-Cookie': `webdav_auth=; Path=/; HttpOnly; ${secureFlag} SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
            'Content-Type': 'text/plain; charset=utf-8'
          }
        });
      }

      // 对所有请求进行身份验证
      const authResult = await authenticateWebDAV(request, env);
      if (!authResult.authenticated) {
        recordAuthResult(request, false);

        return authResult.response;
      }
        recordAuthResult(request, true);


      // 添加CSRF令牌到响应的辅助函数
      const addCsrfToken = (response) => {
        const responseHeaders = new Headers(response.headers);
        if (authResult.csrfToken) {
          responseHeaders.set('X-CSRF-Token', authResult.csrfToken);
        }
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders
        });
      };

      // 确保路径规范化，特别是处理根路径时
      const davPath = path === '/' ? '/' : path;

      // 管理员可在系统设置中配置一个自定义 WebDAV 根路径（存储桶内的某个
      // 前缀），客户端看到的所有路径都相对于它。请求路径在这里统一换算成
      // 真实的存储路径，交给下面各 handler 处理；各 handler 生成响应中的
      // href/Content-Location 等面向客户端的路径时，再换算回客户端视角。
      const webdavRoot = normalizeWebdavRoot(settings.webdavRootPath);
      const storagePath = webdavPathToStorage(davPath, webdavRoot);

      // 处理 WebDAV 方法
      switch (request.method) {
        case 'OPTIONS':
          return addCsrfToken(handleOptions());
        case 'PROPFIND':
          return addCsrfToken(await handlePropfind(request, env, storagePath, webdavRoot));
        case 'GET':
          return addCsrfToken(await handleGet(env, storagePath, request, webdavRoot));
        case 'HEAD':
          // 处理HEAD请求，与GET类似但不返回内容
          const getResponse = await handleGet(env, storagePath, request, webdavRoot);
          return addCsrfToken(new Response(null, {
            headers: getResponse.headers,
            status: getResponse.status
          }));
        case 'PUT':
          // 检查上传大小限制（可在系统设置中调整）
          const contentLength = request.headers.get('Content-Length');
          const maxUploadBytes = (settings.maxUploadSizeMB || DEFAULT_SETTINGS.maxUploadSizeMB) * 1024 * 1024;
          if (contentLength && parseInt(contentLength) > maxUploadBytes) {
            return addCsrfToken(new Response('上传文件过大', {
              status: 413,
              headers: {
                'Content-Type': 'text/plain; charset=utf-8'
              }
            }));
          }
          return addCsrfToken(await handlePut(request, env, storagePath, webdavRoot));
        case 'DELETE':
          return addCsrfToken(await handleDelete(env, storagePath));
        case 'MKCOL':
          return addCsrfToken(await handleMkcol(env, storagePath, webdavRoot));
        // 添加更多WebDAV方法支持
        case 'COPY':
          return addCsrfToken(await handleCopy(request, env, storagePath, webdavRoot));
        case 'MOVE':
          return addCsrfToken(await handleMove(request, env, storagePath, webdavRoot));
        case 'PROPPATCH':
          // PROPPATCH方法用于修改资源属性，基本实现以支持更多客户端
          return addCsrfToken(new Response(null, {
            status: 204,
            headers: {
              'DAV': '1, 2, 3',
              'MS-Author-Via': 'DAV',
              'Allow': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL, COPY, MOVE, PROPPATCH',
              'X-Content-Type-Options': 'nosniff'
            }
          }));
        case 'LOCK':
        case 'UNLOCK':
          // 基本的LOCK/UNLOCK支持，返回200以支持更多客户端
          return addCsrfToken(new Response(null, {
            status: 200,
            headers: {
              'DAV': '1, 2, 3',
              'MS-Author-Via': 'DAV',
              'Allow': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL, COPY, MOVE, PROPPATCH, LOCK, UNLOCK',
              'X-Content-Type-Options': 'nosniff'
            }
          }));
        case 'POST':
          // 处理POST请求（用于创建文件夹、上传文件等操作）
          return addCsrfToken(await handlePost(request, env, storagePath));
        default:
          // 为不支持的方法返回更友好的响应，确保移动文件管理器兼容性
          return addCsrfToken(new Response('方法不支持', {
            status: 200,
            headers: {
              'Allow': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL',
              'DAV': '1, 2, 3',
              'MS-Author-Via': 'DAV',
              'X-Content-Type-Options': 'nosniff',
              'Content-Length': '0',
              'Access-Control-Allow-Origin': '*',
              'Public': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL'
            }
          }));
      }
      // 不再区分路径，所有请求都视为WebDAV请求
      // 移除非/dav路径返回404的逻辑
    } catch (error) {
      console.error('处理WebDAV请求时发生错误:', error);
      // 不向客户端暴露详细错误信息
      return addCsrfToken(new Response('服务器内部错误', {
        status: 500,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'X-Content-Type-Options': 'nosniff'
        }
      }));
    }
  } catch (error) {
    console.error('请求处理错误:', error);
    return new Response('内部服务器错误', {
      status: 500,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Content-Type-Options': 'nosniff'
      }
    });
  }
}

// 不再使用session，直接使用认证方式处理请求

// 渲染登录页面
function renderLoginPage(errorMessage = '') {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>文件管理登录</title>
  <style>
    /* 全局样式 */
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    
    /* 登录容器 */
    .login-container {
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
      padding: 40px;
      width: 100%;
      max-width: 420px;
    }
    
    /* 标题 */
    h1 {
      color: #2d3748;
      font-size: 28px;
      font-weight: 700;
      margin-bottom: 30px;
      text-align: center;
    }
    
    /* 表单组 */
    .form-group {
      margin-bottom: 24px;
    }
    
    /* 标签 */
    label {
      display: block;
      color: #4a5568;
      font-weight: 500;
      margin-bottom: 8px;
    }
    
    /* 输入框 */
    .form-input {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e2e8f0;
      border-radius: 8px;
      font-size: 16px;
      transition: all 0.2s ease;
      background: #f7fafc;
    }
    
    .form-input:focus {
      outline: none;
      border-color: #667eea;
      background: white;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    
    /* 错误信息 */
    .error-message {
      background: #fed7d7;
      color: #c53030;
      padding: 12px;
      border-radius: 6px;
      margin-bottom: 20px;
      font-size: 14px;
      text-align: center;
      border: 1px solid #feb2b2;
    }
    
    /* 登录按钮 */
    .login-button {
      width: 100%;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      padding: 14px;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      margin-bottom: 16px;
    }
    
    .login-button:hover {
      transform: translateY(-1px);
      box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
    }
    
    .login-button:active {
      transform: translateY(0);
    }
    
    /* 页脚 */
    .footer {
      text-align: center;
      color: #718096;
      font-size: 14px;
      margin-top: 20px;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>文件管理登录</h1>
    ${errorMessage ? `<div class="error-message">${errorMessage}</div>` : ''}
    <form method="POST" action="/login">
      <div class="form-group">
        <label for="username">用户名</label>
        <input type="text" id="username" name="username" class="form-input" required>
      </div>
      <div class="form-group">
        <label for="password">密码</label>
        <input type="password" id="password" name="password" class="form-input" required>
      </div>
      <button type="submit" class="login-button">登录</button>
    </form>
    <div class="footer">
      文件管理服务 &copy; ${new Date().getFullYear()}
    </div>
  </div>
</body>
</html>`;
}

// WebDAV 认证函数
async function authenticateWebDAV(request, env) {
  try {
    // 初始化响应头，用于传递CSRF令牌
    const responseHeaders = new Headers();
    // 确保URL是完整的
    let url;
    try {
      // 直接使用 request.url 创建 URL 对象
      url = new URL(request.url);
    } catch (e) {
      // 如果 URL 解析失败，可能是因为 request.url 只是路径部分（如 "/"）
      // 从请求头获取必要信息构建完整 URL
      const host = request.headers.get('Host') || 'localhost';
      const protocol = request.headers.get('X-Forwarded-Proto') || 'http';

      // 确保 request.url 是有效的路径
      let requestPath = request.url;
      if (!requestPath.startsWith('/')) {
        requestPath = `/${requestPath}`;
      }

      // 构建完整 URL
      const fullUrl = `${protocol}://${host}${requestPath}`;
      try {
        url = new URL(fullUrl);
      } catch (innerError) {
        // 如果构建的 URL 仍然无效，使用默认值
        console.warn('无法构建完整 URL，使用默认值:', fullUrl);
        url = new URL(`${protocol}://${host}/`);
      }
    }
    const path = url.pathname;

    // 处理登录请求
    if (path === '/login' && request.method === 'POST') {
      try {
        console.log('开始处理登录请求');
        // 解析表单数据
        const formData = await request.formData();
        console.log('表单数据解析成功');
        const username = formData.get('username');
        const password = formData.get('password');

        console.log('登录表单数据:', { username, password: password ? '[已提供]' : '[未提供]' });

        // 验证凭据
        if (!username || !password) {
          throw new Error('用户名或密码不能为空');
        }

        const isValid = await verifyWebDAVCredentials(env, username, password);

        if (isValid) {
          console.log('登录成功，生成安全令牌和CSRF令牌');
          // 使用完整的URL进行重定向，避免解析错误
          const protocol = request.url.startsWith('https://') ? 'https://' : 'http://';
          const host = request.headers.get('Host') || 'localhost';
          const redirectUrl = `${protocol}${host}/`;

          // 生成随机令牌
          const token = await generateRandomString(64);
          // 生成CSRF令牌
          const csrfToken = await generateRandomString(32);
          const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24小时后过期

          // 将令牌和CSRF令牌存储在KV中
          const tokenKey = `session_${token}`;
          await env.WEBDAV_STORAGE.put(tokenKey, JSON.stringify({
            username,
            createdAt: Date.now(),
            expiresAt,
            csrfToken
          }), { expirationTtl: 24 * 60 * 60 }); // 设置过期时间

          // 创建一个新的响应对象而不是使用Response.redirect()，这样可以修改响应头
          const isHttps = request.url.startsWith('https://');
          const secureFlag = isHttps ? 'Secure;' : '';
          const response = new Response(null, {
            status: 302,
            headers: {
              'Location': redirectUrl,
              'Set-Cookie': `webdav_auth=${token}; Path=/; HttpOnly; ${secureFlag} SameSite=Strict; Max-Age=86400`,
              'X-CSRF-Token': csrfToken,
              'Content-Type': 'text/plain; charset=utf-8'
            }
          });
          return { authenticated: false, response };
        } else {
          console.log('登录失败：用户名或密码错误');
          // 登录失败，显示错误信息
          const html = renderLoginPage('用户名或密码错误');
          return {
            authenticated: false,
            response: new Response(html, {
              status: 401,
              headers: {
                'Content-Type': 'text/html; charset=utf-8'
              }
            })
          };
        }
      } catch (error) {
        console.error('登录处理错误:', error);
        console.error('错误堆栈:', error.stack);
        // 登录失败时不创建会话
        const html = renderLoginPage('登录过程中出错: ' + error.message);
        return {
          authenticated: false,
          response: new Response(html, {
            status: 500,
            headers: {
              'Content-Type': 'text/html; charset=utf-8'
            }
          })
        };
      }
    }

    // 检查认证cookie
    const cookieHeader = request.headers.get('Cookie');
    if (cookieHeader) {
      // 提取令牌
      const tokenMatch = cookieHeader.match(/webdav_auth=([^;]+)/);
      if (tokenMatch && tokenMatch[1]) {
        const token = tokenMatch[1];
        const tokenKey = `session_${token}`;

        try {
          // 从KV中获取令牌信息
          const sessionData = await env.WEBDAV_STORAGE.get(tokenKey, 'json');

          if (sessionData && sessionData.expiresAt > Date.now()) {
            // 令牌有效，实现滑动过期：更新过期时间
            const newExpiresAt = Date.now() + 86400 * 1000; // 24小时后过期
            await env.WEBDAV_STORAGE.put(tokenKey, JSON.stringify({
              ...sessionData,
              expiresAt: newExpiresAt
            }), { expirationTtl: 86400 });
            // 返回认证成功和CSRF令牌
            return { authenticated: true, csrfToken: sessionData.csrfToken };
          } else if (sessionData && sessionData.expiresAt <= Date.now()) {
            // 令牌已过期，清理KV
            await env.WEBDAV_STORAGE.delete(tokenKey);
          }
        } catch (error) {
          console.error('验证令牌时出错:', error);
        }
      }
    }

    // 检查Basic Auth（用于WebDAV客户端）
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Basic ')) {
      // 解码 Basic 认证凭据
      const encodedCredentials = authHeader.slice('Basic '.length);

      // 安全解码
      let decodedCredentials;
      try {
        decodedCredentials = atob(encodedCredentials);
      } catch (e) {
        console.error('凭据解码错误:', e);
        return {
          authenticated: false,
          response: new Response('无效的认证凭据', {
            status: 401,
            headers: {
              'WWW-Authenticate': 'Basic realm="WebDAV Server"',
              'DAV': '1, 2',
              'Content-Type': 'text/plain; charset=utf-8'
            }
          })
        };
      }

      const separatorIndex = decodedCredentials.indexOf(':');
      if (separatorIndex === -1) {
        return {
          authenticated: false,
          response: new Response('无效的认证凭据格式', {
            status: 401,
            headers: {
              'WWW-Authenticate': 'Basic realm="WebDAV Server"',
              'DAV': '1, 2',
              'Content-Type': 'text/plain; charset=utf-8'
            }
          })
        };
      }

      const username = decodedCredentials.substring(0, separatorIndex);
      const password = decodedCredentials.substring(separatorIndex + 1);

      // 验证凭据
      const isValid = await verifyWebDAVCredentials(env, username, password);

      if (isValid) {
        return { authenticated: true };
      }
    }

    // 对于浏览器访问，返回登录页面
    const userAgent = request.headers.get('User-Agent');
    if (userAgent && (userAgent.includes('Mozilla') || userAgent.includes('Chrome') || userAgent.includes('Safari'))) {
      const html = renderLoginPage();
      return {
        authenticated: false,
        response: new Response(html, {
          status: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8'
          }
        })
      };
    }

    // 对于WebDAV客户端，返回Basic Auth挑战
    return {
      authenticated: false,
      response: new Response('WebDAV 需要认证', {
        status: 401,
        headers: {
          'WWW-Authenticate': 'Basic realm="WebDAV Server"',
          'DAV': '1, 2, 3',
          'Content-Type': 'text/plain; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          'MS-Author-Via': 'DAV',
          'Public': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL'
        }
      })
    };
  } catch (error) {
    console.error('WebDAV 认证错误:', error);
    return {
      authenticated: false,
      response: new Response('认证过程中出错', {
        status: 500,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8'
        }
      })
    };
  }
}

// 注意：generateCSRFToken函数已在文件顶部定义为异步版本，这里不再重复定义

// HTML 转义函数，防止 XSS
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// handleLoginPage 和 renderLoginPage 函数已删除（不再需要登录功能）






async function sha256Legacy(password, salt) {
  try {
    // 将密码和盐值转换为字节数组
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password + salt);

    // 计算哈希
    const hashBuffer = await crypto.subtle.digest('SHA-256', passwordData);

    // 转换为十六进制字符串
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return hashHex;
  } catch (error) {
    console.error('密码哈希计算失败:', error);
    throw error;
  }
}



// Web Crypto API 实现的 PBKDF2 函数
async function pbkdf2(password, salt, iterations, keySize) {
  try {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);
    const saltData = encoder.encode(salt);

    // 导入密码
    const importedKey = await crypto.subtle.importKey(
      'raw',
      passwordData,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );

    // 派生密钥
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltData,
        iterations: iterations,
        hash: 'SHA-256'
      },
      importedKey,
      keySize * 8 // 转换为位
    );

    // 转换为十六进制字符串
    const hexString = Array.from(new Uint8Array(derivedBits))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    return hexString;
  } catch (error) {
    console.error('PBKDF2 加密错误:', error);
    throw error;
  }
}

// 验证 WebDAV 凭据 - 直接从环境变量读取
async function verifyWebDAVCredentials(env, username, password) {
  try {
    const envUsername = env.WEBDAV_USERNAME;
    const envPassword = env.WEBDAV_PASSWORD;

    // 安全默认：如果管理员从未配置 WEBDAV_USERNAME / WEBDAV_PASSWORD，
    // 绝不能回退到一个写死在公开源码里、任何人都能查到的默认凭据
    // （历史上这里曾经是 'default'/'default'）。未配置时直接拒绝所有
    // WebDAV 认证请求——"失败即拒绝"，而不是"失败即放行"。
    if (!envUsername || !envPassword) {
      console.error('WebDAV 认证被拒绝：管理员尚未配置 WEBDAV_USERNAME / WEBDAV_PASSWORD');
      return false;
    }
    if (!username || !password) {
      return false;
    }

    // 使用常量时间比较，避免逐字符短路的 `===` 比较被用作计时侧信道
    const [userMatch, passMatch] = await Promise.all([
      timingSafeEqual(username, envUsername),
      timingSafeEqual(password, envPassword),
    ]);
    return userMatch && passMatch;
  } catch (error) {
    console.error('验证 WebDAV 凭证时出错:', error);
    return false;
  }
}

// 处理 POST 请求（用于客户端操作）
async function handlePost(request, env, path) {
  try {
    // 安全地解析URL
    let url;
    try {
      url = new URL(request.url);
    } catch (e) {
      // 如果URL解析失败，尝试从请求头构建完整URL
      const host = request.headers.get('Host') || 'localhost';
      const protocol = request.headers.get('X-Forwarded-Proto') ||
        (request.url.startsWith('https://') ? 'https' : 'http');

      // 确保request.url是有效的路径
      const requestUrl = request.url.startsWith('/') ? request.url : `/${request.url}`;

      url = new URL(`${protocol}://${host}${requestUrl}`);
    }
    const action = url.searchParams.get('action');
    const normalizedPath = normalizePath(path);

    switch (action) {
      case 'createFolder': {
        // 创建文件夹
        const formData = await request.formData();
        const folderName = formData.get('folderName');

        if (!folderName) {
          return new Response(JSON.stringify({ success: false, message: '文件夹名称不能为空' }), {
            status: 400,
            headers: {
              'Content-Type': 'application/json; charset=utf-8'
            }
          });
        }

        const folderPath = normalizedPath === '/' ? `/${folderName}` : `${normalizedPath}/${folderName}`;
        const result = await handleMkcol(env, folderPath);

        return new Response(JSON.stringify({ success: result.status === 201, message: result.status === 201 ? '文件夹创建成功' : '创建文件夹失败' }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json; charset=utf-8'
          }
        });
      }

      case 'delete': {
        // 删除文件或文件夹
        const formData = await request.formData();
        const deletePath = formData.get('path');

        if (!deletePath) {
          return new Response(JSON.stringify({ success: false, message: '删除路径不能为空' }), {
            status: 400,
            headers: {
              'Content-Type': 'application/json; charset=utf-8'
            }
          });
        }

        const result = await handleDelete(env, deletePath);

        return new Response(JSON.stringify({ success: result.status === 204, message: result.status === 204 ? '删除成功' : '删除失败' }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json; charset=utf-8'
          }
        });
      }

      case 'rename': {
        // 重命名文件或文件夹
        const formData = await request.formData();
        const oldPath = formData.get('oldPath');
        const newName = formData.get('newName');

        if (!oldPath || !newName) {
          return new Response(JSON.stringify({ success: false, message: '旧路径和新名称不能为空' }), {
            status: 400,
            headers: {
              'Content-Type': 'application/json; charset=utf-8'
            }
          });
        }

        // 提取旧路径的目录部分
        const oldPathParts = oldPath.split('/');
        oldPathParts.pop(); // 移除文件名/文件夹名
        const parentPath = oldPathParts.join('/') || '/';
        const newPath = parentPath === '/' ? `/${newName}` : `${parentPath}/${newName}`;

        // 使用MOVE方法来实现重命名
        const moveRequest = new Request(oldPath, {
          method: 'MOVE',
          headers: {
            'Destination': newPath
          }
        });

        const result = await handleMove(moveRequest, env, oldPath);

        return new Response(JSON.stringify({ success: result.status === 201 || result.status === 204, message: result.status === 201 || result.status === 204 ? '重命名成功' : '重命名失败' }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json; charset=utf-8'
          }
        });
      }

      default:
        return new Response(JSON.stringify({ success: false, message: '未知操作' }), {
          status: 400,
          headers: {
            'Content-Type': 'application/json; charset=utf-8'
          }
        });
    }
  } catch (error) {
    console.error('处理POST请求失败:', error);
    return new Response(JSON.stringify({ success: false, message: '处理请求时发生错误' }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json; charset=utf-8'
      }
    });
  }
}

// 处理 WebDAV 请求
async function handleWebDAVRequest(request, env) {
  // 验证 WebDAV 账号密码
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return new Response('WebDAV 需要认证', {
      status: 401,
      headers: {
        'WWW-Authenticate': 'Basic realm="WebDAV Server"'
      }
    });
  }

  try {
    // 解码认证信息
    const encodedCredentials = authHeader.split(' ')[1];
    const decodedCredentials = atob(encodedCredentials);
    const [username, password] = decodedCredentials.split(':');

    // 验证账号密码
    const isValid = await verifyWebDAVCredentials(env, username, password);

    if (!isValid) {
      return new Response('认证失败', {
        status: 401,
        headers: {
          'WWW-Authenticate': 'Basic realm="WebDAV Server"'
        }
      });
    }
  } catch (error) {
    console.error('WebDAV 认证错误:', error);
    return new Response('认证过程中发生错误', {
      status: 500
    });
  }

  // 基本的 WebDAV 方法处理
  // 安全地解析URL
  let url;
  try {
    url = new URL(request.url);
  } catch (e) {
    // 如果URL解析失败，尝试从请求头构建完整URL
    const host = request.headers.get('Host') || 'localhost';
    const protocol = request.headers.get('X-Forwarded-Proto') ||
      (request.url.startsWith('https://') ? 'https' : 'http');

    // 确保request.url是有效的路径
    const requestUrl = request.url.startsWith('/') ? request.url : `/${request.url}`;

    url = new URL(`${protocol}://${host}${requestUrl}`);
  }
  const path = url.pathname;

  switch (request.method) {
    case 'OPTIONS':
      return handleOptions();
    case 'PROPFIND':
      return handlePropfind(request, env, path);
    case 'GET':
      return handleGet(env, path, request);
    case 'PUT':
      return handlePut(request, env, path);
    case 'DELETE':
      return handleDelete(env, path);
    case 'MKCOL':
      return handleMkcol(env, path);
    default:
      return new Response('不支持的方法', { status: 501 });
  }
}

// 处理 OPTIONS 请求
function handleOptions() {
  return new Response(null, {
    headers: {
      'DAV': '1, 2, 3',
      'Allow': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL, COPY, MOVE, PROPPATCH, LOCK, UNLOCK',
      'Accept-Ranges': 'bytes',
      'Content-Length': '0',
      'MS-Author-Via': 'DAV',
      'Public': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL, COPY, MOVE, PROPPATCH, LOCK, UNLOCK',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL, COPY, MOVE, PROPPATCH, LOCK, UNLOCK',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, Depth, Overwrite, Destination, X-Requested-With, Lock-Token'
    }
  });
}

// 防止无限递归的最大深度限制
const MAX_PROPFIND_DEPTH = 2;

// 处理 PROPFIND 请求
async function handlePropfind(request, env, path, webdavRoot = '/') {
  try {
    // 规范化路径
    const normalizedPath = normalizePath(path);

    // 获取深度头，为安卓文件管理器提供更好的兼容性
    const depthHeader = request.headers.get('Depth') || '1'; // 默认为1以显示目录内容
    // 安全处理：限制最大深度，防止无限递归
    let depth = depthHeader === 'infinity' ? MAX_PROPFIND_DEPTH : parseInt(depthHeader) || 1; // 安卓客户端通常期望至少为1
    // 确保深度不超过最大限制
    depth = Math.min(depth, MAX_PROPFIND_DEPTH);

    // 确保根目录存在（若配置了自定义 WebDAV 根路径，同时确保该路径本身存在）
    await ensureRootDirectory(env, webdavRoot);

    // 检查资源是否存在
    let resourceInfo = await getResourceInfo(env, normalizedPath);

    // 如果资源不存在但请求的是目录，尝试创建或模拟响应
    if (!resourceInfo) {
      // 如果请求的是根目录或类似目录的路径，返回空目录响应而不是404
      if (normalizedPath === '/' || !normalizedPath.includes('.')) {
        resourceInfo = {
          type: 'directory',
          modifiedAt: new Date().toISOString(),
          size: 0
        };
      } else {
        return new Response('资源不存在', { status: 404 });
      }
    }

    // 构建 XML 响应，使用完整的DAV命名空间
    let xmlBody = '<?xml version="1.0" encoding="utf-8" ?>\n<D:multistatus xmlns:D="DAV:">';

    // 添加当前资源的响应，传入完整的resourceInfo
    // href 需要转换回客户端视角的路径（相对于其挂载的 WebDAV 根目录），
    // 而不是存储桶中的真实键路径
    xmlBody += createResourceResponse(
      storagePathToWebdav(normalizedPath, webdavRoot),
      resourceInfo.type === 'directory',
      new Date(resourceInfo.modifiedAt),
      resourceInfo
    );

    // 如果是深度遍历且是目录，列出子资源
    // 安卓客户端通常需要正确的目录内容列表
    if (depth > 0 && resourceInfo.type === 'directory') {
      let children = [];
      try {
        children = await listDirectoryChildren(env, normalizedPath);
      } catch (error) {
        console.error('列出目录子资源失败:', error);
        // 即使失败也继续，至少返回当前目录信息
      }

      // 确保子资源列表不为空时才处理
      if (children && children.length > 0) {
        for (const child of children) {
          const childPath = normalizedPath === '/' ? `/${child.name}` : `${normalizedPath}/${child.name}`;
          xmlBody += createResourceResponse(
            storagePathToWebdav(childPath, webdavRoot),
            child.type === 'directory',
            new Date(child.modifiedAt),
            child
          );
        }
      }
    }

    xmlBody += '</D:multistatus>';

    // 确保响应头正确设置，特别关注安卓兼容性
    // PROPFIND 必须返回 207 Multi-Status（RFC 4918），否则严格的 WebDAV 客户端
    // （Windows 资源管理器、macOS Finder、rclone 等）会将默认的 200 视为失败
    return new Response(xmlBody, {
      status: 207,
      headers: {
        'Content-Type': 'application/xml; charset=utf-8',
        'DAV': '1, 2, 3',
        'MS-Author-Via': 'DAV',
        'Content-Length': xmlBody.length.toString(),
        'Access-Control-Allow-Origin': '*',
        'Allow': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL',
        'Public': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL',
        'Accept-Ranges': 'bytes',
        'Last-Modified': new Date(resourceInfo.modifiedAt).toUTCString()
      }
    });
  } catch (error) {
    console.error('PROPFIND 处理错误:', error);
    return new Response('处理 PROPFIND 请求时出错', { status: 500 });
  }
}

// 创建资源响应 XML
function createResourceResponse(path, isDirectory, lastModified, resourceInfo = {}) {
  // 确保路径格式正确
  const basePath = path.startsWith('/') ? path : `/${path}`;
  const hrefPath = `${basePath}`.replace(/\/\//g, '/'); // 确保路径正确，避免双斜杠

  const resourceType = isDirectory ? '<D:resourcetype><D:collection/></D:resourcetype>' : '<D:resourcetype/>';
  const formattedDate = lastModified.toUTCString();
  const size = resourceInfo.size || (isDirectory ? 0 : undefined);

  // 为文件设置适当的内容类型
  let contentType = 'application/octet-stream';
  if (!isDirectory && resourceInfo.contentType) {
    contentType = resourceInfo.contentType;
  } else if (!isDirectory) {
    // 尝试根据文件扩展名猜测内容类型
    const extension = hrefPath.split('.').pop()?.toLowerCase();
    const extensionMimeTypes = {
      'txt': 'text/plain',
      'html': 'text/html',
      'htm': 'text/html',
      'css': 'text/css',
      'js': 'application/javascript',
      'json': 'application/json',
      'xml': 'application/xml',
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
      'webp': 'image/webp',
      'pdf': 'application/pdf',
      'zip': 'application/zip',
      'rar': 'application/x-rar-compressed',
      '7z': 'application/x-7z-compressed',
      'mp3': 'audio/mpeg',
      'wav': 'audio/wav',
      'mp4': 'video/mp4',
      'avi': 'video/x-msvideo',
      'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'xls': 'application/vnd.ms-excel',
      'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'ppt': 'application/vnd.ms-powerpoint',
      'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    };
    if (extension && extensionMimeTypes[extension]) {
      contentType = extensionMimeTypes[extension];
    }
  }

  // 生成更安全的ETag
  const etag = resourceInfo.etag || `"${formattedDate}-${size || 0}"`;

  // 获取显示名称
  const displayName = path.split('/').pop() || '/';

  // href 和 displayname 来自用户提供的文件/目录名，写入 XML 前必须转义
  const escapedHref = escapeHtml(hrefPath);
  const escapedDisplayName = escapeHtml(displayName);

  // 为手机文件管理器和其他客户端提供全面的PROPFIND响应
  return `
    <D:response>
      <D:href>${escapedHref}</D:href>
      <D:propstat>
        <D:prop>
          ${resourceType}
          <D:getlastmodified>${formattedDate}</D:getlastmodified>
          <D:displayname>${escapedDisplayName}</D:displayname>
          ${size !== undefined ? `<D:getcontentlength>${size}</D:getcontentlength>` : '<D:getcontentlength>0</D:getcontentlength>'}
          <D:creationdate>${resourceInfo.createdAt ? new Date(resourceInfo.createdAt).toUTCString() : formattedDate}</D:creationdate>
          <D:getetag>${etag}</D:getetag>
          ${!isDirectory ? `<D:getcontenttype>${contentType}</D:getcontenttype>` : ''}
          <!-- 安卓和Windows文件管理器所需的额外属性 -->
          <D:iscollection>${isDirectory ? '1' : '0'}</D:iscollection>
          <!-- 标准WebDAV属性 -->
          <D:supportedlock/>
          <D:lockdiscovery/>
          <D:quota-available-bytes/>
          <D:quota-used-bytes/>
        </D:prop>
        <D:status>HTTP/1.1 200 OK</D:status>
      </D:propstat>
    </D:response>`;
}

// 处理 HEAD 请求
async function handleHead(env, path, request) {
  try {
    const normalizedPath = normalizePath(path);

    // 确保根目录存在
    await ensureRootDirectory(env);

    // 获取资源信息
    const resourceInfo = await getResourceInfo(env, normalizedPath);
    if (!resourceInfo) {
      return new Response(null, {
        status: 404,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8'
        }
      });
    }

    // 检查是否是目录
    if (resourceInfo.type === 'directory') {
      // 对于目录，返回目录相关的头部
      return new Response(null, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Last-Modified': new Date(resourceInfo.modifiedAt).toUTCString(),
          'Accept-Ranges': 'bytes',
          'DAV': '1, 2, 3',
          'MS-Author-Via': 'DAV'
        }
      });
    }

    // 对于文件，获取元数据
    let metaData;
    try {
      metaData = await env.WEBDAV_STORAGE.get(`${normalizedPath}_meta`, 'json');
    } catch (e) {
      metaData = null;
    }

    // 确定内容类型
    const contentType = metaData?.contentType || getContentType(normalizedPath);

    // 创建响应头
    const headers = {
      'Content-Type': contentType,
      'Accept-Ranges': 'bytes',
      'Last-Modified': metaData?.modifiedAt ? new Date(metaData.modifiedAt).toUTCString() : new Date().toUTCString(),
      'DAV': '1, 2, 3',
      'MS-Author-Via': 'DAV'
    };

    // 添加文件大小信息，只使用元数据中的大小
    if (metaData?.size) {
      headers['Content-Length'] = metaData.size.toString();
    }

    // 返回空响应体的响应
    return new Response(null, {
      headers
    });
  } catch (error) {
    console.error('HEAD 处理错误:', error);
    return new Response(null, {
      status: 500,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8'
      }
    });
  }
}

// 处理 GET 请求
async function handleGet(env, path, request, webdavRoot = '/') {
  try {
    const normalizedPath = normalizePath(path);

    // 确保根目录存在（若配置了自定义 WebDAV 根路径，同时确保该路径本身存在）
    await ensureRootDirectory(env, webdavRoot);

    // 获取资源信息
    const resourceInfo = await getResourceInfo(env, normalizedPath);
    if (!resourceInfo) {
      return new Response('文件不存在', { status: 404 });
    }

    // 检查是否是目录
    if (resourceInfo.type === 'directory') {
      // 如果是目录，返回目录列表的 HTML 页面
      return generateDirectoryListing(env, normalizedPath, resourceInfo, webdavRoot);
    }

    // 从 KV 获取文件内容
    const content = await env.WEBDAV_STORAGE.get(normalizedPath, 'arrayBuffer');
    if (!content) {
      return new Response('文件不存在', { status: 404 });
    }

    // 获取文件元数据
    let metaData;
    try {
      metaData = await env.WEBDAV_STORAGE.get(`${normalizedPath}_meta`, 'json');
    } catch (e) {
      metaData = null;
    }

    // 确定内容类型
    const contentType = metaData?.contentType || getContentType(normalizedPath);

    // 创建响应头
    const headers = {
      'Content-Type': contentType,
      'Content-Length': content.byteLength.toString(), // 使用实际内容大小作为主要来源
      'Accept-Ranges': 'bytes',
      'Last-Modified': metaData?.modifiedAt ? new Date(metaData.modifiedAt).toUTCString() : new Date().toUTCString(),
      'Cache-Control': 'public, max-age=3600'
    };

    // 不再覆盖Content-Length，避免潜在的不一致
    // 使用实际读取的内容大小更准确且不需要额外KV访问

    // 处理 Range 请求（部分内容下载）
    const rangeHeader = request && request.headers ? request.headers.get('Range') : null;
    if (rangeHeader) {
      try {
        const rangeMatch = rangeHeader.match(/bytes=(\d+)-(\d*)/);
        if (rangeMatch) {
          const start = parseInt(rangeMatch[1]);
          const end = rangeMatch[2] ? parseInt(rangeMatch[2]) : content.byteLength - 1;

          if (start < content.byteLength && start <= end) {
            const rangeContent = content.slice(start, end + 1);
            headers['Content-Range'] = `bytes ${start}-${end}/${content.byteLength}`;
            headers['Content-Length'] = rangeContent.byteLength.toString();

            return new Response(rangeContent, {
              status: 206,
              headers
            });
          }
        }
      } catch (e) {
        console.error('处理 Range 请求失败:', e);
      }
    }

    return new Response(content, {
      headers
    });
  } catch (error) {
    console.error('GET 处理错误:', error);
    return new Response('下载文件时出错', {
      status: 500,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8'
      }
    });
  }
}

// 生成目录列表 HTML
async function generateDirectoryListing(env, path, resourceInfo, webdavRoot = '/') {
  try {
    const children = await listDirectoryChildren(env, path);

    // 过滤掉任何空名称文件、目录标记和根目录标记
    const filteredChildren = children.filter(child =>
      child.name.trim() !== '' && child.name !== '_dir' && child.name !== '/'
    );

    // 页面中出现的路径一律使用客户端视角的路径（相对于其挂载的 WebDAV 根目录）
    const clientPath = storagePathToWebdav(path, webdavRoot);

    let html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>目录列表 - ${escapeHtml(clientPath)}</title>
  <style>
    /* 全局样式 */
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      margin: 0;
      padding: 20px;
      background-color: #f5f7fa;
      color: #333;
      line-height: 1.6;
    }
    
    /* 标题样式 */
    h1 { 
      color: #2c3e50;
      margin-bottom: 15px;
      font-size: 22px;
      font-weight: 600;
    }
    
    /* 操作区域样式 */
    .actions { 
      margin-bottom: 20px;
      padding: 12px 16px;
      background-color: white;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    
    /* 按钮样式 */
    .actions button { 
      background-color: #3498db;
      color: white;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 500;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 5px;
    }
    
    .actions button:hover { 
      background-color: #2980b9;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(52, 152, 219, 0.3);
    }
    
    .actions button:active { 
      transform: translateY(0);
    }
    
    /* 输入框样式 */
    .actions input[type="text"],
    .actions input[type="file"] {
      padding: 10px;
      border: 1px solid #e1e8ed;
      border-radius: 6px;
      font-size: 14px;
      transition: border-color 0.2s ease;
    }
    
    .actions input[type="text"]:focus {
      outline: none;
      border-color: #3498db;
      box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
    }
    
    /* 模态框样式 */
    .modal { 
      display: none;
      position: fixed;
      z-index: 1000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow: auto;
      background-color: rgba(0, 0, 0, 0.5);
      backdrop-filter: blur(5px);
    }
    
    .modal-content { 
      background-color: white;
      margin: 10% auto;
      padding: 30px;
      border-radius: 10px;
      width: 90%;
      max-width: 450px;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
      animation: modalSlideIn 0.3s ease;
    }
    
    @keyframes modalSlideIn {
      from { 
        opacity: 0;
        transform: translateY(-50px);
      }
      to { 
        opacity: 1;
        transform: translateY(0);
      }
    }
    
    /* 模态框关闭按钮 */
    .close { 
      color: #95a5a6;
      float: right;
      font-size: 28px;
      font-weight: bold;
      cursor: pointer;
      transition: color 0.2s ease;
      line-height: 1;
    }
    
    .close:hover, .close:focus { 
      color: #2c3e50;
    }
    
    /* 模态框标题 */
    .modal-content h2 {
      color: #2c3e50;
      margin-bottom: 20px;
      font-size: 22px;
      font-weight: 600;
    }
    
    /* 模态框输入框 */
    .modal-content input[type="text"] {
      width: 100%;
      padding: 12px;
      border: 1px solid #e1e8ed;
      border-radius: 6px;
      font-size: 14px;
      margin-bottom: 20px;
      transition: border-color 0.2s ease;
    }
    
    .modal-content input[type="text"]:focus {
      outline: none;
      border-color: #3498db;
      box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
    }
    
    /* 模态框按钮容器 */
    .modal-content button {
      padding: 10px 20px;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      margin-right: 10px;
      transition: all 0.2s ease;
    }
    
    /* 确认按钮 */
    #confirmCreateFolder,
    #confirmUploadFile,
    #confirmDelete,
    #confirmRename {
      background-color: #27ae60;
      color: white;
    }
    
    #confirmCreateFolder:hover,
    #confirmUploadFile:hover,
    #confirmDelete:hover,
    #confirmRename:hover {
      background-color: #229954;
      transform: translateY(-1px);
    }
    
    /* 取消按钮 */
    #cancelCreateFolder,
    #cancelUploadFile,
    #cancelDelete,
    #cancelRename {
      background-color: #95a5a6;
      color: white;
    }
    
    #cancelCreateFolder:hover,
    #cancelUploadFile:hover,
    #cancelDelete:hover,
    #cancelRename:hover {
      background-color: #7f8c8d;
    }
    
    /* 表格样式 */
    table { 
      border-collapse: collapse;
      width: 100%;
      background-color: white;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
      overflow: hidden;
    }
    
    th, td { 
      border-bottom: 1px solid #f0f2f5;
      padding: 14px 16px;
      text-align: left;
      font-size: 14px;
    }
    
    th { 
      background-color: #f8f9fa;
      color: #666;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 12px;
      letter-spacing: 0.5px;
    }
    
    tr { 
      transition: background-color 0.2s ease;
    }
    
    tr:hover { 
      background-color: #f8fafc;
    }
    
    /* 链接样式 */
    a { 
      color: #3498db;
      text-decoration: none;
      transition: color 0.2s ease;
    }
    
    a:hover { 
      color: #2980b9;
    }
    
    /* 文件和目录样式 */
    .dir { 
      color: #f39c12;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .file { 
      color: #2c3e50;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    /* 大小列样式 */
    .size { 
      text-align: right;
      color: #666;
    }
    
    /* 消息提示样式 */
    .message { 
      padding: 14px 20px;
      margin: 15px 0;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 500;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
      animation: messageSlideIn 0.3s ease;
    }
    
    @keyframes messageSlideIn {
      from { 
        opacity: 0;
        transform: translateX(-20px);
      }
      to { 
        opacity: 1;
        transform: translateX(0);
      }
    }
    
    .success { 
      background-color: #d4edda;
      color: #155724;
      border-left: 4px solid #27ae60;
    }
    
    .error { 
      background-color: #f8d7da;
      color: #721c24;
      border-left: 4px solid #e74c3c;
    }
    
    /* 操作按钮样式 */
    .rename-btn, .download-btn, .delete-btn {
      background-color: #95a5a6;
      color: white;
      border: none;
      padding: 6px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 500;
      text-decoration: none;
      display: inline-block;
      margin-right: 6px;
      transition: all 0.2s ease;
    }
    
    .rename-btn:hover, .download-btn:hover, .delete-btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    }
    
    .rename-btn { 
      background-color: #f39c12;
    }
    
    .rename-btn:hover { 
      background-color: #e67e22;
    }
    
    .download-btn { 
      background-color: #27ae60;
    }
    
    .download-btn:hover { 
      background-color: #229954;
    }
    
    .delete-btn { 
      background-color: #e74c3c;
    }
    
    .delete-btn:hover { 
      background-color: #c0392b;
    }
    
    /* 响应式设计 */
    @media (max-width: 768px) {
      body {
        padding: 10px;
      }
      
      h1 {
        font-size: 24px;
      }
      
      .actions {
        flex-direction: column;
        align-items: stretch;
      }
      
      .actions button {
        width: 100%;
        justify-content: center;
      }
      
      table {
        font-size: 13px;
      }
      
      th, td {
        padding: 10px;
      }
      
      .modal-content {
        margin: 20% auto;
        width: 95%;
        padding: 20px;
      }
    }
  </style>
</head>
<body>
  <h1>目录: ${escapeHtml(clientPath)}</h1>
  
  <!-- 操作按钮区域 -->
  <div class="actions">
    <button id="createFolderBtn">创建文件夹</button>
    <button id="uploadFileBtn">上传文件</button>
    <button id="logoutBtn" style="margin-left: auto; background-color: #e74c3c;">登出</button>
  </div>
  
  <!-- 创建文件夹模态框 -->
  <div id="createFolderModal" class="modal">
    <div class="modal-content">
      <span class="close">&times;</span>
      <h2>创建新文件夹</h2>
      <input type="text" id="folderName" placeholder="输入文件夹名称">
      <button id="confirmCreateFolder">创建</button>
      <button id="cancelCreateFolder">取消</button>
    </div>
  </div>
  
  <!-- 上传文件模态框 -->
  <div id="uploadFileModal" class="modal">
    <div class="modal-content">
      <span class="close">&times;</span>
      <h2>上传文件</h2>
      <input type="file" id="fileUpload">
      <button id="confirmUploadFile">上传</button>
      <button id="cancelUploadFile">取消</button>
    </div>
  </div>
  
  <!-- 删除确认模态框 -->
  <div id="deleteModal" class="modal">
    <div class="modal-content">
      <span class="close">&times;</span>
      <h2>确认删除</h2>
      <p id="deleteMessage">确定要删除该资源吗？</p>
      <button id="confirmDelete">删除</button>
      <button id="cancelDelete">取消</button>
    </div>
  </div>
  
  <!-- 重命名模态框 -->
  <div id="renameModal" class="modal">
    <div class="modal-content">
      <span class="close">&times;</span>
      <h2>重命名</h2>
      <input type="text" id="newName" placeholder="输入新名称">
      <button id="confirmRename">重命名</button>
      <button id="cancelRename">取消</button>
    </div>
  </div>
  
  <!-- 消息显示区域 -->
  <div id="message"></div>
  
  <table>
    <tr>
      <th>名称</th>
      <th>类型</th>
      <th class="size">大小</th>
      <th>修改时间</th>
      <th>操作</th>
    </tr>`;

    // 添加父目录链接。判断依据是存储路径是否等于 WebDAV 挂载根目录（而不是
    // 存储桶的绝对根目录 '/'）——否则配置了自定义根路径时，客户端会在自己的
    // 根目录看到一个 ".." 链接，从而越权访问挂载根目录以外的存储桶内容。
    if (path !== webdavRoot) {
      const parentPath = getParentPath(path);
      // 使用简单直接的方式构建父目录链接，确保不会出现双斜杠
      const parentLink = escapeHtml(storagePathToWebdav(`${parentPath}`.replace(/\/\//g, '/'), webdavRoot));
      html += `
      <tr>
        <td><a href="${parentLink}" class="dir">..</a></td>
        <td>目录</td>
        <td class="size">-</td>
        <td>-</td>
        <td>-</td>
      </tr>`;
    }

    // 添加子资源
    for (const child of filteredChildren) {
      // 更精确的路径构建，避免根目录下出现双斜杠
      let fullLink;
      if (path === '/') {
        fullLink = `/${child.name}`;
      } else {
        fullLink = `${path}/${child.name}`;
      }
      // 最后再清理可能存在的双斜杠，并转换回客户端视角的路径
      fullLink = storagePathToWebdav(fullLink.replace(/\/\//g, '/'), webdavRoot);
      const linkClass = child.type === 'directory' ? 'dir' : 'file';
      // 确保根目录下的子目录不会显示额外的斜杠
      const displayName = child.type === 'directory' ? `${child.name}/` : child.name;
      // 文件/目录名由用户提供，写入 HTML 前必须转义，避免存储型 XSS
      const escapedLink = escapeHtml(fullLink);
      const escapedName = escapeHtml(child.name);
      const escapedDisplayName = escapeHtml(displayName);

      html += `
      <tr>
        <td><a href="${escapedLink}" class="${linkClass}">${escapedDisplayName}</a></td>
        <td>${child.type === 'directory' ? '目录' : '文件'}</td>
        <td class="size">${child.type === 'directory' ? '-' : (child.size ? formatFileSize(child.size) : '未知')}</td>
        <td>${new Date(child.modifiedAt).toLocaleString()}</td>
        <td><button class="rename-btn" data-path="${escapedLink}" data-name="${escapedName}" data-type="${child.type}">重命名</button> ${child.type === 'directory' ? '' : '<a href="' + escapedLink + '" class="download-btn" download>下载</a>'} <button class="delete-btn" data-path="${escapedLink}" data-name="${escapedName}" data-type="${child.type}">删除</button></td>
      </tr>`;
    }

    html += `
  </table>
  
  <script>
    // 消息显示函数
    function showMessage(text, type) {
      const messageDiv = document.getElementById('message');
      messageDiv.className = 'message ' + type;
      messageDiv.textContent = text;
      messageDiv.style.display = 'block';
      setTimeout(() => {
        messageDiv.style.display = 'none';
      }, 3000);
    }
    
    // 模态框处理
    const createFolderModal = document.getElementById('createFolderModal');
    const uploadFileModal = document.getElementById('uploadFileModal');
    const deleteModal = document.getElementById('deleteModal');
    const renameModal = document.getElementById('renameModal');
    const createFolderBtn = document.getElementById('createFolderBtn');
    const uploadFileBtn = document.getElementById('uploadFileBtn');
    const closeButtons = document.getElementsByClassName('close');
    const cancelCreateFolder = document.getElementById('cancelCreateFolder');
    const cancelUploadFile = document.getElementById('cancelUploadFile');
    const cancelDelete = document.getElementById('cancelDelete');
    const cancelRename = document.getElementById('cancelRename');
    const deleteMessage = document.getElementById('deleteMessage');
    const confirmDelete = document.getElementById('confirmDelete');
    const confirmRename = document.getElementById('confirmRename');
    const newNameInput = document.getElementById('newName');
    let currentDeletePath = '';
    let currentDeleteName = '';
    let currentDeleteType = '';
    let currentRenamePath = '';
    let currentRenameName = '';
    let currentRenameType = '';
    
    // 打开创建文件夹模态框
    createFolderBtn.addEventListener('click', () => {
      createFolderModal.style.display = 'block';
    });
    
    // 打开上传文件模态框
    uploadFileBtn.addEventListener('click', () => {
      uploadFileModal.style.display = 'block';
    });
    
    // 关闭模态框
    for (let i = 0; i < closeButtons.length; i++) {
      closeButtons[i].addEventListener('click', () => {
        createFolderModal.style.display = 'none';
        uploadFileModal.style.display = 'none';
        deleteModal.style.display = 'none';
        renameModal.style.display = 'none';
        newNameInput.value = '';
      });
    }
    
    // 登出功能
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', async () => {
        try {
          // 发送登出请求
          const response = await fetch('/logout', {
            method: 'POST'
          });
          // 检查响应状态
          if (response.ok) {
            // 刷新页面，将被重定向到登录页
            window.location.reload();
          } else {
            throw new Error('登出请求失败');
          }
        } catch (error) {
          console.error('登出失败:', error);
          showMessage('登出失败', 'error');
        }
      });
    }
    

    
    // 取消按钮
    cancelCreateFolder.addEventListener('click', () => {
      createFolderModal.style.display = 'none';
    });
    
    cancelUploadFile.addEventListener('click', () => {
      uploadFileModal.style.display = 'none';
    });
    
    cancelDelete.addEventListener('click', () => {
      deleteModal.style.display = 'none';
    });
    
    cancelRename.addEventListener('click', () => {
      renameModal.style.display = 'none';
      newNameInput.value = '';
    });
    
    // 点击模态框外部关闭
    window.addEventListener('click', (event) => {
      if (event.target === createFolderModal) {
        createFolderModal.style.display = 'none';
      }
      if (event.target === uploadFileModal) {
        uploadFileModal.style.display = 'none';
      }
      if (event.target === deleteModal) {
        deleteModal.style.display = 'none';
      }
      if (event.target === renameModal) {
        renameModal.style.display = 'none';
        newNameInput.value = '';
      }
    });
    
    // 创建文件夹
    document.getElementById('confirmCreateFolder').addEventListener('click', async () => {
      const folderName = document.getElementById('folderName').value.trim();
      if (!folderName) {
        showMessage('请输入文件夹名称', 'error');
        return;
      }
      
      try {
        // 修复路径拼接问题，避免双斜杠
        const folderPath = window.location.pathname.endsWith('/') 
          ? window.location.pathname + folderName 
          : window.location.pathname + '/' + folderName;
        
        const response = await fetch(folderPath, {
          method: 'MKCOL'
        });
        
        if (response.ok) {
          showMessage('文件夹创建成功', 'success');
          createFolderModal.style.display = 'none';
          // 刷新页面
          window.location.reload();
        } else {
          showMessage('文件夹创建失败: ' + response.statusText, 'error');
        }
      } catch (error) {
        showMessage('创建文件夹时发生错误: ' + error.message, 'error');
      }
    });
    
    // 上传文件
    document.getElementById('confirmUploadFile').addEventListener('click', async () => {
      const fileInput = document.getElementById('fileUpload');
      const file = fileInput.files[0];
      
      if (!file) {
        showMessage('请选择要上传的文件', 'error');
        return;
      }
      
      try {
        // 修复路径拼接问题，避免双斜杠
        const filePath = window.location.pathname.endsWith('/') 
          ? window.location.pathname + file.name 
          : window.location.pathname + '/' + file.name;
        
        const response = await fetch(filePath, {
          method: 'PUT',
          body: file
        });
        
        if (response.ok) {
          showMessage('文件上传成功', 'success');
          uploadFileModal.style.display = 'none';
          // 刷新页面
          window.location.reload();
        } else {
          showMessage('文件上传失败: ' + response.statusText, 'error');
        }
      } catch (error) {
        showMessage('上传文件时发生错误: ' + error.message, 'error');
      }
    });
    
    // 重命名功能
    
    // 点击重命名按钮
    document.addEventListener('click', (event) => {
      if (event.target.classList.contains('rename-btn')) {
        currentRenamePath = event.target.getAttribute('data-path');
        currentRenameName = event.target.getAttribute('data-name');
        currentRenameType = event.target.getAttribute('data-type');
        
        newNameInput.value = currentRenameName;
        renameModal.style.display = 'block';
      }
    });
    
    // 确认重命名
    confirmRename.addEventListener('click', async () => {
      const newName = newNameInput.value.trim();
      if (!newName) {
        showMessage('请输入新名称', 'error');
        return;
      }
      
      if (newName === currentRenameName) {
        showMessage('新名称与原名称相同', 'error');
        return;
      }
      
      try {
        // 获取父目录路径
        const parentPath = currentRenamePath.substring(0, currentRenamePath.lastIndexOf('/')) || '/';
        const newPath = parentPath + '/' + newName;
        
        // 发送重命名请求
        const response = await fetch(currentRenamePath, {
          method: 'MOVE',
          headers: {
            'Destination': window.location.origin + newPath
          }
        });
        
        if (response.ok) {
          showMessage((currentRenameType === 'directory' ? '目录' : '文件') + '重命名成功', 'success');
          // 刷新页面
          setTimeout(() => {
            window.location.reload();
          }, 1000);
        } else {
          const errorText = await response.text();
          showMessage((currentRenameType === 'directory' ? '目录' : '文件') + '重命名失败: ' + response.status + ' ' + response.statusText, 'error');
        }
      } catch (error) {
        showMessage('重命名操作失败: ' + error.message, 'error');
      } finally {
        renameModal.style.display = 'none';
        newNameInput.value = '';
      }
    });
    
    // 删除功能
    
    // 点击删除按钮
    document.addEventListener('click', (event) => {
      if (event.target.classList.contains('delete-btn')) {
        currentDeletePath = event.target.getAttribute('data-path');
        currentDeleteName = event.target.getAttribute('data-name');
        currentDeleteType = event.target.getAttribute('data-type');
        
        deleteMessage.textContent = '确定要删除' + (currentDeleteType === 'directory' ? '目录' : '文件') + ' "' + currentDeleteName + '"吗？' + (currentDeleteType === 'directory' ? '（目录可能不为空）' : '');
        deleteModal.style.display = 'block';
      }
    });
    
    // 确认删除
    confirmDelete.addEventListener('click', async () => {
      try {
        const response = await fetch(currentDeletePath, {
          method: 'DELETE'
        });
        
        if (response.ok) {
          showMessage((currentDeleteType === 'directory' ? '目录' : '文件') + '删除成功', 'success');
          deleteModal.style.display = 'none';
          // 刷新页面
          window.location.reload();
        } else {
          showMessage((currentDeleteType === 'directory' ? '目录' : '文件') + '删除失败: ' + response.status + ' ' + response.statusText, 'error');
        }
      } catch (error) {
        showMessage('删除时发生错误: ' + error.message, 'error');
      }
    });
  </script>
</body>
</html>`;

    return new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store, no-cache'
      }
    });
  } catch (error) {
    console.error('生成目录列表失败:', error);
    return new Response('无法生成目录列表', { status: 500 });
  }
}

// 处理 PUT 请求
async function handlePut(request, env, path, webdavRoot = '/') {
  try {
    const normalizedPath = normalizePath(path);

    // 确保根目录存在（若配置了自定义 WebDAV 根路径，同时确保该路径本身存在）
    await ensureRootDirectory(env, webdavRoot);

    // 读取请求体
    const content = await request.arrayBuffer();

    // 确保父目录存在
    const parentPath = getParentPath(normalizedPath);
    if (parentPath) {
      try {
        await ensureDirectoryExists(env, parentPath);
      } catch (error) {
        if (error.message && error.message.includes('路径已被文件占用')) {
          return new Response('父目录路径被文件占用', {
            status: 409,
            headers: {
              'Access-Control-Allow-Origin': '*',
              'DAV': '1, 2, 3',
              'MS-Author-Via': 'DAV',
              'Content-Type': 'text/plain; charset=utf-8'
            }
          });
        }
        throw error;
      }
    }

    // 检查是否与现有目录冲突
    const existingInfo = await getResourceInfo(env, normalizedPath);
    if (existingInfo && existingInfo.type === 'directory') {
      return new Response('不能覆盖目录', {
        status: 409,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'DAV': '1, 2, 3',
          'MS-Author-Via': 'DAV'
        }
      });
    }

    // 保存文件内容
    await env.WEBDAV_STORAGE.put(normalizedPath, content);

    // 创建或更新文件元数据
    const now = new Date().toISOString();
    await env.WEBDAV_STORAGE.put(`${normalizedPath}_meta`, JSON.stringify({
      type: 'file',
      size: content.byteLength,
      modifiedAt: now,
      contentType: request.headers.get('Content-Type') || getContentType(normalizedPath)
    }));

    // 更新父目录修改时间
    await updateDirectoryTimestamp(env, parentPath);

    // 为大多数客户端返回201状态码，这是文件创建的标准响应
    // 同时添加Content-Location头部，提高与各种文件管理器的兼容性
    return new Response(null, {
      status: 201,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'DAV': '1, 2, 3',
        'MS-Author-Via': 'DAV',
        'Public': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL',
        'Content-Location': storagePathToWebdav(normalizedPath, webdavRoot)
      }
    });
  } catch (error) {
    console.error('PUT 处理错误:', error);
    return new Response('上传文件时出错', {
      status: 500,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'DAV': '1, 2, 3',
        'MS-Author-Via': 'DAV',
        'Content-Type': 'text/plain; charset=utf-8'
      }
    });
  }
}

// 处理 DELETE 请求
async function handleDelete(env, path) {
  try {
    const normalizedPath = normalizePath(path);

    // 禁止删除根目录
    if (normalizedPath === '/') {
      return new Response('不能删除根目录', { status: 403 });
    }

    // 检查资源是否存在
    const resourceInfo = await getResourceInfo(env, normalizedPath);
    if (!resourceInfo) {
      return new Response(null, { status: 404 });
    }

    if (resourceInfo.type === 'directory') {
      // 列出目录内容，检查是否为空
      const children = await listDirectoryChildren(env, normalizedPath);
      if (children.length > 0) {
        // 在 Cloudflare KV 中递归删除可能会有性能问题，这里简化处理
        // 实际应用中可能需要限制目录深度或实现异步删除队列
        return new Response('目录不为空', { status: 409 });
      }

      // 删除目录标记（"_dir" 后缀标记 + 与 REST API 共用的嵌套空目录标记）
      const dirPath = `${normalizedPath}_dir`;
      await env.WEBDAV_STORAGE.delete(dirPath);
      await env.WEBDAV_STORAGE.delete(`${normalizedPath}/.emptydir`);
    } else {
      // 删除文件内容和元数据
      await env.WEBDAV_STORAGE.delete(normalizedPath);
      await env.WEBDAV_STORAGE.delete(`${normalizedPath}_meta`);
    }

    // 更新父目录修改时间
    const parentPath = getParentPath(normalizedPath);
    await updateDirectoryTimestamp(env, parentPath);

    return new Response(null, { status: 204 });
  } catch (error) {
    console.error('DELETE 处理错误:', error);
    return new Response('删除文件时出错', { status: 500 });
  }
}

// 递归收集目录树下所有存储键（文件内容、_meta、子目录 _dir 标记），支持分页
async function listAllDescendantKeys(env, dirPath) {
  const prefix = `${dirPath}/`;
  const keys = [];
  let cursor;
  do {
    const listResult = await env.WEBDAV_STORAGE.list({ prefix, cursor, limit: 1000 });
    for (const key of listResult.keys || []) keys.push(key.name);
    cursor = listResult.truncated ? listResult.cursor : undefined;
  } while (cursor);
  return keys;
}

// 处理 COPY 请求
async function handleCopy(request, env, path, webdavRoot = '/') {
  try {
    const normalizedPath = normalizePath(path);

    // 获取目标路径
    const destinationHeader = request.headers.get('Destination');
    if (!destinationHeader) {
      return new Response('缺少目标路径', {
        status: 400,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'DAV': '1, 2, 3',
          'MS-Author-Via': 'DAV'
        }
      });
    }

    let destinationUrl;
    try {
      // 尝试直接解析为完整URL
      destinationUrl = new URL(destinationHeader);
    } catch (e) {
      // 如果是相对路径，使用当前请求的协议和主机构建完整URL
      const currentUrl = new URL(request.url);
      // 确保路径以/开头
      const normalizedDestHeader = destinationHeader.startsWith('/') ? destinationHeader : `/${destinationHeader}`;
      destinationUrl = new URL(normalizedDestHeader, `${currentUrl.protocol}//${currentUrl.host}`);
    }
    let destinationPath = destinationUrl.pathname;

    // Destination 头中的路径是客户端视角的路径（相对于其挂载的 WebDAV 根目录），
    // 需要换算成存储桶中的真实键路径，才能与 normalizedPath（已经是存储路径）
    // 进行比较和操作
    const normalizedDestPath = webdavPathToStorage(destinationPath, webdavRoot);

    // 检查源资源是否存在
    const sourceInfo = await getResourceInfo(env, normalizedPath);
    if (!sourceInfo) {
      return new Response('源资源不存在', {
        status: 404,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'DAV': '1, 2, 3',
          'MS-Author-Via': 'DAV'
        }
      });
    }

    // 检查目标资源是否存在
    const destInfo = await getResourceInfo(env, normalizedDestPath);
    if (destInfo) {
      // 如果目标存在，根据Overwrite头部决定是否覆盖
      const overwriteHeader = request.headers.get('Overwrite') || 'T';
      if (overwriteHeader.toLowerCase() !== 't') {
        return new Response('目标已存在且不允许覆盖', {
          status: 412,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'DAV': '1, 2, 3',
            'MS-Author-Via': 'DAV'
          }
        });
      }
    }

    if (sourceInfo.type === 'file') {
      // 复制文件
      const content = await env.WEBDAV_STORAGE.get(normalizedPath, 'arrayBuffer');
      if (content) {
        await env.WEBDAV_STORAGE.put(normalizedDestPath, content);

        // 复制元数据
        const metaData = await env.WEBDAV_STORAGE.get(`${normalizedPath}_meta`, 'json');
        if (metaData) {
          await env.WEBDAV_STORAGE.put(`${normalizedDestPath}_meta`, JSON.stringify(metaData));
        }
      }
    } else {
      // 复制目录：复制目录标记，并递归复制目录下所有文件内容、元数据及子目录标记
      await env.WEBDAV_STORAGE.put(`${normalizedDestPath}_dir`, JSON.stringify(sourceInfo));

      const descendantKeys = await listAllDescendantKeys(env, normalizedPath);
      for (const key of descendantKeys) {
        const destKey = `${normalizedDestPath}${key.slice(normalizedPath.length)}`;
        const content = await env.WEBDAV_STORAGE.get(key, 'arrayBuffer');
        if (content) {
          await env.WEBDAV_STORAGE.put(destKey, content);
        }
      }
    }

    // 更新父目录时间戳
    const destParentPath = getParentPath(normalizedDestPath);
    await updateDirectoryTimestamp(env, destParentPath);

    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'DAV': '1, 2, 3',
        'MS-Author-Via': 'DAV'
      }
    });
  } catch (error) {
    console.error('COPY 处理错误:', error);
    return new Response('复制资源时出错', {
      status: 500,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'DAV': '1, 2, 3',
        'MS-Author-Via': 'DAV'
      }
    });
  }
}

// 处理 MOVE 请求
async function handleMove(request, env, path, webdavRoot = '/') {
  try {
    const normalizedPath = normalizePath(path);

    // 获取目标路径
    const destinationHeader = request.headers.get('Destination');
    if (!destinationHeader) {
      return new Response('缺少目标路径', {
        status: 400,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'DAV': '1, 2, 3',
          'MS-Author-Via': 'DAV'
        }
      });
    }

    let destinationUrl;
    try {
      // 尝试直接解析为完整URL
      destinationUrl = new URL(destinationHeader);
    } catch (e) {
      // 如果是相对路径，使用当前请求的协议和主机构建完整URL
      const currentUrl = new URL(request.url);
      // 确保路径以/开头
      const normalizedDestHeader = destinationHeader.startsWith('/') ? destinationHeader : `/${destinationHeader}`;
      destinationUrl = new URL(normalizedDestHeader, `${currentUrl.protocol}//${currentUrl.host}`);
    }
    let destinationPath = destinationUrl.pathname;

    // Destination 头中的路径是客户端视角的路径（相对于其挂载的 WebDAV 根目录），
    // 需要换算成存储桶中的真实键路径，才能与 normalizedPath（已经是存储路径）
    // 进行比较和操作
    const normalizedDestPath = webdavPathToStorage(destinationPath, webdavRoot);

    // 检查源资源是否存在
    const sourceInfo = await getResourceInfo(env, normalizedPath);
    if (!sourceInfo) {
      return new Response('源资源不存在', {
        status: 404,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'DAV': '1, 2, 3',
          'MS-Author-Via': 'DAV'
        }
      });
    }

    // 检查目标资源是否存在
    const destInfo = await getResourceInfo(env, normalizedDestPath);
    if (destInfo) {
      // 如果目标存在，根据Overwrite头部决定是否覆盖
      const overwriteHeader = request.headers.get('Overwrite') || 'T';
      if (overwriteHeader.toLowerCase() !== 't') {
        return new Response('目标已存在且不允许覆盖', {
          status: 412,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'DAV': '1, 2, 3',
            'MS-Author-Via': 'DAV'
          }
        });
      }
    }

    if (sourceInfo.type === 'file') {
      // 移动文件
      const content = await env.WEBDAV_STORAGE.get(normalizedPath, 'arrayBuffer');
      if (content) {
        // 先复制到目标
        await env.WEBDAV_STORAGE.put(normalizedDestPath, content);

        // 复制元数据
        const metaData = await env.WEBDAV_STORAGE.get(`${normalizedPath}_meta`, 'json');
        if (metaData) {
          await env.WEBDAV_STORAGE.put(`${normalizedDestPath}_meta`, JSON.stringify(metaData));
        }

        // 删除源文件
        await env.WEBDAV_STORAGE.delete(normalizedPath);
        await env.WEBDAV_STORAGE.delete(`${normalizedPath}_meta`);
      }
    } else {
      // 移动目录：复制目录标记及所有子资源（文件内容、元数据、子目录标记）到新位置，
      // 再删除源目录树，确保嵌套内容不会变成孤儿数据
      await env.WEBDAV_STORAGE.put(`${normalizedDestPath}_dir`, JSON.stringify(sourceInfo));

      const descendantKeys = await listAllDescendantKeys(env, normalizedPath);
      for (const key of descendantKeys) {
        const destKey = `${normalizedDestPath}${key.slice(normalizedPath.length)}`;
        const content = await env.WEBDAV_STORAGE.get(key, 'arrayBuffer');
        if (content) {
          await env.WEBDAV_STORAGE.put(destKey, content);
        }
        await env.WEBDAV_STORAGE.delete(key);
      }

      // 删除源目录标记
      await env.WEBDAV_STORAGE.delete(`${normalizedPath}_dir`);
    }

    // 更新父目录时间戳
    const sourceParentPath = getParentPath(normalizedPath);
    await updateDirectoryTimestamp(env, sourceParentPath);

    const destParentPath = getParentPath(normalizedDestPath);
    await updateDirectoryTimestamp(env, destParentPath);

    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'DAV': '1, 2, 3',
        'MS-Author-Via': 'DAV'
      }
    });
  } catch (error) {
    console.error('MOVE 处理错误:', error);
    return new Response('移动资源时出错', {
      status: 500,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'DAV': '1, 2, 3',
        'MS-Author-Via': 'DAV'
      }
    });
  }
}

// 处理 MKCOL 请求（创建目录）
async function handleMkcol(env, path, webdavRoot = '/') {
  try {
    const normalizedPath = normalizePath(path);

    // 确保根目录存在（若配置了自定义 WebDAV 根路径，同时确保该路径本身存在）
    await ensureRootDirectory(env, webdavRoot);

    // 检查路径是否已存在
    const existingInfo = await getResourceInfo(env, normalizedPath);
    if (existingInfo) {
      if (existingInfo.type === 'directory') {
        // 目录已存在，返回201状态码（标准WebDAV行为）
        return new Response(null, {
          status: 201,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'DAV': '1, 2, 3',
            'MS-Author-Via': 'DAV'
          }
        });
      } else {
        // 路径已存在但不是目录，返回409 Conflict
        return new Response('路径已存在但不是目录', {
          status: 409,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'DAV': '1, 2, 3',
            'MS-Author-Via': 'DAV'
          }
        });
      }
    }

    // 确保父目录存在
    const parentPath = getParentPath(normalizedPath);
    if (parentPath) {
      try {
        // 使用ensureDirectoryExists来确保父目录存在，这样可以捕获路径被文件占用的情况
        await ensureDirectoryExists(env, parentPath);
      } catch (error) {
        if (error.message && error.message.includes('路径已被文件占用')) {
          return new Response('父目录路径被文件占用', {
            status: 409,
            headers: {
              'Access-Control-Allow-Origin': '*',
              'DAV': '1, 2, 3',
              'MS-Author-Via': 'DAV',
              'Content-Type': 'text/plain; charset=utf-8'
            }
          });
        }
        // 对于其他错误，使用更通用的检查
        const parentInfo = await getResourceInfo(env, parentPath);
        if (!parentInfo || parentInfo.type !== 'directory') {
          return new Response('父目录不存在', {
            status: 409,
            headers: {
              'Access-Control-Allow-Origin': '*',
              'DAV': '1, 2, 3',
              'MS-Author-Via': 'DAV',
              'Content-Type': 'text/plain; charset=utf-8'
            }
          });
        }
      }
    }

    // 使用简化的目录存储方式，创建一个目录标记
    const now = new Date().toISOString();
    const dirPath = `${normalizedPath}_dir`;

    await env.WEBDAV_STORAGE.put(dirPath, JSON.stringify({
      type: 'directory',
      createdAt: now,
      modifiedAt: now
    }));

    // 同时写入一个嵌套的空目录标记（与 /api/files/mkdir 使用的约定一致）。
    // /api/files 的文件管理器完全依赖 R2 原生的前缀+分隔符分组来发现文件夹，
    // 不识别上面的 "_dir" 后缀标记；如果没有这个真实的嵌套键，刚创建的空目录
    // 在文件管理器里会不可见，直到目录中出现真正的文件为止。
    await env.WEBDAV_STORAGE.put(`${normalizedPath}/.emptydir`, new Uint8Array(0), {
      customMetadata: { type: 'folder' }
    });

    // 更新父目录修改时间
    await updateDirectoryTimestamp(env, parentPath);

    return new Response(null, {
      status: 201,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'DAV': '1, 2, 3',
        'MS-Author-Via': 'DAV',
        'Public': 'OPTIONS, GET, HEAD, DELETE, PUT, PROPFIND, MKCOL'
      }
    });
  } catch (error) {
    console.error('MKCOL 处理错误:', error);
    return new Response('创建目录时出错', {
      status: 500,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'DAV': '1, 2, 3',
        'MS-Author-Via': 'DAV',
        'Content-Type': 'text/plain; charset=utf-8'
      }
    });
  }
}

// 辅助函数：规范化路径
function normalizePath(path) {
  // 防止空路径或null/undefined
  if (!path) return '/';

  // 确保路径以 / 开头
  let normalized = path.startsWith('/') ? path : '/' + path;

  // 移除连续的斜杠
  normalized = normalized.replace(/\/+/g, '/');

  // 统一格式：始终移除末尾斜杠，除非是根目录
  // 这确保了路径处理的一致性，避免创建重复目录
  if (normalized !== '/' && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }

  // 确保路径不为空
  if (normalized === '') return '/';

  return normalized;
}

// 辅助函数：获取父路径
function getParentPath(path) {
  if (path === '/') return null;
  const parts = path.split('/').filter(Boolean);
  if (parts.length === 0) return '/';
  return '/' + parts.slice(0, -1).join('/');
}

// 安全地连接路径部分，避免双斜杠
function joinPath(base, path) {
  if (!base) return `/${path}`;
  if (!path) return base;

  const baseClean = base.endsWith('/') ? base.slice(0, -1) : base;
  const pathClean = path.startsWith('/') ? path.slice(1) : path;

  const result = `${baseClean}/${pathClean}`;
  // 确保结果规范化，移除连续斜杠
  return result.replace(/\/+/g, '/');
}

// 格式化文件大小为人类可读格式
function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';

  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 辅助函数：确保目录存在
async function ensureDirectoryExists(env, path) {
  if (!path || path === '/') return;

  // 规范化路径，确保无论是否有末尾斜杠都使用统一的路径格式
  const normalizedPath = normalizePath(path);

  // 简化目录存储，只使用统一的目录标记方式
  const dirPath = `${normalizedPath}_dir`;

  try {
    // 首先检查是否有同名文件存在
    const fileExists = await env.WEBDAV_STORAGE.get(normalizedPath) !== null;
    const metaExists = await env.WEBDAV_STORAGE.get(`${normalizedPath}_meta`) !== null;

    if (fileExists || metaExists) {
      // 如果路径上已存在文件，抛出错误
      throw new Error(`路径已被文件占用: ${normalizedPath}`);
    }

    const dirExists = await env.WEBDAV_STORAGE.get(dirPath) !== null;

    if (!dirExists) {
      // 递归创建父目录
      const parentPath = getParentPath(normalizedPath);
      if (parentPath) {
        await ensureDirectoryExists(env, parentPath);
      }

      // 只创建一个目录标记
      await env.WEBDAV_STORAGE.put(dirPath, JSON.stringify({
        type: 'directory',
        createdAt: new Date().toISOString(),
        modifiedAt: new Date().toISOString()
      }));
      console.log(`目录已创建: ${normalizedPath}`);
    }
  } catch (error) {
    console.error(`创建目录失败: ${normalizedPath}`, error);
    throw error; // 重新抛出错误，让调用者知道发生了问题
  }
}

// 辅助函数：更新目录时间戳
async function updateDirectoryTimestamp(env, path) {
  if (!path) return;

  try {
    // 使用新的目录标记方式更新时间戳
    const dirPath = path === '/' ? '/_dir' : `${path}_dir`;
    const dirInfo = await env.WEBDAV_STORAGE.get(dirPath, 'json');

    if (dirInfo && dirInfo.type === 'directory') {
      dirInfo.modifiedAt = new Date().toISOString();
      await env.WEBDAV_STORAGE.put(dirPath, JSON.stringify(dirInfo));
    }
  } catch (error) {
    console.error('更新目录时间戳失败:', error);
  }
}

// 确保根目录存在
async function ensureRootDirectory(env, webdavRoot = '/') {
  try {
    const rootDirPath = '/_dir';
    const rootExists = await env.WEBDAV_STORAGE.get(rootDirPath) !== null;

    if (!rootExists) {
      // 只创建一个根目录标记
      await env.WEBDAV_STORAGE.put(rootDirPath, JSON.stringify({
        type: 'directory',
        createdAt: new Date().toISOString(),
        modifiedAt: new Date().toISOString()
      }));
    }

    // 如果管理员配置了自定义 WebDAV 根路径，确保该路径本身（及其所有祖先目录）
    // 也已存在——否则客户端在这个根路径从未被显式创建过（例如从未执行过 MKCOL）
    // 时会看到"资源不存在"，而不是一个空目录
    const normalizedRoot = normalizeWebdavRoot(webdavRoot);
    if (normalizedRoot !== '/') {
      await ensureDirectoryExists(env, normalizedRoot);
    }
  } catch (error) {
    console.error('初始化根目录失败:', error);
    throw error;
  }
}

// 获取资源信息（优化版：减少KV读取次数）
async function getResourceInfo(env, path) {
  try {
    // 确保路径不为空
    if (!path || path === '') {
      console.error('getResourceInfo: 无效的空路径');
      return null;
    }

    // 检查是否是目录
    const dirPath = path === '/' ? '/_dir' : `${path}_dir`;
    const dirInfo = await env.WEBDAV_STORAGE.get(dirPath, 'json');
    if (dirInfo && dirInfo.type === 'directory') {
      return dirInfo;
    }

    // 检查是否是文件（只获取元数据，不单独检查文件内容）
    const metaPath = `${path}_meta`;
    const metaInfo = await env.WEBDAV_STORAGE.get(metaPath, 'json');
    if (metaInfo && metaInfo.type === 'file') {
      return metaInfo;
    }

    // 兼容通过 REST API（/api/files/mkdir）创建、但还没有 "_dir" 标记的空目录
    // ——例如本次修复之前就已创建的目录，它们只带有嵌套的 ".emptydir" 标记
    if (path !== '/') {
      const emptyDirMarker = await env.WEBDAV_STORAGE.get(`${path}/.emptydir`);
      if (emptyDirMarker) {
        return {
          type: 'directory',
          createdAt: new Date().toISOString(),
          modifiedAt: new Date().toISOString()
        };
      }
    }

    return null;
  } catch (error) {
    console.error('获取资源信息失败:', error);
    return null;
  }
}

// 列出目录子资源（优化版：批量获取减少KV读取次数）
async function listDirectoryChildren(env, path) {
  try {
    // 确保路径不为空
    if (!path || path === '') {
      console.error('listDirectoryChildren: 无效的空路径');
      return [];
    }

    // 规范化路径
    const normalizedPath = normalizePath(path);

    // 存储已处理的子资源名称，避免重复
    const processedChildren = new Set();
    const children = [];

    // 构建前缀。存储键统一带前导 '/'（见 normalizePath），
    // 根目录的前缀同样使用 '/' 而不是空字符串，这样根目录和子目录可以复用同一套
    // "相对路径 = key.substring(prefix.length)" 逻辑。
    // 之前根目录使用空前缀时，key 本身仍以 '/' 开头，导致 !key.name.includes('/')
    // 这类判断永远为假，根目录下的文件/子目录会被判断为"包含路径分隔符"而被跳过，
    // 也就是说根目录下的文件永远不会出现在 PROPFIND / 目录列表页中。
    const prefix = normalizedPath === '/' ? '/' : `${normalizedPath}/`;

    // 列出所有匹配前缀的键
    const listResult = await env.WEBDAV_STORAGE.list({
      prefix: prefix,
      limit: 1000 // 设置合理的限制，避免一次性加载太多项
    });

    // 收集所有需要处理的目录信息
    const directoriesToProcess = [];
    for (const key of listResult.keys) {
      // 过滤掉session数据和非目录项
      if (key.name.endsWith('_meta') || !key.name.endsWith('_dir') || key.name.startsWith('session_')) continue;

      const relativePath = key.name.substring(prefix.length);
      const dirName = relativePath.slice(0, -4); // 去掉末尾的 "_dir"

      if (dirName.trim() === '' || dirName.includes('/') || processedChildren.has(dirName)) continue;

      directoriesToProcess.push({ dirName, keyName: key.name });
    }

    // 批量获取目录信息
    const dirPromises = directoriesToProcess.map(dir =>
      env.WEBDAV_STORAGE.get(dir.keyName, 'json')
    );
    const dirResults = await Promise.all(dirPromises);

    // 添加目录到结果
    directoriesToProcess.forEach((dir, index) => {
      const dirInfo = dirResults[index];
      if (dirInfo) {
        processedChildren.add(dir.dirName);
        children.push({
          name: dir.dirName,
          type: 'directory',
          modifiedAt: dirInfo?.modifiedAt || new Date().toISOString(),
          size: 0,
          contentType: 'httpd/unix-directory'
        });
      }
    });

    // 兼容通过 REST API（/api/files/mkdir）创建、但还没有 "_dir" 标记的空目录
    // ——例如本次修复之前就已创建的目录，它们只带有 ".emptydir" 标记
    const EMPTYDIR_SUFFIX = '/.emptydir';
    for (const key of listResult.keys) {
      if (!key.name.endsWith(EMPTYDIR_SUFFIX)) continue;
      const relativePath = key.name.substring(prefix.length);
      const dirName = relativePath.slice(0, -EMPTYDIR_SUFFIX.length);
      if (!dirName || dirName.includes('/') || processedChildren.has(dirName)) continue;
      processedChildren.add(dirName);
      children.push({
        name: dirName,
        type: 'directory',
        modifiedAt: new Date().toISOString(),
        size: 0,
        contentType: 'httpd/unix-directory'
      });
    }

    // 收集所有需要处理的文件信息
    const filesToProcess = [];
    for (const key of listResult.keys) {
      // 过滤掉session数据、元数据、目录标记和空目录标记（.emptydir 本身不是用户文件）
      if (
        key.name.endsWith('_meta') ||
        key.name.endsWith('_dir') ||
        key.name.startsWith('session_') ||
        key.name.endsWith('.emptydir')
      ) continue;

      const relativePath = key.name.substring(prefix.length);
      // 相对路径为空或仍包含 '/' 说明它不是当前目录的直接子项（是更深层级的文件）
      if (relativePath.trim() === '' || relativePath.includes('/') || processedChildren.has(relativePath)) continue;

      filesToProcess.push({ fileName: relativePath, fileKeyName: key.name });
    }

    // 批量获取文件元数据
    const metaPromises = filesToProcess.map(file =>
      env.WEBDAV_STORAGE.get(`${file.fileKeyName}_meta`, 'json').catch(() => null)
    );
    const metaResults = await Promise.all(metaPromises);

    // 添加文件到结果
    filesToProcess.forEach((file, index) => {
      const metaData = metaResults[index];
      const fileSize = metaData?.size || 0;

      processedChildren.add(file.fileName);
      children.push({
        name: file.fileName,
        type: 'file',
        modifiedAt: metaData?.modifiedAt || new Date().toISOString(),
        size: fileSize,
        contentType: metaData?.contentType
      });
    });

    // 按名称排序，目录在前，文件在后
    children.sort((a, b) => {
      if (a.type === 'directory' && b.type === 'file') return -1;
      if (a.type === 'file' && b.type === 'directory') return 1;
      return a.name.localeCompare(b.name);
    });

    return children;
  } catch (error) {
    console.error('列出目录子资源失败:', error);
    return [];
  }
}

// 获取内容类型
function getContentType(path) {
  const ext = path.split('.').pop().toLowerCase();
  const mimeTypes = {
    'txt': 'text/plain',
    'html': 'text/html',
    'js': 'application/javascript',
    'json': 'application/json',
    'css': 'text/css',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'pdf': 'application/pdf',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  };

  return mimeTypes[ext] || 'application/octet-stream';
}