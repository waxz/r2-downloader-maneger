import { $typst } from 'https://cdn.jsdelivr.net/npm/@myriaddreamin/typst.ts/dist/esm/contrib/snippet.mjs';

// Configured at runtime from the blog page (API key + base URL).
let _apiKey = '';
let _baseUrl = '';

export function configureBackend(baseUrl, apiKey) {
  _baseUrl = baseUrl.replace(/\/$/, '');
  _apiKey = apiKey;
}

// VFS cache: paths already mapped into the WASM memory filesystem.
const vfsCache = new Set();

// Fallback 1×1 transparent red pixel for broken / CORS-blocked images.
const FALLBACK_PNG = new Uint8Array([
  137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1,
  0, 0, 0, 1, 8, 2, 0, 0, 0, 144, 119, 83, 141, 0, 0, 0, 12, 73, 68, 65, 84,
  8, 215, 99, 248, 15, 0, 1, 1, 1, 0, 107, 18, 11, 174, 0, 0, 0, 0, 73, 69,
  78, 68, 174, 66, 96, 130,
]);

function resolveAbsolutePath(baseDir, targetPath) {
  if (targetPath.startsWith('http') || targetPath.startsWith('@')) return targetPath;
  if (targetPath.startsWith('/')) return targetPath;
  const baseParts = baseDir.split('/').filter(Boolean);
  for (const part of targetPath.split('/').filter(Boolean)) {
    if (part === '.') continue;
    if (part === '..') baseParts.pop();
    else baseParts.push(part);
  }
  return '/' + baseParts.join('/');
}

function backendUrl(absolutePath) {
  // Absolute http(s) paths are fetched directly (e.g. Typst package registry).
  if (absolutePath.startsWith('http')) return absolutePath;
  const key = absolutePath.startsWith('/') ? absolutePath.slice(1) : absolutePath;
  const sep = _apiKey ? '?key=' + encodeURIComponent(_apiKey) : '';
  return `${_baseUrl}/get/${key}${sep}`;
}

async function fetchAndMap(absolutePath) {
  const url = backendUrl(absolutePath);
  let res;
  try {
    res = await fetch(url);
  } catch {
    return false;
  }
  if (!res.ok) return false;

  if (/\.(png|jpg|jpeg|gif|webp|svg|ttf|otf|woff|woff2)$/i.test(absolutePath)) {
    await $typst.mapShadow(absolutePath, new Uint8Array(await res.arrayBuffer()));
  } else {
    await $typst.mapShadow(absolutePath, new TextEncoder().encode(await res.text()));
  }
  return true;
}

export async function lazyRenderTypst(mainFilePath, { forceUpdate = false } = {}) {
  if (forceUpdate) vfsCache.clear();

  mainFilePath = resolveAbsolutePath('/', mainFilePath);
  const baseDir = mainFilePath.substring(0, mainFilePath.lastIndexOf('/') + 1);
  const isMarkdown = mainFilePath.toLowerCase().endsWith('.md');

  // Fetch & map entry file.
  let entryText = null;
  if (!vfsCache.has(mainFilePath)) {
    const ok = await fetchAndMap(mainFilePath);
    if (!ok) throw new Error(`Entry file not found: ${mainFilePath}`);
    vfsCache.add(mainFilePath);
    // Re-read for regex pre-fetch (mapShadow consumed the body).
    const url = backendUrl(mainFilePath);
    entryText = await fetch(url).then(r => r.text()).catch(() => null);
  }

  // Regex pre-fetch: parallelise all statically-referenced assets.
  if (entryText) {
    const queue = [];
    const enqueue = (regex, text, isMdImage = false) => {
      let m;
      while ((m = regex.exec(text)) !== null) {
        let raw = isMdImage ? m[1].split(/[\s"']/)[0].trim() : m[1].trim();
        if (raw.startsWith('@')) continue;
        const abs = resolveAbsolutePath(baseDir, raw);
        if (!vfsCache.has(abs)) {
          vfsCache.add(abs);
          queue.push(fetchAndMap(abs).catch(() => { vfsCache.delete(abs); }));
        }
      }
    };
    enqueue(/(?:import|include)\s+["']([^"']+)["']/g, entryText);
    enqueue(/image\s*\(\s*["']([^"']+)["']/g, entryText);
    if (isMarkdown) enqueue(/!\[.*?\]\((.*?)\)/g, entryText, true);
    if (queue.length) await Promise.allSettled(queue);
  }

  // Markdown wrapper: references /renderer.typ stored in R2.
  const embedCode = isMarkdown
    ? `#import "/renderer.typ": render-md-doc\n#render-md-doc("${mainFilePath}")`
    : null;

  // Compilation feedback loop: fetch missing files on demand.
  while (true) {
    try {
      return isMarkdown
        ? await $typst.svg({ mainContent: embedCode })
        : await $typst.svg({ mainFilePath });
    } catch (error) {
      const msg = error.toString();
      const m = msg.match(/(?:file not found|failed to load file)[:\s]*["']?([^"'\n]+)["']?/i);
      if (!m) throw error;

      const abs = resolveAbsolutePath(baseDir, m[1].trim());
      if (vfsCache.has(abs)) throw new Error(`VFS corruption for: ${abs}`);

      const ok = await fetchAndMap(abs);
      if (!ok) {
        if (/\.(png|jpg|jpeg|gif|webp)$/i.test(abs) || abs.startsWith('http')) {
          await $typst.mapShadow(abs, FALLBACK_PNG);
        } else if (/\.svg$/i.test(abs)) {
          await $typst.mapShadow(abs, new TextEncoder().encode(
            `<svg width="100" height="20" xmlns="http://www.w3.org/2000/svg"><rect width="100%" height="100%" fill="red"/><text x="50%" y="50%" font-size="10" fill="white" dominant-baseline="middle" text-anchor="middle">Missing SVG</text></svg>`
          ));
        } else {
          await $typst.mapShadow(abs, new TextEncoder().encode(
            `\n#rect(fill: rgb("ffebee"), stroke: rgb("ff5252"))[**Warning:** Missing file \`${abs}\`]\n`
          ));
        }
      }
      vfsCache.add(abs);
    }
  }
}
