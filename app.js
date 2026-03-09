'use strict';

let scanResults = {};
let checkState = {};


const PROXY_URL = 'proxy.php';
let backendAvailable = false;

// Detect if PHP backend is available
async function detectBackend() {
  try {
    const res = await fetch(PROXY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'ping' }),
      signal: AbortSignal.timeout(3000)
    });
    // Even a 400 means the backend is responding
    backendAvailable = res.status < 500;
    return backendAvailable;
  } catch (e) {
    backendAvailable = false;
    return false;
  }
}

// Call the PHP backend proxy
async function proxyCall(action, params = {}, timeoutMs = 12000) {
  const res = await fetch(PROXY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, ...params }),
    signal: AbortSignal.timeout(timeoutMs)
  });
  const json = await res.json();
  if (!json.ok) throw new Error(json.error || 'Backend error');
  return json.data;
}

// Smart fetch: uses proxy if available, falls back to direct fetch
async function smartFetch(url, options = {}) {
  if (backendAvailable) {
    try {
      const method = (options.method || 'GET').toUpperCase();
      const data = await proxyCall(method === 'HEAD' ? 'headers' : 'fetch', {
        url,
        method
      });
      return {
        status: data.status,
        headers: data.headers || {},
        body: data.body || '',
        redirected: !!data.redirect,
        url: data.finalUrl || url,
        fromProxy: true
      };
    } catch (e) {
      // Proxy failed, fall through to direct fetch
    }
  }

  // Direct fetch fallback (may be blocked by CORS)
  try {
    const res = await fetch(url, {
      ...options,
      cache: 'no-store',
      signal: AbortSignal.timeout(options.timeout || 12000)
    });
    const headers = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    const body = options.method === 'HEAD' ? '' : await res.text();
    return {
      status: res.status,
      headers,
      body,
      redirected: res.redirected,
      url: res.url,
      fromProxy: false
    };
  } catch (e) {
    // Last resort: HEAD-only via no-cors
    if (options.method !== 'HEAD') {
      try {
        const headRes = await fetch(url, {
          method: 'HEAD',
          cache: 'no-store',
          signal: AbortSignal.timeout(8000)
        });
        const headers = {};
        headRes.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
        return { status: headRes.status, headers, body: '', redirected: false, url, fromProxy: false, headOnly: true };
      } catch (e2) { /* fall through */ }
    }
    throw e;
  }
}

// Smart HEAD request for path scanning
async function smartHead(url, timeoutMs = 5000) {
  if (backendAvailable) {
    try {
      const data = await proxyCall('headers', { url }, timeoutMs);
      return { status: data.status, headers: data.headers || {} };
    } catch (e) {
      return { status: 'error', headers: {} };
    }
  }
  // Direct fallback
  try {
    const res = await fetch(url, { method: 'HEAD', cache: 'no-store', signal: AbortSignal.timeout(timeoutMs) });
    return { status: res.status, headers: {} };
  } catch (e) {
    try {
      await fetch(url, { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(3000) });
      return { status: 'opaque', headers: {} };
    } catch (e2) {
      return { status: 'error', headers: {} };
    }
  }
}


//  DATOS: Rutas sensibles
const SENSITIVE_PATHS = [
  { p: '/.env', label: '.env expuesto', sev: 'C' },
  { p: '/.env.backup', label: '.env backup', sev: 'C' },
  { p: '/.env.local', label: '.env.local', sev: 'C' },
  { p: '/.git/HEAD', label: 'Repo Git expuesto', sev: 'C' },
  { p: '/.git/config', label: 'Git config expuesto', sev: 'C' },
  { p: '/backup.sql', label: 'backup.sql', sev: 'C' },
  { p: '/dump.sql', label: 'dump.sql', sev: 'C' },
  { p: '/database.sql', label: 'database.sql', sev: 'C' },
  { p: '/db.sql', label: 'db.sql', sev: 'C' },
  { p: '/wp-config.php.bak', label: 'wp-config backup', sev: 'C' },
  { p: '/wp-config.php.old', label: 'wp-config old', sev: 'C' },
  { p: '/.htpasswd', label: '.htpasswd expuesto', sev: 'C' },
  { p: '/.ssh/id_rsa', label: 'SSH key expuesta', sev: 'C' },
  { p: '/phpmyadmin/', label: 'phpMyAdmin', sev: 'C' },
  { p: '/adminer.php', label: 'Adminer DB manager', sev: 'C' },
  { p: '/wp-admin/', label: 'Panel WordPress', sev: 'H' },
  { p: '/admin', label: 'Panel /admin', sev: 'H' },
  { p: '/admin/', label: 'Panel /admin/', sev: 'H' },
  { p: '/administrator', label: 'Panel Joomla', sev: 'H' },
  { p: '/server-status', label: 'Apache status', sev: 'H' },
  { p: '/server-info', label: 'Apache info', sev: 'H' },
  { p: '/config.json', label: 'config.json', sev: 'H' },
  { p: '/config.yml', label: 'config.yml', sev: 'H' },
  { p: '/config.php', label: 'config.php', sev: 'H' },
  { p: '/debug', label: 'Debug endpoint', sev: 'H' },
  { p: '/_debug', label: '_debug endpoint', sev: 'H' },
  { p: '/elmah.axd', label: 'ELMAH error log', sev: 'H' },
  { p: '/trace.axd', label: 'ASP.NET Trace', sev: 'H' },
  { p: '/info.php', label: 'phpinfo()', sev: 'H' },
  { p: '/phpinfo.php', label: 'phpinfo()', sev: 'H' },
  { p: '/test.php', label: 'test.php', sev: 'H' },
  { p: '/nuxt.config.ts', label: 'Nuxt config expuesta', sev: 'H' },
  { p: '/wp-json/wp/v2/users', label: 'WP users API', sev: 'H' },
  { p: '/api/', label: 'API root', sev: 'M' },
  { p: '/api/v1/', label: 'API v1', sev: 'M' },
  { p: '/api/v2/', label: 'API v2', sev: 'M' },
  { p: '/graphql', label: 'GraphQL endpoint', sev: 'M' },
  { p: '/swagger/', label: 'Swagger UI', sev: 'M' },
  { p: '/swagger.json', label: 'Swagger JSON', sev: 'M' },
  { p: '/api-docs', label: 'API Docs', sev: 'M' },
  { p: '/package.json', label: 'package.json', sev: 'M' },
  { p: '/crossdomain.xml', label: 'crossdomain.xml', sev: 'M' },
  { p: '/xmlrpc.php', label: 'XML-RPC (WordPress)', sev: 'M' },
  { p: '/.DS_Store', label: '.DS_Store expuesto', sev: 'M' },
  { p: '/Thumbs.db', label: 'Thumbs.db expuesto', sev: 'M' },
  { p: '/web.config', label: 'web.config expuesto', sev: 'M' },
  { p: '/composer.json', label: 'composer.json', sev: 'L' },
  { p: '/composer.lock', label: 'composer.lock', sev: 'L' },
  { p: '/package-lock.json', label: 'package-lock.json', sev: 'L' },
  { p: '/yarn.lock', label: 'yarn.lock', sev: 'L' },
  { p: '/changelog.txt', label: 'Changelog', sev: 'L' },
  { p: '/readme.html', label: 'Readme HTML', sev: 'L' },
  { p: '/README.md', label: 'README.md', sev: 'L' },
  { p: '/license.txt', label: 'License', sev: 'I' },
  { p: '/sitemap.xml', label: 'Sitemap', sev: 'I' },
  { p: '/sitemap_index.xml', label: 'Sitemap index', sev: 'I' },
  { p: '/robots.txt', label: 'robots.txt', sev: 'I' },
  { p: '/.well-known/security.txt', label: 'security.txt', sev: 'I' },
  { p: '/humans.txt', label: 'humans.txt', sev: 'I' },
  { p: '/favicon.ico', label: 'Favicon', sev: 'I' },
];


//  DATOS: Cabeceras de seguridad

const SEC_HEADERS = [
  {
    h: 'x-frame-options', label: 'X-Frame-Options', good: v => !!v, sev: 'H',
    fix: 'Agrega X-Frame-Options: DENY o SAMEORIGIN para prevenir clickjacking.'
  },
  {
    h: 'content-security-policy', label: 'Content-Security-Policy', good: v => !!v, sev: 'H',
    fix: 'Define directivas CSP para restringir recursos (Nota: Asegúrate de permitir CDNs legítimos como cdnjs o fonts.googleapis para no romper la estética de tu app).'
  },
  {
    h: 'strict-transport-security', label: 'HSTS', good: v => !!v, sev: 'H',
    fix: 'Agrega Strict-Transport-Security: max-age=31536000; includeSubDomains'
  },
  {
    h: 'x-content-type-options', label: 'X-Content-Type-Options', good: v => v === 'nosniff', sev: 'M',
    fix: 'Agrega X-Content-Type-Options: nosniff para evitar MIME sniffing.'
  },
  {
    h: 'referrer-policy', label: 'Referrer-Policy', good: v => !!v, sev: 'M',
    fix: 'Usa Referrer-Policy: strict-origin-when-cross-origin.'
  },
  {
    h: 'permissions-policy', label: 'Permissions-Policy', good: v => !!v, sev: 'M',
    fix: 'Define una Permissions-Policy para controlar APIs del navegador.'
  },
  {
    h: 'cross-origin-opener-policy', label: 'Cross-Origin-Opener-Policy', good: v => !!v, sev: 'M',
    fix: 'Agrega Cross-Origin-Opener-Policy: same-origin para aislar el contexto del navegador.'
  },
  {
    h: 'cross-origin-resource-policy', label: 'Cross-Origin-Resource-Policy', good: v => !!v, sev: 'L',
    fix: 'Agrega Cross-Origin-Resource-Policy: same-origin (Nota: usa "cross-origin" si tu sitio carga recursos de otros dominios, de lo contrario bloqueará iconos/fuentes).'
  },
  {
    h: 'cross-origin-embedder-policy', label: 'Cross-Origin-Embedder-Policy', good: v => !!v, sev: 'L',
    fix: 'Agrega Cross-Origin-Embedder-Policy: require-corp (⚠ Advertencia: Muy restrictiva, puede romper scripts externos o iframes si no están configurados correctamente).'
  },
  {
    h: 'x-xss-protection', label: 'X-XSS-Protection', good: v => !!v, sev: 'L',
    fix: 'Agrega X-XSS-Protection: 1; mode=block (legacy, pero útil en navegadores antiguos).'
  },
  {
    h: 'x-powered-by', label: 'X-Powered-By (expuesto)', good: v => !v, sev: 'L',
    fix: 'Elimina la cabecera X-Powered-By para no revelar el stack tecnológico.'
  },
  {
    h: 'server', label: 'Server header (expuesto)', good: v => !v, sev: 'L',
    fix: 'Elimina o anonimiza la cabecera Server para ocultar la versión del servidor.'
  },
  {
    h: 'x-aspnet-version', label: 'X-AspNet-Version (expuesto)', good: v => !v, sev: 'L',
    fix: 'Elimina X-AspNet-Version para no revelar la versión de ASP.NET.'
  },
];

//  UTILIDADES 
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function sevOrder(s) { return { C: 0, H: 1, M: 2, L: 3, I: 4 }[s] ?? 5; }
function escHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function addLog(html) {
  const log = document.getElementById('progress-log');
  log.innerHTML += html + '\n';
  log.scrollTop = log.scrollHeight;
}
function setProgress(pct, label) {
  document.getElementById('prog-fill').style.width = pct + '%';
  document.getElementById('progress-label').textContent = label;
}

// Generate AI-ready prompt for a finding
function generateAIPrompt(finding, url) {
  const sevName = { C: 'CRITICO', H: 'ALTO', M: 'MEDIO', L: 'BAJO', I: 'INFO' }[finding.sev] || 'UNKNOWN';
  return `Tengo un problema de seguridad web en mi sitio ${url} que necesito corregir.

HALLAZGO [${sevName}]: ${finding.title}

DESCRIPCION: ${finding.desc.replace(/<[^>]+>/g, '')}

${finding.code ? `EVIDENCIA:\n${finding.code}\n` : ''}CORRECCION RECOMENDADA: ${finding.fix}

Por favor:
1. Explica exactamente que archivo(s) necesito modificar
2. Dame el codigo o configuracion exacta para implementar la correccion
3. Si es una cabecera HTTP, dame la configuracion para Nginx, Apache y Cloudflare
4. Verifica que la correccion no rompa funcionalidad existente`;
}

// Copy prompt to clipboard
function copyPrompt(btn, index) {
  const finding = scanResults.findings[index];
  if (!finding) return;
  const prompt = generateAIPrompt(finding, scanResults.url);
  navigator.clipboard.writeText(prompt).then(() => {
    btn.classList.add('copied');
    btn.innerHTML = '✓ Copiado';
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = '⎘ Copiar prompt';
    }, 2000);
  }).catch(() => {
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = prompt;
    ta.style.cssText = 'position:fixed;left:-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    btn.classList.add('copied');
    btn.innerHTML = '✓ Copiado';
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = '⎘ Copiar prompt';
    }, 2000);
  });
}


//  DETECCIÓN DE TECNOLOGÍAS

function detectTech(html, headers) {
  const techs = [];
  const h = html.toLowerCase();
  const rules = [
    [() => h.includes('__nuxt') || h.includes('/_nuxt/'), 'Nuxt.js'],
    [() => h.includes('__next') || h.includes('/_next/'), 'Next.js'],
    [() => h.includes('wp-content') || h.includes('wp-json'), 'WordPress'],
    [() => h.includes('shopify.theme') || h.includes('cdn.shopify'), 'Shopify'],
    [() => h.includes('gatsby-') || h.includes('gatsby'), 'Gatsby'],
    [() => h.includes('svelte') || h.includes('__svelte'), 'Svelte'],
    [() => h.includes('ng-version') || h.includes('ng-app'), 'Angular'],
    [() => h.includes('data-reactroot') || h.includes('_reactroot'), 'React'],
    [() => h.includes('data-v-') || h.includes('vue-'), 'Vue.js'],
    [() => h.includes('astro-'), 'Astro'],
    [() => h.includes('remix-'), 'Remix'],
    [() => h.includes('laravel') || h.includes('csrf-token'), 'Laravel'],
    [() => h.includes('django') || h.includes('csrfmiddlewaretoken'), 'Django'],
    [() => h.includes('rails') || h.includes('csrf-token') && h.includes('authenticity'), 'Ruby on Rails'],
    [() => h.includes('bootstrap'), 'Bootstrap'],
    [() => h.includes('tailwindcss') || h.includes('tailwind'), 'Tailwind CSS'],
    [() => h.includes('jquery') || h.includes('jquery.min.js'), 'jQuery'],
    [() => h.includes('cloudflare'), 'Cloudflare'],
    [() => h.includes('clarity.ms'), 'MS Clarity'],
    [() => h.includes('googletagmanager') || h.includes('gtag'), 'Google Analytics'],
    [() => h.includes('google-analytics'), 'Google Analytics'],
    [() => h.includes('fb-root') || h.includes('facebook'), 'Facebook SDK'],
    [() => h.includes('stripe.com'), 'Stripe'],
    [() => h.includes('recaptcha'), 'reCAPTCHA'],
    [() => h.includes('hotjar'), 'Hotjar'],
    [() => h.includes('intercom'), 'Intercom'],
    [() => h.includes('crisp.chat'), 'Crisp Chat'],
    [() => h.includes('tawk.to'), 'Tawk.to'],
  ];
  rules.forEach(([test, name]) => { if (test()) techs.push(name); });

  // Headers
  const xp = (headers['x-powered-by'] || '').toLowerCase();
  const sv = (headers['server'] || '').toLowerCase();
  if (xp.includes('php')) techs.push('PHP');
  if (xp.includes('express')) techs.push('Express.js');
  if (xp.includes('asp.net')) techs.push('ASP.NET');
  if (sv.includes('nginx')) techs.push('Nginx');
  if (sv.includes('apache')) techs.push('Apache');
  if (sv.includes('cloudflare')) techs.push('Cloudflare');
  if (sv.includes('iis')) techs.push('IIS');
  if (sv.includes('litespeed')) techs.push('LiteSpeed');
  if (headers['x-vercel-id']) techs.push('Vercel');
  if (headers['x-netlify-request-id']) techs.push('Netlify');
  if (sv.includes('github')) techs.push('GitHub Pages');

  return [...new Set(techs)];
}


//  ANÁLISIS DE HTML 

function analyzeHTML(html, url) {
  const findings = [];
  if (!html) return findings;

  // 1. Canonical apunta a localhost
  if (html.includes('localhost') && (html.includes('canonical') || html.includes('og:url'))) {
    findings.push({
      sev: 'C', title: 'Canonical/meta apunta a localhost en producción',
      desc: 'Las etiquetas canonical, og:url u otras referencias apuntan a localhost.',
      code: html.match(/localhost[^"']*/)?.[0]?.substring(0, 80) || 'localhost',
      fix: 'Configura correctamente SITE_URL o BASE_URL en tu servidor.'
    });
  }

  // 2. API keys o tokens en HTML
  const apiKeyPatterns = [
    { re: /['"](sk_(?:live|test|mock)_[a-zA-Z0-9]{20,})['"]/g, name: 'Stripe Secret Key' },
    { re: /['"](AKIA[0-9A-Z]{16})['"]/g, name: 'AWS Access Key' },
    { re: /['"](AIza[0-9A-Za-z\-_]{35})['"]/g, name: 'Google API Key' },
    { re: /['"]([a-f0-9]{32})['"]\s*[,;]\s*\/\/.*(?:api|key|secret|token)/gi, name: 'API Key/Secret' },
    { re: /(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{3,})['"]/gi, name: 'Password en código' },
    { re: /(?:token|api_key|apikey|secret)\s*[:=]\s*['"]([^'"]{8,})['"]/gi, name: 'Token/Secret en código' },
  ];
  for (const pat of apiKeyPatterns) {
    const match = pat.re.exec(html);
    if (match) {
      findings.push({
        sev: 'C', title: `${pat.name} expuesto en código fuente`,
        desc: `Se detectó lo que parece ser un ${pat.name} directamente en el HTML público.`,
        code: match[0].substring(0, 60) + '...', fix: 'Mueve todos los secrets al servidor. Nunca expongas keys en el frontend.'
      });
    }
  }

  // 3. Build ID expuesto
  if (html.includes('buildId') || html.includes('build_id')) {
    findings.push({
      sev: 'H', title: 'Build ID expuesto en HTML',
      desc: 'El build ID permite correlacionar versiones con CVEs conocidos.',
      code: html.match(/"buildId"\s*:\s*"[^"]+"/)?.[0]?.substring(0, 60) || '"buildId":"..."',
      fix: 'Configura el framework para omitir buildId en producción.'
    });
  }

  // 4. Formularios sin protección CSRF
  const formCount = (html.match(/<form/gi) || []).length;
  const csrfCount = (html.match(/csrf|_token|authenticity_token/gi) || []).length;
  if (formCount > 0 && csrfCount === 0) {
    findings.push({
      sev: 'H', title: `${formCount} formulario(s) sin protección CSRF visible`,
      desc: 'No se detectan tokens CSRF en los formularios. Esto puede permitir ataques Cross-Site Request Forgery.',
      code: `${formCount} <form> detectados, 0 tokens CSRF encontrados`,
      fix: 'Implementa tokens CSRF en todos los formularios que modifiquen datos.'
    });
  }

  // 5. Formularios con autocomplete en campos sensibles
  if (html.match(/<input[^>]*type=["']password["'][^>]*(?!autocomplete)/i) &&
    !html.match(/autocomplete=["']off["']/i)) {
    findings.push({
      sev: 'M', title: 'Campo de password sin autocomplete="off"',
      desc: 'Los campos de contraseña permiten autocompletado del navegador, lo que puede ser un riesgo en computadoras compartidas.',
      code: '<input type="password"> sin autocomplete="off"',
      fix: 'Agrega autocomplete="off" o autocomplete="new-password" a campos sensibles.'
    });
  }

  // 6. Email(s) expuestos
  const emailMatches = html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
  if (emailMatches) {
    const emails = [...new Set(emailMatches)].slice(0, 3);
    findings.push({
      sev: 'I', title: 'Email(s) expuesto(s): ' + emails.join(', '),
      desc: 'Correos expuestos en código fuente pueden ser objetivo de spam. Si son para contacto público es normal, pero si son internos es un riesgo.',
      code: emails.join('\n'), fix: 'Si no es público, usa JavaScript para ocultarlo o emplea un formulario de contacto en su lugar.'
    });
  }

  // 7. Mixed content
  if (html.includes('src="http://') || html.includes('href="http://')) {
    findings.push({
      sev: 'M', title: 'Contenido mixto HTTP detectado',
      desc: 'Se cargan recursos por HTTP en una página HTTPS. Vector de ataque MITM.',
      code: (html.match(/src="http:\/\/[^"]+"/) || ['src="http://..."'])[0].substring(0, 60),
      fix: 'Cambia todas las URLs de recursos a HTTPS.'
    });
  }

  // 8. Comentarios HTML con info sensible
  const comments = html.match(/<!--[\s\S]*?-->/g) || [];
  const sensitiveComments = comments.filter(c =>
    /todo|fixme|hack|bug|password|secret|key|token|admin|debug|test/i.test(c)
  );
  if (sensitiveComments.length > 0) {
    findings.push({
      sev: 'M', title: `${sensitiveComments.length} comentario(s) HTML con info sensible`,
      desc: 'Se encontraron comentarios que pueden revelar información de desarrollo, TODOs o credenciales.',
      code: sensitiveComments[0].substring(0, 80) + '...',
      fix: 'Elimina todos los comentarios de desarrollo del código en producción.'
    });
  }

  // 9. iframes externos
  const iframes = html.match(/<iframe[^>]*src=["'][^"']+["']/gi) || [];
  const extIframes = iframes.filter(f => !f.includes(new URL(url).hostname));
  if (extIframes.length > 0) {
    findings.push({
      sev: 'M', title: `${extIframes.length} iframe(s) externo(s) detectado(s)`,
      desc: 'Los iframes externos pueden ser usados para phishing o inyección de contenido malicioso.',
      code: extIframes[0].substring(0, 80), fix: 'Verifica que los iframes sean de fuentes confiables y usa sandbox.'
    });
  }

  // 10. target="_blank" sin rel="noopener"
  const blankLinks = (html.match(/target=["']_blank["']/gi) || []).length;
  const noopenerLinks = (html.match(/rel=["'][^"']*noopener[^"']*["']/gi) || []).length;
  if (blankLinks > noopenerLinks && blankLinks > 0) {
    findings.push({
      sev: 'L', title: `Links con target="_blank" sin rel="noopener"`,
      desc: 'Links que abren en nueva pestaña sin noopener pueden permitir tab-nabbing.',
      code: `${blankLinks} target="_blank", solo ${noopenerLinks} con rel="noopener"`,
      fix: 'Agrega rel="noopener noreferrer" a todos los links con target="_blank".'
    });
  }

  // 11. Scripts inline
  const inlineScripts = (html.match(/<script(?![^>]*src)[^>]*>/g) || []).length;
  if (inlineScripts > 3) {
    findings.push({
      sev: 'L', title: `${inlineScripts} scripts inline dificultan CSP`,
      desc: 'Muchos scripts inline hacen imposible implementar CSP sin unsafe-inline.',
      code: `${inlineScripts} scripts inline detectados`,
      fix: 'Mueve la lógica JS a archivos externos y usa nonces en CSP.'
    });
  }

  // 12. Meta viewport ausente (seguridad mobile)
  if (!html.includes('viewport')) {
    findings.push({
      sev: 'L', title: 'Meta viewport ausente',
      desc: 'Sin viewport configurado, la página puede ser vulnerable a ataques de UI redressing en móviles.',
      code: '<meta name="viewport"> no encontrado',
      fix: 'Agrega <meta name="viewport" content="width=device-width, initial-scale=1.0">.'
    });
  }

  // 13. Versión de dependencia expuesta
  const vMatch = html.match(/version["']?\s*:\s*["'][\d.]+["']/);
  if (vMatch) {
    findings.push({
      sev: 'L', title: 'Versión de dependencia expuesta en HTML',
      desc: 'Versiones exactas facilitan la búsqueda de CVEs.',
      code: vMatch[0].substring(0, 60), fix: 'No incluyas metadatos de versiones en el frontend.'
    });
  }

  // 14. Sin favicon (indica config incompleta)
  if (!html.includes('favicon') && !html.includes('shortcut icon')) {
    findings.push({
      sev: 'I', title: 'No se detecta favicon configurado',
      desc: 'Sin favicon puede resultar en 404 repetidos en logs del servidor.',
      code: '<link rel="icon"> no encontrado',
      fix: 'Agrega un favicon para evitar 404 innecesarios y mejorar UX.'
    });
  }

  // 15. Sin lang attribute
  if (!html.match(/<html[^>]*lang=/i)) {
    findings.push({
      sev: 'I', title: 'Atributo lang ausente en <html>',
      desc: 'Requerido por accesibilidad y ayuda a prevenir ataques i18n.',
      code: '<html> sin atributo lang', fix: 'Agrega lang="es" o el idioma correspondiente.'
    });
  }

  return findings;
}


//  ANÁLISIS DE COOKIES

function analyzeCookies(headers) {
  const findings = [];
  const setCookie = headers['set-cookie'] || '';
  if (!setCookie) return findings;

  const cookies = setCookie.split(',').map(c => c.trim());
  for (const cookie of cookies) {
    const name = cookie.split('=')[0] || 'unknown';
    if (!cookie.toLowerCase().includes('httponly')) {
      findings.push({
        sev: 'M', title: `Cookie "${name}" sin flag HttpOnly`,
        desc: 'Las cookies sin HttpOnly pueden ser robadas mediante XSS.',
        code: cookie.substring(0, 60), fix: 'Agrega HttpOnly a todas las cookies de sesión.'
      });
    }
    if (!cookie.toLowerCase().includes('secure')) {
      findings.push({
        sev: 'M', title: `Cookie "${name}" sin flag Secure`,
        desc: 'Las cookies sin Secure pueden ser interceptadas en conexiones HTTP.',
        code: cookie.substring(0, 60), fix: 'Agrega Secure a todas las cookies.'
      });
    }
    if (!cookie.toLowerCase().includes('samesite')) {
      findings.push({
        sev: 'L', title: `Cookie "${name}" sin flag SameSite`,
        desc: 'Sin SameSite la cookie es vulnerable a ataques CSRF.',
        code: cookie.substring(0, 60), fix: 'Agrega SameSite=Strict o SameSite=Lax.'
      });
    }
  }
  return findings;
}

//  ANÁLISIS DE robots.txt
async function analyzeRobotsTxt(url) {
  const findings = [];
  try {
    let txt = null;
    let status = 0;

    if (backendAvailable) {
      const res = await proxyCall('fetch', { url: url + '/robots.txt', method: 'GET' });
      status = res.status;
      txt = res.body;
    } else {
      const res = await fetch(url + '/robots.txt', { cache: 'no-store', signal: AbortSignal.timeout(5000) });
      status = res.status;
      txt = await res.text();
    }

    if (status !== 200 || !txt || txt.includes('<html') || txt.includes('<!DOCTYPE')) {
      return { findings, content: null, disallowed: [] };
    }

    const lines = txt.split('\n').map(l => l.trim());
    const disallowed = lines.filter(l => l.toLowerCase().startsWith('disallow:')).map(l => l.split(':').slice(1).join(':').trim()).filter(Boolean);
    const sitemaps = lines.filter(l => l.toLowerCase().startsWith('sitemap:')).map(l => l.split(':').slice(1).join(':').trim());

    // Check for sensitive paths revealed
    const sensitiveKeywords = ['admin', 'login', 'dashboard', 'panel', 'config', 'backup', 'private', 'secret', 'api', 'internal', 'staging', 'dev', 'test', 'debug', 'wp-', 'cgi-bin', 'phpmyadmin', 'cpanel', 'webmail'];
    const revealedPaths = disallowed.filter(p => sensitiveKeywords.some(k => p.toLowerCase().includes(k)));

    if (revealedPaths.length > 0) {
      findings.push({
        sev: 'H', title: `robots.txt revela ${revealedPaths.length} ruta(s) sensible(s)`,
        desc: 'El archivo robots.txt está exponiendo rutas administrativas o sensibles. Los atacantes las verifican siempre.',
        code: revealedPaths.slice(0, 5).join('\n'), fix: 'Elimina rutas sensibles de robots.txt. Usa autenticación en vez de ocultarlas.'
      });
    }

    if (lines.some(l => l.match(/disallow:\s*$/i)) || lines.some(l => l.match(/allow:\s*\/\s*$/i) && lines.some(l2 => l2.match(/user-agent:\s*\*/i)))) {
      // Check if everything is allowed
    }

    if (disallowed.includes('/') || disallowed.includes('/ ')) {
      findings.push({
        sev: 'I', title: 'robots.txt bloquea toda la indexación',
        desc: 'El sitio prohíbe a todos los crawlers indexar cualquier contenido.', code: 'Disallow: /',
        fix: 'Si es intencional, está bien. Si no, actualiza robots.txt para permitir indexación selectiva.'
      });
    }

    if (disallowed.length === 0 && !lines.some(l => l.toLowerCase().startsWith('allow'))) {
      findings.push({
        sev: 'I', title: 'robots.txt no tiene reglas Disallow',
        desc: 'El robots.txt existe pero no bloquea ninguna ruta.', code: txt.substring(0, 100),
        fix: 'Considera agregar Disallow para rutas que no necesitan ser indexadas.'
      });
    }

    return { findings, content: txt, disallowed, sitemaps };
  } catch (e) {
    return { findings, content: null, disallowed: [] };
  }
}

//  ANÁLISIS DE SCRIPTS DE TERCEROS
function analyzeThirdPartyScripts(html, baseUrl) {
  const findings = [];
  if (!html) return { findings, stats: {} };

  const hostname = new URL(baseUrl).hostname;
  const scriptTags = html.match(/<script[^>]*src=["'][^"']+["'][^>]*>/gi) || [];
  const linkTags = html.match(/<link[^>]*href=["'][^"']+["'][^>]*>/gi) || [];

  let internal = 0, external = 0, withSRI = 0, withoutSRI = 0;
  const externalDomains = new Set();
  const riskyScripts = [];

  for (const tag of scriptTags) {
    const srcMatch = tag.match(/src=["']([^"']+)["']/i);
    if (!srcMatch) continue;
    const src = srcMatch[1];

    // Determine internal vs external
    try {
      const scriptUrl = new URL(src, baseUrl);
      if (scriptUrl.hostname === hostname || scriptUrl.hostname === 'localhost') {
        internal++;
      } else {
        external++;
        externalDomains.add(scriptUrl.hostname);
        // Check SRI
        if (tag.includes('integrity=')) { withSRI++; }
        else {
          withoutSRI++;
          riskyScripts.push(scriptUrl.hostname + scriptUrl.pathname.substring(0, 40));
        }
      }
    } catch (e) {
      if (src.startsWith('//') || src.startsWith('http')) {
        external++;
      } else { internal++; }
    }
  }

  if (withoutSRI > 0) {
    findings.push({
      sev: 'M',
      title: `${withoutSRI} script(s) externo(s) sin Subresource Integrity (SRI)`,
      desc: 'Los scripts cargados de CDNs sin SRI podrían ser modificados maliciosamente sin que el navegador lo detecte.',
      code: riskyScripts.slice(0, 3).join('\n'),
      fix: 'Agrega atributo integrity="sha384-..." y crossorigin="anonymous" a cada <script> externo.'
    });
  }

  if (external > 5) {
    findings.push({
      sev: 'L', title: `Alto número de scripts externos (${external})`,
      desc: `El sitio carga ${external} scripts de ${externalDomains.size} dominio(s) externo(s). Cada uno es un vector de ataque supply-chain.`,
      code: [...externalDomains].slice(0, 5).join('\n'),
      fix: 'Reduce dependencias externas. Considera self-hosting de librerías críticas.'
    });
  }

  // Check for known risky domains
  const riskyDomains = ['cdn.jsdelivr.net', 'unpkg.com', 'rawgit.com', 'raw.githubusercontent.com'];
  const foundRisky = [...externalDomains].filter(d => riskyDomains.some(r => d.includes(r)));
  if (foundRisky.length > 0) {
    findings.push({
      sev: 'M', title: 'Scripts cargados de CDN público sin versión fija',
      desc: 'Se detectan scripts de CDNs públicos que podrían servir versiones comprometidas.',
      code: foundRisky.join('\n'),
      fix: 'Usa versiones fijas (ej: lib@1.2.3) y agrega SRI. Considera self-hosting.'
    });
  }

  const stats = { internal, external, externalDomains: externalDomains.size, withSRI, withoutSRI, domains: [...externalDomains] };
  return { findings, stats };
}

//  ANÁLISIS DE DOM XSS SINKS
function analyzeDOMSinks(html) {
  const findings = [];
  if (!html) return findings;

  const sinks = [
    { re: /\.innerHTML\s*=/g, name: 'innerHTML', sev: 'M', risk: 'XSS via innerHTML' },
    { re: /\.outerHTML\s*=/g, name: 'outerHTML', sev: 'M', risk: 'XSS via outerHTML' },
    { re: /document\.write\s*\(/g, name: 'document.write', sev: 'H', risk: 'DOM XSS via document.write' },
    { re: /document\.writeln\s*\(/g, name: 'document.writeln', sev: 'H', risk: 'DOM XSS via document.writeln' },
    { re: /eval\s*\(/g, name: 'eval()', sev: 'H', risk: 'Ejecución de código arbitrario' },
    { re: /setTimeout\s*\(\s*['"]/g, name: 'setTimeout(string)', sev: 'M', risk: 'Evaluación implícita de string' },
    { re: /setInterval\s*\(\s*['"]/g, name: 'setInterval(string)', sev: 'M', risk: 'Evaluación implícita de string' },
    { re: /new\s+Function\s*\(/g, name: 'new Function()', sev: 'H', risk: 'Ejecución dinámica de código' },
    { re: /\.insertAdjacentHTML\s*\(/g, name: 'insertAdjacentHTML', sev: 'M', risk: 'XSS via HTML injection' },
    { re: /location\s*=|location\.href\s*=/g, name: 'location redirect', sev: 'L', risk: 'Open redirect potencial' },
  ];

  const detected = [];
  for (const sink of sinks) {
    const matches = html.match(sink.re);
    if (matches && matches.length > 0) {
      detected.push({ ...sink, count: matches.length });
    }
  }

  if (detected.length > 0) {
    const critical = detected.filter(d => d.sev === 'H');
    const medium = detected.filter(d => d.sev === 'M');

    if (critical.length > 0) {
      findings.push({
        sev: 'H',
        title: `${critical.length} sink(s) DOM XSS de alto riesgo detectado(s)`,
        desc: 'Se encontraron funciones peligrosas que pueden ser explotadas para inyección de código JavaScript malicioso.',
        code: critical.map(d => `${d.name} (×${d.count}) — ${d.risk}`).join('\n'),
        fix: 'Reemplaza eval() con JSON.parse(), document.write con DOM API, innerHTML con textContent cuando sea posible.'
      });
    }
    if (medium.length > 0) {
      findings.push({
        sev: 'M',
        title: `${medium.length} sink(s) DOM XSS de riesgo medio detectado(s)`,
        desc: 'Se encontraron funciones que pueden ser vectores de XSS si reciben datos no sanitizados del usuario.',
        code: medium.map(d => `${d.name} (×${d.count}) — ${d.risk}`).join('\n'),
        fix: 'Sanitiza toda entrada del usuario antes de pasarla a estas funciones. Usa DOMPurify o libraries similares.'
      });
    }
  }
  return findings;
}

//  ANÁLISIS DE RENDIMIENTO Y SEGURIDAD DE RECURSOS
function analyzePerformanceSecurity(html, headers) {
  const findings = [];
  if (!html) return { findings, metrics: {} };

  const scripts = (html.match(/<script/gi) || []).length;
  const styles = (html.match(/<link[^>]*stylesheet/gi) || []).length + (html.match(/<style/gi) || []).length;
  const images = (html.match(/<img/gi) || []).length;
  const iframes = (html.match(/<iframe/gi) || []).length;
  const forms = (html.match(/<form/gi) || []).length;
  const inputs = (html.match(/<input/gi) || []).length;
  const htmlSize = new Blob([html]).size;

  // Excesivo tamaño de HTML
  if (htmlSize > 500000) {
    findings.push({
      sev: 'L', title: `HTML excesivamente grande (${(htmlSize / 1024).toFixed(0)} KB)`,
      desc: 'Un HTML muy grande aumenta los tiempos de carga y la superficie de ataque para análisis de código.',
      code: `Tamaño del HTML: ${(htmlSize / 1024).toFixed(1)} KB`,
      fix: 'Optimiza el HTML. Usa lazy loading, code splitting y compresión gzip/brotli.'
    });
  }

  // Cache headers
  const cacheControl = headers['cache-control'] || '';
  if (!cacheControl) {
    findings.push({
      sev: 'L', title: 'Sin cabecera Cache-Control',
      desc: 'Sin Cache-Control, los proxies intermedios pueden cachear contenido sensible.',
      code: 'Cache-Control: [AUSENTE]',
      fix: 'Agrega Cache-Control: no-store, private para páginas con datos sensibles.'
    });
  }

  // Check for error information disclosure
  if (html.match(/stack\s*trace|exception|error.*at\s+\w+|traceback|warning.*on\s+line/i)) {
    findings.push({
      sev: 'H', title: 'Información de debug/error expuesta en HTML',
      desc: 'El HTML contiene traces de error o stack traces que revelan estructura interna del servidor.',
      code: (html.match(/(?:stack\s*trace|exception|traceback).{0,60}/i) || [''])[0],
      fix: 'Deshabilita mensajes de error detallados en producción. Usa páginas de error personalizadas.'
    });
  }

  const metrics = { scripts, styles, images, iframes, forms, inputs, htmlSizeKB: (htmlSize / 1024).toFixed(1) };
  return { findings, metrics };
}

//  ANÁLISIS DE OPEN GRAPH Y EXPOSICIÓN SOCIAL
function analyzeOpenGraph(html) {
  const findings = [];
  if (!html) return findings;

  // Check for sensitive data in OG/meta tags
  const ogTags = html.match(/<meta[^>]*property=["']og:[^"']*["'][^>]*>/gi) || [];
  const hasOG = ogTags.length > 0;

  // Check for internal URLs in OG tags
  for (const tag of ogTags) {
    if (/localhost|127\.0\.0\.1|192\.168\.|10\.\d+\.\d+\.\d+/.test(tag)) {
      findings.push({
        sev: 'H', title: 'Open Graph meta tag expone URL interna',
        desc: 'Las etiquetas Open Graph contienen URLs internas (localhost/IP privada) que se comparten en redes sociales.',
        code: tag.substring(0, 80), fix: 'Configura las URLs de OG con el dominio público correcto.'
      });
    }
  }

  // Check for Twitter card info
  const twitterTags = html.match(/<meta[^>]*name=["']twitter:[^"']*["'][^>]*>/gi) || [];

  // Check if staging/dev environment indicators are in meta
  const metaTagsStr = (html.match(/<meta[^>]*>/gi) || []).join(' ');
  if (metaTagsStr.match(/\b(staging environment|development server|test environment)\b/i)) {
    findings.push({
      sev: 'M', title: 'Indicadores de entorno de desarrollo en meta tags',
      desc: 'Los meta tags contienen frases como "staging environment" o "test environment", indicando un posible entorno de pruebas.',
      code: (metaTagsStr.match(/<meta[^>]*(?:staging|development|test)[^>]*>/i) || [''])[0].substring(0, 80),
      fix: 'Asegúrate de que los meta tags reflejan el entorno de producción.'
    });
  }

  return findings;
}

//  ANÁLISIS CORS
async function analyzeCORS(url) {
  const findings = [];
  try {
    const badOrigin = 'https://evil.local';
    let headers = null;

    if (backendAvailable) {
      const res = await proxyCall('fetch', {
        url,
        method: 'HEAD',
        headers: { 'Origin': badOrigin, 'Cache-Control': 'no-cache' }
      });
      headers = new Headers(res.headers);
    } else {
      const res = await fetch(url, {
        method: 'HEAD', cache: 'no-store',
        headers: {
          'Origin': badOrigin, // Simulate cross-origin request
          'Cache-Control': 'no-cache'
        },
        signal: AbortSignal.timeout(4000)
      });
      headers = res.headers;
    }

    const acao = headers.get('access-control-allow-origin');
    const acac = headers.get('access-control-allow-credentials');

    if (acao) {
      if (acao === '*') {
        findings.push({
          sev: acac === 'true' ? 'C' : 'M',
          title: 'CORS permite cualquier origen (Access-Control-Allow-Origin: *)',
          desc: 'El servidor permite solicitudes cross-origin desde cualquier dominio.' + (acac === 'true' ? ' Combinado con Allow-Credentials, esto es CRÍTICO.' : ''),
          code: `Access-Control-Allow-Origin: *${acac ? '\nAccess-Control-Allow-Credentials: ' + acac : ''}`,
          fix: 'Configura CORS para permitir solo orígenes específicos y confiables.'
        });
      } else if (acao === 'https://evil.local') {
        findings.push({
          sev: 'C', title: 'CORS refleja cualquier origen (Origin Reflection)',
          desc: 'El servidor refleja el Origin del atacante en Access-Control-Allow-Origin, permitiendo a cualquier sitio malicioso leer respuestas.',
          code: `Origin: https://evil.local\n→ Access-Control-Allow-Origin: https://evil.local`,
          fix: 'No reflejes el Origin ciegamente. Usa una whitelist de orígenes permitidos.'
        });
      }
    }
  } catch (e) { /* CORS puede impedir esta petición, lo cual es bueno */ }
  return findings;
}

//  ANÁLISIS DNS (SPF, DMARC, DNSSEC, MX) — Backend-powered when available
async function analyzeDNS(hostname) {
  const findings = [];
  const dnsData = { spf: null, dmarc: null, dkim: null, mx: [], ns: [], a: [], aaaa: [], caa: [], soa: null, dnssec: false };

  // ═══ BACKEND PATH: Real DNS via PHP dns_get_record() ═══
  if (backendAvailable) {
    try {
      const dns = await proxyCall('dns', { hostname }, 15000);

      dnsData.spf = dns.spf;
      dnsData.dmarc = dns.dmarc;
      dnsData.dkim = dns.dkim_selector;
      dnsData.mx = (dns.mx || []).map(m => `${m.priority} ${m.host}`);
      dnsData.ns = dns.ns || [];
      dnsData.a = dns.a || [];
      dnsData.aaaa = dns.aaaa || [];
      dnsData.soa = dns.soa;
      dnsData.caa = dns.caa || [];
      dnsData.dnssec = !!dns.dnssec;

      // SPF Analysis
      if (!dnsData.spf) {
        findings.push({
          sev: 'H', title: 'Sin registro SPF configurado',
          desc: 'El dominio no tiene un registro SPF (Sender Policy Framework). Esto permite que cualquier servidor envíe correos haciéndose pasar por tu dominio.',
          code: `Dominio: ${hostname}\nRegistro SPF: [NO ENCONTRADO]`,
          fix: 'Agrega un registro TXT en tu DNS: v=spf1 include:_spf.google.com ~all (ajusta según tu proveedor de correo).'
        });
      } else {
        if (dnsData.spf.includes('+all')) {
          findings.push({
            sev: 'C', title: 'SPF configurado con +all (inseguro)',
            desc: 'El registro SPF usa +all, lo que permite que CUALQUIER servidor envíe correos como tu dominio.',
            code: `SPF: ${dnsData.spf}`,
            fix: 'Cambia +all por ~all (soft fail) o -all (hard fail) para restringir el envío.'
          });
        } else if (dnsData.spf.includes('?all')) {
          findings.push({
            sev: 'M', title: 'SPF configurado con ?all (neutral)',
            desc: 'SPF usa ?all (neutral), no prohíbe que otros servidores envíen correos en tu nombre.',
            code: `SPF: ${dnsData.spf}`,
            fix: 'Cambia ?all por ~all o -all para una protección más estricta.'
          });
        }
      }

      // DMARC Analysis
      if (!dnsData.dmarc) {
        findings.push({
          sev: 'H', title: 'Sin registro DMARC configurado',
          desc: 'Sin DMARC, no hay forma de indicar a los servidores de correo qué hacer con mensajes que fallan SPF/DKIM.',
          code: `_dmarc.${hostname}: [NO ENCONTRADO]`,
          fix: 'Agrega un registro TXT: v=DMARC1; p=quarantine; rua=mailto:dmarc@tudominio.com'
        });
      } else {
        const pMatch = dnsData.dmarc.match(/p=(none|quarantine|reject)/i);
        if (pMatch && pMatch[1].toLowerCase() === 'none') {
          findings.push({
            sev: 'M', title: 'Política DMARC en modo "none" (solo monitoreo)',
            desc: 'DMARC con p=none solo monitorea pero no bloquea correos fraudulentos.',
            code: `DMARC: ${dnsData.dmarc}`,
            fix: 'Cambia la política a p=quarantine o p=reject.'
          });
        }
      }

      // DKIM check
      if (!dnsData.dkim) {
        findings.push({
          sev: 'M', title: 'Sin registro DKIM detectado',
          desc: 'No se encontró DKIM (DomainKeys Identified Mail) en selectores comunes. DKIM firma los correos para verificar autenticidad.',
          code: `Selectores verificados: default, google, selector1, selector2, k1, mail, dkim`,
          fix: 'Configura DKIM con tu proveedor de correo para firmar todos los correos salientes.'
        });
      }

      // CAA check
      if (dnsData.caa.length === 0) {
        findings.push({
          sev: 'L', title: 'Sin registros CAA configurados',
          desc: 'CAA (Certificate Authority Authorization) restringe qué CAs pueden emitir certificados para tu dominio. Sin CAA, cualquier CA puede emitir certificados.',
          code: `CAA para ${hostname}: [NO ENCONTRADO]`,
          fix: 'Agrega registros CAA en DNS: 0 issue "letsencrypt.org" (ajusta la CA según uses).'
        });
      }

      // DNSSEC
      if (!dnsData.dnssec) {
        findings.push({
          sev: 'L', title: 'DNSSEC no habilitado',
          desc: 'Sin DNSSEC, los atacantes pueden redirigir tráfico a servidores falsos (DNS spoofing).',
          code: `DNSKEY para ${hostname}: [NO ENCONTRADO]`,
          fix: 'Habilita DNSSEC en tu registrador de dominio. Cloudflare lo activa con un clic.'
        });
      }

      // NS single point of failure
      if (dnsData.ns.length > 0) {
        const nsProviders = new Set(dnsData.ns.map(ns => ns.split('.').slice(-3).join('.')));
        if (nsProviders.size === 1 && dnsData.ns.length < 2) {
          findings.push({
            sev: 'L', title: 'Solo un servidor DNS configurado',
            desc: 'El dominio depende de un solo nameserver. Si falla, todo el sitio queda inaccesible.',
            code: `NS: ${dnsData.ns.join(', ')}`,
            fix: 'Configura al menos 2 nameservers de distintos proveedores.'
          });
        }
      }

      return { findings, data: dnsData };
    } catch (e) {
      // Backend DNS failed, fall through to Cloudflare DoH
    }
  }

  // ═══ FALLBACK: Cloudflare DNS-over-HTTPS (client-side) ═══
  async function dnsQuery(name, type) {
    try {
      const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(5000)
      });
      if (!res.ok) return null;
      return await res.json();
    } catch (e) { return null; }
  }

  const txtResult = await dnsQuery(hostname, 'TXT');
  if (txtResult && txtResult.Answer) {
    for (const ans of txtResult.Answer) {
      const val = (ans.data || '').replace(/"/g, '');
      if (val.startsWith('v=spf1')) dnsData.spf = val;
    }
  }

  if (!dnsData.spf) {
    findings.push({
      sev: 'H', title: 'Sin registro SPF configurado',
      desc: 'El dominio no tiene un registro SPF. Permite que cualquier servidor envíe correos haciéndose pasar por tu dominio.',
      code: `Dominio: ${hostname}\nRegistro SPF: [NO ENCONTRADO]`,
      fix: 'Agrega un registro TXT: v=spf1 include:_spf.google.com ~all'
    });
  } else {
    if (dnsData.spf.includes('+all')) {
      findings.push({ sev: 'C', title: 'SPF con +all (inseguro)', desc: 'SPF usa +all, permite que CUALQUIER servidor envíe correos como tu dominio.', code: `SPF: ${dnsData.spf}`, fix: 'Cambia +all por ~all o -all.' });
    } else if (dnsData.spf.includes('?all')) {
      findings.push({ sev: 'M', title: 'SPF con ?all (neutral)', desc: 'SPF usa ?all (neutral).', code: `SPF: ${dnsData.spf}`, fix: 'Cambia ?all por ~all o -all.' });
    }
  }

  const dmarcResult = await dnsQuery('_dmarc.' + hostname, 'TXT');
  if (dmarcResult && dmarcResult.Answer) {
    for (const ans of dmarcResult.Answer) {
      const val = (ans.data || '').replace(/"/g, '');
      if (val.startsWith('v=DMARC1')) dnsData.dmarc = val;
    }
  }
  if (!dnsData.dmarc) {
    findings.push({ sev: 'H', title: 'Sin registro DMARC configurado', desc: 'Sin DMARC, no hay forma de manejar mensajes que fallan SPF/DKIM.', code: `_dmarc.${hostname}: [NO ENCONTRADO]`, fix: 'Agrega TXT: v=DMARC1; p=quarantine; rua=mailto:dmarc@tudominio.com' });
  } else {
    const pMatch = dnsData.dmarc.match(/p=(none|quarantine|reject)/i);
    if (pMatch && pMatch[1].toLowerCase() === 'none') {
      findings.push({ sev: 'M', title: 'DMARC en modo "none"', desc: 'DMARC con p=none solo monitorea.', code: `DMARC: ${dnsData.dmarc}`, fix: 'Cambia a p=quarantine o p=reject.' });
    }
  }

  const mxResult = await dnsQuery(hostname, 'MX');
  if (mxResult && mxResult.Answer) dnsData.mx = mxResult.Answer.map(a => (a.data || '').trim()).filter(Boolean);
  const nsResult = await dnsQuery(hostname, 'NS');
  if (nsResult && nsResult.Answer) dnsData.ns = nsResult.Answer.map(a => (a.data || '').trim()).filter(Boolean);

  const dsResult = await dnsQuery(hostname, 'DNSKEY');
  if (dsResult && (dsResult.AD || (dsResult.Answer && dsResult.Answer.length > 0))) {
    dnsData.dnssec = true;
  } else {
    findings.push({ sev: 'L', title: 'DNSSEC no habilitado', desc: 'Sin DNSSEC, ataques de DNS spoofing son posibles.', code: `DNSKEY: [NO ENCONTRADO]`, fix: 'Habilita DNSSEC en tu registrador de dominio.' });
  }

  if (dnsData.ns.length > 0) {
    const nsProviders = new Set(dnsData.ns.map(ns => ns.split('.').slice(-3).join('.')));
    if (nsProviders.size === 1 && dnsData.ns.length < 2) {
      findings.push({ sev: 'L', title: 'Solo un servidor DNS', desc: 'Si falla, el sitio queda inaccesible.', code: `NS: ${dnsData.ns.join(', ')}`, fix: 'Configura al menos 2 nameservers.' });
    }
  }

  return { findings, data: dnsData };
}

// ═══════════════════════════════════════════════════════════════
//  ANÁLISIS SSL/TLS (Requiere backend PHP)
// ═══════════════════════════════════════════════════════════════
async function analyzeSSL(hostname) {
  const findings = [];
  const sslData = { available: false };

  if (!backendAvailable) {
    return { findings, data: sslData, backendRequired: true };
  }

  try {
    const ssl = await proxyCall('ssl', { hostname }, 20000);
    sslData.available = true;
    Object.assign(sslData, ssl);

    if (ssl.error) {
      findings.push({
        sev: 'C', title: 'Error en conexión SSL/TLS',
        desc: `No se pudo establecer una conexión SSL segura con el servidor: ${ssl.error}`,
        code: `Hostname: ${hostname}\nError: ${ssl.error}`,
        fix: 'Verifica que el certificado SSL esté correctamente instalado y no haya expirado.'
      });
      return { findings, data: sslData };
    }

    // Certificate expiry
    if (ssl.daysRemaining !== null) {
      if (ssl.daysRemaining <= 0) {
        findings.push({
          sev: 'C', title: 'Certificado SSL EXPIRADO',
          desc: 'El certificado SSL/TLS ha expirado. Los navegadores mostrarán advertencias de seguridad.',
          code: `Expiró: ${ssl.validTo}\nDías: ${ssl.daysRemaining}`,
          fix: 'Renueva el certificado SSL inmediatamente. Si usas Let\'s Encrypt, verifica que la renovación automática funcione.'
        });
      } else if (ssl.daysRemaining <= 14) {
        findings.push({
          sev: 'H', title: `Certificado SSL expira en ${ssl.daysRemaining} día(s)`,
          desc: 'El certificado SSL está por expirar. Si no se renueva, los usuarios verán advertencias de seguridad.',
          code: `Expira: ${ssl.validTo}\nDías restantes: ${ssl.daysRemaining}`,
          fix: 'Renueva el certificado SSL antes de que expire. Configura renovación automática con certbot.'
        });
      } else if (ssl.daysRemaining <= 30) {
        findings.push({
          sev: 'M', title: `Certificado SSL expira en ${ssl.daysRemaining} días`,
          desc: 'El certificado expira pronto. Es recomendable renovarlo con anticipación.',
          code: `Expira: ${ssl.validTo}\nDías: ${ssl.daysRemaining}`,
          fix: 'Programa la renovación del certificado para evitar interrupciones.'
        });
      }
    }

    // Self-signed cert
    if (ssl.isSelfSigned) {
      findings.push({
        sev: 'H', title: 'Certificado auto-firmado (self-signed)',
        desc: 'El certificado no fue emitido por una autoridad de confianza. Los navegadores mostrarán advertencias.',
        code: `Issuer: ${ssl.issuer}\nSubject: ${ssl.subject}`,
        fix: 'Usa un certificado de una CA reconocida. Let\'s Encrypt es gratuito.'
      });
    }

    // Weak key
    if (ssl.keySize && ssl.keySize < 2048 && ssl.keyType === 'RSA') {
      findings.push({
        sev: 'H', title: `Clave RSA débil (${ssl.keySize} bits)`,
        desc: 'El certificado usa una clave RSA menor a 2048 bits, considerada insegura.',
        code: `Tipo: ${ssl.keyType}\nTamaño: ${ssl.keySize} bits`,
        fix: 'Regenera el certificado con una clave RSA de 2048 bits mínimo, o usa EC P-256.'
      });
    }

    // Weak signature algorithm
    if (ssl.signatureAlgorithm && /sha1|md5/i.test(ssl.signatureAlgorithm)) {
      findings.push({
        sev: 'H', title: `Algoritmo de firma débil: ${ssl.signatureAlgorithm}`,
        desc: 'El certificado usa SHA-1 o MD5, que son vulnerables a ataques de colisión.',
        code: `Algoritmo: ${ssl.signatureAlgorithm}`,
        fix: 'Regenera el certificado con SHA-256 o superior.'
      });
    }

    // TLS 1.0/1.1 enabled
    const oldProtos = (ssl.protocols || []).filter(p => p === 'TLSv1.0' || p === 'TLSv1.1');
    if (oldProtos.length > 0) {
      findings.push({
        sev: 'M', title: `Protocolos TLS obsoletos habilitados: ${oldProtos.join(', ')}`,
        desc: 'TLS 1.0 y 1.1 tienen vulnerabilidades conocidas (POODLE, BEAST). Los navegadores modernos ya los han deprecado.',
        code: `Protocolos soportados: ${(ssl.protocols || []).join(', ')}`,
        fix: 'Deshabilita TLS 1.0 y 1.1 en la configuración del servidor. Usa TLS 1.2 mínimo, preferiblemente TLS 1.3.'
      });
    }

    // No TLS 1.3
    if (ssl.protocols && !ssl.protocols.includes('TLSv1.3')) {
      findings.push({
        sev: 'L', title: 'TLS 1.3 no soportado',
        desc: 'El servidor no soporta TLS 1.3, que ofrece mejor seguridad y rendimiento.',
        code: `Protocolos: ${(ssl.protocols || []).join(', ')}`,
        fix: 'Habilita TLS 1.3 en tu servidor web para mayor seguridad y velocidad de conexión.'
      });
    }

  } catch (e) {
    // SSL analysis failed silently
  }

  return { findings, data: sslData };
}

// ═══════════════════════════════════════════════════════════════
//  PORT SCANNING (Requiere backend PHP)
// ═══════════════════════════════════════════════════════════════
async function scanPorts(hostname) {
  const findings = [];
  const portData = { available: false, openPorts: [] };

  if (!backendAvailable) {
    return { findings, data: portData, backendRequired: true };
  }

  try {
    const result = await proxyCall('ports', { hostname }, 60000);
    portData.available = true;
    portData.openPorts = result.openPorts || [];
    portData.totalScanned = result.totalScanned;

    // Classify risky open ports
    const riskyPorts = {
      21: 'FTP', 23: 'Telnet', 25: 'SMTP', 445: 'SMB',
      1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
      3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
      6379: 'Redis', 9200: 'Elasticsearch', 27017: 'MongoDB'
    };

    const openRisky = portData.openPorts.filter(p => riskyPorts[p.port]);
    const openDB = portData.openPorts.filter(p => [3306, 5432, 1433, 1521, 27017, 6379, 9200].includes(p.port));

    if (openDB.length > 0) {
      findings.push({
        sev: 'C', title: `${openDB.length} puerto(s) de base de datos expuesto(s)`,
        desc: 'Puertos de bases de datos abiertos al público es extremadamente peligroso. Atacantes pueden intentar acceso por fuerza bruta.',
        code: openDB.map(p => `Puerto ${p.port} (${p.service}): ABIERTO${p.banner ? ' — ' + p.banner : ''}`).join('\n'),
        fix: 'Cierra estos puertos con firewall. Las bases de datos NUNCA deben ser accesibles desde Internet.'
      });
    }

    if (openRisky.length > openDB.length) {
      const nonDb = openRisky.filter(p => !openDB.find(d => d.port === p.port));
      if (nonDb.length > 0) {
        findings.push({
          sev: 'H', title: `${nonDb.length} servicio(s) potencialmente riesgoso(s) expuesto(s)`,
          desc: 'Servicios como FTP, Telnet, RDP y VNC abiertos al público aumentan significativamente la superficie de ataque.',
          code: nonDb.map(p => `Puerto ${p.port} (${p.service}): ABIERTO${p.banner ? ' — ' + p.banner : ''}`).join('\n'),
          fix: 'Usa VPN para acceder a estos servicios. Cierra los puertos innecesarios con firewall.'
        });
      }
    }

    // Banners revealing version info
    const bannerPorts = portData.openPorts.filter(p => p.banner && p.banner.length > 5);
    if (bannerPorts.length > 0) {
      findings.push({
        sev: 'L', title: `${bannerPorts.length} servicio(s) revelan información en banners`,
        desc: 'Los banners de servicio exponen información de versión que facilita la identificación de vulnerabilidades.',
        code: bannerPorts.map(p => `${p.port}: ${p.banner}`).join('\n'),
        fix: 'Configura los servicios para no enviar banners con información de versión.'
      });
    }

  } catch (e) {
    // Port scanning failed silently
  }

  return { findings, data: portData };
}

//  ENUMERACIÓN DE SUBDOMINIOS
async function enumerateSubdomains(hostname) {
  const findings = [];
  let found = [];

  if (backendAvailable) {
    try {
      const result = await proxyCall('subdomains', { hostname }, 30000);
      found = (result.found || []).map(s => ({
        sub: s.subdomain,
        fqdn: s.fqdn,
        ip: s.ip,
        cname: s.cname || '',
        risky: s.risky
      }));

      if (found.length > 0) {
        const risky = found.filter(s => s.risky);
        const infra = found.filter(s => !s.risky);

        if (risky.length > 0) {
          findings.push({
            sev: 'H',
            title: `${risky.length} subdominio(s) sensible(s) detectado(s)`,
            desc: 'Se encontraron subdominios que podrían exponer entornos de desarrollo, administración o infraestructura interna.',
            code: risky.map(s => `${s.fqdn} → ${s.ip}${s.cname ? ' (CNAME: ' + s.cname + ')' : ''}`).join('\n'),
            fix: 'Protege estos subdominios con autenticación, VPN o firewall. Elimina los que no estén en uso.'
          });
        }

        if (infra.length > 0) {
          findings.push({
            sev: 'I',
            title: `${infra.length} subdominio(s) de infraestructura detectado(s)`,
            desc: 'Subdominios de infraestructura normal. No necesariamente un riesgo, pero es bueno mantener un inventario.',
            code: infra.map(s => `${s.fqdn} → ${s.ip}${s.cname ? ' (CNAME: ' + s.cname + ')' : ''}`).join('\n'),
            fix: 'Revisa que todos estos subdominios sean intencionales y estén actualizados.'
          });
        }
      }
      return { findings, found };
    } catch (e) {
      // Fall through to client-side
    }
  }

  // ═══ FALLBACK: Cloudflare DoH (client-side) ═══
  const commonSubs = [
    'dev', 'staging', 'stage', 'test', 'qa', 'uat',
    'admin', 'panel', 'dashboard', 'cms',
    'api', 'api-dev', 'api-staging',
    'mail', 'webmail', 'smtp',
    'ftp', 'sftp', 'cdn', 'static', 'assets',
    'db', 'database', 'mongo', 'redis',
    'jenkins', 'ci', 'gitlab', 'git',
    'vpn', 'internal', 'intranet'
  ];

  const batchSize = 6;
  for (let i = 0; i < commonSubs.length; i += batchSize) {
    const batch = commonSubs.slice(i, i + batchSize);
    await Promise.allSettled(batch.map(async sub => {
      const fqdn = sub + '.' + hostname;
      try {
        const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(fqdn)}&type=A`, {
          headers: { 'Accept': 'application/dns-json' },
          signal: AbortSignal.timeout(3000)
        });
        if (!res.ok) return;
        const data = await res.json();
        if (data.Answer && data.Answer.length > 0) {
          const ip = data.Answer.find(a => a.type === 1)?.data || '';
          found.push({ sub, fqdn, ip });
        }
      } catch (e) { /* subdomain doesn't exist */ }
    }));
  }

  if (found.length > 0) {
    const riskyNames = ['dev', 'staging', 'stage', 'test', 'qa', 'uat', 'admin', 'panel', 'jenkins', 'ci', 'gitlab', 'git', 'internal', 'intranet', 'db', 'database', 'mongo', 'redis', 'api-dev', 'api-staging'];
    const risky = found.filter(s => riskyNames.includes(s.sub));
    const infra = found.filter(s => !risky.includes(s));

    if (risky.length > 0) {
      findings.push({
        sev: 'H', title: `${risky.length} subdominio(s) sensible(s) detectado(s)`,
        desc: 'Se encontraron subdominios que podrían exponer entornos de desarrollo o infraestructura interna.',
        code: risky.map(s => `${s.fqdn} → ${s.ip}`).join('\n'),
        fix: 'Protege estos subdominios con autenticación, VPN o firewall.'
      });
    }
    if (infra.length > 0) {
      findings.push({
        sev: 'I', title: `${infra.length} subdominio(s) de infraestructura`,
        desc: 'Subdominios de infraestructura normal.',
        code: infra.map(s => `${s.fqdn} → ${s.ip}`).join('\n'),
        fix: 'Revisa que todos estos subdominios sean intencionales.'
      });
    }
  }

  return { findings, found };
}

//  DETECCIÓN DE WAF (Web Application Firewall)
function detectWAF(headers) {
  const findings = [];
  const detected = [];

  const wafSignatures = [
    { name: 'Cloudflare', headers: ['cf-ray', 'cf-cache-status'], serverMatch: /cloudflare/i },
    { name: 'Akamai', headers: ['x-akamai-transformed', 'akamai-origin-hop'], serverMatch: /akamaighost/i },
    { name: 'Sucuri', headers: ['x-sucuri-id', 'x-sucuri-cache'], serverMatch: /sucuri/i },
    { name: 'Imperva (Incapsula)', headers: ['x-iinfo', 'x-cdn'], serverMatch: /incapsula|imperva/i },
    { name: 'AWS CloudFront', headers: ['x-amz-cf-id', 'x-amz-cf-pop'], serverMatch: /cloudfront/i },
    { name: 'AWS WAF', headers: ['x-amzn-waf-action'], serverMatch: null },
    { name: 'Fastly', headers: ['x-fastly-request-id', 'fastly-io-info'], serverMatch: /fastly/i },
    { name: 'KeyCDN', headers: ['x-edge-location'], serverMatch: /keycdn/i },
    { name: 'Varnish', headers: ['x-varnish'], serverMatch: /varnish/i },
    { name: 'DDoS-Guard', headers: [], serverMatch: /ddos-guard/i },
    { name: 'StackPath', headers: ['x-sp-url'], serverMatch: /stackpath/i },
    { name: 'Vercel', headers: ['x-vercel-id', 'x-vercel-cache'], serverMatch: /vercel/i },
    { name: 'Netlify', headers: ['x-nf-request-id'], serverMatch: /netlify/i },
  ];

  for (const sig of wafSignatures) {
    let isDetected = false;
    // Check WAF-specific headers
    for (const h of sig.headers) {
      if (headers[h]) { isDetected = true; break; }
    }
    // Check server header
    if (!isDetected && sig.serverMatch) {
      const srv = headers['server'] || '';
      const via = headers['via'] || '';
      if (sig.serverMatch.test(srv) || sig.serverMatch.test(via)) isDetected = true;
    }
    if (isDetected) detected.push(sig.name);
  }

  if (detected.length > 0) {
    findings.push({
      sev: 'I',
      title: 'WAF/CDN detectado: ' + detected.join(', '),
      desc: 'El sitio está protegido por ' + detected.join(' + ') + '. Esto añade una capa de defensa contra ataques DDoS, inyecciones y bots maliciosos.',
      code: 'Protección detectada: ' + detected.join(', '),
      fix: 'Esto es positivo. Asegúrate de que las reglas del WAF estén actualizadas y configuradas correctamente.'
    });
  } else {
    findings.push({
      sev: 'M',
      title: 'No se detectó WAF/CDN de protección',
      desc: 'No se encontraron firmas de un Web Application Firewall ni CDN con protección DDoS. El servidor está expuesto directamente a Internet.',
      code: 'WAF: [NO DETECTADO]\nCDN: [NO DETECTADO]',
      fix: 'Considera implementar un WAF como Cloudflare (gratis), Sucuri o AWS WAF para proteger tu sitio contra ataques comunes.'
    });
  }

  return { findings, detected };
}

//  ANÁLISIS DE security.txt Y sitemap.xml
async function analyzeSecurityTxt(url) {
  const findings = [];
  const data = { securityTxt: null, sitemap: null };

  // 1. Check /.well-known/security.txt (RFC 9116)
  try {
    let txt = null;
    let ok = false;

    if (backendAvailable) {
      const res = await proxyCall('fetch', { url: url + '/.well-known/security.txt', method: 'GET' });
      ok = (res.status === 200);
      txt = res.body;
    } else {
      const res = await fetch(url + '/.well-known/security.txt', { signal: AbortSignal.timeout(5000), redirect: 'follow' });
      ok = res.ok;
      if (ok) txt = await res.text();
    }

    if (ok && txt) {
      if (txt.includes('Contact:') || txt.includes('contact:')) {
        data.securityTxt = txt;
        // Verify required fields
        const hasContact = /Contact:/im.test(txt);
        const hasExpires = /Expires:/im.test(txt);
        if (!hasExpires) {
          findings.push({
            sev: 'L',
            title: 'security.txt sin fecha de expiración',
            desc: 'El archivo security.txt existe pero no tiene el campo Expires obligatorio según RFC 9116.',
            code: 'Campos encontrados: ' + (hasContact ? 'Contact ✓' : 'Contact ✗') + ', Expires ✗',
            fix: 'Agrega el campo Expires: con una fecha futura. Ejemplo: Expires: 2025-12-31T23:59:00.000Z'
          });
        }
      }
    }
  } catch (e) { /* not found */ }

  if (!data.securityTxt) {
    findings.push({
      sev: 'L',
      title: 'No existe security.txt (RFC 9116)',
      desc: 'El archivo /.well-known/security.txt no está presente. Este archivo es un estándar para que investigadores de seguridad puedan reportar vulnerabilidades de forma responsable.',
      code: 'GET /.well-known/security.txt → 404',
      fix: 'Crea el archivo con al menos los campos Contact: y Expires:. Usa https://securitytxt.org/ como guía.'
    });
  }

  // 2. Check sitemap.xml for exposed routes
  try {
    let xml = null;
    let ok = false;

    if (backendAvailable) {
      const res = await proxyCall('fetch', { url: url + '/sitemap.xml', method: 'GET' });
      ok = (res.status === 200);
      xml = res.body;
    } else {
      const res = await fetch(url + '/sitemap.xml', { signal: AbortSignal.timeout(5000), redirect: 'follow' });
      ok = res.ok;
      if (ok) xml = await res.text();
    }

    if (ok && xml) {
      if (xml.includes('<urlset') || xml.includes('<sitemapindex')) {
        data.sitemap = true;
        // Check for sensitive paths in sitemap
        const sensitiveInSitemap = [];
        const patterns = [/admin/i, /dashboard/i, /internal/i, /staging/i, /test/i, /debug/i, /private/i, /api\/v\d/i, /wp-admin/i, /panel/i];
        const urls = xml.match(/<loc>([^<]+)<\/loc>/gi) || [];
        for (const u of urls) {
          const clean = u.replace(/<\/?loc>/gi, '');
          for (const p of patterns) {
            if (p.test(clean)) { sensitiveInSitemap.push(clean); break; }
          }
        }
        if (sensitiveInSitemap.length > 0) {
          findings.push({
            sev: 'M',
            title: 'sitemap.xml expone rutas sensibles',
            desc: 'El sitemap contiene URLs que parecen ser administrativas o internas.',
            code: sensitiveInSitemap.slice(0, 5).join('\n'),
            fix: 'Elimina las rutas sensibles del sitemap. El sitemap solo debe contener páginas públicas.'
          });
        }
      }
    }
  } catch (e) { /* not found */ }

  return { findings, data };
}

//  DETECCIÓN AVANZADA DE SECRETOS
function analyzeSecrets(html) {
  const findings = [];
  if (!html) return findings;

  const secretPatterns = [
    { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, sev: 'C' },
    { name: 'AWS Secret Key', regex: /(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, sev: 'C' },
    { name: 'Stripe Secret Key', regex: /sk_(?:live|test|mock)_[0-9a-zA-Z]{24,}/g, sev: 'C' },
    { name: 'Stripe Publishable Key', regex: /pk_(?:live|test|mock)_[0-9a-zA-Z]{24,}/g, sev: 'M' },
    { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g, sev: 'H' },
    { name: 'Google OAuth Token', regex: /ya29\.[0-9A-Za-z\-_]+/g, sev: 'C' },
    { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g, sev: 'C' },
    { name: 'Private Key (RSA/SSH)', regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/gi, sev: 'C' },
    { name: 'JWT Token', regex: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*/g, sev: 'H' },
    { name: 'Slack Webhook', regex: /hooks\.slack\.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[A-Za-z0-9]{24}/g, sev: 'H' },
    { name: 'Firebase API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g, sev: 'H' },
    { name: 'SendGrid API Key', regex: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g, sev: 'C' },
    { name: 'Twilio API Key', regex: /SK[0-9a-fA-F]{32}/g, sev: 'H' },
    { name: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/g, sev: 'H' },
    { name: 'PayPal/Braintree Token', regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g, sev: 'C' },
    { name: 'Hardcoded Password', regex: /(?:password|passwd|pwd|secret)\s*[:=]\s*['"]([^'"]{6,})['"](?!.*\{\{)/gi, sev: 'H' },
  ];

  for (const sp of secretPatterns) {
    const matches = html.match(sp.regex);
    if (matches && matches.length > 0) {
      const unique = [...new Set(matches)];
      findings.push({
        sev: sp.sev,
        title: `Secreto expuesto: ${sp.name} (${unique.length} encontrado${unique.length > 1 ? 's' : ''})`,
        desc: `Se detectó un patrón que coincide con <code>${sp.name}</code> en el código fuente HTML. Esto es extremadamente peligroso si es una clave real.`,
        code: unique.map(m => m.substring(0, 12) + '...[REDACTED]').join('\n'),
        fix: 'Elimina inmediatamente este secreto del código, revoca la clave comprometida y genera una nueva. Usa variables de entorno del servidor.'
      });
    }
  }

  return findings;
}

//  DETECCIÓN DE LIBRERÍAS DESACTUALIZADAS CON CVEs
function analyzeOutdatedLibs(html) {
  const findings = [];
  if (!html) return findings;

  const knownVulnerable = [
    {
      name: 'jQuery', regex: /jquery[.\-/]v?(1\.\d+|2\.\d+|3\.[0-4])\b/gi,
      minSafe: '3.5.0', cves: 'CVE-2020-11022, CVE-2020-11023, CVE-2019-11358'
    },
    {
      name: 'jQuery', regex: /jquery\.min\.js\?v=(1\.\d+|2\.\d+|3\.[0-4])/gi,
      minSafe: '3.5.0', cves: 'CVE-2020-11022, CVE-2019-11358'
    },
    {
      name: 'AngularJS (1.x)', regex: /angular[.\-/]v?1\.\d+/gi,
      minSafe: 'EOL', cves: 'CVE-2022-25869, CVE-2020-7676 (XSS, Prototype Pollution)'
    },
    {
      name: 'Bootstrap', regex: /bootstrap[.\-/]v?(3\.\d+|4\.[0-5])\b/gi,
      minSafe: '5.3.0', cves: 'CVE-2019-8331, CVE-2018-14040, CVE-2016-10735 (XSS)'
    },
    {
      name: 'Lodash', regex: /lodash[.\-/]v?(4\.[0-9]|4\.1[0-6])\b/gi,
      minSafe: '4.17.21', cves: 'CVE-2021-23337, CVE-2020-28500, CVE-2019-10744 (Prototype Pollution)'
    },
    {
      name: 'Moment.js', regex: /moment[.\-/]v?2\.\d+/gi,
      minSafe: 'EOL', cves: 'CVE-2022-24785 (Path Traversal) - Librería abandonada, migra a dayjs o date-fns'
    },
    {
      name: 'Vue.js', regex: /vue[.\-/]v?2\.\d+/gi,
      minSafe: '3.x', cves: 'Vue 2 en fin de vida (EOL Dec 2023). Sin parches de seguridad futuros.'
    },
    {
      name: 'React', regex: /react[.\-/]v?(15\.\d+|16\.[0-7])\b/gi,
      minSafe: '18.x', cves: 'Versiones antiguas con XSS vectors en dangerouslySetInnerHTML y SSR hydration.'
    },
    {
      name: 'WordPress', regex: /wp-(includes|content)\/.*ver=(4\.\d+|5\.[0-7])\b/gi,
      minSafe: '6.x', cves: 'Múltiples CVEs de XSS, SQLi y escalamiento de privilegios en versiones anteriores.'
    },
    {
      name: 'TinyMCE', regex: /tinymce[.\-/]v?(4\.\d+|5\.[0-9])\b/gi,
      minSafe: '6.x', cves: 'CVE-2022-23494, CVE-2020-17480 (XSS en editor)'
    },
  ];

  for (const lib of knownVulnerable) {
    const matches = html.match(lib.regex);
    if (matches && matches.length > 0) {
      const version = matches[0].match(/\d+\.\d+(\.\d+)?/)?.[0] || 'detectada';
      findings.push({
        sev: lib.minSafe === 'EOL' ? 'H' : 'M',
        title: `${lib.name} v${version} — versión vulnerable`,
        desc: `Se detectó <code>${lib.name}</code> versión <code>${version}</code> que es anterior a la versión segura mínima (${lib.minSafe}).`,
        code: `Detectado: ${matches[0]}\nVersion segura minima: ${lib.minSafe}\nCVEs conocidos: ${lib.cves}`,
        fix: `Actualiza ${lib.name} a la versión ${lib.minSafe} o superior. Consulta https://nvd.nist.gov/ para ver los CVEs específicos.`
      });
    }
  }

  return findings;
}


// ═══════════════════════════════════════════════════════════════
//  ANÁLISIS DE VULNERABILIDADES ACTIVAS (Backend PHP required)
// ═══════════════════════════════════════════════════════════════
async function scanActiveVulnerabilities(url) {
  const findings = [];
  const data = {
    available: false,
    totalTests: 0,
    totalVulnerabilities: 0,
    xss: [],
    sqli: [],
    pathTraversal: [],
    ssrf: [],
    openRedirect: [],
    paramsDiscovered: []
  };

  if (!backendAvailable) {
    return { findings, data, backendRequired: true };
  }

  try {
    const result = await proxyCall('vuln_scan', { url, scanType: 'all', maxTests: 40, delayMs: 200 }, 120000);
    data.available = true;
    data.totalTests = result.totalTests || 0;
    data.totalVulnerabilities = result.totalVulnerabilities || 0;
    data.xss = result.xss || [];
    data.sqli = result.sqli || [];
    data.pathTraversal = result.pathTraversal || [];
    data.ssrf = result.ssrf || [];
    data.openRedirect = result.openRedirect || [];
    data.paramsDiscovered = result.paramsDiscovered || [];

    // ── XSS Findings ──
    if (data.xss.length > 0) {
      for (const xss of data.xss) {
        findings.push({
          sev: 'C',
          title: `XSS Reflejado en parámetro "${xss.param}"`,
          desc: `Se detectó inyección XSS reflejada tipo <code>${escHtml(xss.type)}</code> en el parámetro <code>${escHtml(xss.param)}</code>. El payload inyectado aparece sin sanitizar en la respuesta HTML, permitiendo ejecución de código JavaScript malicioso.`,
          code: `Método: ${xss.method}\nParámetro: ${xss.param}\nPayload: ${xss.payload}\nEvidencia: ${xss.evidence || 'Payload reflejado en respuesta'}`,
          fix: 'Implementa sanitización de entrada (input validation) y codificación de salida (output encoding). Usa funciones como htmlspecialchars() en PHP o DOMPurify en JavaScript. Configura CSP para bloquear inline scripts.'
        });
      }
    }

    // ── SQL Injection Findings ──
    if (data.sqli.length > 0) {
      for (const sqli of data.sqli) {
        findings.push({
          sev: 'C',
          title: `SQL Injection en parámetro "${sqli.param}"`,
          desc: `Se detectaron indicadores de inyección SQL tipo <code>${escHtml(sqli.type)}</code> en el parámetro <code>${escHtml(sqli.param)}</code>. El servidor reveló errores de base de datos o mostró comportamiento anómalo ante payloads SQL.`,
          code: `Parámetro: ${sqli.param}\nPayload: ${sqli.payload}\nIndicadores:\n${(sqli.indicators || []).join('\n')}`,
          fix: 'Usa consultas parametrizadas (prepared statements) SIEMPRE. Nunca concatenes entrada del usuario directamente en consultas SQL. Implementa un ORM o query builder seguro.'
        });
      }
    }

    // ── Path Traversal Findings ──
    if (data.pathTraversal.length > 0) {
      for (const pt of data.pathTraversal) {
        findings.push({
          sev: 'C',
          title: `Path Traversal en parámetro "${pt.param}"`,
          desc: `Se detectó vulnerabilidad de recorrido de directorios (<code>Path Traversal / LFI</code>) en el parámetro <code>${escHtml(pt.param)}</code>. El servidor devuelve contenido de archivos del sistema como /etc/passwd o win.ini.`,
          code: `Parámetro: ${pt.param}\nPayload: ${pt.payload}\nTipo: ${pt.type}\nMarcador encontrado: ${pt.marker}\nEvidencia: ${pt.evidence || ''}`,
          fix: 'Nunca uses entrada del usuario directamente en rutas de archivo. Implementa una whitelist de archivos permitidos. Usa realpath() para validar que la ruta no sale del directorio permitido. Deshabilita allow_url_include en PHP.'
        });
      }
    }

    // ── SSRF Findings ──
    if (data.ssrf.length > 0) {
      for (const ssrf of data.ssrf) {
        findings.push({
          sev: 'C',
          title: `SSRF detectado en parámetro "${ssrf.param}"`,
          desc: `Se detectó Server-Side Request Forgery (<code>SSRF</code>) en el parámetro <code>${escHtml(ssrf.param)}</code>. El servidor realiza peticiones a URLs internas controladas por el atacante, exponiendo servicios internos y metadata de la nube.`,
          code: `Parámetro: ${ssrf.param}\nPayload: ${ssrf.payload}\nTipo: ${ssrf.type}\nIndicadores:\n${(ssrf.indicators || []).join('\n')}`,
          fix: 'Implementa una whitelist de dominios/IPs permitidos. Bloquea rangos IP internos (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, 192.168.0.0/16). Usa IMDSv2 en AWS. Valida esquemas de URL (solo http/https).'
        });
      }
    }

    // ── Open Redirect Findings ──
    if (data.openRedirect.length > 0) {
      for (const redir of data.openRedirect) {
        findings.push({
          sev: 'H',
          title: `Open Redirect en parámetro "${redir.param}"`,
          desc: `Se detectó redirección abierta (<code>Open Redirect</code>) en el parámetro <code>${escHtml(redir.param)}</code>. Un atacante puede crear URLs que redirigen a sitios maliciosos usando tu dominio como fachada, facilitando phishing.`,
          code: `Parámetro: ${redir.param}\nPayload: ${redir.payload}\nTipo: ${redir.type}\nIndicadores:\n${(redir.indicators || []).join('\n')}`,
          fix: 'Valida las URLs de redirección contra una whitelist. Usa solo rutas relativas para redirecciones. Si necesitas URLs externas, mantén un mapeo ID→URL en el servidor.'
        });
      }
    }

  } catch (e) {
    // Vuln scan failed silently
  }

  return { findings, data };
}


// ═══════════════════════════════════════════════════════════════
//  WORDPRESS & DEPENDENCY CVE SCANNING (Backend PHP required)
// ═══════════════════════════════════════════════════════════════
async function scanWordPressCVEs(url, mainHTML) {
  const findings = [];
  const data = {
    available: false,
    isWordPress: false,
    wpVersion: null,
    plugins: [],
    themes: [],
    vulnerablePlugins: [],
  };

  // Quick check if site is WordPress (client-side)
  const isWP = mainHTML && (
    mainHTML.includes('wp-content') ||
    mainHTML.includes('wp-includes') ||
    mainHTML.includes('wp-json')
  );

  if (!isWP && !backendAvailable) {
    return { findings, data };
  }

  if (backendAvailable) {
    try {
      const result = await proxyCall('wp_scan', { url }, 60000);
      data.available = true;
      data.isWordPress = result.isWordPress || false;
      data.wpVersion = result.wpVersion || null;
      data.plugins = result.plugins || [];
      data.themes = result.themes || [];
      data.vulnerablePlugins = result.vulnerablePlugins || [];

      if (!data.isWordPress) {
        return { findings, data };
      }

      // Add WP-specific findings from backend
      const wpFindings = result.wpFindings || [];
      for (const wf of wpFindings) {
        findings.push({
          sev: wf.sev,
          title: wf.title,
          desc: wf.desc,
          code: wf.code || '',
          fix: wf.fix
        });
      }

      // Add vulnerable plugin findings
      for (const vp of data.vulnerablePlugins) {
        for (const cve of (vp.cves || [])) {
          findings.push({
            sev: cve.sev || 'H',
            title: `Plugin WP vulnerable: ${vp.slug} ${vp.version ? 'v' + vp.version : '(versión desconocida)'}`,
            desc: `El plugin <code>${escHtml(vp.slug)}</code> tiene vulnerabilidades conocidas: <code>${escHtml(cve.desc)}</code> (${escHtml(cve.cve)}).`,
            code: `Plugin: ${vp.slug}\nVersión detectada: ${vp.version || 'No determinada'}\nVersión segura mínima: ${cve.below}\nCVE: ${cve.cve}\nDescripción: ${cve.desc}`,
            fix: `Actualiza el plugin ${vp.slug} a la versión ${cve.below} o superior. Si no lo usas, desinstálalo completamente.`
          });
        }
      }

    } catch (e) {
      // WP scan failed
    }
  } else {
    // Client-side WordPress detection only
    data.isWordPress = isWP;
    if (mainHTML) {
      // Extract version
      const verMatch = mainHTML.match(/content="WordPress (\d+\.\d+\.?\d*)"/);
      if (verMatch) data.wpVersion = verMatch[1];

      // Extract plugins
      const pluginMatches = mainHTML.matchAll(/wp-content\/plugins\/([a-z0-9_-]+)\//gi);
      const pluginSet = new Set();
      for (const pm of pluginMatches) pluginSet.add(pm[1]);
      data.plugins = [...pluginSet].map(slug => ({ slug, version: null }));

      if (data.plugins.length > 0) {
        findings.push({
          sev: 'I',
          title: `WordPress detectado con ${data.plugins.length} plugin(s)`,
          desc: `Plugins detectados: ${data.plugins.map(p => p.slug).join(', ')}. Para análisis de CVEs en plugins, usa el modo backend.`,
          code: data.plugins.map(p => `Plugin: ${p.slug}`).join('\n'),
          fix: 'Mantén todos los plugins actualizados. Ejecuta el escaneo con el backend PHP habilitado para verificar CVEs específicos.'
        });
      }
    }
  }

  return { findings, data };
}


// ═══════════════════════════════════════════════════════════════
//  ANÁLISIS MEJORADO DE DEPENDENCIAS CON CVEs ESPECÍFICOS
// ═══════════════════════════════════════════════════════════════
function analyzeEnhancedDependencies(html) {
  const findings = [];
  if (!html) return findings;

  // ── Enhanced detection patterns with specific version extraction ──
  const libraryDetectors = [
    {
      name: 'jQuery',
      patterns: [
        /jquery[.\-\/]v?(\d+\.\d+\.?\d*)/gi,
        /jquery\.min\.js\?v=(\d+\.\d+\.?\d*)/gi,
        /jQuery v(\d+\.\d+\.?\d*)/gi,
        /jquery@(\d+\.\d+\.?\d*)/gi,
      ],
      vulnerabilities: [
        { below: '3.5.0', cve: 'CVE-2020-11022', desc: 'XSS en .html() con input no sanitizado', sev: 'H', cvss: 6.1 },
        { below: '3.5.0', cve: 'CVE-2020-11023', desc: 'XSS en .html() con regex', sev: 'H', cvss: 6.1 },
        { below: '3.4.0', cve: 'CVE-2019-11358', desc: 'Prototype Pollution en jQuery.extend()', sev: 'M', cvss: 6.1 },
        { below: '3.0.0', cve: 'CVE-2015-9251', desc: 'XSS en ajax con cross-domain', sev: 'M', cvss: 6.1 },
        { below: '1.12.0', cve: 'CVE-2011-4969', desc: 'XSS en selector selector', sev: 'H', cvss: 4.3 },
      ]
    },
    {
      name: 'AngularJS',
      patterns: [/angular[.\-\/]v?1\.(\d+\.?\d*)/gi],
      vulnerabilities: [
        { below: '999.0.0', cve: 'CVE-2022-25869', desc: 'XSS via CDATA injection (EOL)', sev: 'H', cvss: 6.1 },
        { below: '999.0.0', cve: 'CVE-2020-7676', desc: 'Prototype Pollution (EOL)', sev: 'M', cvss: 5.4 },
      ]
    },
    {
      name: 'Bootstrap',
      patterns: [
        /bootstrap[.\-\/]v?(\d+\.\d+\.?\d*)/gi,
        /bootstrap@(\d+\.\d+\.?\d*)/gi,
        /Bootstrap v(\d+\.\d+\.?\d*)/gi,
      ],
      vulnerabilities: [
        { below: '4.3.1', cve: 'CVE-2019-8331', desc: 'XSS en tooltip/popover data-template', sev: 'M', cvss: 6.1 },
        { below: '4.1.2', cve: 'CVE-2018-14040', desc: 'XSS en collapse data-parent', sev: 'M', cvss: 6.1 },
        { below: '3.4.0', cve: 'CVE-2016-10735', desc: 'XSS en data-target attribute', sev: 'M', cvss: 6.1 },
      ]
    },
    {
      name: 'Lodash',
      patterns: [
        /lodash[.\-\/]v?(\d+\.\d+\.?\d*)/gi,
        /lodash@(\d+\.\d+\.?\d*)/gi,
      ],
      vulnerabilities: [
        { below: '4.17.21', cve: 'CVE-2021-23337', desc: 'Command Injection en template()', sev: 'C', cvss: 7.2 },
        { below: '4.17.20', cve: 'CVE-2020-28500', desc: 'ReDoS en trim()', sev: 'M', cvss: 5.3 },
        { below: '4.17.12', cve: 'CVE-2019-10744', desc: 'Prototype Pollution en defaultsDeep()', sev: 'C', cvss: 9.1 },
      ]
    },
    {
      name: 'React',
      patterns: [
        /react[.\-\/]v?(\d+\.\d+\.?\d*)/gi,
        /react@(\d+\.\d+\.?\d*)/gi,
        /React v(\d+\.\d+\.?\d*)/gi,
      ],
      vulnerabilities: [
        { below: '16.13.0', cve: 'CVE-2020-7919', desc: 'XSS en SSR hydration', sev: 'M', cvss: 5.4 },
        { below: '16.4.2', cve: 'CVE-2018-6341', desc: 'XSS en attribute names en SSR', sev: 'H', cvss: 6.1 },
      ]
    },
    {
      name: 'Vue.js',
      patterns: [
        /vue[.\-\/]v?(\d+\.\d+\.?\d*)/gi,
        /vue@(\d+\.\d+\.?\d*)/gi,
        /Vue\.js v(\d+\.\d+\.?\d*)/gi,
      ],
      vulnerabilities: [
        { below: '2.8.0', cve: 'CVE-2018-11235', desc: 'XSS en template compiler', sev: 'H', cvss: 6.1 },
      ]
    },
    {
      name: 'Moment.js',
      patterns: [
        /moment[.\-\/]v?(\d+\.\d+\.?\d*)/gi,
        /moment@(\d+\.\d+\.?\d*)/gi,
      ],
      vulnerabilities: [
        { below: '999.0.0', cve: 'CVE-2022-24785', desc: 'Path Traversal (librería abandonada/EOL)', sev: 'H', cvss: 7.5 },
        { below: '2.29.2', cve: 'CVE-2022-31129', desc: 'ReDoS en parsing', sev: 'H', cvss: 7.5 },
      ]
    },
    {
      name: 'Axios',
      patterns: [
        /axios[.\-\/]v?(\d+\.\d+\.?\d*)/gi,
        /axios@(\d+\.\d+\.?\d*)/gi,
      ],
      vulnerabilities: [
        { below: '1.6.0', cve: 'CVE-2023-45857', desc: 'CSRF token disclosure', sev: 'H', cvss: 6.5 },
        { below: '0.21.1', cve: 'CVE-2021-3749', desc: 'ReDoS', sev: 'H', cvss: 7.5 },
      ]
    },
    {
      name: 'DOMPurify',
      patterns: [/dompurify[.\-\/]v?(\d+\.\d+\.?\d*)/gi],
      vulnerabilities: [
        { below: '3.0.6', cve: 'CVE-2023-49146', desc: 'Mutation XSS bypass', sev: 'H', cvss: 6.1 },
        { below: '2.4.1', cve: 'CVE-2023-23631', desc: 'XSS bypass via nesting', sev: 'H', cvss: 6.1 },
      ]
    },
    {
      name: 'Socket.IO',
      patterns: [/socket\.io[.\-\/]v?(\d+\.\d+\.?\d*)/gi],
      vulnerabilities: [
        { below: '4.6.2', cve: 'CVE-2023-32695', desc: 'DoS via malformed packets', sev: 'H', cvss: 7.5 },
      ]
    },
    {
      name: 'Express.js',
      patterns: [/express[.\-\/]v?(\d+\.\d+\.?\d*)/gi],
      vulnerabilities: [
        { below: '4.17.3', cve: 'CVE-2022-24999', desc: 'Prototype Pollution via qs', sev: 'H', cvss: 7.5 },
      ]
    },
    {
      name: 'TinyMCE',
      patterns: [/tinymce[.\-\/]v?(\d+\.\d+\.?\d*)/gi],
      vulnerabilities: [
        { below: '6.8.1', cve: 'CVE-2024-29203', desc: 'XSS via noscript parsing', sev: 'M', cvss: 6.1 },
        { below: '5.10.9', cve: 'CVE-2022-23494', desc: 'XSS via special characters', sev: 'M', cvss: 6.1 },
      ]
    },
    {
      name: 'CKEditor',
      patterns: [/ckeditor[.\-\/]v?(\d+\.\d+\.?\d*)/gi],
      vulnerabilities: [
        { below: '4.24.0', cve: 'CVE-2024-24816', desc: 'XSS via content injection', sev: 'M', cvss: 6.1 },
      ]
    },
  ];

  // Compare versions: returns true if version < threshold
  function versionBelow(version, threshold) {
    if (!version || !threshold) return false;
    const v = version.split('.').map(Number);
    const t = threshold.split('.').map(Number);
    for (let i = 0; i < Math.max(v.length, t.length); i++) {
      const a = v[i] || 0;
      const b = t[i] || 0;
      if (a < b) return true;
      if (a > b) return false;
    }
    return false;
  }

  for (const lib of libraryDetectors) {
    for (const pattern of lib.patterns) {
      pattern.lastIndex = 0; // Reset regex
      const matches = [...html.matchAll(pattern)];
      if (matches.length === 0) continue;

      const version = matches[0][1];
      if (!version) continue;

      // Check against known vulnerabilities
      const applicableCVEs = lib.vulnerabilities.filter(v => versionBelow(version, v.below));
      if (applicableCVEs.length > 0) {
        const highestSev = applicableCVEs.reduce((best, v) => {
          const order = { C: 0, H: 1, M: 2, L: 3, I: 4 };
          return (order[v.sev] || 5) < (order[best.sev] || 5) ? v : best;
        });

        findings.push({
          sev: highestSev.sev,
          title: `${lib.name} v${version} — ${applicableCVEs.length} CVE(s) conocido(s)`,
          desc: `Se detectó <code>${lib.name}</code> versión <code>${version}</code> con <strong>${applicableCVEs.length}</strong> vulnerabilidad(es) conocida(s). La más severa: <code>${highestSev.cve}</code> (CVSS: ${highestSev.cvss}).`,
          code: applicableCVEs.map(v => `${v.cve} [${v.sev}] CVSS:${v.cvss} — ${v.desc} (corregido en v${v.below})`).join('\n'),
          fix: `Actualiza ${lib.name} a la última versión estable. Consulta https://nvd.nist.gov/ y https://security.snyk.io/ para más detalles sobre cada CVE.`
        });
      }
      break; // Found version from one pattern, no need to check others
    }
  }

  // ── Detect package.json exposure for npm audit info ──
  // (This is detected in path scanning, but we add extra context if found)

  return findings;
}


//  HISTORIAL DE REPORTES (localStorage)
function saveReportHistory(url, score, findings) {
  try {
    const history = JSON.parse(localStorage.getItem('websec_history') || '[]');
    const counts = { C: 0, H: 0, M: 0, L: 0, I: 0 };
    findings.forEach(f => counts[f.sev]++);
    history.unshift({
      url, score, counts, total: findings.length,
      date: new Date().toISOString(),
      dateStr: new Date().toLocaleString('es-MX')
    });
    // Keep max 20 records
    if (history.length > 20) history.length = 20;
    localStorage.setItem('websec_history', JSON.stringify(history));
  } catch (e) { /* localStorage not available */ }
}

function getReportHistory() {
  try { return JSON.parse(localStorage.getItem('websec_history') || '[]'); }
  catch (e) { return []; }
}


//  MOTOR PRINCIPAL DE ESCANEO

async function startScan() {
  let url = document.getElementById('url-input').value.trim();
  if (!url) return;
  if (!url.startsWith('http')) url = 'https://' + url;

  try { url = new URL(url).origin; }
  catch (e) { alert('URL inválida. Ejemplo: https://tusitio.com'); return; }

  scanResults = { url, findings: [], recon: {}, headers: {}, paths: {}, checklist: [] };
  checkState = {};

  // Deshabilitar botón
  document.getElementById('scan-btn').disabled = true;

  // Cambiar vista
  document.getElementById('hero-section').style.display = 'none';
  document.getElementById('report-section').style.display = 'none';
  document.getElementById('progress-section').style.display = 'flex';
  document.getElementById('progress-log').innerHTML = '';
  document.getElementById('prog-fill').style.width = '0%';

  addLog('<span class="log-info">// WEBSEC AUDIT ENGINE v5.0</span>');
  addLog('<span class="log-info">// Target: ' + url + '</span>');
  addLog('<span class="log-dim">// ─────────────────────────────────────</span>');

  // ── FASE 0: Detección de backend ──
  setProgress(2, 'Detectando backend...');
  addLog('');
  addLog('<span class="log-info">[00] Detectando backend PHP...</span>');
  await detectBackend();
  if (backendAvailable) {
    addLog('<span class="log-ok">  ✓ Backend PHP disponible — análisis profundo habilitado</span>');
    addLog('<span class="log-ok">    · Proxy CORS activo (sin limitaciones de origen)</span>');
    addLog('<span class="log-ok">    · DNS real (dns_get_record)</span>');
    addLog('<span class="log-ok">    · SSL/TLS (certificado + protocolos)</span>');
    addLog('<span class="log-ok">    · Port scanning (fsockopen)</span>');
    addLog('<span class="log-ok">    · Subdominios (70+ comunes)</span>');
    addLog('<span class="log-ok">    · Vuln activo (XSS, SQLi, LFI, SSRF, Redirect)</span>');
    addLog('<span class="log-ok">    · WordPress CVE scanner (plugins + core)</span>');
  } else {
    addLog('<span class="log-warn">   Backend PHP no disponible — modo cliente</span>');
    addLog('<span class="log-dim">  · Algunas funciones estarán limitadas por CORS</span>');
    addLog('<span class="log-dim">  · Para análisis completo, sirve desde WAMP/Apache</span>');
  }
  addLog('');
  await sleep(300);

  // ── FASE 1: Descarga HTML ──
  setProgress(5, 'Conectando al servidor...');
  addLog('<span class="log-info">[01] Descargando página principal...' + (backendAvailable ? ' (via proxy)' : '') + '</span>');

  let mainHTML = '', mainHeaders = {};
  try {
    const mainRes = await smartFetch(url);
    mainHTML = mainRes.body || '';
    mainHeaders = mainRes.headers || {};
    scanResults.recon.status = mainRes.status;
    scanResults.recon.redirect = mainRes.redirected ? mainRes.url : '—';
    scanResults.headers = mainHeaders;
    const proxyTag = mainRes.fromProxy ? ' (proxy)' : '';
    addLog('<span class="log-ok">  ✓ HTTP ' + mainRes.status + ' — ' + mainRes.url + proxyTag + '</span>');
    if (mainRes.headOnly) {
      addLog('<span class="log-warn">   Solo cabeceras obtenidas (body no disponible por CORS)</span>');
    }
  } catch (e) {
    addLog('<span class="log-err">  ✗ No se pudo conectar: ' + e.message + '</span>');
  }
  await sleep(300);

  // ── FASE 2: Tecnologías ──
  setProgress(12, 'Analizando tecnologías...');
  addLog(''); addLog('<span class="log-info">[02] Detectando tecnologías...</span>');
  const tech = detectTech(mainHTML, mainHeaders);
  scanResults.recon.tech = tech.join(', ') || 'No detectado';
  scanResults.recon.server = mainHeaders['server'] || mainHeaders['x-powered-by'] || '—';
  addLog('<span class="log-ok">  ✓ Tecnologías: ' + scanResults.recon.tech + '</span>');
  if (scanResults.recon.server !== '—')
    addLog('<span class="log-warn">   Server header expuesto: ' + scanResults.recon.server + '</span>');
  await sleep(200);

  // ── FASE 3: Cabeceras de seguridad ──
  setProgress(20, 'Auditando cabeceras de seguridad...');
  addLog(''); addLog('<span class="log-info">[03] Analizando cabeceras de seguridad (' + SEC_HEADERS.length + ')...</span>');
  const headerFindings = [];
  for (const hdr of SEC_HEADERS) {
    const val = mainHeaders[hdr.h];
    const ok = hdr.good(val);
    if (!ok) {
      const msg = val ? 'valor inseguro: ' + val.substring(0, 40) : 'AUSENTE';
      addLog('<span class="log-err">  ✗ ' + hdr.label + ' — ' + msg + '</span>');
      headerFindings.push({ ...hdr, val, type: 'header' });
    } else {
      addLog('<span class="log-ok">  ✓ ' + hdr.label + ' — ' + (val || 'OK').substring(0, 40) + '</span>');
    }
  }
  await sleep(200);

  // ── FASE 4: Cookies ──
  setProgress(28, 'Analizando cookies...');
  addLog(''); addLog('<span class="log-info">[04] Analizando cookies...</span>');
  const cookieFindings = analyzeCookies(mainHeaders);
  if (cookieFindings.length > 0) {
    addLog('<span class="log-warn">   ' + cookieFindings.length + ' problemas en cookies</span>');
  } else {
    addLog('<span class="log-ok">  ✓ No se detectan cookies inseguras</span>');
  }
  await sleep(200);

  // ── FASE 5: HTTPS check ──
  setProgress(32, 'Verificando HTTPS...');
  addLog(''); addLog('<span class="log-info">[05] Verificando configuración HTTPS...</span>');
  const httpsFindings = [];
  if (!url.startsWith('https')) {
    httpsFindings.push({
      sev: 'C', title: 'El sitio no usa HTTPS',
      desc: 'La comunicación no está cifrada. Cualquier dato transmitido puede ser interceptado.',
      code: 'HTTP:// en lugar de HTTPS://', fix: 'Configura un certificado SSL/TLS y redirige todo a HTTPS.'
    });
    addLog('<span class="log-err">  ✗ El sitio NO usa HTTPS</span>');
  } else {
    addLog('<span class="log-ok">  ✓ Conexión HTTPS activa</span>');
    if (!mainHeaders['strict-transport-security']) {
      addLog('<span class="log-warn">   HSTS no configurado — posible downgrade a HTTP</span>');
    }
  }
  await sleep(200);

  // ── FASE 6: SSL/TLS Certificate Analysis (BACKEND) ──
  setProgress(35, 'Analizando certificado SSL/TLS...');
  const hostname = new URL(url).hostname;
  addLog(''); addLog('<span class="log-info">[06] Analizando certificado SSL/TLS...</span>');
  let sslResult = { findings: [], data: { available: false } };
  if (url.startsWith('https')) {
    sslResult = await analyzeSSL(hostname);
    scanResults.ssl = sslResult.data;
    if (sslResult.data.available) {
      addLog('<span class="log-ok">  ✓ Certificado: ' + (sslResult.data.subject || '—') + '</span>');
      addLog('<span class="log-dim">  · Emisor: ' + (sslResult.data.issuer || '—') + '</span>');
      addLog('<span class="log-dim">  · Válido hasta: ' + (sslResult.data.validTo || '—') + ' (' + (sslResult.data.daysRemaining || '?') + ' días)</span>');
      addLog('<span class="log-dim">  · Clave: ' + (sslResult.data.keyType || '—') + ' ' + (sslResult.data.keySize || '—') + ' bits</span>');
      if (sslResult.data.protocols && sslResult.data.protocols.length > 0) {
        addLog('<span class="log-dim">  · Protocolos: ' + sslResult.data.protocols.join(', ') + '</span>');
      }
      if (sslResult.findings.length > 0) {
        addLog('<span class="log-warn">   ' + sslResult.findings.length + ' problema(s) de SSL/TLS</span>');
      }
    } else if (sslResult.backendRequired) {
      addLog('<span class="log-dim">  · Requiere backend PHP para análisis de certificados</span>');
    }
  } else {
    addLog('<span class="log-dim">  · No aplica (sitio no usa HTTPS)</span>');
  }
  await sleep(200);

  // ── FASE 7: Rutas sensibles (con Soft 404 mejorado + anti-rate-limit) ──
  setProgress(38, 'Escaneando rutas sensibles...');
  addLog(''); addLog('<span class="log-info">[07] Escaneando ' + SENSITIVE_PATHS.length + ' rutas sensibles...</span>');

  // ── Improved Soft 404 detection ──
  let isSoft404 = false;
  let soft404ContentHash = '';
  try {
    const randomPath1 = '/this-is-a-random-404-check-' + Date.now();
    const randomPath2 = '/another-nonexistent-check-' + Math.random().toString(36).substr(2);

    if (backendAvailable) {
      const [r1, r2] = await Promise.all([
        smartFetch(url + randomPath1, { method: 'GET' }).catch(() => null),
        smartFetch(url + randomPath2, { method: 'GET' }).catch(() => null)
      ]);

      if (r1 && r2 && r1.status === 200 && r2.status === 200) {
        const body1 = (r1.body || '').substring(0, 500);
        const body2 = (r2.body || '').substring(0, 500);
        if (body1.length > 100 && body2.length > 100) {
          const similarity = calcSimilarity(body1, body2);
          if (similarity > 0.7) {
            isSoft404 = true;
            soft404ContentHash = body1.substring(0, 200);
          }
        } else {
          isSoft404 = true;
        }
      }
    } else {
      const r404 = await smartHead(url + randomPath1, 3000);
      if (r404.status === 200) {
        isSoft404 = true;
      }
    }

    if (isSoft404) {
      addLog('<span class="log-warn">  ⚠ Detectado enrutador catch-all (Soft 404). Verificación de contenido activada.</span>');
    }
  } catch (e) { /* ignore */ }

  const exposedPaths = [];
  let doneCount = 0;

  // ═══ STRATEGY A: Backend batch_head endpoint (single call, server-side throttling) ═══
  if (backendAvailable) {
    addLog('<span class="log-dim">  ℹ Usando escaneo batch server-side (anti-rate-limit)...</span>');
    try {
      const pathStrings = SENSITIVE_PATHS.map(p => p.p);
      const batchData = await proxyCall('batch_head', {
        baseUrl: url,
        paths: pathStrings,
        delayMs: 150 // 150ms between each request on the server side
      }, 90000); // 90s timeout for batch scanning

      const batchResults = batchData.results || [];
      addLog('<span class="log-dim">  ℹ Batch completado: ' + batchResults.length + ' rutas escaneadas (delay: ' + (batchData.delayUsed || 150) + 'ms)</span>');

      for (const br of batchResults) {
        const pathInfo = SENSITIVE_PATHS.find(sp => sp.p === br.path);
        if (!pathInfo) continue;
        const r = { p: br.path, label: pathInfo.label, sev: pathInfo.sev, status: br.status };

        scanResults.paths[r.p] = r.status;
        if (r.status === 200) {
          if (isSoft404) {
            if (soft404ContentHash) {
              try {
                const verifyRes = await smartFetch(url + r.p);
                const body = (verifyRes.body || '').substring(0, 200);
                const similarity = calcSimilarity(body, soft404ContentHash);
                if (similarity > 0.7) {
                  addLog('<span class="log-dim">  ·  200 (Soft 404 ✓) — ' + r.p + '</span>');
                  doneCount++;
                  continue;
                }
              } catch (e) { /* assume it's real */ }
            } else {
              addLog('<span class="log-dim">  ·  200 (Soft 404) — ' + r.p + '</span>');
              doneCount++;
              continue;
            }
          }

          // Anti-False Positive: Ignore 'I' (Info) paths from being actual findings
          // these are things like robots.txt or favicon which are MEANT to be public
          if (r.sev === 'I') {
            addLog('<span class="log-ok">  ✓ 200 — ' + r.p + ' (Público)</span>');
          } else {
            addLog('<span class="log-err">  🚨 200 — ' + r.p + ' (' + r.label + ') EXPUESTO</span>');
            exposedPaths.push(r);
          }
        } else if (r.status === 429) {
          addLog('<span class="log-warn">  ⚡ 429 (rate limited) — ' + r.p + '</span>');
        } else if (r.status === 403) {
          addLog('<span class="log-ok">  🔒 403 — ' + r.p + '</span>');
        } else {
          addLog('<span class="log-dim">  ·  ' + r.status + ' — ' + r.p + '</span>');
        }
        doneCount++;

        // Update progress periodically
        if (doneCount % 10 === 0) {
          setProgress(38 + Math.round((doneCount / SENSITIVE_PATHS.length) * 25),
            `Procesando rutas (${doneCount}/${SENSITIVE_PATHS.length})...`);
        }
      }
    } catch (batchError) {
      addLog('<span class="log-warn">  ⚠ Batch falló (' + (batchError.message || 'error') + '). Usando fallback con throttle...</span>');
      // Fall through to Strategy B
      doneCount = 0;
    }
  }

  // ═══ STRATEGY B: Client-side fallback with progressive throttling ═══
  if (!backendAvailable || doneCount === 0) {
    const pathBatchSize = 3; // Small batches to avoid rate limiting
    let currentDelay = 300;  // Start with 300ms between batches
    let consecutiveErrors = 0;

    for (let i = 0; i < SENSITIVE_PATHS.length; i += pathBatchSize) {
      const batch = SENSITIVE_PATHS.slice(i, i + pathBatchSize);
      const results = await Promise.allSettled(batch.map(async ({ p, label, sev }) => {
        const fullUrl = url + p;
        const headResult = await smartHead(fullUrl, 5000);
        return { p, label, sev, status: headResult.status };
      }));

      let batchHas429 = false;
      for (const result of results) {
        if (result.status !== 'fulfilled') continue;
        const r = result.value;
        scanResults.paths[r.p] = r.status;

        if (r.status === 429) {
          batchHas429 = true;
          addLog('<span class="log-warn">  ⚡ 429 (rate limited) — ' + r.p + '</span>');
        } else if (r.status === 200) {
          if (isSoft404) {
            if (backendAvailable && soft404ContentHash) {
              try {
                const verifyRes = await smartFetch(url + r.p);
                const body = (verifyRes.body || '').substring(0, 400).toLowerCase();
                const similarity = calcSimilarity(body, soft404ContentHash);

                // Extra check: common 404 keywords in a 200 page
                const hasNotFoundKeywords = body.includes('not found') || body.includes('404') || body.includes('error') || body.includes('no encontrado');

                if (similarity > 0.7 || hasNotFoundKeywords) {
                  addLog('<span class="log-dim">  ·  200 (Soft 404 ✓) — ' + r.p + '</span>');
                  doneCount++;
                  continue;
                }
              } catch (e) { /* assume it's real */ }
            } else {
              addLog('<span class="log-dim">  ·  200 (Soft 404) — ' + r.p + '</span>');
              doneCount++;
              continue;
            }
          }

          // Anti-False Positive: Ignore 'I' (Info) paths
          if (r.sev === 'I') {
            addLog('<span class="log-ok">  ✓ 200 — ' + r.p + ' (Público)</span>');
          } else {
            addLog('<span class="log-err">  🚨 200 — ' + r.p + ' (' + r.label + ') EXPUESTO</span>');
            exposedPaths.push(r);
            consecutiveErrors = 0;
          }
        } else if (r.status === 'opaque') {
          addLog('<span class="log-warn">  ~  opaque — ' + r.p + '</span>');
        } else if (r.status === 403) {
          addLog('<span class="log-ok">  🔒 403 — ' + r.p + '</span>');
          consecutiveErrors = 0;
        } else if (r.status === 'error') {
          consecutiveErrors++;
        } else {
          addLog('<span class="log-dim">  ·  ' + r.status + ' — ' + r.p + '</span>');
          consecutiveErrors = 0;
        }
        doneCount++;
      }

      // Adaptive throttling: back off if rate limited or too many errors
      if (batchHas429) {
        currentDelay = Math.min(currentDelay * 2, 5000); // Exponential backoff, max 5s
        addLog('<span class="log-warn">  ⏳ Rate limit detectado. Esperando ' + currentDelay + 'ms...</span>');
      } else if (consecutiveErrors > 3) {
        currentDelay = Math.min(currentDelay * 1.5, 3000);
        consecutiveErrors = 0;
      } else if (currentDelay > 300) {
        currentDelay = Math.max(currentDelay * 0.8, 300); // Gradually recover
      }

      setProgress(38 + Math.round((doneCount / SENSITIVE_PATHS.length) * 25),
        `Escaneando rutas (${doneCount}/${SENSITIVE_PATHS.length})...`);
      await sleep(currentDelay);
    }
  }

  // ═══ FINAL VALIDATION: Massive False Positive Protection ═══
  // If we found too many exposed paths (e.g. > 35% of the total list), 
  // it's almost certainly a misconfiguration of our scanner or a very weird SPA router.
  if (exposedPaths.length > (SENSITIVE_PATHS.length * 0.35)) {
    addLog('<span class="log-warn">  ⚠️ ALERTA: Se detectaron demasiados positivos (' + exposedPaths.length + ').</span>');
    addLog('<span class="log-warn">  ⚠️ Probable falso positivo masivo por ruteo dinámico. Limpiando hallazgos dudosos...</span>');
    exposedPaths.length = 0; // Clear the list to be safe
    addLog('<span class="log-ok">  ✓ Hallazgos de rutas descartados para evitar ruidos en el reporte.</span>');
  }

  await sleep(200);

  // ── FASE 8: WAF Detection ──
  setProgress(64, 'Detectando WAF/CDN...');
  addLog(''); addLog('<span class="log-info">[08] Detectando WAF/CDN de protección...</span>');
  const wafResult = detectWAF(mainHeaders);
  scanResults.waf = wafResult.detected;
  if (wafResult.detected.length > 0) {
    addLog('<span class="log-ok">  🛡 WAF detectado: ' + wafResult.detected.join(', ') + '</span>');
  } else {
    addLog('<span class="log-warn">   No se detectó WAF/CDN</span>');
  }
  await sleep(200);

  // ── FASE 9: Análisis HTML ──
  setProgress(66, 'Analizando código HTML...');
  addLog(''); addLog('<span class="log-info">[09] Analizando código fuente HTML...</span>');
  const htmlFindings = analyzeHTML(mainHTML, url);
  addLog('<span class="log-ok">  ✓ ' + htmlFindings.length + ' hallazgos de código fuente</span>');
  await sleep(200);

  // ── FASE 10: robots.txt ──
  setProgress(68, 'Analizando robots.txt...');
  addLog(''); addLog('<span class="log-info">[10] Analizando robots.txt...</span>');
  const robotsResult = await analyzeRobotsTxt(url);
  if (robotsResult.content) {
    addLog('<span class="log-ok">  ✓ robots.txt encontrado (' + robotsResult.disallowed.length + ' reglas Disallow)</span>');
    if (robotsResult.findings.length > 0) addLog('<span class="log-warn">   ' + robotsResult.findings.length + ' hallazgo(s)</span>');
  } else {
    addLog('<span class="log-dim">  · robots.txt no encontrado</span>');
  }
  await sleep(200);

  // ── FASE 11: security.txt & sitemap.xml ──
  setProgress(70, 'Verificando security.txt y sitemap...');
  addLog(''); addLog('<span class="log-info">[11] Verificando security.txt (RFC 9116) y sitemap.xml...</span>');
  const secTxtResult = await analyzeSecurityTxt(url);
  if (secTxtResult.data.securityTxt) addLog('<span class="log-ok">  ✓ security.txt encontrado</span>');
  else addLog('<span class="log-warn">   security.txt no encontrado</span>');
  if (secTxtResult.data.sitemap) addLog('<span class="log-ok">  ✓ sitemap.xml encontrado</span>');
  else addLog('<span class="log-dim">  · sitemap.xml no encontrado</span>');
  await sleep(200);

  // ── FASE 12: Secretos avanzados ──
  setProgress(72, 'Escaneando secretos expuestos...');
  addLog(''); addLog('<span class="log-info">[12] Escaneando secretos avanzados (AWS, Stripe, GitHub, JWT...)...</span>');
  const secretFindings = analyzeSecrets(mainHTML);
  if (secretFindings.length > 0) {
    addLog('<span class="log-err">  🚨 ' + secretFindings.length + ' secreto(s) potencialmente expuesto(s)</span>');
  } else {
    addLog('<span class="log-ok">  ✓ No se detectaron secretos expuestos</span>');
  }
  await sleep(200);

  // ── FASE 13: Librerías desactualizadas ──
  setProgress(74, 'Detectando librerías vulnerables...');
  addLog(''); addLog('<span class="log-info">[13] Detectando librerías desactualizadas con CVEs conocidos...</span>');
  const outdatedFindings = analyzeOutdatedLibs(mainHTML);
  if (outdatedFindings.length > 0) {
    addLog('<span class="log-warn">   ' + outdatedFindings.length + ' librería(s) potencialmente vulnerable(s)</span>');
    for (const of2 of outdatedFindings) addLog('<span class="log-err">  ⚠ ' + of2.title + '</span>');
  } else {
    addLog('<span class="log-ok">  ✓ No se detectaron librerías vulnerables conocidas</span>');
  }
  await sleep(200);

  // ── FASE 14: Scripts de terceros y SRI ──
  setProgress(76, 'Analizando scripts de terceros...');
  addLog(''); addLog('<span class="log-info">[14] Analizando scripts de terceros y SRI...</span>');
  const thirdPartyResult = analyzeThirdPartyScripts(mainHTML, url);
  addLog('<span class="log-ok">  ✓ ' + (thirdPartyResult.stats.internal || 0) + ' internos, ' + (thirdPartyResult.stats.external || 0) + ' externos' + (thirdPartyResult.stats.withoutSRI > 0 ? ' (' + thirdPartyResult.stats.withoutSRI + ' sin SRI)' : '') + '</span>');
  await sleep(200);

  // ── FASE 15: DOM XSS Sinks ──
  setProgress(78, 'Detectando sinks DOM XSS...');
  addLog(''); addLog('<span class="log-info">[15] Detectando sinks DOM XSS...</span>');
  const domSinkFindings = analyzeDOMSinks(mainHTML);
  addLog('<span class="log-ok">  ✓ ' + domSinkFindings.length + ' patrones de riesgo detectados</span>');
  await sleep(200);

  // ── FASE 16: Performance & CORS & OG ──
  setProgress(80, 'Analizando rendimiento, CORS y Open Graph...');
  addLog(''); addLog('<span class="log-info">[16] Analizando rendimiento, CORS y metadatos sociales...</span>');
  const perfResult = analyzePerformanceSecurity(mainHTML, mainHeaders);
  const corsFindings = await analyzeCORS(url);
  const ogFindings = analyzeOpenGraph(mainHTML);
  scanResults.metrics = perfResult.metrics;
  addLog('<span class="log-ok">  ✓ Recursos: ' + (perfResult.metrics.scripts || 0) + ' scripts, ' + (perfResult.metrics.styles || 0) + ' hojas de estilo, ' + (perfResult.metrics.images || 0) + ' imágenes</span>');
  if (corsFindings.length > 0) addLog('<span class="log-warn">   CORS misconfiguration detectada</span>');
  await sleep(200);

  // ── FASE 17: DNS Security (SPF, DMARC, DKIM, DNSSEC, CAA) ──
  setProgress(83, 'Analizando registros DNS...');
  addLog(''); addLog('<span class="log-info">[17] Analizando seguridad DNS' + (backendAvailable ? ' (dns_get_record)' : ' (DoH)') + '...</span>');
  const dnsResult = await analyzeDNS(hostname);
  scanResults.dns = dnsResult.data;
  if (dnsResult.data.spf) addLog('<span class="log-ok">  ✓ SPF: ' + dnsResult.data.spf.substring(0, 50) + '</span>');
  else addLog('<span class="log-err">  ✗ SPF: No configurado</span>');
  if (dnsResult.data.dmarc) addLog('<span class="log-ok">  ✓ DMARC: ' + dnsResult.data.dmarc.substring(0, 50) + '</span>');
  else addLog('<span class="log-err">  ✗ DMARC: No configurado</span>');
  if (dnsResult.data.dkim) addLog('<span class="log-ok">  ✓ DKIM: selector "' + dnsResult.data.dkim + '" encontrado</span>');
  else if (backendAvailable) addLog('<span class="log-warn">   DKIM: No detectado en selectores comunes</span>');
  if (dnsResult.data.dnssec) addLog('<span class="log-ok">  ✓ DNSSEC: Activo</span>');
  else addLog('<span class="log-warn">   DNSSEC: No habilitado</span>');
  if (dnsResult.data.caa && dnsResult.data.caa.length > 0) addLog('<span class="log-ok">  ✓ CAA: ' + dnsResult.data.caa.length + ' registro(s)</span>');
  else if (backendAvailable) addLog('<span class="log-warn">   CAA: No configurado</span>');
  if (dnsResult.data.mx && dnsResult.data.mx.length > 0) addLog('<span class="log-dim">  · MX: ' + dnsResult.data.mx.length + ' registro(s)</span>');
  if (dnsResult.data.ns && dnsResult.data.ns.length > 0) addLog('<span class="log-dim">  · NS: ' + dnsResult.data.ns.join(', ').substring(0, 60) + '</span>');
  await sleep(200);

  // ── FASE 18: Subdomain Enumeration ──
  setProgress(87, 'Enumerando subdominios...');
  addLog(''); addLog('<span class="log-info">[18] Enumerando subdominios' + (backendAvailable ? ' (70+ comunes)' : ' (30 comunes)') + '...</span>');
  const subdomainResult = await enumerateSubdomains(hostname);
  if (subdomainResult.found.length > 0) {
    addLog('<span class="log-warn">   ' + subdomainResult.found.length + ' subdominio(s) encontrado(s):</span>');
    for (const s of subdomainResult.found.slice(0, 8)) {
      const isRisky = s.risky || ['dev', 'staging', 'stage', 'test', 'qa', 'admin', 'panel', 'jenkins', 'internal', 'db'].includes(s.sub);
      addLog(`<span class="${isRisky ? 'log-err' : 'log-dim'}">  ${isRisky ? '🚨' : '·'} ${s.fqdn} → ${s.ip}${s.cname ? ' (→ ' + s.cname + ')' : ''}</span>`);
    }
    if (subdomainResult.found.length > 8) addLog('<span class="log-dim">  ... y ' + (subdomainResult.found.length - 8) + ' más</span>');
  } else {
    addLog('<span class="log-ok">  ✓ No se encontraron subdominios expuestos</span>');
  }
  scanResults.subdomains = subdomainResult.found;
  await sleep(200);

  // ── FASE 19: Port Scanning (BACKEND) ──
  setProgress(92, 'Escaneando puertos...');
  addLog(''); addLog('<span class="log-info">[19] Escaneando puertos comunes...</span>');
  let portResult = { findings: [], data: { available: false, openPorts: [] } };
  if (backendAvailable) {
    portResult = await scanPorts(hostname);
    scanResults.ports = portResult.data;
    if (portResult.data.openPorts.length > 0) {
      addLog('<span class="log-warn">   ' + portResult.data.openPorts.length + ' puerto(s) abierto(s):</span>');
      for (const p of portResult.data.openPorts.slice(0, 10)) {
        const isDangerous = [21, 23, 3306, 5432, 27017, 6379, 9200, 3389, 5900].includes(p.port);
        addLog(`<span class="${isDangerous ? 'log-err' : 'log-dim'}">  ${isDangerous ? '🚨' : '·'} Puerto ${p.port} (${p.service}): ABIERTO${p.banner ? ' — ' + p.banner.substring(0, 40) : ''}</span>`);
      }
    } else {
      addLog('<span class="log-ok">  ✓ Solo puertos web estándar abiertos</span>');
    }
  } else {
    addLog('<span class="log-dim">  · Requiere backend PHP para escaneo de puertos</span>');
  }
  await sleep(200);

  // ── FASE 20: Active Vulnerability Scanning (BACKEND) ──
  setProgress(93, 'Escaneando vulnerabilidades activas...');
  addLog(''); addLog('<span class="log-info">[20] Escaneando vulnerabilidades activas (XSS, SQLi, LFI, SSRF, Redirect)...</span>');
  let vulnResult = { findings: [], data: { available: false } };
  if (backendAvailable) {
    addLog('<span class="log-dim">  ℹ Enviando payloads seguros a parámetros descubiertos...</span>');
    vulnResult = await scanActiveVulnerabilities(url);
    scanResults.vulnScan = vulnResult.data;
    if (vulnResult.data.available) {
      addLog('<span class="log-dim">  ℹ ' + vulnResult.data.totalTests + ' pruebas realizadas en ' + (vulnResult.data.paramsDiscovered || []).length + ' parámetros</span>');
      if (vulnResult.data.totalVulnerabilities > 0) {
        addLog('<span class="log-err">  🚨 ' + vulnResult.data.totalVulnerabilities + ' vulnerabilidad(es) activa(s) detectada(s):</span>');
        if (vulnResult.data.xss.length > 0) addLog('<span class="log-err">    · XSS Reflejado: ' + vulnResult.data.xss.length + ' parámetro(s)</span>');
        if (vulnResult.data.sqli.length > 0) addLog('<span class="log-err">    · SQL Injection: ' + vulnResult.data.sqli.length + ' parámetro(s)</span>');
        if (vulnResult.data.pathTraversal.length > 0) addLog('<span class="log-err">    · Path Traversal: ' + vulnResult.data.pathTraversal.length + ' parámetro(s)</span>');
        if (vulnResult.data.ssrf.length > 0) addLog('<span class="log-err">    · SSRF: ' + vulnResult.data.ssrf.length + ' parámetro(s)</span>');
        if (vulnResult.data.openRedirect.length > 0) addLog('<span class="log-warn">    · Open Redirect: ' + vulnResult.data.openRedirect.length + ' parámetro(s)</span>');
      } else {
        addLog('<span class="log-ok">  ✓ No se detectaron vulnerabilidades activas</span>');
      }
    }
  } else {
    addLog('<span class="log-dim">  · Requiere backend PHP para escaneo activo de vulnerabilidades</span>');
  }
  await sleep(200);

  // ── FASE 21: WordPress & Plugin CVE Scanning ──
  setProgress(95, 'Escaneando WordPress y CVEs...');
  addLog(''); addLog('<span class="log-info">[21] Escaneando WordPress y vulnerabilidades de plugins...</span>');
  const wpResult = await scanWordPressCVEs(url, mainHTML);
  scanResults.wordpress = wpResult.data;
  if (wpResult.data.isWordPress) {
    addLog('<span class="log-warn">  🔍 WordPress detectado' + (wpResult.data.wpVersion ? ' v' + wpResult.data.wpVersion : '') + '</span>');
    if (wpResult.data.plugins.length > 0) {
      addLog('<span class="log-dim">  · ' + wpResult.data.plugins.length + ' plugin(s) detectado(s): ' + wpResult.data.plugins.map(p => p.slug).slice(0, 5).join(', ') + '</span>');
    }
    if (wpResult.data.vulnerablePlugins.length > 0) {
      addLog('<span class="log-err">  🚨 ' + wpResult.data.vulnerablePlugins.length + ' plugin(s) con CVEs conocidos</span>');
    }
    if (wpResult.findings.length > 0) {
      addLog('<span class="log-warn">   ' + wpResult.findings.length + ' hallazgo(s) de seguridad WordPress</span>');
    }
  } else {
    addLog('<span class="log-dim">  · No es WordPress — omitiendo escaneo WP</span>');
  }
  await sleep(200);

  // ── FASE 22: Enhanced Dependency CVE Analysis ──
  setProgress(96, 'Analizando dependencias con CVEs...');
  addLog(''); addLog('<span class="log-info">[22] Analizando dependencias con CVEs específicos (CVSS scoring)...</span>');
  const enhancedDepFindings = analyzeEnhancedDependencies(mainHTML);
  if (enhancedDepFindings.length > 0) {
    addLog('<span class="log-err">  🚨 ' + enhancedDepFindings.length + ' librería(s) con CVEs específicos detectada(s)</span>');
    for (const edf of enhancedDepFindings) addLog('<span class="log-warn">    · ' + edf.title + '</span>');
  } else {
    addLog('<span class="log-ok">  ✓ No se detectaron dependencias con CVEs conocidos</span>');
  }
  await sleep(200);

  // ── FASE 23: Construcción del reporte ──
  setProgress(97, 'Construyendo informe...');
  addLog(''); addLog('<span class="log-info">[23] Construyendo informe final...</span>');
  await sleep(400);

  const totalPhases = 23;

  const allFindings = [
    ...vulnResult.findings,
    ...httpsFindings,
    ...sslResult.findings,
    ...corsFindings,
    ...portResult.findings,
    ...dnsResult.findings,
    ...subdomainResult.findings,
    ...wafResult.findings,
    ...secretFindings,
    ...outdatedFindings,
    ...enhancedDepFindings,
    ...wpResult.findings,
    ...secTxtResult.findings,
    ...exposedPaths.map(ep => ({
      sev: ep.sev, title: 'Ruta sensible expuesta: ' + ep.p,
      desc: `La ruta <code>${ep.p}</code> (${ep.label}) devuelve HTTP 200 y es accesible públicamente.`,
      code: `HTTP GET ${url}${ep.p}\n→ 200 OK  ← EXPUESTO`,
      fix: 'Bloquea esta ruta, borra el archivo o protégela con autenticación.'
    })),
    ...headerFindings.map(h => ({
      sev: h.sev, title: 'Cabecera ausente: ' + h.label,
      desc: `La cabecera <code>${h.label}</code> no está configurada correctamente.`,
      code: h.val ? `${h.h}: ${h.val}  ← valor inseguro` : `${h.h}: [AUSENTE]`, fix: h.fix
    })),
    ...cookieFindings,
    ...robotsResult.findings,
    ...thirdPartyResult.findings,
    ...domSinkFindings,
    ...perfResult.findings,
    ...ogFindings,
    ...htmlFindings
  ].sort((a, b) => sevOrder(a.sev) - sevOrder(b.sev));

  scanResults.findings = allFindings;
  scanResults.thirdPartyStats = thirdPartyResult.stats;
  scanResults.backendUsed = backendAvailable;

  addLog('<span class="log-ok">  ✓ Total hallazgos: ' + allFindings.length + '</span>');
  addLog('');
  addLog('<span class="log-ok">══════════════════════════════════════</span>');
  addLog('<span class="log-ok">  ESCANEO COMPLETADO ✓ (' + totalPhases + ' fases' + (backendAvailable ? ' + backend' : '') + ')</span>');
  addLog('<span class="log-ok">══════════════════════════════════════</span>');

  setProgress(100, 'Listo');
  await sleep(500);
  renderReport(url, allFindings, mainHeaders);
}

// Utility: simple text similarity (0-1) for Soft 404 detection
function calcSimilarity(str1, str2) {
  if (!str1 || !str2) return 0;
  const s1 = str1.replace(/\s+/g, ' ').trim();
  const s2 = str2.replace(/\s+/g, ' ').trim();
  if (s1 === s2) return 1;
  const longer = s1.length > s2.length ? s1 : s2;
  const shorter = s1.length > s2.length ? s2 : s1;
  if (longer.length === 0) return 1;
  // Simple bigram comparison
  const bigrams1 = new Set();
  for (let i = 0; i < shorter.length - 1; i++) bigrams1.add(shorter.substr(i, 2));
  let matches = 0;
  for (let i = 0; i < longer.length - 1; i++) {
    if (bigrams1.has(longer.substr(i, 2))) matches++;
  }
  return (2 * matches) / (shorter.length + longer.length - 2);
}


//  RENDERIZADO DEL REPORTE

function renderReport(url, findings, headers) {
  document.getElementById('progress-section').style.display = 'none';
  document.getElementById('report-section').style.display = 'block';
  document.getElementById('r-url').textContent = url;
  document.getElementById('r-ts').textContent = 'Generado el ' + new Date().toLocaleString('es-MX');

  // ── Score ──
  const counts = { C: 0, H: 0, M: 0, L: 0, I: 0 };
  findings.forEach(f => counts[f.sev]++);

  // Fórmula mejorada: penaliza pero nunca llega a 0 para que sea visible
  let score = 100 - (counts.C * 15) - (counts.H * 8) - (counts.M * 3) - (counts.L * 1);
  score = Math.max(5, Math.min(100, Math.round(score))); // Mínimo 5 para que sea visible

  // Save to history
  saveReportHistory(url, score, findings);

  const scoreEl = document.getElementById('score-num');
  const lblEl = document.getElementById('score-lbl');
  const descEl = document.getElementById('score-desc');

  // Reset semáforos
  ['sem-red', 'sem-yellow', 'sem-green'].forEach(id =>
    document.getElementById(id).classList.remove('on'));

  // Animación del score
  scoreEl.textContent = '0';
  let current = 0;
  if (score > 0) {
    const scoreInterval = setInterval(() => {
      current += Math.ceil((score - current) / 10) || 1;
      if (current >= score) { current = score; clearInterval(scoreInterval); }
      scoreEl.textContent = current;
    }, 30);
  }

  if (score < 40) {
    document.getElementById('sem-red').classList.add('on');
    lblEl.textContent = 'RIESGO ALTO';
    lblEl.style.color = 'var(--red)';
    descEl.textContent = 'Se encontraron vulnerabilidades críticas o altas que requieren atención inmediata.';
    scoreEl.style.cssText = '-webkit-text-fill-color: var(--red); background: none;';
  } else if (score < 70) {
    document.getElementById('sem-yellow').classList.add('on');
    lblEl.textContent = 'RIESGO MEDIO';
    lblEl.style.color = 'var(--yellow)';
    descEl.textContent = 'Existen problemas de seguridad que deben corregirse.';
    scoreEl.style.cssText = '-webkit-text-fill-color: var(--yellow); background: none;';
  } else {
    document.getElementById('sem-green').classList.add('on');
    lblEl.textContent = 'SEGURIDAD ROBUSTA';
    lblEl.style.color = 'var(--green)';
    descEl.textContent = 'El sitio tiene una buena postura de seguridad. Revisa los detalles menores.';
    scoreEl.style.cssText = '-webkit-text-fill-color: var(--green); background: none;';
  }

  // Pills
  const sevMeta = { C: ['Críticos', 'pill-red'], H: ['Altos', 'pill-orange'], M: ['Medios', 'pill-yellow'], L: ['Bajos', 'pill-green'], I: ['Info', 'pill-blue'] };
  document.getElementById('score-pills').innerHTML = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `<span class="score-pill ${sevMeta[s][1]}">${n} ${sevMeta[s][0]}</span>`).join('');

  // ── Recon grid (expanded with new modules) ──
  const exposedCount = Object.values(scanResults.paths).filter(v => v === 200).length;
  const m = scanResults.metrics || {};
  const tps = scanResults.thirdPartyStats || {};
  const dns = scanResults.dns || {};
  const subs = scanResults.subdomains || [];
  const waf = scanResults.waf || [];
  const ssl = scanResults.ssl || {};
  const ports = scanResults.ports || {};
  const vulnScan = scanResults.vulnScan || {};
  const wp = scanResults.wordpress || {};
  const reconData = [
    { label: 'URL analizada', val: url, cls: '' },
    { label: 'Modo', val: scanResults.backendUsed ? '🟢 Backend (análisis profundo)' : '🟡 Cliente (limitado)', cls: scanResults.backendUsed ? 'rc-green' : 'rc-yellow' },
    { label: 'HTTP Status', val: scanResults.recon.status || '—', cls: scanResults.recon.status === 200 ? 'rc-green' : 'rc-yellow' },
    { label: 'Tecnologías', val: scanResults.recon.tech || '—', cls: '' },
    { label: 'WAF/CDN', val: waf.length > 0 ? '🛡 ' + waf.join(', ') : 'No detectado', cls: waf.length > 0 ? 'rc-green' : 'rc-yellow' },
    { label: 'HTTPS', val: url.startsWith('https') ? 'Sí ✓' : 'No ✗', cls: url.startsWith('https') ? 'rc-green' : 'rc-red' },
    { label: 'Certificado SSL', val: ssl.available ? (ssl.subject || '—') + ' (' + (ssl.daysRemaining || '?') + 'd)' : (url.startsWith('https') ? 'Requiere backend' : 'N/A'), cls: ssl.daysRemaining > 30 ? 'rc-green' : ssl.daysRemaining > 0 ? 'rc-yellow' : ssl.available ? 'rc-red' : '' },
    { label: 'TLS', val: ssl.protocols ? ssl.protocols.join(', ') : (url.startsWith('https') ? 'Requiere backend' : 'N/A'), cls: ssl.protocols && !ssl.protocols.includes('TLSv1.0') ? 'rc-green' : 'rc-yellow' },
    { label: 'Rutas expuestas', val: exposedCount + ' detectadas', cls: exposedCount > 0 ? 'rc-red' : 'rc-green' },
    { label: 'Vuln Activas', val: vulnScan.available ? (vulnScan.totalVulnerabilities > 0 ? '🚨 ' + vulnScan.totalVulnerabilities + ' encontrada(s)' : '✓ 0 detectadas') : (scanResults.backendUsed ? '✓ 0' : 'Requiere backend'), cls: vulnScan.totalVulnerabilities > 0 ? 'rc-red' : vulnScan.available ? 'rc-green' : '' },
    { label: 'XSS/SQLi/LFI', val: vulnScan.available ? (vulnScan.xss || []).length + '/' + (vulnScan.sqli || []).length + '/' + (vulnScan.pathTraversal || []).length : '—', cls: ((vulnScan.xss || []).length + (vulnScan.sqli || []).length + (vulnScan.pathTraversal || []).length) > 0 ? 'rc-red' : vulnScan.available ? 'rc-green' : '' },
    { label: 'WordPress', val: wp.isWordPress ? '🔍 WP' + (wp.wpVersion ? ' v' + wp.wpVersion : '') : 'No detectado', cls: wp.isWordPress ? (wp.vulnerablePlugins && wp.vulnerablePlugins.length > 0 ? 'rc-red' : 'rc-yellow') : '' },
    { label: 'Plugins WP', val: wp.isWordPress ? wp.plugins.length + ' detectados' + (wp.vulnerablePlugins && wp.vulnerablePlugins.length > 0 ? ' (🚨' + wp.vulnerablePlugins.length + ' vuln)' : '') : '—', cls: wp.vulnerablePlugins && wp.vulnerablePlugins.length > 0 ? 'rc-red' : wp.isWordPress ? 'rc-green' : '' },
    { label: 'SPF', val: dns.spf ? '✓ Configurado' : '✗ Ausente', cls: dns.spf ? 'rc-green' : 'rc-red' },
    { label: 'DMARC', val: dns.dmarc ? '✓ Configurado' : '✗ Ausente', cls: dns.dmarc ? 'rc-green' : 'rc-red' },
    { label: 'DKIM', val: dns.dkim ? '✓ Selector: ' + dns.dkim : (scanResults.backendUsed ? '✗ No detectado' : '—'), cls: dns.dkim ? 'rc-green' : (scanResults.backendUsed ? 'rc-yellow' : '') },
    { label: 'DNSSEC', val: dns.dnssec ? '✓ Activo' : '✗ Inactivo', cls: dns.dnssec ? 'rc-green' : 'rc-yellow' },
    { label: 'Subdominios', val: subs.length + ' encontrados', cls: subs.length > 5 ? 'rc-yellow' : '' },
    { label: 'Puertos abiertos', val: ports.available ? (ports.openPorts ? ports.openPorts.length : 0) + ' / ' + (ports.totalScanned || '?') : 'Requiere backend', cls: ports.openPorts && ports.openPorts.length > 5 ? 'rc-red' : ports.available ? 'rc-green' : '' },
    { label: 'SRI Coverage', val: tps.external > 0 ? Math.round((tps.withSRI / tps.external) * 100) + '%' : 'N/A', cls: tps.withoutSRI > 0 ? 'rc-red' : 'rc-green' },
    { label: 'Puntuación', val: score + '/100', cls: score < 40 ? 'rc-red' : score < 70 ? 'rc-yellow' : 'rc-green' },
  ];

  document.getElementById('recon-grid').innerHTML = reconData
    .map(r => `<div class="recon-card"><div class="rc-label">${r.label}</div><div class="rc-val ${r.cls}">${escHtml(String(r.val))}</div></div>`).join('');

  // ── Headers grid ──
  document.getElementById('headers-grid').innerHTML = SEC_HEADERS.map(hdr => {
    const val = headers[hdr.h];
    const ok = hdr.good(val);
    const cls = ok ? 'rc-green' : 'rc-red';
    const isExposed = hdr.h.includes('powered') || hdr.h.includes('server') || hdr.h.includes('aspnet');
    const display = isExposed
      ? (val ? ' ' + val.substring(0, 30) : '✓ Oculto')
      : (val ? '✓ ' + val.substring(0, 30) : '✗ Ausente');
    return `<div class="recon-card"><div class="rc-label">${hdr.label}</div><div class="rc-val ${cls}">${escHtml(display)}</div></div>`;
  }).join('');

  // ── Findings ──
  const fl = document.getElementById('findings-list');
  if (findings.length === 0) {
    fl.innerHTML = '<div style="padding:24px;text-align:center;color:var(--green);font-size:.85rem;">✓ No se encontraron hallazgos significativos. ¡Excelente!</div>';
  } else {
    const sevLabel = { C: 'Crítico', H: 'Alto', M: 'Medio', L: 'Bajo', I: 'Info' };
    fl.innerHTML = findings.map((f, i) => {
      const promptText = generateAIPrompt(f, url);
      return `
      <div class="finding" id="finding-${i}">
        <div class="finding-hd" onclick="toggleFinding(${i})">
          <span class="sev sev-${f.sev}">${sevLabel[f.sev]}</span>
          <span class="finding-title">${escHtml(f.title)}</span>
          <span class="finding-chevron">▶</span>
        </div>
        <div class="finding-body">
          <p>${f.desc}</p>
          ${f.code ? `<div class="code-snip">${escHtml(f.code)}</div>` : ''}
          <div class="fix-card"><h5>✓ Corrección recomendada</h5><p>${escHtml(f.fix)}</p></div>
          <div class="ai-prompt-card">
            <div class="ai-prompt-hd">
              <h5>Prompt para IA</h5>
              <button class="copy-prompt-btn" onclick="event.stopPropagation(); copyPrompt(this, ${i})">⎘ Copiar prompt</button>
            </div>
            <pre class="ai-prompt-text">${escHtml(promptText)}</pre>
          </div>
        </div>
      </div>
    `}).join('');
  }

  // ── Checklist ──
  const sevPriority = { C: '🔴 Crítico', H: '🟠 Alto', M: '🟡 Medio', L: '🟢 Bajo', I: '🔵 Info' };
  const checkItems = findings.map((f, i) => ({ id: 'cl-' + i, text: f.title, sev: sevPriority[f.sev], fix: f.fix }));
  scanResults.checklist = checkItems;
  document.getElementById('cl-total').textContent = checkItems.length;

  document.getElementById('checklist').innerHTML = checkItems.map(item => `
    <div class="check-item" id="${item.id}" onclick="toggleCheck('${item.id}')">
      <div class="check-box" id="${item.id}-box"></div>
      <div class="check-content">
        <span class="check-text">${escHtml(item.text)}</span>
        <span class="check-meta"><span class="check-sev">${item.sev}</span> ${escHtml(item.fix.substring(0, 80))}${item.fix.length > 80 ? '…' : ''}</span>
      </div>
    </div>
  `).join('');

  updateChecklistProgress();

  // ── Render history ──
  renderHistory();

  document.getElementById('report-section').scrollIntoView({ behavior: 'smooth' });
}

// ── RENDER HISTORY WITH TREND CHART ──
function renderHistory() {
  const container = document.getElementById('history-section');
  if (!container) return;
  const history = getReportHistory();
  if (history.length <= 1) { container.style.display = 'none'; return; }
  container.style.display = 'block';

  container.innerHTML = `
    <div class="sec-hdr">Historial y Tendencias</div>
    <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:12px;padding:20px;margin-bottom:20px;">
      <canvas id="trend-chart" width="800" height="200" style="width:100%;height:200px;"></canvas>
    </div>
    <div class="recon-grid">
      ${history.slice(0, 10).map((h, i) => `
        <div class="recon-card${i === 0 ? ' latest' : ''}">
          <div class="rc-label">${escHtml(h.dateStr)}</div>
          <div class="rc-val ${h.score < 40 ? 'rc-red' : h.score < 70 ? 'rc-yellow' : 'rc-green'}">${h.score}/100</div>
          <div style="font-size:.65rem;color:var(--muted);margin-top:6px;font-family:var(--font-mono)">
            ${escHtml(h.url.replace(/https?:\/\//, ''))}<br>
            ${h.total} hallazgo${h.total !== 1 ? 's' : ''}
          </div>
        </div>
      `).join('')}
    </div>
  `;

  // Draw trend chart
  requestAnimationFrame(() => drawTrendChart(history));
}

function drawTrendChart(history) {
  const canvas = document.getElementById('trend-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;

  canvas.width = canvas.offsetWidth * dpr;
  canvas.height = 200 * dpr;
  ctx.scale(dpr, dpr);

  const W = canvas.offsetWidth;
  const H = 200;
  const padL = 40, padR = 20, padT = 20, padB = 30;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;

  // Background zones
  const zones = [
    { y1: 0, y2: 40, color: 'rgba(255, 60, 90, 0.06)' },   // red zone (0-40)
    { y1: 40, y2: 70, color: 'rgba(245, 200, 66, 0.06)' },  // yellow zone (40-70)
    { y1: 70, y2: 100, color: 'rgba(45, 224, 138, 0.06)' },  // green zone (70-100)
  ];

  for (const z of zones) {
    const top = padT + chartH * (1 - z.y2 / 100);
    const bot = padT + chartH * (1 - z.y1 / 100);
    ctx.fillStyle = z.color;
    ctx.fillRect(padL, top, chartW, bot - top);
  }

  // Grid lines
  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth = 1;
  for (let v = 0; v <= 100; v += 20) {
    const y = padT + chartH * (1 - v / 100);
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillStyle = 'rgba(255,255,255,0.3)';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(v, padL - 6, y + 3);
  }

  // Threshold lines
  const thresholds = [
    { val: 40, color: 'rgba(255, 60, 90, 0.3)' },
    { val: 70, color: 'rgba(245, 200, 66, 0.3)' },
  ];
  for (const t of thresholds) {
    const y = padT + chartH * (1 - t.val / 100);
    ctx.strokeStyle = t.color;
    ctx.setLineDash([4, 4]);
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.setLineDash([]);
  }

  // Data points (reversed so oldest is left)
  const data = history.slice(0, 15).reverse();
  if (data.length < 2) return;

  const points = data.map((d, i) => ({
    x: padL + (i / (data.length - 1)) * chartW,
    y: padT + chartH * (1 - d.score / 100),
    score: d.score,
    label: d.dateStr || ''
  }));

  // Draw line
  ctx.strokeStyle = 'rgba(255,255,255,0.8)';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.beginPath();
  ctx.moveTo(points[0].x, points[0].y);
  for (let i = 1; i < points.length; i++) {
    ctx.lineTo(points[i].x, points[i].y);
  }
  ctx.stroke();

  // Gradient fill under line
  const gradient = ctx.createLinearGradient(0, padT, 0, H - padB);
  gradient.addColorStop(0, 'rgba(45, 224, 138, 0.15)');
  gradient.addColorStop(1, 'rgba(45, 224, 138, 0)');
  ctx.fillStyle = gradient;
  ctx.beginPath();
  ctx.moveTo(points[0].x, H - padB);
  ctx.lineTo(points[0].x, points[0].y);
  for (let i = 1; i < points.length; i++) ctx.lineTo(points[i].x, points[i].y);
  ctx.lineTo(points[points.length - 1].x, H - padB);
  ctx.closePath();
  ctx.fill();

  // Draw points
  for (const p of points) {
    const col = p.score < 40 ? '#ff3c5a' : p.score < 70 ? '#f5c842' : '#2de08a';
    ctx.beginPath();
    ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
    ctx.fillStyle = col;
    ctx.fill();
    ctx.strokeStyle = 'rgba(0,0,0,0.5)';
    ctx.lineWidth = 1;
    ctx.stroke();

    // Score label above point
    ctx.fillStyle = col;
    ctx.font = 'bold 10px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(p.score, p.x, p.y - 8);
  }

  // X labels (dates)
  ctx.fillStyle = 'rgba(255,255,255,0.3)';
  ctx.font = '9px sans-serif';
  ctx.textAlign = 'center';
  const showEvery = Math.max(1, Math.floor(points.length / 6));
  for (let i = 0; i < points.length; i += showEvery) {
    const short = points[i].label.split(',')[0] || '';
    ctx.fillText(short, points[i].x, H - 8);
  }
}


//  INTERACCIONES UI

function toggleFinding(i) { document.getElementById('finding-' + i).classList.toggle('open'); }

function toggleCheck(id) {
  checkState[id] = !checkState[id];
  const item = document.getElementById(id);
  const box = document.getElementById(id + '-box');
  if (checkState[id]) { item.classList.add('done'); box.textContent = '✓'; }
  else { item.classList.remove('done'); box.textContent = ''; }
  updateChecklistProgress();
}

function updateChecklistProgress() {
  const total = scanResults.checklist?.length || 0;
  const done = Object.values(checkState).filter(Boolean).length;
  document.getElementById('cl-done').textContent = done;
  document.getElementById('cl-total').textContent = total;
  document.getElementById('cl-fill').style.width = total ? Math.round((done / total) * 100) + '%' : '0%';
}

function resetScan() {
  checkState = {}; scanResults = {};
  ['sem-red', 'sem-yellow', 'sem-green'].forEach(id => document.getElementById(id).classList.remove('on'));
  const scoreEl = document.getElementById('score-num');
  scoreEl.style.cssText = '';
  scoreEl.textContent = '--';
  document.getElementById('report-section').style.display = 'none';
  document.getElementById('progress-section').style.display = 'none';
  document.getElementById('hero-section').style.display = 'flex';
  document.getElementById('url-input').value = '';
  document.getElementById('scan-btn').disabled = false;

  // Restore elements that might have been hidden by SAST local scan
  const headersHeader = [...document.querySelectorAll('.sec-hdr')].find(el => el.textContent.includes('Cabeceras HTTP'));
  if (headersHeader) headersHeader.style.display = '';
  const headersGrid = document.getElementById('headers-grid');
  if (headersGrid) headersGrid.style.display = '';

  window.scrollTo({ top: 0, behavior: 'smooth' });
}


//  EXPORTAR PDF

async function exportPDF() {
  const btn = document.querySelector('.export-btn');
  btn.textContent = '⏳ Generando...'; btn.disabled = true;
  try {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: 'p', unit: 'mm', format: 'a4' });
    const url = scanResults.url || 'Unknown';
    const W = 210, margin = 18;

    const COL = {
      dark: [10, 10, 10], surface: [20, 20, 20], accent: [255, 255, 255],
      green: [45, 224, 138], yellow: [245, 200, 66], red: [255, 60, 90],
      white: [255, 255, 255], muted: [120, 120, 120], text: [200, 200, 200],
      orange: [255, 123, 44], blue: [160, 160, 160]
    };
    const SEV_COLORS = { C: COL.red, H: COL.orange, M: COL.yellow, L: COL.green, I: COL.blue };
    const SEV_LABELS = { C: 'CRITICO', H: 'ALTO', M: 'MEDIO', L: 'BAJO', I: 'INFO' };
    // Sanitize text for PDF (remove chars jsPDF can't render)
    function pdfSafe(str) { return String(str).replace(/[^\x00-\x7F]/g, c => ({ 'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u', 'ñ': 'n', 'Á': 'A', 'É': 'E', 'Í': 'I', 'Ó': 'O', 'Ú': 'U', 'Ñ': 'N', '—': '-', '–': '-', '‘': "'", '’': "'", '“': '"', '”': '"', '…': '...', '✓': '>', '▸': '>', '→': '->', '←': '<-', '•': '-', '×': 'x', '·': '.', '«': '<<', '»': '>>', '≥': '>=', '≤': '<=', '©': '(c)', '®': '(R)' }[c] || '')); }

    let y = 0;
    function newPage() { doc.addPage(); doc.setFillColor(...COL.dark); doc.rect(0, 0, W, 297, 'F'); y = margin; }
    function checkY(n = 20) { if (y + n > 280) newPage(); }

    // Portada
    doc.setFillColor(...COL.dark); doc.rect(0, 0, W, 297, 'F');
    doc.setFillColor(...COL.accent); doc.rect(0, 0, W, 2, 'F');

    y = 20;
    doc.setFont('helvetica', 'bold'); doc.setFontSize(36);
    doc.setTextColor(...COL.white); doc.text('WEBSEC', margin, y);
    doc.setTextColor(...COL.muted); doc.text('AUDIT', margin + 60, y);

    y += 8; doc.setFontSize(9); doc.setTextColor(...COL.muted);
    doc.setFont('helvetica', 'normal'); doc.text('// INFORME DE SEGURIDAD WEB v4.0 - 20 modulos de analisis', margin, y);
    y += 8; doc.setFontSize(8);
    doc.text('Target: ' + url, margin, y); y += 5;
    doc.text('Fecha: ' + new Date().toLocaleString('es-MX'), margin, y);

    // Score box
    y += 12;
    const findings = scanResults.findings || [];
    const counts = { C: 0, H: 0, M: 0, L: 0, I: 0 };
    findings.forEach(f => counts[f.sev]++);
    // Fórmula mejorada: penaliza pero nunca llega a 0 para que sea visible
    let score = 100 - (counts.C * 15) - (counts.H * 8) - (counts.M * 3) - (counts.L * 1);
    score = Math.max(5, Math.min(100, Math.round(score))); // Mínimo 5 para que sea visible

    doc.setFillColor(...COL.surface); doc.roundedRect(margin, y, W - margin * 2, 32, 3, 3, 'F');
    const scoreColor = score < 40 ? COL.red : score < 70 ? COL.yellow : COL.green;
    doc.setFont('helvetica', 'bold'); doc.setFontSize(28);
    doc.setTextColor(...scoreColor); doc.text(String(score), margin + 8, y + 21);
    doc.setFontSize(11); doc.setTextColor(...COL.white);
    doc.text(score < 40 ? 'RIESGO ALTO' : score < 70 ? 'RIESGO MEDIO' : 'SEGURIDAD ROBUSTA', margin + 30, y + 14);
    doc.setFontSize(7); doc.setFont('helvetica', 'normal');
    let px = margin + 30;
    for (const [s, lbl] of [['C', 'Criticos'], ['H', 'Altos'], ['M', 'Medios'], ['L', 'Bajos'], ['I', 'Info']]) {
      doc.setTextColor(...SEV_COLORS[s]); doc.setFont('helvetica', 'bold');
      doc.text(counts[s] + ' ' + lbl, px, y + 24); px += 28;
    }

    // Módulos analizados
    y += 40;
    doc.setDrawColor(...COL.surface); doc.setLineWidth(.5); doc.line(margin, y, W - margin, y); y += 8;
    doc.setFont('courier', 'bold'); doc.setFontSize(7);
    doc.setTextColor(...COL.muted); doc.text('// 23 MODULOS ANALIZADOS', margin, y); y += 6;
    const modules = ['Backend detect', 'Conexion HTTP', 'Tecnologias', 'Cabeceras', 'Cookies', 'HTTPS/TLS', 'SSL Certificado', 'Rutas expuestas', 'WAF/CDN', 'Codigo HTML', 'robots.txt', 'sec.txt/sitemap', 'Secretos', 'Libs CVEs ext', 'Scripts & SRI', 'DOM XSS', 'CORS/Perf', 'DNS Security', 'Subdominios', 'Port Scanner', 'Vuln Activas', 'WP & Plugins', 'Reporte PDF'];
    doc.setFont('helvetica', 'normal'); doc.setFontSize(5.5);
    doc.setTextColor(...COL.text);
    const modText = modules.map((m, i) => `${String(i + 1).padStart(2, '0')}. ${m}`);
    const modLine1 = modText.slice(0, 8).join(' | ');
    const modLine2 = modText.slice(8, 16).join(' | ');
    const modLine3 = modText.slice(16).join(' | ');
    doc.text(modLine1, margin, y); y += 4;
    doc.text(modLine2, margin, y); y += 4;
    doc.text(modLine3, margin, y);
    y += 8;

    // Recon
    doc.setDrawColor(...COL.surface); doc.line(margin, y, W - margin, y); y += 8;
    doc.setFont('courier', 'bold'); doc.setFontSize(7);
    doc.setTextColor(...COL.muted); doc.text('// RECONOCIMIENTO', margin, y); y += 6;
    const dnsD = scanResults.dns || {};
    const reconRows = [
      ['URL', url], ['HTTP Status', String(scanResults.recon.status || '-')],
      ['Tecnologias', scanResults.recon.tech || '-'], ['Server', scanResults.recon.server || '-'],
      ['SPF', dnsD.spf ? 'Configurado' : 'AUSENTE'],
      ['DMARC', dnsD.dmarc ? 'Configurado' : 'AUSENTE'],
      ['DNSSEC', dnsD.dnssec ? 'Activo' : 'Inactivo'],
      ['Subdominios', String((scanResults.subdomains || []).length) + ' encontrados'],
    ];
    doc.setFont('helvetica', 'normal'); doc.setFontSize(7.5);
    for (const [k, v] of reconRows) {
      checkY(8); doc.setTextColor(...COL.muted); doc.text(k + ':', margin, y);
      doc.setTextColor(...COL.text); doc.text(pdfSafe(v).substring(0, 70), margin + 35, y); y += 6;
    }

    // Findings
    y += 6; doc.setDrawColor(...COL.surface); doc.line(margin, y, W - margin, y); y += 8;
    doc.setFont('courier', 'bold'); doc.setFontSize(7);
    doc.setTextColor(...COL.muted); doc.text('// HALLAZGOS (' + findings.length + ')', margin, y); y += 8;

    for (const f of findings) {
      checkY(32);
      const col = SEV_COLORS[f.sev] || COL.muted;
      doc.setFillColor(...col); doc.roundedRect(margin, y - 4, 20, 6, 1, 1, 'F');
      doc.setFont('helvetica', 'bold'); doc.setFontSize(6);
      doc.setTextColor(...COL.dark); doc.text(SEV_LABELS[f.sev], margin + 1.5, y + 0.5);
      doc.setFontSize(8); doc.setTextColor(...COL.white);
      const tl = doc.splitTextToSize(pdfSafe(f.title), W - margin * 2 - 26);
      doc.text(tl, margin + 24, y + 0.5); y += Math.max(8, tl.length * 4.5);
      doc.setFont('helvetica', 'normal'); doc.setFontSize(7); doc.setTextColor(...COL.muted);
      const dt = pdfSafe(f.desc.replace(/<[^>]+>/g, ''));
      const dl = doc.splitTextToSize(dt, W - margin * 2 - 4); checkY(dl.length * 4 + 10);
      doc.text(dl, margin + 2, y); y += dl.length * 4 + 3;
      // Fix box - use helvetica (not courier) to avoid encoding issues
      doc.setFillColor(15, 25, 15);
      const fixText = pdfSafe('> ' + f.fix);
      const fl2 = doc.splitTextToSize(fixText, W - margin * 2 - 8);
      doc.roundedRect(margin + 2, y - 2, W - margin * 2 - 4, fl2.length * 4 + 4, 1, 1, 'F');
      doc.setTextColor(...COL.green); doc.setFont('helvetica', 'normal'); doc.setFontSize(6.5);
      doc.text(fl2, margin + 5, y + 2); y += fl2.length * 4 + 6;
      // Evidence code block
      if (f.code) {
        checkY(12);
        doc.setFillColor(18, 18, 18);
        const codeText = pdfSafe(f.code);
        const cl = doc.splitTextToSize(codeText, W - margin * 2 - 12);
        doc.roundedRect(margin + 2, y - 2, W - margin * 2 - 4, cl.length * 3.5 + 4, 1, 1, 'F');
        doc.setTextColor(160, 160, 160); doc.setFont('courier', 'normal'); doc.setFontSize(5.5);
        doc.text(cl, margin + 5, y + 1.5); y += cl.length * 3.5 + 6;
      }
      doc.setDrawColor(25, 25, 25); doc.line(margin, y - 2, W - margin, y - 2); y += 4;
    }

    // Footer
    const pc = doc.getNumberOfPages();
    for (let i = 1; i <= pc; i++) {
      doc.setPage(i); doc.setFillColor(...COL.accent); doc.rect(0, 295, W, 2, 'F');
      doc.setFont('helvetica', 'normal'); doc.setFontSize(6); doc.setTextColor(...COL.muted);
      doc.text('WEBSEC AUDIT v5.0 - ' + url + ' - Pag. ' + i + '/' + pc, margin, 294);
    }

    doc.save('websec-audit-' + url.replace(/https?:\/\//, '').replace(/\//g, '-') + '.pdf');
  } catch (e) { console.error(e); alert('Error: ' + e.message); }
  btn.textContent = '⬇ Exportar PDF'; btn.disabled = false;
}


//  EVENTOS

document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});
