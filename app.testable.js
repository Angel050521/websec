
'use strict';

// ─── Utility Functions ───
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function sevOrder(s) { return { C: 0, H: 1, M: 2, L: 3, I: 4 }[s] ?? 5; }
function escHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── AI Prompt Generator ───
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

// ─── Technology Detection ───
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

// ─── HTML Analysis ───
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

// ─── Cookie Analysis ───
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

// ─── Third-Party Scripts Analysis ───
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

        try {
            const scriptUrl = new URL(src, baseUrl);
            if (scriptUrl.hostname === hostname || scriptUrl.hostname === 'localhost') {
                internal++;
            } else {
                external++;
                externalDomains.add(scriptUrl.hostname);
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

// ─── DOM XSS Sinks Analysis ───
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

// ─── Performance & Security Analysis ───
function analyzePerformanceSecurity(html, headers) {
    const findings = [];
    if (!html) return { findings, metrics: {} };

    const scripts = (html.match(/<script/gi) || []).length;
    const styles = (html.match(/<link[^>]*stylesheet/gi) || []).length + (html.match(/<style/gi) || []).length;
    const images = (html.match(/<img/gi) || []).length;
    const iframes = (html.match(/<iframe/gi) || []).length;
    const forms = (html.match(/<form/gi) || []).length;
    const inputs = (html.match(/<input/gi) || []).length;
    const htmlSize = Buffer.byteLength(html, 'utf8');

    if (htmlSize > 500000) {
        findings.push({
            sev: 'L', title: `HTML excesivamente grande (${(htmlSize / 1024).toFixed(0)} KB)`,
            desc: 'Un HTML muy grande aumenta los tiempos de carga y la superficie de ataque para análisis de código.',
            code: `Tamaño del HTML: ${(htmlSize / 1024).toFixed(1)} KB`,
            fix: 'Optimiza el HTML. Usa lazy loading, code splitting y compresión gzip/brotli.'
        });
    }

    const cacheControl = headers['cache-control'] || '';
    if (!cacheControl) {
        findings.push({
            sev: 'L', title: 'Sin cabecera Cache-Control',
            desc: 'Sin Cache-Control, los proxies intermedios pueden cachear contenido sensible.',
            code: 'Cache-Control: [AUSENTE]',
            fix: 'Agrega Cache-Control: no-store, private para páginas con datos sensibles.'
        });
    }

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

// ─── Open Graph Analysis ───
function analyzeOpenGraph(html) {
    const findings = [];
    if (!html) return findings;

    const ogTags = html.match(/<meta[^>]*property=["']og:[^"']*["'][^>]*>/gi) || [];

    for (const tag of ogTags) {
        if (/localhost|127\.0\.0\.1|192\.168\.|10\.\d+\.\d+\.\d+/.test(tag)) {
            findings.push({
                sev: 'H', title: 'Open Graph meta tag expone URL interna',
                desc: 'Las etiquetas Open Graph contienen URLs internas (localhost/IP privada) que se comparten en redes sociales.',
                code: tag.substring(0, 80), fix: 'Configura las URLs de OG con el dominio público correcto.'
            });
        }
    }

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

// ─── WAF Detection ───
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
        for (const h of sig.headers) {
            if (headers[h]) { isDetected = true; break; }
        }
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

// ─── Secrets Detection ───
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

// ─── Outdated Libraries Detection ───
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

// ─── Text Similarity (Soft 404) ───
function calcSimilarity(str1, str2) {
    if (!str1 || !str2) return 0;
    const s1 = str1.replace(/\s+/g, ' ').trim();
    const s2 = str2.replace(/\s+/g, ' ').trim();
    if (s1 === s2) return 1;
    const longer = s1.length > s2.length ? s1 : s2;
    const shorter = s1.length > s2.length ? s2 : s1;
    if (longer.length === 0) return 1;
    const bigrams1 = new Set();
    for (let i = 0; i < shorter.length - 1; i++) bigrams1.add(shorter.substr(i, 2));
    let matches = 0;
    for (let i = 0; i < longer.length - 1; i++) {
        if (bigrams1.has(longer.substr(i, 2))) matches++;
    }
    return (2 * matches) / (shorter.length + longer.length - 2);
}

// ─── Security Headers Data ───
const SEC_HEADERS = [
    { h: 'x-frame-options', label: 'X-Frame-Options', good: v => !!v, sev: 'H', fix: 'Agrega X-Frame-Options: DENY o SAMEORIGIN para prevenir clickjacking.' },
    { h: 'content-security-policy', label: 'Content-Security-Policy', good: v => !!v, sev: 'H', fix: 'Define directivas CSP para restringir qué recursos puede cargar la página.' },
    { h: 'strict-transport-security', label: 'HSTS', good: v => !!v, sev: 'H', fix: 'Agrega Strict-Transport-Security: max-age=31536000; includeSubDomains' },
    { h: 'x-content-type-options', label: 'X-Content-Type-Options', good: v => v === 'nosniff', sev: 'M', fix: 'Agrega X-Content-Type-Options: nosniff para evitar MIME sniffing.' },
    { h: 'referrer-policy', label: 'Referrer-Policy', good: v => !!v, sev: 'M', fix: 'Usa Referrer-Policy: strict-origin-when-cross-origin.' },
    { h: 'permissions-policy', label: 'Permissions-Policy', good: v => !!v, sev: 'M', fix: 'Define una Permissions-Policy para controlar APIs del navegador.' },
    { h: 'cross-origin-opener-policy', label: 'Cross-Origin-Opener-Policy', good: v => !!v, sev: 'M', fix: 'Agrega Cross-Origin-Opener-Policy: same-origin para aislar el contexto del navegador.' },
    { h: 'cross-origin-resource-policy', label: 'Cross-Origin-Resource-Policy', good: v => !!v, sev: 'L', fix: 'Agrega Cross-Origin-Resource-Policy: same-origin para evitar carga cross-origin no autorizada.' },
    { h: 'cross-origin-embedder-policy', label: 'Cross-Origin-Embedder-Policy', good: v => !!v, sev: 'L', fix: 'Agrega Cross-Origin-Embedder-Policy: require-corp para mayor aislamiento.' },
    { h: 'x-xss-protection', label: 'X-XSS-Protection', good: v => !!v, sev: 'L', fix: 'Agrega X-XSS-Protection: 1; mode=block (legacy, pero útil en navegadores antiguos).' },
    { h: 'x-powered-by', label: 'X-Powered-By (expuesto)', good: v => !v, sev: 'L', fix: 'Elimina la cabecera X-Powered-By para no revelar el stack tecnológico.' },
    { h: 'server', label: 'Server header (expuesto)', good: v => !v, sev: 'L', fix: 'Elimina o anonimiza la cabecera Server para ocultar la versión del servidor.' },
    { h: 'x-aspnet-version', label: 'X-AspNet-Version (expuesto)', good: v => !v, sev: 'L', fix: 'Elimina X-AspNet-Version para no revelar la versión de ASP.NET.' },
];

// ─── Sensitive Paths Data ───
const SENSITIVE_PATHS = [
    { p: '/.env', label: '.env expuesto', sev: 'C' },
    { p: '/.env.backup', label: '.env backup', sev: 'C' },
    { p: '/.git/HEAD', label: 'Repo Git expuesto', sev: 'C' },
    { p: '/backup.sql', label: 'backup.sql', sev: 'C' },
    { p: '/phpmyadmin/', label: 'phpMyAdmin', sev: 'C' },
    { p: '/wp-admin/', label: 'Panel WordPress', sev: 'H' },
    { p: '/admin', label: 'Panel /admin', sev: 'H' },
    { p: '/config.json', label: 'config.json', sev: 'H' },
    { p: '/api/', label: 'API root', sev: 'M' },
    { p: '/package.json', label: 'package.json', sev: 'M' },
    { p: '/composer.json', label: 'composer.json', sev: 'L' },
    { p: '/robots.txt', label: 'robots.txt', sev: 'I' },
];

module.exports = {
    // Utilities
    sleep,
    sevOrder,
    escHtml,
    calcSimilarity,
    generateAIPrompt,
    // Analysis Functions
    detectTech,
    analyzeHTML,
    analyzeCookies,
    analyzeThirdPartyScripts,
    analyzeDOMSinks,
    analyzePerformanceSecurity,
    analyzeOpenGraph,
    detectWAF,
    analyzeSecrets,
    analyzeOutdatedLibs,
    // Data
    SEC_HEADERS,
    SENSITIVE_PATHS,
};
