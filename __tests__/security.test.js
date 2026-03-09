
'use strict';

const {
    detectWAF,
    analyzeDOMSinks,
    analyzeSecrets,
    analyzeOutdatedLibs,
    analyzeOpenGraph,
    analyzeThirdPartyScripts,
    analyzePerformanceSecurity,
} = require('../app.testable');


describe('detectWAF', () => {
    test('detecta Cloudflare por cf-ray', () => {
        const { findings, detected } = detectWAF({ 'cf-ray': '12345-LAX' });
        expect(detected).toContain('Cloudflare');
        expect(findings[0].sev).toBe('I');
    });

    test('detecta Cloudflare por server header', () => {
        const { detected } = detectWAF({ 'server': 'cloudflare' });
        expect(detected).toContain('Cloudflare');
    });

    test('detecta Vercel por x-vercel-id', () => {
        const { detected } = detectWAF({ 'x-vercel-id': 'iad1::12345' });
        expect(detected).toContain('Vercel');
    });

    test('detecta Netlify por x-nf-request-id', () => {
        const { detected } = detectWAF({ 'x-nf-request-id': 'abc123' });
        expect(detected).toContain('Netlify');
    });

    test('detecta AWS CloudFront por x-amz-cf-id', () => {
        const { detected } = detectWAF({ 'x-amz-cf-id': 'abc123' });
        expect(detected).toContain('AWS CloudFront');
    });

    test('detecta Akamai por header', () => {
        const { detected } = detectWAF({ 'x-akamai-transformed': 'true' });
        expect(detected).toContain('Akamai');
    });

    test('detecta Sucuri por x-sucuri-id', () => {
        const { detected } = detectWAF({ 'x-sucuri-id': '12345' });
        expect(detected).toContain('Sucuri');
    });

    test('detecta Varnish por x-varnish', () => {
        const { detected } = detectWAF({ 'x-varnish': '12345' });
        expect(detected).toContain('Varnish');
    });

    test('detecta DDoS-Guard por server header', () => {
        const { detected } = detectWAF({ 'server': 'DDoS-Guard' });
        expect(detected).toContain('DDoS-Guard');
    });

    test('detecta Fastly por x-fastly-request-id', () => {
        const { detected } = detectWAF({ 'x-fastly-request-id': 'abc' });
        expect(detected).toContain('Fastly');
    });

    test('detecta Imperva por x-iinfo', () => {
        const { detected } = detectWAF({ 'x-iinfo': 'some-info' });
        expect(detected).toContain('Imperva (Incapsula)');
    });

    test('detecta múltiples WAFs/CDNs', () => {
        const { detected } = detectWAF({
            'cf-ray': '12345',
            'x-varnish': '67890'
        });
        expect(detected).toContain('Cloudflare');
        expect(detected).toContain('Varnish');
        expect(detected.length).toBeGreaterThanOrEqual(2);
    });

    test('reporta severidad M cuando no se detecta WAF', () => {
        const { findings, detected } = detectWAF({});
        expect(detected).toHaveLength(0);
        expect(findings[0].sev).toBe('M');
        expect(findings[0].title).toContain('No se detectó WAF');
    });

    test('detecta WAF por header via', () => {
        const { detected } = detectWAF({ 'via': '1.1 varnish (Varnish/6.0)' });
        expect(detected).toContain('Varnish');
    });
});


describe('analyzeDOMSinks', () => {
    test('retorna array vacío para HTML vacío', () => {
        expect(analyzeDOMSinks('')).toEqual([]);
        expect(analyzeDOMSinks(null)).toEqual([]);
    });

    test('detecta eval() como alto riesgo', () => {
        const html = '<script>eval(userInput);</script>';
        const findings = analyzeDOMSinks(html);
        const f = findings.find(f => f.sev === 'H');
        expect(f).toBeDefined();
        expect(f.code).toContain('eval()');
    });

    test('detecta document.write como alto riesgo', () => {
        const html = '<script>document.write(data);</script>';
        const findings = analyzeDOMSinks(html);
        const f = findings.find(f => f.sev === 'H');
        expect(f).toBeDefined();
        expect(f.code).toContain('document.write');
    });

    test('detecta innerHTML como riesgo medio', () => {
        const html = '<script>el.innerHTML = data;</script>';
        const findings = analyzeDOMSinks(html);
        const f = findings.find(f => f.sev === 'M');
        expect(f).toBeDefined();
        expect(f.code).toContain('innerHTML');
    });

    test('detecta new Function() como alto riesgo', () => {
        const html = '<script>var fn = new Function("return x");</script>';
        const findings = analyzeDOMSinks(html);
        const f = findings.find(f => f.sev === 'H');
        expect(f).toBeDefined();
        expect(f.code).toContain('new Function()');
    });

    test('detecta insertAdjacentHTML como riesgo medio', () => {
        const html = '<script>el.insertAdjacentHTML("beforeend", data);</script>';
        const findings = analyzeDOMSinks(html);
        const f = findings.find(f => f.sev === 'M');
        expect(f).toBeDefined();
        expect(f.code).toContain('insertAdjacentHTML');
    });

    test('detecta múltiples sinks simultaneamente', () => {
        const html = '<script>eval(x); document.write(y); el.innerHTML = z;</script>';
        const findings = analyzeDOMSinks(html);
        expect(findings.length).toBeGreaterThanOrEqual(2);
    });

    test('no reporta HTML seguro', () => {
        const html = '<script>const x = 1; console.log(x);</script>';
        const findings = analyzeDOMSinks(html);
        expect(findings).toHaveLength(0);
    });

    test('cuenta correctamente múltiples ocurrencias', () => {
        const html = '<script>eval(a); eval(b); eval(c);</script>';
        const findings = analyzeDOMSinks(html);
        const f = findings.find(f => f.sev === 'H');
        expect(f).toBeDefined();
        expect(f.code).toContain('×3');
    });
});


describe('analyzeSecrets', () => {
    test('retorna array vacío para HTML vacío', () => {
        expect(analyzeSecrets('')).toEqual([]);
        expect(analyzeSecrets(null)).toEqual([]);
    });

    test('detecta AWS Access Key', () => {
        const html = 'var key = "AKIAIOSFODNN7EXAMPLE";';
        const findings = analyzeSecrets(html);
        const f = findings.find(f => f.title.includes('AWS Access Key'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('C');
    });

    test('detecta Stripe Secret Key', () => {
        const html = 'var key = "sk_mock_abcdefghijklmnopqrstuvwx";';
        const findings = analyzeSecrets(html);
        const f = findings.find(f => f.title.includes('Stripe Secret Key'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('C');
    });

    test('detecta GitHub Token', () => {
        const html = 'var token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";';
        const findings = analyzeSecrets(html);
        const f = findings.find(f => f.title.includes('GitHub Token'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('C');
    });

    test('detecta Private Key', () => {
        const html = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...';
        const findings = analyzeSecrets(html);
        const f = findings.find(f => f.title.includes('Private Key'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('C');
    });

    test('detecta JWT Token', () => {
        const html = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        const findings = analyzeSecrets(html);
        const f = findings.find(f => f.title.includes('JWT Token'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('H');
    });

    test('detecta hardcoded password', () => {
        const html = 'password = "SuperSecret123!"';
        const findings = analyzeSecrets(html);
        const f = findings.find(f => f.title.includes('Hardcoded Password'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('H');
    });

    test('redacta los secretos en el output', () => {
        const html = 'var key = "AKIAIOSFODNN7EXAMPLE";';
        const findings = analyzeSecrets(html);
        const f = findings.find(f => f.title.includes('AWS'));
        expect(f.code).toContain('[REDACTED]');
    });

    test('no reporta HTML limpio', () => {
        const html = '<html><body><p>Hello World</p></body></html>';
        const findings = analyzeSecrets(html);
        expect(findings).toHaveLength(0);
    });
});


describe('analyzeOutdatedLibs', () => {
    test('retorna array vacío para HTML vacío', () => {
        expect(analyzeOutdatedLibs('')).toEqual([]);
        expect(analyzeOutdatedLibs(null)).toEqual([]);
    });

    test('detecta jQuery 1.x como vulnerable', () => {
        const html = '<script src="jquery/1.12.4/jquery.min.js"></script>';
        const findings = analyzeOutdatedLibs(html);
        const f = findings.find(f => f.title.includes('jQuery'));
        expect(f).toBeDefined();
        expect(f.code).toContain('CVE');
    });

    test('detecta jQuery 2.x como vulnerable', () => {
        const html = '<script src="jquery-2.2.4.min.js"></script>';
        const findings = analyzeOutdatedLibs(html);
        const f = findings.find(f => f.title.includes('jQuery'));
        expect(f).toBeDefined();
    });

    test('detecta AngularJS 1.x como EOL', () => {
        const html = '<script src="angular/1.8.2/angular.min.js"></script>';
        const findings = analyzeOutdatedLibs(html);
        const f = findings.find(f => f.title.includes('AngularJS'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('H'); // EOL = High
    });

    test('detecta Bootstrap 3.x como vulnerable', () => {
        const html = '<link href="bootstrap/3.3.7/css/bootstrap.min.css">';
        const findings = analyzeOutdatedLibs(html);
        const f = findings.find(f => f.title.includes('Bootstrap'));
        expect(f).toBeDefined();
    });

    test('detecta Moment.js como EOL', () => {
        const html = '<script src="moment/2.29.4/moment.min.js"></script>';
        const findings = analyzeOutdatedLibs(html);
        const f = findings.find(f => f.title.includes('Moment.js'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('H'); // EOL
    });

    test('no reporta librerías modernas', () => {
        const html = '<script src="some-modern-lib.js"></script>';
        const findings = analyzeOutdatedLibs(html);
        expect(findings).toHaveLength(0);
    });

    test('incluye versión segura mínima y CVEs en el reporte', () => {
        const html = '<script src="jquery-1.12.4.min.js"></script>';
        const findings = analyzeOutdatedLibs(html);
        const f = findings.find(f => f.title.includes('jQuery'));
        expect(f.code).toContain('Version segura minima');
        expect(f.code).toContain('CVEs conocidos');
    });
});


describe('analyzeOpenGraph', () => {
    test('retorna array vacío para HTML vacío', () => {
        expect(analyzeOpenGraph('')).toEqual([]);
        expect(analyzeOpenGraph(null)).toEqual([]);
    });

    test('detecta localhost en Open Graph tags', () => {
        const html = '<meta property="og:url" content="http://localhost:3000/page">';
        const findings = analyzeOpenGraph(html);
        const f = findings.find(f => f.title.includes('Open Graph'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('H');
    });

    test('detecta IP privada en Open Graph', () => {
        const html = '<meta property="og:image" content="http://192.168.1.100/image.jpg">';
        const findings = analyzeOpenGraph(html);
        const f = findings.find(f => f.title.includes('Open Graph'));
        expect(f).toBeDefined();
    });

    test('detecta 127.0.0.1 en Open Graph', () => {
        const html = '<meta property="og:url" content="http://127.0.0.1/app">';
        const findings = analyzeOpenGraph(html);
        const f = findings.find(f => f.title.includes('Open Graph'));
        expect(f).toBeDefined();
    });

    test('detecta indicadores de desarrollo en meta tags', () => {
        const html = '<meta name="description" content="Staging environment - test application">';
        const findings = analyzeOpenGraph(html);
        const f = findings.find(f => f.title.includes('desarrollo'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('M');
    });

    test('no reporta OG tags con URLs públicas', () => {
        const html = '<meta property="og:url" content="https://example.com/page"><meta property="og:image" content="https://example.com/image.jpg">';
        const findings = analyzeOpenGraph(html);
        const f = findings.find(f => f.title.includes('Open Graph'));
        expect(f).toBeUndefined();
    });
});


describe('analyzeThirdPartyScripts', () => {
    const BASE_URL = 'https://example.com';

    test('retorna findings vacíos para HTML vacío', () => {
        const { findings } = analyzeThirdPartyScripts('', BASE_URL);
        expect(findings).toEqual([]);
    });

    test('detecta scripts externos sin SRI', () => {
        const html = '<script src="https://cdn.example.com/lib.js"></script>';
        const { findings } = analyzeThirdPartyScripts(html, BASE_URL);
        const f = findings.find(f => f.title.includes('SRI'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('M');
    });

    test('no reporta script externo con SRI', () => {
        const html = '<script src="https://cdn.example.com/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script>';
        const { findings, stats } = analyzeThirdPartyScripts(html, BASE_URL);
        expect(stats.withSRI).toBe(1);
        expect(stats.withoutSRI).toBe(0);
    });

    test('detecta scripts de CDN público riesgoso', () => {
        const html = '<script src="https://cdn.jsdelivr.net/npm/lib@latest/dist/lib.js"></script>';
        const { findings } = analyzeThirdPartyScripts(html, BASE_URL);
        const f = findings.find(f => f.title.includes('CDN público'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('M');
    });

    test('contabiliza scripts internos vs externos correctamente', () => {
        const html = `
      <script src="/js/app.js"></script>
      <script src="https://external.com/lib.js"></script>
    `;
        const { stats } = analyzeThirdPartyScripts(html, BASE_URL);
        expect(stats.internal).toBe(1);
        expect(stats.external).toBe(1);
    });

    test('detecta alto número de scripts externos (>5)', () => {
        let html = '';
        for (let i = 0; i < 7; i++) {
            html += `<script src="https://ext${i}.com/lib.js"></script>\n`;
        }
        const { findings } = analyzeThirdPartyScripts(html, BASE_URL);
        const f = findings.find(f => f.title.includes('Alto número'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('L');
    });
});

describe('analyzePerformanceSecurity', () => {
    test('retorna findings vacíos para HTML vacío', () => {
        const { findings } = analyzePerformanceSecurity('', {});
        expect(findings).toEqual([]);
    });

    test('detecta ausencia de Cache-Control', () => {
        const { findings } = analyzePerformanceSecurity('<html><body>Hello</body></html>', {});
        const f = findings.find(f => f.title.includes('Cache-Control'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('L');
    });

    test('no reporta Cache-Control si está presente', () => {
        const { findings } = analyzePerformanceSecurity(
            '<html><body>Hello</body></html>',
            { 'cache-control': 'no-store, private' }
        );
        const f = findings.find(f => f.title.includes('Cache-Control'));
        expect(f).toBeUndefined();
    });

    test('detecta información de debug en HTML', () => {
        const html = '<html><body>Uncaught exception at Module.load - stack trace follows</body></html>';
        const { findings } = analyzePerformanceSecurity(html, {});
        const f = findings.find(f => f.title.includes('debug'));
        expect(f).toBeDefined();
        expect(f.sev).toBe('H');
    });

    test('genera métricas correctas', () => {
        const html = `
      <html>
        <head><style>.a{}</style><link rel="stylesheet" href="x.css"></head>
        <body>
          <script>var a=1;</script>
          <script src="app.js"></script>
          <img src="photo.jpg"><img src="logo.png">
          <iframe src="embed.html"></iframe>
          <form><input><input></form>
        </body>
      </html>
    `;
        const { metrics } = analyzePerformanceSecurity(html, { 'cache-control': 'no-cache' });
        expect(metrics.scripts).toBe(2);
        expect(metrics.styles).toBe(2); // 1 <style> + 1 <link stylesheet>
        expect(metrics.images).toBe(2);
        expect(metrics.iframes).toBe(1);
        expect(metrics.forms).toBe(1);
        expect(metrics.inputs).toBe(2);
    });
});
