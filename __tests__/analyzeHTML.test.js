
'use strict';

const { analyzeHTML } = require('../app.testable');

const BASE_URL = 'https://example.com';

describe('analyzeHTML', () => {

    // ── Input Validation ──
    describe('Validación de entrada', () => {
        test('retorna array vacío para HTML vacío', () => {
            expect(analyzeHTML('', BASE_URL)).toEqual([]);
        });

        test('retorna array vacío para HTML nulo', () => {
            expect(analyzeHTML(null, BASE_URL)).toEqual([]);
        });

        test('retorna array vacío para HTML undefined', () => {
            expect(analyzeHTML(undefined, BASE_URL)).toEqual([]);
        });
    });

    // ── Localhost in canonical ──
    describe('Canonical apunta a localhost', () => {
        test('detecta localhost en canonical', () => {
            const html = '<link rel="canonical" href="http://localhost:3000/page">';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('localhost'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('C');
        });

        test('detecta localhost en og:url', () => {
            const html = '<meta property="og:url" content="http://localhost/app">';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('localhost'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('C');
        });

        test('no reporta localhost sin canonical/og:url', () => {
            const html = '<p>Visit localhost for more info</p>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('localhost'));
            expect(f).toBeUndefined();
        });
    });

    // ── API Keys ──
    describe('API Keys expuestas', () => {
        test('detecta Stripe Secret Key en HTML', () => {
            const html = `<script>const key = "sk_mock_abcdefghijklmnopqrst1234";</script>`;
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('Stripe'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('C');
        });

        test('detecta AWS Access Key en HTML', () => {
            const html = `<script>var awsKey = "AKIAIOSFODNN7EXAMPLE";</script>`;
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('AWS'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('C');
        });

        test('detecta passwords hardcodeadas en HTML', () => {
            const html = `<script>const password = "mi_password_secreto";</script>`;
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('Password'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('C');
        });
    });

    // ── Build ID ──
    describe('Build ID expuesto', () => {
        test('detecta buildId en HTML', () => {
            const html = '<script id="__NEXT_DATA__">{"buildId":"abc123xyz"}</script>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('Build ID'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('H');
        });

        test('detecta build_id en HTML', () => {
            const html = '<meta name="build_id" content="v1.2.3">';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('Build ID'));
            expect(f).toBeDefined();
        });
    });

    // ── CSRF ──
    describe('Formularios sin CSRF', () => {
        test('detecta formulario sin token CSRF', () => {
            const html = '<form action="/submit" method="POST"><input name="email"><button>Send</button></form>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('CSRF'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('H');
        });

        test('no reporta si el formulario tiene token CSRF', () => {
            const html = '<form action="/submit"><input name="csrf" value="token123"><button>Send</button></form>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('CSRF'));
            expect(f).toBeUndefined();
        });

        test('detecta múltiples formularios sin CSRF', () => {
            const html = '<form action="/a"><input></form><form action="/b"><input></form>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('CSRF'));
            expect(f).toBeDefined();
            expect(f.title).toContain('2');
        });
    });

    // ── Emails ──
    describe('Emails expuestos', () => {
        test('detecta emails en HTML', () => {
            const html = '<p>Contact us at admin@example.com</p>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('Email'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('I');
        });

        test('detecta múltiples emails', () => {
            const html = '<p>admin@test.com, info@test.com, support@test.com</p>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('Email'));
            expect(f).toBeDefined();
        });
    });

    // ── Mixed Content ──
    describe('Contenido mixto HTTP', () => {
        test('detecta src con HTTP', () => {
            const html = '<img src="http://example.com/image.jpg">';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('mixto'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('M');
        });

        test('detecta href con HTTP', () => {
            const html = '<link href="http://example.com/style.css" rel="stylesheet">';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('mixto'));
            expect(f).toBeDefined();
        });

        test('no reporta si todo es HTTPS', () => {
            const html = '<img src="https://example.com/image.jpg"><link href="https://example.com/style.css">';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('mixto'));
            expect(f).toBeUndefined();
        });
    });

    // ── HTML Comments ──
    describe('Comentarios HTML sensibles', () => {
        test('detecta comentarios con TODO', () => {
            const html = '<!-- TODO: fix authentication bypass -->';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('comentario'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('M');
        });

        test('detecta comentarios con password', () => {
            const html = '<!-- password: admin123 -->';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('comentario'));
            expect(f).toBeDefined();
        });

        test('detecta comentarios con debug', () => {
            const html = '<!-- debug mode enabled -->';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('comentario'));
            expect(f).toBeDefined();
        });

        test('no reporta comentarios inofensivos', () => {
            const html = '<!-- Navigation menu --><p>Hello</p>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('comentario'));
            expect(f).toBeUndefined();
        });
    });

    // ── External iframes ──
    describe('iframes externos', () => {
        test('detecta iframe externo', () => {
            const html = '<iframe src="https://malicious-site.com/embed"></iframe>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('iframe'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('M');
        });

        test('no reporta iframe del mismo dominio', () => {
            const html = '<iframe src="https://example.com/embed"></iframe>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('iframe'));
            expect(f).toBeUndefined();
        });
    });

    // ── target="_blank" sin noopener ──
    describe('Links target="_blank" sin noopener', () => {
        test('detecta link con _blank sin noopener', () => {
            const html = '<a href="https://ext.com" target="_blank">Link</a>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('noopener'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('L');
        });

        test('no reporta si tiene rel="noopener"', () => {
            const html = '<a href="https://ext.com" target="_blank" rel="noopener noreferrer">Link</a>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('noopener'));
            expect(f).toBeUndefined();
        });
    });

    // ── Inline Scripts ──
    describe('Scripts inline', () => {
        test('detecta muchos scripts inline (>3)', () => {
            const html = `
        <script>var a=1;</script>
        <script>var b=2;</script>
        <script>var c=3;</script>
        <script>var d=4;</script>
      `;
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('inline'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('L');
        });

        test('no reporta 3 o menos scripts inline', () => {
            const html = '<script>var a=1;</script><script>var b=2;</script>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('inline'));
            expect(f).toBeUndefined();
        });
    });

    // ── Viewport ──
    describe('Meta viewport', () => {
        test('detecta viewport ausente', () => {
            const html = '<html><head><title>Test</title></head><body></body></html>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('viewport'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('L');
        });

        test('no reporta si viewport está presente', () => {
            const html = '<html><head><meta name="viewport" content="width=device-width"></head></html>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('viewport'));
            expect(f).toBeUndefined();
        });
    });

    // ── Favicon ──
    describe('Favicon', () => {
        test('detecta favicon ausente', () => {
            const html = '<html><head><title>Test</title></head><body></body></html>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('favicon'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('I');
        });

        test('no reporta si favicon está presente', () => {
            const html = '<html><head><link rel="icon" href="favicon.ico"></head></html>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('favicon'));
            expect(f).toBeUndefined();
        });
    });

    // ── Lang attribute ──
    describe('Atributo lang', () => {
        test('detecta lang ausente en <html>', () => {
            const html = '<html><head></head><body></body></html>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('lang'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('I');
        });

        test('no reporta si lang está presente', () => {
            const html = '<html lang="es"><head></head><body></body></html>';
            const findings = analyzeHTML(html, BASE_URL);
            const f = findings.find(f => f.title.includes('lang'));
            expect(f).toBeUndefined();
        });
    });
});
