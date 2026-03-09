
'use strict';

const { SEC_HEADERS, SENSITIVE_PATHS } = require('../app.testable');


describe('SEC_HEADERS', () => {
    test('tiene al menos 10 headers de seguridad definidos', () => {
        expect(SEC_HEADERS.length).toBeGreaterThanOrEqual(10);
    });

    test('cada header tiene las propiedades requeridas', () => {
        for (const header of SEC_HEADERS) {
            expect(header).toHaveProperty('h');
            expect(header).toHaveProperty('label');
            expect(header).toHaveProperty('good');
            expect(header).toHaveProperty('sev');
            expect(header).toHaveProperty('fix');
            expect(typeof header.h).toBe('string');
            expect(typeof header.label).toBe('string');
            expect(typeof header.good).toBe('function');
            expect(['C', 'H', 'M', 'L', 'I']).toContain(header.sev);
            expect(typeof header.fix).toBe('string');
        }
    });

    test('los nombres de headers están en minúsculas', () => {
        for (const header of SEC_HEADERS) {
            expect(header.h).toBe(header.h.toLowerCase());
        }
    });

    test('contiene los headers críticos de seguridad', () => {
        const headerNames = SEC_HEADERS.map(h => h.h);
        expect(headerNames).toContain('x-frame-options');
        expect(headerNames).toContain('content-security-policy');
        expect(headerNames).toContain('strict-transport-security');
        expect(headerNames).toContain('x-content-type-options');
        expect(headerNames).toContain('referrer-policy');
    });

    test('evalúa correctamente los valores "good" de headers de presencia', () => {
        const xfo = SEC_HEADERS.find(h => h.h === 'x-frame-options');
        expect(xfo.good('DENY')).toBe(true);
        expect(xfo.good('')).toBe(false);
        expect(xfo.good(null)).toBe(false);
        expect(xfo.good(undefined)).toBe(false);
    });

    test('evalúa correctamente X-Content-Type-Options', () => {
        const xcto = SEC_HEADERS.find(h => h.h === 'x-content-type-options');
        expect(xcto.good('nosniff')).toBe(true);
        expect(xcto.good('other')).toBe(false);
        expect(xcto.good('')).toBe(false);
    });

    test('evalúa correctamente headers que NO deben existir (x-powered-by)', () => {
        const xpb = SEC_HEADERS.find(h => h.h === 'x-powered-by');
        // good means it's NOT present
        expect(xpb.good(undefined)).toBe(true);
        expect(xpb.good(null)).toBe(true);
        expect(xpb.good('')).toBe(true);
        expect(xpb.good('PHP/8.2')).toBe(false);
    });

    test('evalúa correctamente server header (no debe existir)', () => {
        const srv = SEC_HEADERS.find(h => h.h === 'server');
        expect(srv.good(undefined)).toBe(true);
        expect(srv.good('nginx/1.24')).toBe(false);
    });
});


describe('SENSITIVE_PATHS', () => {
    test('tiene al menos 10 rutas sensibles definidas', () => {
        expect(SENSITIVE_PATHS.length).toBeGreaterThanOrEqual(10);
    });

    test('cada ruta tiene las propiedades requeridas', () => {
        for (const path of SENSITIVE_PATHS) {
            expect(path).toHaveProperty('p');
            expect(path).toHaveProperty('label');
            expect(path).toHaveProperty('sev');
            expect(typeof path.p).toBe('string');
            expect(typeof path.label).toBe('string');
            expect(['C', 'H', 'M', 'L', 'I']).toContain(path.sev);
        }
    });

    test('todas las rutas comienzan con /', () => {
        for (const path of SENSITIVE_PATHS) {
            expect(path.p.startsWith('/')).toBe(true);
        }
    });

    test('contiene rutas críticas como .env y .git', () => {
        const paths = SENSITIVE_PATHS.map(p => p.p);
        expect(paths).toContain('/.env');
        expect(paths).toContain('/.git/HEAD');
    });

    test('las rutas .env tienen severidad Crítica', () => {
        const envPaths = SENSITIVE_PATHS.filter(p => p.p.includes('.env'));
        for (const ep of envPaths) {
            expect(ep.sev).toBe('C');
        }
    });

    test('las rutas informativas tienen severidad I', () => {
        const robotsPath = SENSITIVE_PATHS.find(p => p.p === '/robots.txt');
        expect(robotsPath).toBeDefined();
        expect(robotsPath.sev).toBe('I');
    });

    test('no hay rutas duplicadas', () => {
        const paths = SENSITIVE_PATHS.map(p => p.p);
        const uniquePaths = [...new Set(paths)];
        expect(paths.length).toBe(uniquePaths.length);
    });
});
