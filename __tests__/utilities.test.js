
'use strict';

const {
    sevOrder,
    escHtml,
    calcSimilarity,
    generateAIPrompt,
    sleep,
} = require('../app.testable');


describe('sevOrder', () => {
    test('retorna 0 para severidad Crítica (C)', () => {
        expect(sevOrder('C')).toBe(0);
    });

    test('retorna 1 para severidad Alta (H)', () => {
        expect(sevOrder('H')).toBe(1);
    });

    test('retorna 2 para severidad Media (M)', () => {
        expect(sevOrder('M')).toBe(2);
    });

    test('retorna 3 para severidad Baja (L)', () => {
        expect(sevOrder('L')).toBe(3);
    });

    test('retorna 4 para Informativo (I)', () => {
        expect(sevOrder('I')).toBe(4);
    });

    test('retorna 5 para severidad desconocida', () => {
        expect(sevOrder('X')).toBe(5);
        expect(sevOrder('')).toBe(5);
        expect(sevOrder(null)).toBe(5);
    });

    test('el orden es correcto: C < H < M < L < I', () => {
        const severities = ['C', 'H', 'M', 'L', 'I'];
        for (let i = 0; i < severities.length - 1; i++) {
            expect(sevOrder(severities[i])).toBeLessThan(sevOrder(severities[i + 1]));
        }
    });
});


describe('escHtml', () => {
    test('escapa caracteres peligrosos de HTML', () => {
        expect(escHtml('<script>alert("xss")</script>')).toBe(
            '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
        );
    });

    test('escapa ampersands', () => {
        expect(escHtml('a & b')).toBe('a &amp; b');
    });

    test('maneja strings vacíos', () => {
        expect(escHtml('')).toBe('');
    });

    test('convierte números a string', () => {
        expect(escHtml(42)).toBe('42');
    });

    test('maneja null/undefined graciosamente', () => {
        expect(escHtml(null)).toBe('null');
        expect(escHtml(undefined)).toBe('undefined');
    });

    test('no modifica texto sin caracteres especiales', () => {
        expect(escHtml('Texto normal sin peligro')).toBe('Texto normal sin peligro');
    });

    test('escapa múltiples caracteres mezclados', () => {
        expect(escHtml('a < b & c > d "quotes"')).toBe(
            'a &lt; b &amp; c &gt; d &quot;quotes&quot;'
        );
    });
});


describe('calcSimilarity', () => {
    test('retorna 1 para strings idénticos', () => {
        expect(calcSimilarity('hello world', 'hello world')).toBe(1);
    });

    test('retorna 0 para strings vacíos/nulos', () => {
        expect(calcSimilarity('', 'hello')).toBe(0);
        expect(calcSimilarity(null, 'hello')).toBe(0);
        expect(calcSimilarity('hello', null)).toBe(0);
    });

    test('retorna 1 para strings con whitespace diferente pero mismo contenido', () => {
        expect(calcSimilarity('hello  world', 'hello world')).toBe(1);
    });

    test('retorna alta similitud para strings muy parecidos', () => {
        const sim = calcSimilarity('Page Not Found', 'Page Not Found!');
        expect(sim).toBeGreaterThan(0.8);
    });

    test('retorna baja similitud para strings muy diferentes', () => {
        const sim = calcSimilarity('Hello World', 'xyz abc 123');
        expect(sim).toBeLessThan(0.3);
    });

    test('es simétrico (misma similitud en ambas direcciones)', () => {
        const a = 'Error 404 Not Found';
        const b = '404 Page Not Found Here';
        expect(calcSimilarity(a, b)).toBeCloseTo(calcSimilarity(b, a), 10);
    });
});


describe('sleep', () => {
    test('retorna una Promise', () => {
        const result = sleep(1);
        expect(result).toBeInstanceOf(Promise);
    });

    test('resuelve después del tiempo dado', async () => {
        const start = Date.now();
        await sleep(50);
        const elapsed = Date.now() - start;
        expect(elapsed).toBeGreaterThanOrEqual(40); // small tolerance
    });
});


describe('generateAIPrompt', () => {
    const baseFinding = {
        sev: 'H',
        title: 'Header X-Frame-Options faltante',
        desc: 'No se encuentra la cabecera <code>X-Frame-Options</code>.',
        code: 'X-Frame-Options: [AUSENTE]',
        fix: 'Agrega X-Frame-Options: DENY.'
    };

    test('genera prompt con severidad correcta', () => {
        const prompt = generateAIPrompt(baseFinding, 'https://test.com');
        expect(prompt).toContain('[ALTO]');
        expect(prompt).toContain('https://test.com');
    });

    test('remueve tags HTML de la descripción', () => {
        const prompt = generateAIPrompt(baseFinding, 'https://test.com');
        expect(prompt).not.toContain('<code>');
        expect(prompt).not.toContain('</code>');
        expect(prompt).toContain('X-Frame-Options');
    });

    test('incluye la evidencia (code) cuando existe', () => {
        const prompt = generateAIPrompt(baseFinding, 'https://test.com');
        expect(prompt).toContain('EVIDENCIA:');
        expect(prompt).toContain('X-Frame-Options: [AUSENTE]');
    });

    test('omite la sección de evidencia si no hay code', () => {
        const finding = { ...baseFinding, code: '' };
        const prompt = generateAIPrompt(finding, 'https://test.com');
        expect(prompt).not.toContain('EVIDENCIA:');
    });

    test('incluye la corrección recomendada', () => {
        const prompt = generateAIPrompt(baseFinding, 'https://test.com');
        expect(prompt).toContain('CORRECCION RECOMENDADA:');
        expect(prompt).toContain('Agrega X-Frame-Options: DENY.');
    });

    test('mapea todas las severidades correctamente', () => {
        const sevMap = { C: 'CRITICO', H: 'ALTO', M: 'MEDIO', L: 'BAJO', I: 'INFO' };
        for (const [sev, name] of Object.entries(sevMap)) {
            const finding = { ...baseFinding, sev };
            const prompt = generateAIPrompt(finding, 'https://test.com');
            expect(prompt).toContain(`[${name}]`);
        }
    });

    test('incluye instrucciones para el AI', () => {
        const prompt = generateAIPrompt(baseFinding, 'https://test.com');
        expect(prompt).toContain('Explica exactamente que archivo(s)');
        expect(prompt).toContain('Nginx, Apache y Cloudflare');
    });
});
